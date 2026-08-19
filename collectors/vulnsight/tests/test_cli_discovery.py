"""Command-line tests for read-only discovery (no networking)."""

from __future__ import annotations

import pytest

from vulnsight import cli
from vulnsight.nessus.client import Outcome
from vulnsight.nessus.discovery import DiscoveryError
from vulnsight.nessus.models import (
    HistoryDiscoveryResult,
    HistorySummary,
    ScanDiscoveryResult,
    ScanSummary,
)
from conftest import FAKE_ACCESS_KEY, FAKE_SECRET_KEY, make_config

#: The identifier the deployed standalone scanner actually returned.
OBSERVED_PROVIDER_UUID = "01234567-89ab-cdef-0123-456789abcdef0123456789abcdef"

SCAN_ROWS = ScanDiscoveryResult(
    scans=(
        ScanSummary(
            scan_id=5,
            uuid=OBSERVED_PROVIDER_UUID,
            name="synthetic-lab-scan",
            status="completed",
            folder_id=3,
            last_modification_date=1_700_000_000,
        ),
        ScanSummary(scan_id=7),
    )
)

HISTORY_ROWS = HistoryDiscoveryResult(
    scan_identifier="5",
    runs=(
        HistorySummary(
            history_id=11,
            uuid="10000011-89ab-cdef-0123-456789abcdef",
            status="completed",
            creation_date=1_700_000_000,
            last_modification_date=1_700_003_600,
            run_type="local",
            is_rollover=False,
        ),
        HistorySummary(history_id=12, status="running"),
    ),
)


@pytest.fixture
def stub_discovery(monkeypatch):
    """Replace configuration loading and the discovery functions."""

    calls: dict[str, object] = {}

    def _install(*, scans=None, history=None, exception=None, config=None):
        monkeypatch.setattr(
            cli, "load_config", lambda: make_config() if config is None else config
        )

        def _list_scans(cfg):
            calls["list_scans"] = cfg
            if exception is not None:
                raise exception
            return scans

        def _list_history(cfg, identifier):
            calls["list_scan_history"] = identifier
            if exception is not None:
                raise exception
            return history

        monkeypatch.setattr(cli, "list_scans", _list_scans)
        monkeypatch.setattr(cli, "list_scan_history", _list_history)
        return calls

    return _install


# ---------------------------------------------------------------------------
# Scan listing
# ---------------------------------------------------------------------------


def test_scan_list_output(stub_discovery, capsys):
    stub_discovery(scans=SCAN_ROWS)

    code = cli.main(["nessus", "scans", "list"])
    out = capsys.readouterr().out

    assert code == 0
    assert "SCAN ID" in out and "LAST MODIFIED (UTC)" in out
    assert "synthetic-lab-scan" in out
    assert OBSERVED_PROVIDER_UUID in out
    assert "completed" in out
    assert "2023-11-14T22:13:20Z" in out
    # The second scan supplies nothing but its ID.
    assert "not supplied" in out
    # Ordering follows the model, which the discovery layer already sorted.
    assert out.index("\n5 ") < out.index("\n7 ")


def test_scan_list_is_a_table_and_one_next_line(stub_discovery, capsys):
    stub_discovery(scans=SCAN_ROWS)

    cli.main(["nessus", "scans", "list"])
    lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]

    # Header, rule, two rows, one Next: line — and nothing else.
    assert len(lines) == 5
    assert lines[0].startswith("SCAN ID")
    assert lines[-1] == (
        "Next: python -m vulnsight nessus scans histories --scan <SCAN ID>"
    )
    assert sum(line.startswith("Next:") for line in lines) == 1


def test_scan_list_explanatory_paragraphs_are_gone(stub_discovery, capsys):
    stub_discovery(scans=SCAN_ROWS)

    cli.main(["nessus", "scans", "list"])
    out = capsys.readouterr().out

    for removed in (
        "Status values are shown exactly",
        "was not saved",
        "provenance",
        "never selects a scan by name",
        "Nessus scans visible to this account",
    ):
        assert removed not in out


def test_scan_list_emits_a_compact_tls_warning_on_stderr(stub_discovery, capsys):
    stub_discovery(scans=SCAN_ROWS, config=make_config(NESSUS_VERIFY_TLS="false"))

    code = cli.main(["nessus", "scans", "list"])
    captured = capsys.readouterr()

    assert code == 0
    warnings = [line for line in captured.err.splitlines() if line.strip()]
    assert len(warnings) == 1
    assert warnings[0].startswith("Warning: ")
    assert "TLS" in warnings[0]
    assert "Warning" not in captured.out


def test_scan_list_is_deterministic(stub_discovery, capsys):
    stub_discovery(scans=SCAN_ROWS)
    cli.main(["nessus", "scans", "list"])
    first = capsys.readouterr().out

    stub_discovery(scans=SCAN_ROWS)
    cli.main(["nessus", "scans", "list"])
    second = capsys.readouterr().out

    assert first == second


def test_empty_scan_list_is_a_success(stub_discovery, capsys):
    stub_discovery(scans=ScanDiscoveryResult(scans=()))

    code = cli.main(["nessus", "scans", "list"])
    captured = capsys.readouterr()

    assert code == 0
    assert "No scans returned" in captured.out
    assert captured.err == ""


@pytest.mark.parametrize(
    ("outcome", "expected_code"),
    [
        (Outcome.NETWORK_ERROR, 3),
        (Outcome.AUTHENTICATION_ERROR, 4),
        (Outcome.API_ERROR, 5),
    ],
)
def test_discovery_error_exit_codes(stub_discovery, capsys, outcome, expected_code):
    stub_discovery(exception=DiscoveryError(outcome, "Synthetic discovery failure."))

    code = cli.main(["nessus", "scans", "list"])
    captured = capsys.readouterr()

    assert code == expected_code
    assert "Synthetic discovery failure." in captured.err
    assert captured.out == ""


def test_unexpected_internal_error_exits_with_code_five(stub_discovery, capsys):
    stub_discovery(exception=RuntimeError("something unforeseen"))

    code = cli.main(["nessus", "scans", "list"])
    captured = capsys.readouterr()

    assert code == 5
    assert "Unexpected internal error" in captured.err
    assert "something unforeseen" not in captured.err
    assert "Traceback" not in captured.err


def test_missing_env_file_is_a_configuration_error(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    code = cli.main(["nessus", "scans", "list"])

    assert code == 2
    assert "Configuration error" in capsys.readouterr().err


# ---------------------------------------------------------------------------
# History listing
# ---------------------------------------------------------------------------


def test_history_output(stub_discovery, capsys):
    calls = stub_discovery(history=HISTORY_ROWS)

    code = cli.main(["nessus", "scans", "histories", "--scan", "5"])
    out = capsys.readouterr().out

    assert code == 0
    assert calls["list_scan_history"].value == "5"
    assert "HISTORY ID" in out and "EXPORT-ELIGIBLE" in out
    assert "10000011-89ab-cdef-0123-456789abcdef" in out
    assert "2023-11-14T22:13:20Z" in out
    assert "running" in out


def test_history_output_is_a_table_and_one_next_line(stub_discovery, capsys):
    stub_discovery(history=HISTORY_ROWS)

    cli.main(["nessus", "scans", "histories", "--scan", "5"])
    lines = [line for line in capsys.readouterr().out.splitlines() if line.strip()]

    # Header, rule, two rows, one Next: line — and nothing else.
    assert len(lines) == 5
    assert lines[0].startswith("HISTORY ID")
    assert lines[-1] == (
        "Next: python -m vulnsight nessus scans export --scan 5 "
        '--history <HISTORY_ID> --output-dir ".\\evidence\\raw\\nessus"'
    )
    assert sum(line.startswith("Next:") for line in lines) == 1


def test_the_history_next_line_never_claims_a_selection(stub_discovery, capsys):
    stub_discovery(history=HISTORY_ROWS)

    cli.main(["nessus", "scans", "histories", "--scan", "5"])
    out = capsys.readouterr().out

    assert "<HISTORY_ID>" in out
    for claim in ("selected", "chosen", "1 run(s) are export-eligible"):
        assert claim not in out


def test_history_explanatory_paragraphs_are_gone(stub_discovery, capsys):
    stub_discovery(history=HISTORY_ROWS)

    cli.main(["nessus", "scans", "histories", "--scan", "5"])
    out = capsys.readouterr().out

    for removed in (
        "Source: the 'history' collection",
        "were not parsed, shown or saved",
        "Status values are shown exactly",
        "No run has been selected",
        "Execution history for scan",
    ):
        assert removed not in out


def test_history_output_never_mentions_paging(stub_discovery, capsys):
    stub_discovery(history=HISTORY_ROWS)

    cli.main(["nessus", "scans", "histories", "--scan", "5"])
    out = capsys.readouterr().out.lower()

    assert "paging" not in out
    assert "page(s)" not in out
    assert "pagination" not in out


def test_empty_history_is_a_success(stub_discovery, capsys):
    stub_discovery(history=HistoryDiscoveryResult(scan_identifier="5", runs=()))

    code = cli.main(["nessus", "scans", "histories", "--scan", "5"])
    captured = capsys.readouterr()

    assert code == 0
    assert "No history returned for scan '5'" in captured.out
    assert captured.err == ""


def test_scan_not_found_is_not_reported_as_authentication(stub_discovery, capsys):
    stub_discovery(
        exception=DiscoveryError(
            Outcome.API_ERROR,
            "Scan identifier '5' was not found, or is not visible to the "
            "configured account (HTTP 404). This is not an authentication "
            "failure.",
        )
    )

    code = cli.main(["nessus", "scans", "histories", "--scan", "5"])
    err = capsys.readouterr().err

    assert code == 5
    assert "was not found" in err
    assert "not an authentication failure" in err


def test_method_not_allowed_is_reported_as_api_incompatibility(
    stub_discovery, capsys
):
    stub_discovery(
        exception=DiscoveryError(
            Outcome.API_ERROR,
            "The scanner rejected GET /scans/5 with HTTP 405 (method not "
            "allowed). The deployed Nessus API does not support this "
            "endpoint.",
        )
    )

    code = cli.main(["nessus", "scans", "histories", "--scan", "5"])
    err = capsys.readouterr().err

    assert code == 5
    assert "405" in err
    assert "does not support this endpoint" in err


@pytest.mark.parametrize(
    "value",
    [
        "0",
        "-1",
        "",
        "   ",
        "../7",
        "7/history",
        "7\\history",
        "7?a=1",
        "7#f",
        "synthetic-lab-scan",
        "latest",
    ],
)
def test_malformed_scan_identifier_exits_two_without_a_request(
    stub_discovery, capsys, value
):
    calls = stub_discovery(history=HISTORY_ROWS)

    code = cli.main(["nessus", "scans", "histories", "--scan", value])
    captured = capsys.readouterr()

    assert code == 2
    assert "Invalid --scan value" in captured.err
    assert "list_scan_history" not in calls


@pytest.mark.parametrize(
    "value", ["5", OBSERVED_PROVIDER_UUID, "01234567-89ab-cdef-0123-456789abcdef"]
)
def test_accepted_identifiers_reach_the_discovery_layer(stub_discovery, value):
    calls = stub_discovery(
        history=HistoryDiscoveryResult(scan_identifier=value, runs=())
    )

    code = cli.main(["nessus", "scans", "histories", "--scan", value])

    assert code == 0
    assert calls["list_scan_history"].value == value


def test_scan_argument_is_required():
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["nessus", "scans", "histories"])

    assert excinfo.value.code == 2


# ---------------------------------------------------------------------------
# Contract regressions
# ---------------------------------------------------------------------------


def test_scans_without_a_subcommand_prints_help(capsys):
    code = cli.main(["nessus", "scans"])

    assert code == 2
    assert "usage:" in capsys.readouterr().out


def test_check_command_is_still_registered():
    parser = cli.build_parser()
    args = parser.parse_args(["nessus", "check"])

    assert args.command == "nessus"
    assert args.subcommand == "check"


def test_histories_help_recommends_the_numeric_scan_id(capsys):
    with pytest.raises(SystemExit):
        cli.main(["nessus", "scans", "histories", "--help"])

    # argparse re-wraps help text, so compare on normalised whitespace.
    out = " ".join(capsys.readouterr().out.split())
    assert "numeric SCAN ID" in out
    assert "never selects a scan by name" in out


def test_discovery_output_never_contains_secrets(stub_discovery, capsys):
    stub_discovery(scans=SCAN_ROWS)
    cli.main(["nessus", "scans", "list"])
    stub_discovery(history=HISTORY_ROWS)
    cli.main(["nessus", "scans", "histories", "--scan", "5"])

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert FAKE_ACCESS_KEY not in rendered
    assert FAKE_SECRET_KEY not in rendered
