"""Command-line tests for native .nessus export (no networking)."""

from __future__ import annotations

from pathlib import Path

import pytest

from vulnsight import cli
from vulnsight.nessus.acquisition import AcquisitionResult
from vulnsight.nessus.client import Outcome
from vulnsight.nessus.errors import EvidenceError, ExportError, XmlValidationError
from vulnsight.nessus.models import HistorySummary
from vulnsight.nessus.nessus_xml import XmlValidation
from conftest import FAKE_ACCESS_KEY, FAKE_SECRET_KEY, make_config

DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
OUTPUT_DIR = r".\evidence\raw\nessus"

RESULT = AcquisitionResult(
    raw_path=Path(OUTPUT_DIR) / "synthetic-lab-scan__scan-5__history-6.nessus",
    manifest_path=Path(OUTPUT_DIR) / "synthetic-lab-scan__scan-5__history-6.manifest.json",
    size_bytes=48_213,
    sha256=DIGEST,
    file_id="9",
    polls=2,
    history=HistorySummary(history_id=6, status="completed"),
    validation=XmlValidation(
        root="NessusClientData_v2",
        report_count=1,
        report_host_count=1,
        report_item_count=2,
    ),
)


@pytest.fixture
def stub_export(monkeypatch):
    """Replace configuration loading and the acquisition pipeline."""

    calls: dict[str, object] = {}

    def _install(*, result=RESULT, exception=None, config=None):
        monkeypatch.setattr(
            cli, "load_config", lambda: make_config() if config is None else config
        )

        def _acquire(cfg, scan, history_id, output_dir, **kwargs):
            calls["scan"] = scan
            calls["history_id"] = history_id
            calls["output_dir"] = output_dir
            if exception is not None:
                raise exception
            return result

        monkeypatch.setattr(cli, "acquire_export", _acquire)
        return calls

    return _install


def export_argv(scan="5", history="6", output_dir=OUTPUT_DIR):
    return [
        "nessus",
        "scans",
        "export",
        "--scan",
        scan,
        "--history",
        history,
        "--output-dir",
        output_dir,
    ]


# ---------------------------------------------------------------------------
# Successful export output
# ---------------------------------------------------------------------------


def test_successful_export_prints_a_compact_table(stub_export, capsys):
    calls = stub_export()

    code = cli.main(export_argv())
    captured = capsys.readouterr()

    assert code == 0
    assert calls["scan"].numeric_id == 5
    assert calls["history_id"] == 6
    assert calls["output_dir"] == OUTPUT_DIR
    lines = captured.out.strip().splitlines()
    assert lines[0].split() == ["ITEM", "VALUE"]
    assert lines[1].startswith("----")
    assert lines[2].startswith("File")
    assert lines[3].startswith("Manifest")
    assert lines[4].startswith("Bytes")
    assert lines[5].startswith("SHA-256")
    assert len(lines) == 6
    assert DIGEST in captured.out
    assert "48213" in captured.out
    assert captured.err == ""


def test_successful_export_prints_no_essay(stub_export, capsys):
    stub_export()

    cli.main(export_argv())
    out = capsys.readouterr().out

    for forbidden in ("Next:", "Status values", "immutab", "provenance"):
        assert forbidden not in out


def test_export_emits_a_compact_tls_warning_on_stderr(stub_export, capsys):
    stub_export(config=make_config(NESSUS_VERIFY_TLS="false"))

    code = cli.main(export_argv())
    captured = capsys.readouterr()

    assert code == 0
    warnings = [line for line in captured.err.splitlines() if line.strip()]
    assert len(warnings) == 1
    assert warnings[0].startswith("Warning: ")
    assert "TLS" in warnings[0]
    assert "Warning" not in captured.out


# ---------------------------------------------------------------------------
# Identifier validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "scan",
    [
        "0",
        "-1",
        "",
        "   ",
        "05",
        "../5",
        "5/export",
        "5\\export",
        "5?a=1",
        "5#f",
        "latest",
        "synthetic-lab-scan",
        "01234567-89ab-cdef-0123-456789abcdef0123456789abcdef",
        "01234567-89ab-cdef-0123-456789abcdef",
    ],
)
def test_export_requires_a_positive_numeric_scan_id(stub_export, capsys, scan):
    calls = stub_export()

    code = cli.main(export_argv(scan=scan))
    captured = capsys.readouterr()

    assert code == 2
    assert "Invalid --scan value" in captured.err
    assert calls == {}


@pytest.mark.parametrize(
    "history",
    [
        "0",
        "-1",
        "",
        "   ",
        "06",
        "../6",
        "6/download",
        "6\\download",
        "6?a=1",
        "6#f",
        "latest",
        "most-recent",
        "10000006-89ab-cdef-0123-456789abcdef",
        "6.0",
    ],
)
def test_export_requires_a_positive_numeric_history_id(stub_export, capsys, history):
    calls = stub_export()

    code = cli.main(export_argv(history=history))
    captured = capsys.readouterr()

    assert code == 2
    assert "Invalid --history value" in captured.err
    assert calls == {}


def test_a_blank_output_directory_is_refused(stub_export, capsys):
    calls = stub_export()

    code = cli.main(export_argv(output_dir="   "))

    assert code == 2
    assert "Invalid --output-dir value" in capsys.readouterr().err
    assert calls == {}


@pytest.mark.parametrize(
    "missing", [["--history", "6"], ["--scan", "5"], ["--scan", "5", "--history", "6"]]
)
def test_every_export_argument_is_required(missing):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["nessus", "scans", "export", *missing])

    assert excinfo.value.code == 2


def test_there_is_no_force_flag():
    with pytest.raises(SystemExit) as excinfo:
        cli.main([*export_argv(), "--force"])

    assert excinfo.value.code == 2


@pytest.mark.parametrize("fmt", ["csv", "html", "pdf", "db"])
def test_no_alternative_export_format_is_offered(fmt):
    with pytest.raises(SystemExit) as excinfo:
        cli.main([*export_argv(), "--format", fmt])

    assert excinfo.value.code == 2


# ---------------------------------------------------------------------------
# Failure reporting
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exception", "expected_code"),
    [
        (ExportError(Outcome.CONFIGURATION_ERROR, "Not completed."), 2),
        (EvidenceError(Outcome.CONFIGURATION_ERROR, "Already exists."), 2),
        (ExportError(Outcome.NETWORK_ERROR, "Connection failed."), 3),
        (ExportError(Outcome.AUTHENTICATION_ERROR, "HTTP 401."), 4),
        (ExportError(Outcome.API_ERROR, "HTTP 500."), 5),
        (XmlValidationError(Outcome.API_ERROR, "Bad XML."), 5),
    ],
)
def test_failures_map_onto_the_exit_code_contract(
    stub_export, capsys, exception, expected_code
):
    stub_export(exception=exception)

    code = cli.main(export_argv())
    captured = capsys.readouterr()

    assert code == expected_code
    assert "Nessus export failed" in captured.err
    assert exception.summary in captured.err
    assert captured.out == ""


def test_failure_output_is_concise_and_actionable(stub_export, capsys):
    stub_export(
        exception=ExportError(
            Outcome.CONFIGURATION_ERROR,
            "History 6 of scan 5 has the provider status 'running'.",
            "detail line",
        )
    )

    cli.main(export_argv())
    err = capsys.readouterr().err.strip().splitlines()

    assert len(err) == 2
    assert err[0].startswith("Nessus export failed: ")
    assert err[1].startswith("Detail: ")
    assert "Traceback" not in "\n".join(err)


def test_an_unexpected_internal_error_exits_with_code_five(stub_export, capsys):
    stub_export(exception=RuntimeError("something unforeseen"))

    code = cli.main(export_argv())
    captured = capsys.readouterr()

    assert code == 5
    assert "Unexpected internal error" in captured.err
    assert "something unforeseen" not in captured.err
    assert "Traceback" not in captured.err


def test_a_filesystem_error_exits_with_code_five(stub_export, capsys):
    stub_export(exception=PermissionError(13, "Access is denied"))

    code = cli.main(export_argv())
    captured = capsys.readouterr()

    assert code == 5
    assert "could not be written" in captured.err
    assert "Access is denied" not in captured.err


def test_missing_configuration_is_reported_before_any_work(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.chdir(tmp_path)

    code = cli.main(export_argv())

    assert code == 2
    assert "Configuration error" in capsys.readouterr().err


def test_export_output_never_contains_secrets(stub_export, capsys):
    stub_export()
    cli.main(export_argv())
    stub_export(exception=ExportError(Outcome.API_ERROR, "Failed."))
    cli.main(export_argv())

    captured = capsys.readouterr()
    rendered = captured.out + captured.err
    assert FAKE_ACCESS_KEY not in rendered
    assert FAKE_SECRET_KEY not in rendered
    assert "token" not in rendered.lower()


# ---------------------------------------------------------------------------
# Help text
# ---------------------------------------------------------------------------


def test_export_help_states_the_explicit_selection_rules(capsys):
    with pytest.raises(SystemExit):
        cli.main(["nessus", "scans", "export", "--help"])

    out = " ".join(capsys.readouterr().out.split())
    assert "no 'latest'" in out
    assert "never overwritten" in out
    assert "no finding is parsed" in out
