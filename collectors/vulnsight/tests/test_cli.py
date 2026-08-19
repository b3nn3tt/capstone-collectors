"""Command-line interface tests (no networking, no real configuration)."""

from __future__ import annotations

import pytest

from vulnsight import cli
from vulnsight.nessus.client import ConnectivityResult, Outcome, Stage
from conftest import FAKE_ACCESS_KEY, FAKE_SECRET_KEY, make_config

ENDPOINT = "https://nessus.lab.invalid:8834"


def make_result(
    outcome: Outcome,
    *,
    verify_tls: bool = True,
    summary: str = "Synthetic outcome.",
    detail: str = "",
    http_status: int | None = None,
    warnings: tuple[str, ...] = (),
) -> ConnectivityResult:
    success = outcome is Outcome.SUCCESS
    return ConnectivityResult(
        outcome=outcome,
        stage=Stage.API_RESPONSE,
        summary=("Nessus connectivity and authentication verified." if success else summary),
        endpoint=ENDPOINT,
        verify_tls=verify_tls,
        detail=detail,
        http_status=200 if success else http_status,
        tcp_connected=True,
        authenticated=success,
        json_valid=success,
        warnings=warnings,
    )


@pytest.fixture
def stub_check(monkeypatch):
    """Replace configuration loading and the connectivity check."""

    def _install(result=None, exception=None):
        monkeypatch.setattr(cli, "load_config", lambda: make_config())

        def _check(config):
            if exception is not None:
                raise exception
            return result

        monkeypatch.setattr(cli, "check_connectivity", _check)

    return _install


@pytest.mark.parametrize(
    ("outcome", "expected_code"),
    [
        (Outcome.SUCCESS, 0),
        (Outcome.CONFIGURATION_ERROR, 2),
        (Outcome.NETWORK_ERROR, 3),
        (Outcome.AUTHENTICATION_ERROR, 4),
        (Outcome.API_ERROR, 5),
    ],
)
def test_exit_code_mapping(stub_check, outcome, expected_code):
    stub_check(result=make_result(outcome))

    assert cli.main(["nessus", "check"]) == expected_code


def test_success_output_is_brief_and_complete(stub_check, capsys):
    stub_check(result=make_result(Outcome.SUCCESS))

    code = cli.main(["nessus", "check"])
    captured = capsys.readouterr()

    assert code == 0
    assert "PASSED" in captured.out
    assert ENDPOINT in captured.out
    assert "TCP connectivity" in captured.out
    assert "API authentication" in captured.out
    assert "GET /scans" in captured.out
    assert "TLS verification" in captured.out
    assert "enabled" in captured.out
    assert captured.err == ""


def test_success_output_states_tls_verification_disabled(stub_check, capsys):
    stub_check(
        result=make_result(
            Outcome.SUCCESS,
            verify_tls=False,
            warnings=("TLS certificate verification is disabled.",),
        )
    )

    cli.main(["nessus", "check"])
    captured = capsys.readouterr()

    assert "DISABLED" in captured.out


def test_success_output_does_not_print_scans(stub_check, capsys):
    stub_check(result=make_result(Outcome.SUCCESS))

    cli.main(["nessus", "check"])
    captured = capsys.readouterr()

    assert "Sensitive Lab Scan Name" not in captured.out
    assert "folders" not in captured.out


def test_missing_env_file_exits_with_configuration_code(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)

    code = cli.main(["nessus", "check"])
    captured = capsys.readouterr()

    assert code == 2
    assert "Configuration error" in captured.err
    assert ".env.example" in captured.err


def test_failure_output_contains_no_traceback(stub_check, capsys):
    stub_check(
        result=make_result(
            Outcome.AUTHENTICATION_ERROR,
            summary="Authentication was rejected (HTTP 401).",
            detail="HTTPError: 401 Client Error",
            http_status=401,
        )
    )

    code = cli.main(["nessus", "check"])
    captured = capsys.readouterr()

    assert code == 4
    assert "FAILED" in captured.err
    assert "Traceback" not in captured.err
    assert "HTTPError" not in captured.err


def test_failure_output_contains_no_secrets(stub_check, capsys):
    stub_check(
        result=make_result(
            Outcome.NETWORK_ERROR,
            summary="The connection failed.",
            detail="ConnectionError: connection aborted",
        )
    )

    cli.main(["nessus", "check"])
    captured = capsys.readouterr()

    assert FAKE_ACCESS_KEY not in captured.out + captured.err
    assert FAKE_SECRET_KEY not in captured.out + captured.err


def test_unexpected_internal_error_exits_with_code_five(stub_check, capsys):
    stub_check(exception=RuntimeError("something unforeseen"))

    code = cli.main(["nessus", "check"])
    captured = capsys.readouterr()

    assert code == 5
    assert "Unexpected internal error" in captured.err
    assert "something unforeseen" not in captured.err
    assert "Traceback" not in captured.err


def test_no_command_prints_help(capsys):
    code = cli.main([])
    captured = capsys.readouterr()

    assert code == 2
    assert "usage:" in captured.out


def test_nessus_without_subcommand_prints_help(capsys):
    code = cli.main(["nessus"])
    captured = capsys.readouterr()

    assert code == 2
    assert "usage:" in captured.out


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--version"])

    assert excinfo.value.code == 0
    assert capsys.readouterr().out.strip() == "vulnsight 0.3.1"


def test_package_version_matches_the_current_tranche():
    from vulnsight import __version__

    assert __version__ == "0.3.1"
