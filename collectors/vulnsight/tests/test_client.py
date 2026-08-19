"""Nessus connectivity preflight tests.

All networking is mocked. Representative Python exception types are used so
that the classification does not depend on Windows message text.
"""

from __future__ import annotations

import socket
from dataclasses import fields

import pytest
import requests

from vulnsight.nessus.client import Outcome, Stage, check_connectivity
from conftest import (
    FAKE_ACCESS_KEY,
    FAKE_SECRET_KEY,
    SAMPLE_SCANS_PAYLOAD,
    FakeResponse,
    make_config,
)


# ---------------------------------------------------------------------------
# Success paths
# ---------------------------------------------------------------------------


def test_successful_check(config, patch_tcp_success, patch_session):
    patch_session(response=FakeResponse(200))

    result = check_connectivity(config)

    assert result.ok is True
    assert result.outcome is Outcome.SUCCESS
    assert result.exit_code == 0
    assert result.stage is Stage.API_RESPONSE
    assert result.tcp_connected is True
    assert result.authenticated is True
    assert result.json_valid is True
    assert result.http_status == 200
    assert result.endpoint == "https://nessus.lab.invalid:8834"
    assert patch_tcp_success == [(("nessus.lab.invalid", 8834), 5.0)]


def test_successful_check_with_tls_verification_disabled(
    patch_tcp_success, patch_session
):
    config = make_config(NESSUS_VERIFY_TLS="false")
    session = patch_session(response=FakeResponse(200))

    result = check_connectivity(config)

    assert result.ok is True
    assert result.verify_tls is False
    assert session.get_calls[0][1]["verify"] is False


def test_only_a_get_request_is_used(config, patch_tcp_success, patch_session):
    session = patch_session(response=FakeResponse(200))

    check_connectivity(config)

    assert len(session.get_calls) == 1
    assert session.forbidden_calls == []
    args, kwargs = session.get_calls[0]
    assert args[0] == "https://nessus.lab.invalid:8834/scans"
    assert kwargs["allow_redirects"] is False


def test_request_uses_explicit_timeouts_and_api_key_header(
    config, patch_tcp_success, patch_session
):
    session = patch_session(response=FakeResponse(200))

    check_connectivity(config)

    _, kwargs = session.get_calls[0]
    assert kwargs["timeout"] == (5.0, 15.0)
    assert kwargs["verify"] is True
    assert kwargs["headers"]["X-ApiKeys"] == (
        f"accessKey={FAKE_ACCESS_KEY}; secretKey={FAKE_SECRET_KEY}"
    )


def test_session_is_closed(config, patch_tcp_success, patch_session):
    session = patch_session(response=FakeResponse(200))

    check_connectivity(config)

    assert session.closed is True


def test_scan_list_response_is_not_retained(
    config, patch_tcp_success, patch_session, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    patch_session(response=FakeResponse(200))

    result = check_connectivity(config)

    scan_name = SAMPLE_SCANS_PAYLOAD["scans"][0]["name"]
    assert scan_name not in repr(result)
    for field_info in fields(result):
        value = getattr(result, field_info.name)
        assert not isinstance(value, (dict, list))
        assert scan_name not in str(value)
    assert list(tmp_path.iterdir()) == []


# ---------------------------------------------------------------------------
# Network failures
# ---------------------------------------------------------------------------


def test_dns_resolution_failure(config, patch_tcp_failure):
    patch_tcp_failure(socket.gaierror(11001, "getaddrinfo failed"))

    result = check_connectivity(config)

    assert result.outcome is Outcome.NETWORK_ERROR
    assert result.stage is Stage.TARGET_RESOLUTION
    assert result.exit_code == 3
    assert "resolved" in result.summary


def test_connection_refused(config, patch_tcp_failure):
    patch_tcp_failure(ConnectionRefusedError(10061, "Connection refused"))

    result = check_connectivity(config)

    assert result.outcome is Outcome.NETWORK_ERROR
    assert result.stage is Stage.TCP_CONNECTIVITY
    assert result.exit_code == 3
    assert "refused" in result.summary


def test_tcp_connection_timeout(config, patch_tcp_failure):
    patch_tcp_failure(TimeoutError("timed out"))

    result = check_connectivity(config)

    assert result.outcome is Outcome.NETWORK_ERROR
    assert result.stage is Stage.TCP_CONNECTIVITY
    assert "timed out" in result.summary


def test_network_route_failure(config, patch_tcp_failure):
    patch_tcp_failure(OSError(10051, "A socket operation was attempted to an unreachable network"))

    result = check_connectivity(config)

    assert result.outcome is Outcome.NETWORK_ERROR
    assert result.exit_code == 3
    assert "route" in result.summary


def test_tls_verification_failure(config, patch_tcp_success, patch_session):
    patch_session(
        exception=requests.exceptions.SSLError("certificate verify failed")
    )

    result = check_connectivity(config)

    assert result.outcome is Outcome.NETWORK_ERROR
    assert result.stage is Stage.API_REQUEST
    assert result.exit_code == 3
    assert "TLS certificate" in result.summary
    assert "NESSUS_VERIFY_TLS=false" in result.summary


def test_request_connect_timeout(config, patch_tcp_success, patch_session):
    patch_session(exception=requests.exceptions.ConnectTimeout("connect timed out"))

    result = check_connectivity(config)

    assert result.outcome is Outcome.NETWORK_ERROR
    assert "timed out" in result.summary


def test_request_read_timeout(config, patch_tcp_success, patch_session):
    patch_session(exception=requests.exceptions.ReadTimeout("read timed out"))

    result = check_connectivity(config)

    assert result.outcome is Outcome.NETWORK_ERROR
    assert "did not respond" in result.summary


def test_request_connection_error(config, patch_tcp_success, patch_session):
    patch_session(exception=requests.exceptions.ConnectionError("connection aborted"))

    result = check_connectivity(config)

    assert result.outcome is Outcome.NETWORK_ERROR
    assert result.exit_code == 3


def test_generic_request_exception(config, patch_tcp_success, patch_session):
    patch_session(exception=requests.exceptions.TooManyRedirects("loop"))

    result = check_connectivity(config)

    assert result.outcome is Outcome.NETWORK_ERROR
    assert result.exit_code == 3


# ---------------------------------------------------------------------------
# HTTP status classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "outcome", "exit_code"),
    [
        (401, Outcome.AUTHENTICATION_ERROR, 4),
        (403, Outcome.AUTHENTICATION_ERROR, 4),
        (404, Outcome.API_ERROR, 5),
        (500, Outcome.API_ERROR, 5),
        (503, Outcome.API_ERROR, 5),
        (302, Outcome.API_ERROR, 5),
    ],
)
def test_http_status_classification(
    config, patch_tcp_success, patch_session, status, outcome, exit_code
):
    patch_session(response=FakeResponse(status))

    result = check_connectivity(config)

    assert result.outcome is outcome
    assert result.exit_code == exit_code
    assert result.http_status == status
    assert result.tcp_connected is True
    assert result.ok is False


def test_authentication_failure_is_not_retried(
    config, patch_tcp_success, patch_session
):
    session = patch_session(response=FakeResponse(401))

    check_connectivity(config)

    assert len(session.get_calls) == 1


# ---------------------------------------------------------------------------
# Response validation
# ---------------------------------------------------------------------------


def test_invalid_json_response(config, patch_tcp_success, patch_session):
    patch_session(
        response=FakeResponse(
            200, json_exception=ValueError("Expecting value: line 1 column 1")
        )
    )

    result = check_connectivity(config)

    assert result.outcome is Outcome.API_ERROR
    assert result.exit_code == 5
    assert result.json_valid is False
    assert "not valid JSON" in result.summary


def test_json_response_of_unexpected_shape(config, patch_tcp_success, patch_session):
    patch_session(response=FakeResponse(200, payload=["unexpected"]))

    result = check_connectivity(config)

    assert result.outcome is Outcome.API_ERROR
    assert result.exit_code == 5
    assert result.json_valid is False


# ---------------------------------------------------------------------------
# Secret hygiene
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        "tls",
        "refused",
        "unauthorised",
        "leaky_exception",
    ],
)
def test_results_never_contain_secrets(
    config, patch_tcp_success, patch_tcp_failure, patch_session, failure
):
    if failure == "refused":
        patch_tcp_failure(ConnectionRefusedError(10061, "Connection refused"))
    elif failure == "tls":
        patch_session(exception=requests.exceptions.SSLError("certificate error"))
    elif failure == "unauthorised":
        patch_session(response=FakeResponse(401))
    else:
        # A third-party exception that carelessly echoes the header value back.
        patch_session(
            exception=requests.exceptions.ConnectionError(
                f"failed sending accessKey={FAKE_ACCESS_KEY}; "
                f"secretKey={FAKE_SECRET_KEY}"
            )
        )

    result = check_connectivity(config)

    rendered = " ".join(
        [repr(result), result.summary, result.detail, " ".join(result.warnings)]
    )
    assert FAKE_ACCESS_KEY not in rendered
    assert FAKE_SECRET_KEY not in rendered


def test_technical_detail_is_retained_for_diagnosis(config, patch_tcp_failure):
    patch_tcp_failure(ConnectionRefusedError(10061, "Connection refused"))

    result = check_connectivity(config)

    assert "ConnectionRefusedError" in result.detail
