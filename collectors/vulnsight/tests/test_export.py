"""Export request, bounded polling and streamed download tests.

Every request is mocked and every wait uses an injected clock, so no test
contacts Nessus and no test waits in real time.
"""

from __future__ import annotations

import hashlib

import pytest
import requests

from vulnsight.nessus.client import Outcome
from vulnsight.nessus.errors import ExportError
from vulnsight.nessus.export import (
    EXPORT_FORMAT,
    ExportSettings,
    download_export,
    download_path,
    export_path,
    export_request_body,
    request_export,
    status_path,
    wait_until_ready,
)
from conftest import FAKE_ACCESS_KEY, FAKE_SECRET_KEY, FakeApiSession, FakeResponse

ENDPOINT = "https://nessus.lab.invalid:8834"
EXPORT_URL = f"{ENDPOINT}/scans/5/export"
STATUS_URL = f"{ENDPOINT}/scans/5/export/9/status"
DOWNLOAD_URL = f"{ENDPOINT}/scans/5/export/9/download"

#: A synthetic download token. It must never reach a result, the terminal,
#: an exception, a representation or the manifest.
FAKE_TOKEN = "TOKENtokenTOKEN-must-never-be-persisted"

SETTINGS = ExportSettings(
    poll_interval_seconds=2.0, poll_timeout_seconds=10.0, max_bytes=1024
)


def export_response(file_id: object = 9, **extra) -> FakeResponse:
    payload = {"file": file_id, "token": FAKE_TOKEN}
    payload.update(extra)
    return FakeResponse(200, payload=payload)


def status_response(status: str) -> FakeResponse:
    return FakeResponse(200, payload={"status": status})


def download_response(chunks: list[bytes], **kwargs) -> FakeResponse:
    headers = kwargs.pop("headers", None)
    return FakeResponse(200, payload=None, headers=headers, chunks=chunks, **kwargs)


# ---------------------------------------------------------------------------
# Paths and request body
# ---------------------------------------------------------------------------


def test_export_paths_are_exact():
    assert export_path(5) == "/scans/5/export"
    assert status_path(5, "9") == "/scans/5/export/9/status"
    assert download_path(5, "9") == "/scans/5/export/9/download"


def test_export_request_body_is_exact():
    assert export_request_body(6) == {"format": "nessus", "history_id": 6}
    assert EXPORT_FORMAT == "nessus"


# ---------------------------------------------------------------------------
# Step 1: the export request
# ---------------------------------------------------------------------------


def test_export_uses_one_post_to_the_documented_endpoint(config):
    session = FakeApiSession(responses=[export_response(9)])

    file_id = request_export(session, config, 5, 6)

    assert file_id == "9"
    assert session.methods == ["POST"]
    assert session.urls == [EXPORT_URL]
    assert session.forbidden_calls == []
    _method, _url, kwargs = session.calls[0]
    assert kwargs["json"] == {"format": "nessus", "history_id": 6}
    assert kwargs["timeout"] == (5.0, 15.0)
    assert kwargs["verify"] is True
    assert kwargs["allow_redirects"] is False


def test_the_history_id_is_never_omitted_from_the_body(config):
    session = FakeApiSession(responses=[export_response(9)])

    request_export(session, config, 5, 6)

    assert "history_id" in session.calls[0][2]["json"]


def test_no_other_write_method_is_reachable(config):
    session = FakeApiSession(responses=[export_response(9)])

    request_export(session, config, 5, 6)

    for name in ("put", "patch", "delete"):
        with pytest.raises(AssertionError):
            getattr(session, name)(EXPORT_URL)


def test_the_download_token_is_never_returned_or_represented(config):
    session = FakeApiSession(responses=[export_response(9)])

    file_id = request_export(session, config, 5, 6)

    assert FAKE_TOKEN not in repr(file_id)
    assert file_id == "9"


def test_the_token_never_reaches_an_error_message(config):
    session = FakeApiSession(responses=[FakeResponse(200, payload={"token": FAKE_TOKEN})])

    with pytest.raises(ExportError) as excinfo:
        request_export(session, config, 5, 6)

    rendered = f"{excinfo.value.summary} {excinfo.value.detail} {excinfo.value!r}"
    assert FAKE_TOKEN not in rendered


@pytest.mark.parametrize(
    ("file_id", "expected"),
    [(9, "9"), (12345, "12345"), ("9", "9"), ("12345", "12345")],
)
def test_acceptable_file_identifiers(config, file_id, expected):
    session = FakeApiSession(responses=[export_response(file_id)])

    assert request_export(session, config, 5, 6) == expected


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"file_id": 9},
        {"file": None},
        {"file": True},
        {"file": False},
        {"file": 0},
        {"file": -1},
        {"file": 1.5},
        {"file": "9/../4"},
        {"file": "../9"},
        {"file": "9?x=1"},
        {"file": "abc"},
        {"file": ""},
        {"file": "09"},
        {"file": ["9"]},
        {"file": {"id": 9}},
        ["file", 9],
        "9",
        42,
        None,
    ],
)
def test_malformed_export_responses_are_rejected(config, payload):
    session = FakeApiSession(responses=[FakeResponse(200, payload=payload)])

    with pytest.raises(ExportError) as excinfo:
        request_export(session, config, 5, 6)

    assert excinfo.value.exit_code == 5


def test_invalid_json_export_response_is_rejected(config):
    session = FakeApiSession(
        responses=[FakeResponse(200, json_exception=ValueError("no json"))]
    )

    with pytest.raises(ExportError) as excinfo:
        request_export(session, config, 5, 6)

    assert excinfo.value.exit_code == 5
    assert "not valid JSON" in excinfo.value.summary


@pytest.mark.parametrize(
    ("status", "outcome", "exit_code"),
    [
        (400, Outcome.API_ERROR, 5),
        (401, Outcome.AUTHENTICATION_ERROR, 4),
        (403, Outcome.AUTHENTICATION_ERROR, 4),
        (404, Outcome.API_ERROR, 5),
        (405, Outcome.API_ERROR, 5),
        (429, Outcome.API_ERROR, 5),
        (500, Outcome.API_ERROR, 5),
        (503, Outcome.API_ERROR, 5),
    ],
)
def test_export_http_status_handling(config, status, outcome, exit_code):
    session = FakeApiSession(responses=[FakeResponse(status)])

    with pytest.raises(ExportError) as excinfo:
        request_export(session, config, 5, 6)

    assert excinfo.value.outcome is outcome
    assert excinfo.value.exit_code == exit_code
    # Authentication and authorisation failures are never retried.
    assert len(session.calls) == 1


def test_400_reports_the_exact_contract_without_trying_alternatives(config):
    session = FakeApiSession(responses=[FakeResponse(400)])

    with pytest.raises(ExportError) as excinfo:
        request_export(session, config, 5, 6)

    assert "HTTP 400" in excinfo.value.summary
    assert "will not try" in excinfo.value.summary
    assert len(session.calls) == 1


def test_export_transport_failure_is_a_network_error(config):
    session = FakeApiSession(responses=[requests.exceptions.SSLError("bad cert")])

    with pytest.raises(ExportError) as excinfo:
        request_export(session, config, 5, 6)

    assert excinfo.value.outcome is Outcome.NETWORK_ERROR
    assert excinfo.value.exit_code == 3


# ---------------------------------------------------------------------------
# Step 2: bounded polling
# ---------------------------------------------------------------------------


def test_immediate_ready_needs_no_sleep(config, fake_clock):
    session = FakeApiSession(responses=[status_response("ready")])

    polls = wait_until_ready(
        session, config, 5, "9", SETTINGS, fake_clock.as_clock()
    )

    assert polls == 1
    assert fake_clock.sleeps == []
    assert session.methods == ["GET"]
    assert session.urls == [STATUS_URL]


def test_loading_then_ready(config, fake_clock):
    session = FakeApiSession(
        responses=[
            status_response("loading"),
            status_response("loading"),
            status_response("ready"),
        ]
    )

    polls = wait_until_ready(
        session, config, 5, "9", SETTINGS, fake_clock.as_clock()
    )

    assert polls == 3
    assert fake_clock.sleeps == [2.0, 2.0]
    assert session.methods == ["GET", "GET", "GET"]


@pytest.mark.parametrize("status", ["ready", "READY", "Ready"])
def test_ready_is_matched_case_insensitively(config, fake_clock, status):
    session = FakeApiSession(responses=[status_response(status)])

    assert wait_until_ready(
        session, config, 5, "9", SETTINGS, fake_clock.as_clock()
    ) == 1


def test_provider_error_state_fails_immediately(config, fake_clock):
    session = FakeApiSession(responses=[status_response("error")])

    with pytest.raises(ExportError) as excinfo:
        wait_until_ready(session, config, 5, "9", SETTINGS, fake_clock.as_clock())

    assert excinfo.value.exit_code == 5
    assert "error" in excinfo.value.summary
    assert fake_clock.sleeps == []


@pytest.mark.parametrize("status", ["queued", "pending", "finished", "unknown", "done"])
def test_undocumented_status_is_a_contract_error_not_a_loop(
    config, fake_clock, status
):
    session = FakeApiSession(responses=[status_response(status)])

    with pytest.raises(ExportError) as excinfo:
        wait_until_ready(session, config, 5, "9", SETTINGS, fake_clock.as_clock())

    assert excinfo.value.exit_code == 5
    assert "undocumented" in excinfo.value.summary
    assert len(session.calls) == 1


@pytest.mark.parametrize(
    "payload",
    [{}, {"status": None}, {"status": ""}, {"status": 7}, {"status": ["ready"]}, [], "ready"],
)
def test_malformed_status_responses_are_rejected(config, fake_clock, payload):
    session = FakeApiSession(responses=[FakeResponse(200, payload=payload)])

    with pytest.raises(ExportError) as excinfo:
        wait_until_ready(session, config, 5, "9", SETTINGS, fake_clock.as_clock())

    assert excinfo.value.exit_code == 5


def test_polling_is_bounded_by_the_documented_timeout(config, fake_clock):
    session = FakeApiSession(responses=[status_response("loading")] * 20)

    with pytest.raises(ExportError) as excinfo:
        wait_until_ready(session, config, 5, "9", SETTINGS, fake_clock.as_clock())

    assert excinfo.value.exit_code == 5
    assert "10 seconds" in excinfo.value.summary
    # A 10s budget at 2s intervals allows five sleeps; the sixth poll finds
    # no time left for another interval and stops rather than looping on.
    assert fake_clock.sleeps == [2.0, 2.0, 2.0, 2.0, 2.0]
    assert len(session.calls) == 6


def test_polling_authentication_failure_is_not_retried(config, fake_clock):
    session = FakeApiSession(responses=[FakeResponse(401)])

    with pytest.raises(ExportError) as excinfo:
        wait_until_ready(session, config, 5, "9", SETTINGS, fake_clock.as_clock())

    assert excinfo.value.outcome is Outcome.AUTHENTICATION_ERROR
    assert len(session.calls) == 1
    assert fake_clock.sleeps == []


def test_polling_transport_failure_fails_cleanly(config, fake_clock):
    session = FakeApiSession(
        responses=[
            status_response("loading"),
            requests.exceptions.ConnectionError("dropped"),
        ]
    )

    with pytest.raises(ExportError) as excinfo:
        wait_until_ready(session, config, 5, "9", SETTINGS, fake_clock.as_clock())

    assert excinfo.value.outcome is Outcome.NETWORK_ERROR
    assert excinfo.value.exit_code == 3


# ---------------------------------------------------------------------------
# Step 3: the streamed download
# ---------------------------------------------------------------------------


def test_download_streams_chunks_and_hashes_exactly(config, tmp_path):
    chunks = [b"<Nessus", b"ClientData", b"_v2/>"]
    payload = b"".join(chunks)
    session = FakeApiSession(responses=[download_response(chunks)])
    destination = tmp_path / "artefact.part"

    result = download_export(session, config, 5, "9", SETTINGS, destination)

    assert session.urls == [DOWNLOAD_URL]
    assert session.methods == ["GET"]
    assert destination.read_bytes() == payload
    assert result.size_bytes == len(payload)
    assert result.sha256 == hashlib.sha256(payload).hexdigest()


def test_download_requests_a_stream_with_explicit_timeouts(config, tmp_path):
    session = FakeApiSession(responses=[download_response([b"<a/>"])])

    download_export(session, config, 5, "9", SETTINGS, tmp_path / "a.part")

    _method, _url, kwargs = session.calls[0]
    assert kwargs["stream"] is True
    assert kwargs["timeout"] == (5.0, 15.0)
    assert kwargs["allow_redirects"] is False


def test_download_uses_bounded_chunks(config, tmp_path):
    response = download_response([b"abc"])
    session = FakeApiSession(responses=[response])
    settings = ExportSettings(2.0, 10.0, 1024, chunk_bytes=8)

    download_export(session, config, 5, "9", settings, tmp_path / "a.part")

    assert response.chunk_sizes == [8]


def test_download_closes_the_response(config, tmp_path):
    response = download_response([b"<a/>"])
    session = FakeApiSession(responses=[response])

    download_export(session, config, 5, "9", SETTINGS, tmp_path / "a.part")

    assert response.closed is True


def test_download_closes_the_response_on_failure(config, tmp_path):
    response = download_response([], headers={"Content-Length": "0"})
    session = FakeApiSession(responses=[response])

    with pytest.raises(ExportError):
        download_export(session, config, 5, "9", SETTINGS, tmp_path / "a.part")

    assert response.closed is True


def test_content_length_is_honoured(config, tmp_path):
    chunks = [b"12345"]
    session = FakeApiSession(
        responses=[download_response(chunks, headers={"Content-Length": "5"})]
    )

    result = download_export(session, config, 5, "9", SETTINGS, tmp_path / "a.part")

    assert result.size_bytes == 5


def test_a_truncated_download_is_rejected(config, tmp_path):
    session = FakeApiSession(
        responses=[download_response([b"123"], headers={"Content-Length": "9"})]
    )

    with pytest.raises(ExportError) as excinfo:
        download_export(session, config, 5, "9", SETTINGS, tmp_path / "a.part")

    assert excinfo.value.exit_code == 5
    assert "incomplete" in excinfo.value.summary


def test_a_declared_size_over_the_limit_is_refused_before_streaming(
    config, tmp_path
):
    response = download_response([b"x"], headers={"Content-Length": "99999"})
    session = FakeApiSession(responses=[response])
    destination = tmp_path / "a.part"

    with pytest.raises(ExportError) as excinfo:
        download_export(session, config, 5, "9", SETTINGS, destination)

    assert "exceeds the permitted maximum" in excinfo.value.summary
    assert response.chunk_sizes == []
    assert not destination.exists()


def test_the_size_limit_is_enforced_while_streaming(config, tmp_path):
    settings = ExportSettings(2.0, 10.0, max_bytes=10)
    session = FakeApiSession(responses=[download_response([b"x" * 8, b"y" * 8])])

    with pytest.raises(ExportError) as excinfo:
        download_export(session, config, 5, "9", settings, tmp_path / "a.part")

    assert excinfo.value.exit_code == 5
    assert "while downloading" in excinfo.value.summary


@pytest.mark.parametrize(
    "response_kwargs",
    [
        {"chunks": []},
        {"chunks": [b""]},
        {"chunks": [], "headers": {"Content-Length": "0"}},
    ],
)
def test_a_zero_byte_download_is_rejected(config, tmp_path, response_kwargs):
    session = FakeApiSession(responses=[FakeResponse(200, payload=None, **response_kwargs)])

    with pytest.raises(ExportError) as excinfo:
        download_export(session, config, 5, "9", SETTINGS, tmp_path / "a.part")

    assert excinfo.value.exit_code == 5
    assert "zero" in excinfo.value.summary.lower()


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json",
        "application/json; charset=utf-8",
        "text/html",
        "text/html; charset=iso-8859-1",
    ],
)
def test_an_error_body_masquerading_as_a_download_is_rejected(
    config, tmp_path, content_type
):
    destination = tmp_path / "a.part"
    session = FakeApiSession(
        responses=[
            download_response(
                [b'{"error":"nope"}'], headers={"Content-Type": content_type}
            )
        ]
    )

    with pytest.raises(ExportError) as excinfo:
        download_export(session, config, 5, "9", SETTINGS, destination)

    assert excinfo.value.exit_code == 5
    assert not destination.exists()


def test_an_interrupted_download_propagates_as_a_network_error(config, tmp_path):
    session = FakeApiSession(
        responses=[
            FakeResponse(
                200,
                payload=None,
                chunks=[b"<Nessus"],
                chunk_exception=requests.exceptions.ConnectionError("reset"),
            )
        ]
    )

    with pytest.raises(ExportError) as excinfo:
        download_export(session, config, 5, "9", SETTINGS, tmp_path / "a.part")

    assert excinfo.value.outcome is Outcome.NETWORK_ERROR
    assert excinfo.value.exit_code == 3


def test_download_http_errors_are_classified(config, tmp_path):
    session = FakeApiSession(responses=[FakeResponse(404, payload=None)])

    with pytest.raises(ExportError) as excinfo:
        download_export(session, config, 5, "9", SETTINGS, tmp_path / "a.part")

    assert excinfo.value.exit_code == 5
    assert "expired" in excinfo.value.summary


def test_download_refuses_to_overwrite_its_own_temporary_file(config, tmp_path):
    destination = tmp_path / "a.part"
    destination.write_bytes(b"pre-existing")
    session = FakeApiSession(responses=[download_response([b"<a/>"])])

    with pytest.raises(FileExistsError):
        download_export(session, config, 5, "9", SETTINGS, destination)

    assert destination.read_bytes() == b"pre-existing"


def test_export_errors_never_contain_secrets(config, tmp_path):
    session = FakeApiSession(
        responses=[
            requests.exceptions.ConnectionError(
                f"accessKey={FAKE_ACCESS_KEY}; secretKey={FAKE_SECRET_KEY}"
            )
        ]
    )

    with pytest.raises(ExportError) as excinfo:
        request_export(session, config, 5, 6)

    rendered = f"{excinfo.value.summary} {excinfo.value.detail}"
    assert FAKE_ACCESS_KEY not in rendered
    assert FAKE_SECRET_KEY not in rendered


def test_export_settings_come_from_configuration(config):
    settings = ExportSettings.from_config(config)

    assert settings.poll_interval_seconds == 2.0
    assert settings.poll_timeout_seconds == 600.0
    assert settings.max_bytes == 1_073_741_824
