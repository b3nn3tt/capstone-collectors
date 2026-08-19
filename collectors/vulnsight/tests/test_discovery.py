"""Read-only scan and history discovery tests.

Every request is mocked. No test contacts a real Nessus instance, and no
test writes a response to disk.

History is read from the ``history`` collection of a single
``GET /scans/{identifier}`` scan-details response. The cloud-style
``GET /scans/{identifier}/history`` endpoint returned HTTP 405 on the
deployed standalone Nessus 10.12 scanner and is not used.
"""

from __future__ import annotations

import socket
from dataclasses import fields

import pytest
import requests

from vulnsight.nessus.client import Outcome
from vulnsight.nessus.discovery import DiscoveryError, list_scan_history, list_scans
from vulnsight.nessus.identifiers import parse_scan_identifier
from conftest import FAKE_ACCESS_KEY, FAKE_SECRET_KEY, FakeResponse

SCANS_URL = "https://nessus.lab.invalid:8834/scans"
SCAN_DETAILS_URL = f"{SCANS_URL}/5"

IDENTIFIER = parse_scan_identifier("5")
PROVIDER_IDENTIFIER = parse_scan_identifier(
    "01234567-89ab-cdef-0123-456789abcdef0123456789abcdef"
)

#: Values that must never reach a result object, the terminal or the disk.
SENSITIVE_MARKERS = (
    "10.0.0.7",
    "CVE-1999-0001",
    "administrator",
    "credentialed_scan",
)


# ---------------------------------------------------------------------------
# Payload builders
# ---------------------------------------------------------------------------


def scan_record(scan_id: int, **overrides):
    record = {
        "id": scan_id,
        "uuid": f"0000000{scan_id}-89ab-cdef-0123-456789abcdef",
        "name": f"Scan {scan_id}",
        "status": "completed",
        "folder_id": 2,
        "last_modification_date": 1_700_000_000 + scan_id,
    }
    record.update(overrides)
    return record


def scans_payload(*records):
    return {"folders": [{"id": 2, "name": "My Scans"}], "scans": list(records)}


def history_record(history_id: int, **overrides):
    record = {
        "history_id": history_id,
        "uuid": f"1000000{history_id}-89ab-cdef-0123-456789abcdef",
        "status": "completed",
        "creation_date": 1_700_000_000 + history_id,
        "last_modification_date": 1_700_003_600 + history_id,
        "type": "local",
        "is_rollover": False,
    }
    record.update(overrides)
    return record


def details_payload(*records, history="__records__", **overrides):
    """A scan-details response, complete with fields VulnSight must ignore."""
    payload = {
        "info": {
            "name": "synthetic-lab-scan",
            "targets": "10.0.0.7",
            "policy": "credentialed_scan",
            "scan_start": 1_700_000_000,
        },
        "hosts": [{"hostname": "10.0.0.7", "critical": 3, "host_id": 2}],
        "vulnerabilities": [
            {"plugin_name": "CVE-1999-0001", "plugin_id": 10180, "count": 4}
        ],
        "notes": [{"title": "administrator", "message": "credentialed_scan"}],
        "compliance": [],
        "filters": [],
        "remediations": {"remediations": []},
    }
    if history == "__records__":
        payload["history"] = list(records)
    elif history is not ...:
        payload["history"] = history
    payload.update(overrides)
    return payload


# ---------------------------------------------------------------------------
# Scan discovery: success
# ---------------------------------------------------------------------------


def test_valid_multi_scan_response(config, patch_session):
    patch_session(
        response=FakeResponse(200, payload=scans_payload(scan_record(7), scan_record(2)))
    )

    result = list_scans(config)

    assert result.count == 2
    assert result.is_empty is False
    assert [scan.scan_id for scan in result.scans] == [2, 7]


def test_scan_ordering_is_deterministic(config, patch_session):
    records = [scan_record(sid) for sid in (30, 4, 11, 2)]
    patch_session(response=FakeResponse(200, payload=scans_payload(*records)))

    first = list_scans(config)

    patch_session(
        response=FakeResponse(200, payload=scans_payload(*reversed(records)))
    )
    second = list_scans(config)

    assert [s.scan_id for s in first.scans] == [2, 4, 11, 30]
    assert [s.scan_id for s in first.scans] == [s.scan_id for s in second.scans]


def test_empty_scan_array_is_a_successful_empty_result(config, patch_session):
    patch_session(response=FakeResponse(200, payload=scans_payload()))

    result = list_scans(config)

    assert result.is_empty is True
    assert result.count == 0
    assert result.scans == ()


def test_scan_status_is_preserved_verbatim(config, patch_session):
    patch_session(
        response=FakeResponse(
            200, payload=scans_payload(scan_record(1, status="ImPorting"))
        )
    )

    result = list_scans(config)

    assert result.scans[0].status == "ImPorting"


def test_extended_provider_uuid_is_preserved_verbatim(config, patch_session):
    observed = "01234567-89ab-cdef-0123-456789abcdef0123456789abcdef"
    patch_session(
        response=FakeResponse(200, payload=scans_payload(scan_record(5, uuid=observed)))
    )

    assert list_scans(config).scans[0].uuid == observed


def test_missing_optional_scan_fields_stay_neutral(config, patch_session):
    record = {"id": 5}
    patch_session(response=FakeResponse(200, payload=scans_payload(record)))

    scan = list_scans(config).scans[0]

    assert scan.scan_id == 5
    assert scan.uuid is None
    assert scan.name is None
    assert scan.status is None
    assert scan.folder_id is None
    assert scan.last_modification_date is None
    assert scan.last_modification_iso is None


def test_scan_timestamp_conversion_retains_the_raw_integer(config, patch_session):
    patch_session(
        response=FakeResponse(
            200,
            payload=scans_payload(scan_record(1, last_modification_date=1_700_000_000)),
        )
    )

    scan = list_scans(config).scans[0]

    assert scan.last_modification_date == 1_700_000_000
    assert scan.last_modification_iso == "2023-11-14T22:13:20Z"


@pytest.mark.parametrize(
    "name",
    [
        "synthetic-lab-scan",
        "Weekly Lab Sweep",
        "Analyse — réseau (été)",
        "スキャン 東京",
        "  padded name  ",
    ],
)
def test_scan_names_with_spaces_and_unicode_are_preserved(config, patch_session, name):
    patch_session(
        response=FakeResponse(200, payload=scans_payload(scan_record(1, name=name)))
    )

    assert list_scans(config).scans[0].name == name


# ---------------------------------------------------------------------------
# Scan discovery: response-contract failures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("payload", "fragment"),
    [
        ({"folders": []}, "no 'scans' field"),
        ({"scans": None}, "null 'scans' field"),
        ({"scans": {"id": 1}}, "not a list"),
        ({"scans": "1,2,3"}, "not a list"),
        (["unexpected"], "not the expected object structure"),
        ("unexpected", "not the expected object structure"),
    ],
)
def test_invalid_scan_collections_are_rejected(config, patch_session, payload, fragment):
    patch_session(response=FakeResponse(200, payload=payload))

    with pytest.raises(DiscoveryError) as excinfo:
        list_scans(config)

    assert excinfo.value.outcome is Outcome.API_ERROR
    assert excinfo.value.exit_code == 5
    assert fragment in excinfo.value.summary


@pytest.mark.parametrize(
    "record",
    [
        {"name": "no identifier"},
        {"id": None},
        {"id": "41"},
        {"id": 0},
        {"id": -3},
        {"id": True},
        {"id": 1, "name": 42},
        {"id": 1, "status": ["completed"]},
        {"id": 1, "folder_id": "2"},
        "not an object",
        None,
    ],
)
def test_malformed_scan_records_are_reported_not_skipped(
    config, patch_session, record
):
    patch_session(
        response=FakeResponse(200, payload=scans_payload(scan_record(1000), record))
    )

    with pytest.raises(DiscoveryError) as excinfo:
        list_scans(config)

    assert excinfo.value.exit_code == 5


@pytest.mark.parametrize(
    "value", ["1700000000", 1.5, -1, 253_402_300_800, True, {"t": 1}]
)
def test_malformed_scan_timestamps_fail_rather_than_fabricate(
    config, patch_session, value
):
    patch_session(
        response=FakeResponse(
            200,
            payload=scans_payload(scan_record(1, last_modification_date=value)),
        )
    )

    with pytest.raises(DiscoveryError) as excinfo:
        list_scans(config)

    assert excinfo.value.exit_code == 5
    assert "last_modification_date" in excinfo.value.summary


def test_duplicate_scan_identifier_is_a_contract_error(config, patch_session):
    patch_session(
        response=FakeResponse(
            200, payload=scans_payload(scan_record(9), scan_record(9, name="Other"))
        )
    )

    with pytest.raises(DiscoveryError) as excinfo:
        list_scans(config)

    assert excinfo.value.exit_code == 5
    assert "more than one scan with ID 9" in excinfo.value.summary


# ---------------------------------------------------------------------------
# Request shape and hygiene
# ---------------------------------------------------------------------------


def test_scan_discovery_uses_one_get_request_only(config, patch_session):
    session = patch_session(response=FakeResponse(200, payload=scans_payload()))

    list_scans(config)

    assert len(session.get_calls) == 1
    assert session.forbidden_calls == []
    args, kwargs = session.get_calls[0]
    assert args[0] == SCANS_URL
    assert kwargs["timeout"] == (5.0, 15.0)
    assert kwargs["verify"] is True
    assert kwargs["allow_redirects"] is False
    assert "params" not in kwargs
    assert session.closed is True


def test_history_discovery_requests_exactly_the_scan_details_endpoint(
    config, patch_session
):
    session = patch_session(response=FakeResponse(200, payload=details_payload()))

    list_scan_history(config, IDENTIFIER)

    assert len(session.get_calls) == 1
    assert session.forbidden_calls == []
    args, kwargs = session.get_calls[0]
    assert args[0] == SCAN_DETAILS_URL
    assert kwargs["timeout"] == (5.0, 15.0)
    assert kwargs["allow_redirects"] is False
    assert "params" not in kwargs
    assert session.closed is True


def test_the_cloud_history_endpoint_is_never_requested(config, patch_session):
    session = patch_session(
        response=FakeResponse(200, payload=details_payload(history_record(1)))
    )

    list_scan_history(config, IDENTIFIER)

    for args, _kwargs in session.get_calls:
        assert not args[0].endswith("/history")
        assert "/history" not in args[0]


def test_history_url_uses_a_provider_identifier_verbatim(config, patch_session):
    session = patch_session(response=FakeResponse(200, payload=details_payload()))

    list_scan_history(config, PROVIDER_IDENTIFIER)

    assert session.get_calls[0][0][0] == (
        f"{SCANS_URL}/01234567-89ab-cdef-0123-456789abcdef0123456789abcdef"
    )


def test_nothing_is_written_to_disk(config, patch_session, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    patch_session(
        response=FakeResponse(200, payload=scans_payload(scan_record(1)))
    )

    list_scans(config)

    assert list(tmp_path.iterdir()) == []


def test_scan_details_response_is_not_retained_or_persisted(
    config, patch_session, tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    patch_session(
        response=FakeResponse(200, payload=details_payload(history_record(1)))
    )

    result = list_scan_history(config, IDENTIFIER)

    rendered = [repr(result)]
    rendered.extend(
        str(getattr(result, field_info.name)) for field_info in fields(result)
    )
    for text in rendered:
        for marker in SENSITIVE_MARKERS:
            assert marker not in text
    assert list(tmp_path.iterdir()) == []


def test_only_history_and_the_admitted_scan_name_are_parsed(config, patch_session):
    """The result carries the history, and one narrowly admitted field.

    ``info.name`` is admitted deliberately, because a safe output filename
    needs it. Nothing else from the scan-details response is parsed — not the
    sibling ``info`` keys, and not the hosts, vulnerabilities, notes, targets
    or policy data alongside them.
    """
    patch_session(
        response=FakeResponse(
            200, payload=details_payload(history_record(1), history_record(2))
        )
    )

    result = list_scan_history(config, IDENTIFIER)

    assert result.count == 2
    assert [run.history_id for run in result.runs] == [1, 2]

    # The admitted field is present and holds exactly what info.name supplied.
    assert result.scan_name == "synthetic-lab-scan"

    # The model is exactly these three fields — never a subset check, because
    # a fourth field would mean something new had been admitted silently.
    assert set(f.name for f in fields(result)) == {
        "scan_identifier",
        "scan_name",
        "runs",
    }

    # No host, vulnerability, note, target or policy data survives parsing —
    # including the info keys sitting beside the admitted name.
    rendered = repr(result)
    for marker in SENSITIVE_MARKERS:
        assert marker not in rendered
    for sibling in ("targets", "policy", "scan_start", "hosts", "vulnerabilities"):
        assert sibling not in rendered


def test_discovery_errors_never_contain_secrets(config, patch_session):
    patch_session(
        exception=requests.exceptions.ConnectionError(
            f"failed sending accessKey={FAKE_ACCESS_KEY}; "
            f"secretKey={FAKE_SECRET_KEY}"
        )
    )

    with pytest.raises(DiscoveryError) as excinfo:
        list_scans(config)

    rendered = f"{excinfo.value.summary} {excinfo.value.detail} {excinfo.value!r}"
    assert FAKE_ACCESS_KEY not in rendered
    assert FAKE_SECRET_KEY not in rendered


def _package_sources() -> dict[str, str]:
    """The source text of every module in the Nessus package."""
    from pathlib import Path

    import vulnsight.nessus as package

    directory = Path(package.__file__).parent
    return {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(directory.glob("*.py"))
    }


@pytest.mark.parametrize(
    "method", ["put", "patch", "delete", "head", "options", "request"]
)
def test_no_put_patch_or_delete_exists_anywhere_in_the_package(method):
    """A static guard: VulnSight never modifies or removes anything."""
    for name, source in _package_sources().items():
        assert f"session.{method}" not in source, f"{name} uses {method}"
        assert f".{method}(" not in source, f"{name} uses {method}"


def test_the_only_post_is_the_documented_export_creation():
    """POST is issued in exactly one place: the shared client's sender."""
    sources = _package_sources()

    for name, source in sources.items():
        if name == "client.py":
            continue
        assert "session.post" not in source, f"{name} issues a POST directly"

    assert sources["client.py"].count("session.post") == 1


def test_the_read_only_discovery_path_never_posts():
    """A static guard on the read-only discovery modules specifically."""
    sources = _package_sources()

    for name in ("discovery.py", "identifiers.py", "models.py"):
        assert "session.post" not in sources[name]
        assert "perform_post" not in sources[name]


# ---------------------------------------------------------------------------
# HTTP and transport failures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "outcome", "exit_code"),
    [
        (401, Outcome.AUTHENTICATION_ERROR, 4),
        (403, Outcome.AUTHENTICATION_ERROR, 4),
        (404, Outcome.API_ERROR, 5),
        (405, Outcome.API_ERROR, 5),
        (429, Outcome.API_ERROR, 5),
        (500, Outcome.API_ERROR, 5),
        (302, Outcome.API_ERROR, 5),
    ],
)
def test_http_status_classification(
    config, patch_session, status, outcome, exit_code
):
    session = patch_session(response=FakeResponse(status))

    with pytest.raises(DiscoveryError) as excinfo:
        list_scans(config)

    assert excinfo.value.outcome is outcome
    assert excinfo.value.exit_code == exit_code
    # Authentication, authorisation and rate-limit failures are never retried.
    assert len(session.get_calls) == 1


def test_history_404_reports_a_missing_scan_not_an_auth_failure(
    config, patch_session
):
    patch_session(response=FakeResponse(404))

    with pytest.raises(DiscoveryError) as excinfo:
        list_scan_history(config, IDENTIFIER)

    assert excinfo.value.outcome is Outcome.API_ERROR
    assert excinfo.value.exit_code == 5
    assert "'5' was not found" in excinfo.value.summary
    assert "not an authentication failure" in excinfo.value.summary


def test_405_reports_api_incompatibility(config, patch_session):
    patch_session(response=FakeResponse(405))

    with pytest.raises(DiscoveryError) as excinfo:
        list_scan_history(config, IDENTIFIER)

    assert excinfo.value.exit_code == 5
    assert "405" in excinfo.value.summary
    assert "does not support this endpoint" in excinfo.value.summary
    assert "GET /scans/5" in excinfo.value.summary


@pytest.mark.parametrize(
    ("exception", "fragment"),
    [
        (requests.exceptions.SSLError("bad certificate"), "TLS certificate"),
        (requests.exceptions.ConnectTimeout("slow"), "timed out"),
        (requests.exceptions.ReadTimeout("slow"), "did not respond"),
        (requests.exceptions.ConnectionError("refused"), "connection to"),
        (requests.exceptions.TooManyRedirects("loop"), "could not be completed"),
    ],
)
def test_transport_failures_are_network_errors(
    config, patch_session, exception, fragment
):
    patch_session(exception=exception)

    with pytest.raises(DiscoveryError) as excinfo:
        list_scans(config)

    assert excinfo.value.outcome is Outcome.NETWORK_ERROR
    assert excinfo.value.exit_code == 3
    assert fragment.lower() in excinfo.value.summary.lower()


def test_invalid_json_is_an_api_error(config, patch_session):
    patch_session(
        response=FakeResponse(200, json_exception=ValueError("Expecting value"))
    )

    with pytest.raises(DiscoveryError) as excinfo:
        list_scans(config)

    assert excinfo.value.exit_code == 5
    assert "not valid JSON" in excinfo.value.summary


def test_socket_errors_are_not_swallowed(config, patch_session):
    patch_session(exception=requests.exceptions.ConnectionError(socket.gaierror()))

    with pytest.raises(DiscoveryError) as excinfo:
        list_scans(config)

    assert excinfo.value.exit_code == 3


# ---------------------------------------------------------------------------
# History discovery: success
# ---------------------------------------------------------------------------


def test_the_scan_name_is_read_from_the_same_details_response(config, patch_session):
    session = patch_session(
        response=FakeResponse(200, payload=details_payload(history_record(1)))
    )

    result = list_scan_history(config, IDENTIFIER)

    assert result.scan_name == "synthetic-lab-scan"
    # No extra request is made to obtain the name.
    assert len(session.get_calls) == 1
    assert session.get_calls[0][0][0] == SCAN_DETAILS_URL


@pytest.mark.parametrize(
    ("info", "expected"),
    [
        ({"name": "synthetic-lab-scan"}, "synthetic-lab-scan"),
        ({"name": "Weekly Perimeter Sweep"}, "Weekly Perimeter Sweep"),
        ({"name": "  padded  "}, "  padded  "),
        ({"name": "Réseau Été"}, "Réseau Été"),
        ({"name": ""}, ""),
        ({"name": None}, None),
        ({"name": 5}, None),
        ({"name": True}, None),
        ({"name": ["a"]}, None),
        ({"name": {"n": "a"}}, None),
        ({"targets": "10.0.0.7"}, None),
        ({}, None),
        (None, None),
        ("not an object", None),
        ([{"name": "x"}], None),
        (5, None),
    ],
)
def test_scan_name_extraction_handles_every_shape(config, patch_session, info, expected):
    payload = details_payload(history_record(1))
    payload["info"] = info
    patch_session(response=FakeResponse(200, payload=payload))

    result = list_scan_history(config, IDENTIFIER)

    assert result.scan_name == expected
    # A missing name never disturbs the history itself.
    assert [run.history_id for run in result.runs] == [1]


def test_an_absent_info_block_yields_no_scan_name(config, patch_session):
    payload = details_payload(history_record(1))
    del payload["info"]
    patch_session(response=FakeResponse(200, payload=payload))

    assert list_scan_history(config, IDENTIFIER).scan_name is None


def test_no_other_info_field_is_retained_by_discovery(config, patch_session):
    patch_session(
        response=FakeResponse(200, payload=details_payload(history_record(1)))
    )

    result = list_scan_history(config, IDENTIFIER)

    rendered = repr(result)
    for marker in ("10.0.0.7", "credentialed_scan", "targets", "scan_start"):
        assert marker not in rendered


def test_valid_completed_history(config, patch_session):
    patch_session(
        response=FakeResponse(
            200, payload=details_payload(history_record(4), history_record(1))
        )
    )

    result = list_scan_history(config, IDENTIFIER)

    assert result.scan_identifier == "5"
    assert [run.history_id for run in result.runs] == [1, 4]
    assert result.runs[0].started_iso == "2023-11-14T22:13:21Z"
    assert result.runs[0].last_modification_iso == "2023-11-14T23:13:21Z"
    assert result.runs[0].run_type == "local"
    assert result.runs[0].is_rollover is False


def test_history_ordering_is_deterministic(config, patch_session):
    records = [history_record(hid) for hid in (9, 3, 21, 1)]
    patch_session(response=FakeResponse(200, payload=details_payload(*records)))
    first = list_scan_history(config, IDENTIFIER)

    patch_session(
        response=FakeResponse(200, payload=details_payload(*reversed(records)))
    )
    second = list_scan_history(config, IDENTIFIER)

    assert [run.history_id for run in first.runs] == [1, 3, 9, 21]
    assert [r.history_id for r in first.runs] == [r.history_id for r in second.runs]


def test_legacy_id_field_is_accepted_for_history_records(config, patch_session):
    record = history_record(3)
    record["id"] = record.pop("history_id")
    patch_session(response=FakeResponse(200, payload=details_payload(record)))

    assert list_scan_history(config, IDENTIFIER).runs[0].history_id == 3


@pytest.mark.parametrize(
    ("status", "eligible"),
    [
        ("completed", True),
        ("COMPLETED", True),
        ("Completed", True),
        ("running", False),
        ("canceled", False),
        ("cancelled", False),
        ("aborted", False),
        ("paused", False),
        ("empty", False),
        ("completed successfully", False),
        ("", False),
        (None, False),
    ],
)
def test_only_the_completed_status_is_export_eligible(
    config, patch_session, status, eligible
):
    record = history_record(1)
    if status is None:
        record.pop("status")
    else:
        record["status"] = status
    patch_session(response=FakeResponse(200, payload=details_payload(record)))

    run = list_scan_history(config, IDENTIFIER).runs[0]

    assert run.status == status
    assert run.export_eligible is eligible


def test_mixed_statuses_are_preserved_verbatim(config, patch_session):
    payload = details_payload(
        history_record(1, status="completed"),
        history_record(2, status="Running"),
        history_record(3, status="canceled"),
    )
    patch_session(response=FakeResponse(200, payload=payload))

    result = list_scan_history(config, IDENTIFIER)

    assert [run.status for run in result.runs] == ["completed", "Running", "canceled"]
    assert [run.export_eligible for run in result.runs] == [True, False, False]
    assert len(result.export_eligible_runs) == 1


def test_completion_is_not_inferred_from_timestamps(config, patch_session):
    record = history_record(
        1, status="running", last_modification_date=1_700_099_999
    )
    patch_session(response=FakeResponse(200, payload=details_payload(record)))

    run = list_scan_history(config, IDENTIFIER).runs[0]

    assert run.last_modification_date == 1_700_099_999
    assert run.export_eligible is False


def test_no_run_is_selected_automatically(config, patch_session):
    payload = details_payload(
        history_record(1, status="completed"),
        history_record(2, status="completed"),
    )
    patch_session(response=FakeResponse(200, payload=payload))

    result = list_scan_history(config, IDENTIFIER)

    assert not hasattr(result, "selected_run")
    assert not hasattr(result, "latest_run")
    assert len(result.export_eligible_runs) == 2


def test_empty_history_is_successful_and_distinguishable(config, patch_session):
    patch_session(response=FakeResponse(200, payload=details_payload()))

    result = list_scan_history(config, IDENTIFIER)

    assert result.is_empty is True
    assert result.count == 0
    assert result.runs == ()


def test_missing_optional_history_fields_stay_neutral(config, patch_session):
    patch_session(
        response=FakeResponse(200, payload=details_payload({"history_id": 8}))
    )

    run = list_scan_history(config, IDENTIFIER).runs[0]

    assert run.history_id == 8
    assert run.uuid is None
    assert run.status is None
    assert run.creation_date is None
    assert run.started_iso is None
    assert run.run_type is None
    assert run.is_rollover is None
    assert run.export_eligible is False


# ---------------------------------------------------------------------------
# History discovery: response-contract failures
# ---------------------------------------------------------------------------


def test_missing_history_field_fails_and_names_the_shape(config, patch_session):
    patch_session(
        response=FakeResponse(200, payload=details_payload(history=...))
    )

    with pytest.raises(DiscoveryError) as excinfo:
        list_scan_history(config, IDENTIFIER)

    summary = excinfo.value.summary
    assert excinfo.value.exit_code == 5
    assert "no 'history' field" in summary
    assert "will not guess" in summary
    # Field *names* guide the repair; field *values* are never shown.
    assert "hosts" in summary and "vulnerabilities" in summary
    for marker in SENSITIVE_MARKERS:
        assert marker not in summary


@pytest.mark.parametrize(
    ("payload", "fragment"),
    [
        ({"info": {}}, "no 'history' field"),
        (details_payload(history=None), "null 'history' field"),
        (details_payload(history={"history_id": 1}), "not a list"),
        (details_payload(history="1,2"), "not a list"),
        (details_payload(history=5), "not a list"),
        (["unexpected"], "not the expected object structure"),
        ("unexpected", "not the expected object structure"),
        (42, "not the expected object structure"),
    ],
)
def test_invalid_history_collections_are_rejected(
    config, patch_session, payload, fragment
):
    patch_session(response=FakeResponse(200, payload=payload))

    with pytest.raises(DiscoveryError) as excinfo:
        list_scan_history(config, IDENTIFIER)

    assert excinfo.value.exit_code == 5
    assert fragment in excinfo.value.summary


@pytest.mark.parametrize(
    "record",
    [
        {"uuid": "no identifier"},
        {"history_id": None},
        {"history_id": "7"},
        {"history_id": 0},
        {"history_id": -1},
        {"history_id": 1, "status": 7},
        {"history_id": 1, "creation_date": "yesterday"},
        {"history_id": 1, "last_modification_date": 1.5},
        {"history_id": 1, "is_rollover": "true"},
        {"history_id": 1, "type": 3},
        "not an object",
        None,
    ],
)
def test_malformed_history_records_are_reported_not_skipped(
    config, patch_session, record
):
    patch_session(
        response=FakeResponse(
            200, payload=details_payload(history_record(500), record)
        )
    )

    with pytest.raises(DiscoveryError) as excinfo:
        list_scan_history(config, IDENTIFIER)

    assert excinfo.value.exit_code == 5


def test_duplicate_history_identifier_is_a_contract_error(config, patch_session):
    patch_session(
        response=FakeResponse(
            200,
            payload=details_payload(
                history_record(6), history_record(6, status="running")
            ),
        )
    )

    with pytest.raises(DiscoveryError) as excinfo:
        list_scan_history(config, IDENTIFIER)

    assert excinfo.value.exit_code == 5
    assert "more than one run with ID 6" in excinfo.value.summary
