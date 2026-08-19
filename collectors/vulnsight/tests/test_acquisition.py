"""End-to-end acquisition tests: eligibility, pipeline, commit and manifest.

Every request is mocked, every wait uses an injected clock, and every file is
written under pytest's ``tmp_path``. No test contacts Nessus.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from vulnsight.nessus.acquisition import acquire_export, select_completed_history
from vulnsight.nessus.client import Outcome
from vulnsight.nessus.errors import EvidenceError, ExportError, XmlValidationError
from vulnsight.nessus.identifiers import parse_scan_identifier
from conftest import (
    FAKE_ACCESS_KEY,
    FAKE_SECRET_KEY,
    VALID_NESSUS_XML,
    FakeResponse,
)

SCAN = parse_scan_identifier("5")
HISTORY_ID = 6
ENDPOINT = "https://nessus.lab.invalid:8834"

FAKE_TOKEN = "TOKENtokenTOKEN-must-never-be-persisted"

#: Values from the scan-details response that must never be parsed, shown or
#: written anywhere.
SENSITIVE_MARKERS = ("10.0.0.7", "CVE-1999-0001", "credentialed_scan")

DIGEST = hashlib.sha256(VALID_NESSUS_XML).hexdigest()


def history_record(history_id: int = HISTORY_ID, status: str = "completed", **extra):
    record = {
        "history_id": history_id,
        "uuid": f"1000000{history_id}-89ab-cdef-0123-456789abcdef",
        "status": status,
        "creation_date": 1_700_000_000,
        "last_modification_date": 1_700_003_600,
        "type": "local",
        "is_rollover": False,
    }
    record.update(extra)
    return record


#: The live scan name, and the stem it must produce.
SCAN_NAME = "synthetic-lab-scan"
STEM = "synthetic-lab-scan__scan-5__history-6"
FALLBACK_STEM = "nessus__scan-5__history-6"

#: Sentinel so a test can remove the ``info`` block entirely.
NO_INFO = object()


def details_response(*records, info=NO_INFO) -> FakeResponse:
    """A scan-details response carrying much that must be ignored."""
    payload = {
        "hosts": [{"hostname": "10.0.0.7", "critical": 3}],
        "vulnerabilities": [{"plugin_name": "CVE-1999-0001", "count": 4}],
        "notes": [{"title": "credentialed_scan"}],
        "history": list(records) or [history_record()],
    }
    if info is NO_INFO:
        payload["info"] = {"name": SCAN_NAME, "targets": "10.0.0.7"}
    elif info is not None:
        payload["info"] = info
    return FakeResponse(200, payload=payload)


def export_response(file_id: object = 9) -> FakeResponse:
    return FakeResponse(200, payload={"file": file_id, "token": FAKE_TOKEN})


def status_response(status: str = "ready") -> FakeResponse:
    return FakeResponse(200, payload={"status": status})


def download_response(payload: bytes = VALID_NESSUS_XML, **kwargs) -> FakeResponse:
    return FakeResponse(200, payload=None, chunks=[payload], **kwargs)


def happy_path(*, history=None, payload: bytes = VALID_NESSUS_XML) -> list:
    return [
        details_response(*(history or [history_record()])),
        export_response(),
        status_response("ready"),
        download_response(payload),
    ]


def output_dir(tmp_path):
    return tmp_path / "evidence" / "raw" / "nessus"


def run(config, patch_api_session, tmp_path, fake_clock, responses=None, **kwargs):
    session = patch_api_session(responses if responses is not None else happy_path())
    result = acquire_export(
        config,
        kwargs.pop("scan", SCAN),
        kwargs.pop("history_id", HISTORY_ID),
        kwargs.pop("directory", output_dir(tmp_path)),
        clock=fake_clock.as_clock(),
        now=kwargs.pop("now", lambda: "2026-08-19T07:40:00Z"),
    )
    return session, result


# ---------------------------------------------------------------------------
# Eligibility
# ---------------------------------------------------------------------------


def test_the_requested_history_must_exist(config, patch_api_session):
    patch_api_session([details_response(history_record(6))])

    with pytest.raises(ExportError) as excinfo:
        select_completed_history(config, SCAN, 99)

    assert excinfo.value.outcome is Outcome.CONFIGURATION_ERROR
    assert excinfo.value.exit_code == 2
    assert "was not found" in excinfo.value.summary
    assert "Available history IDs: 6" in excinfo.value.summary
    assert "No export was requested" in excinfo.value.summary


@pytest.mark.parametrize("status", ["completed", "COMPLETED", "Completed"])
def test_completed_is_accepted_case_insensitively(config, patch_api_session, status):
    patch_api_session([details_response(history_record(6, status=status))])

    selected = select_completed_history(config, SCAN, 6)

    assert selected.history.history_id == 6
    assert selected.history.status == status
    assert selected.scan_name == SCAN_NAME


@pytest.mark.parametrize(
    "status", ["running", "canceled", "cancelled", "aborted", "paused", "empty", ""]
)
def test_an_ineligible_history_is_refused_before_any_export_request(
    config, patch_api_session, status
):
    session = patch_api_session([details_response(history_record(6, status=status))])

    with pytest.raises(ExportError) as excinfo:
        select_completed_history(config, SCAN, 6)

    assert excinfo.value.exit_code == 2
    assert "not 'completed'" in excinfo.value.summary
    assert session.methods == ["GET"]
    assert "POST" not in session.methods


def test_timestamps_never_imply_completion(config, patch_api_session):
    patch_api_session(
        [
            details_response(
                history_record(
                    6, status="running", last_modification_date=1_700_099_999
                )
            )
        ]
    )

    with pytest.raises(ExportError):
        select_completed_history(config, SCAN, 6)


def test_no_history_is_selected_implicitly(config, patch_api_session):
    """A completed run at another ID is never substituted for the request."""
    patch_api_session(
        [details_response(history_record(6, status="running"), history_record(7))]
    )

    with pytest.raises(ExportError) as excinfo:
        select_completed_history(config, SCAN, 6)

    assert "not 'completed'" in excinfo.value.summary


def test_eligibility_uses_the_read_only_scan_details_endpoint(
    config, patch_api_session
):
    session = patch_api_session([details_response()])

    select_completed_history(config, SCAN, HISTORY_ID)

    assert session.methods == ["GET"]
    assert session.urls == [f"{ENDPOINT}/scans/5"]


# ---------------------------------------------------------------------------
# Scan name, taken from the eligibility response
# ---------------------------------------------------------------------------


def test_the_scan_name_comes_from_the_existing_eligibility_request(
    config, patch_api_session
):
    session = patch_api_session([details_response()])

    selected = select_completed_history(config, SCAN, HISTORY_ID)

    # One request, and it is the read-only details request already required.
    assert len(session.calls) == 1
    assert session.methods == ["GET"]
    assert session.urls == [f"{ENDPOINT}/scans/5"]
    assert selected.scan_name == SCAN_NAME


@pytest.mark.parametrize(
    ("info", "expected"),
    [
        ({"name": "synthetic-lab-scan"}, "synthetic-lab-scan"),
        ({"name": "Weekly Perimeter Sweep"}, "Weekly Perimeter Sweep"),
        ({"name": "  padded  "}, "  padded  "),
        ({"name": ""}, ""),
        ({"name": None}, None),
        ({"name": 5}, None),
        ({"name": ["a"]}, None),
        ({"targets": "10.0.0.7"}, None),
        ({}, None),
        (None, None),
        ("not an object", None),
        ([{"name": "x"}], None),
    ],
)
def test_scan_name_extraction_is_forgiving(config, patch_api_session, info, expected):
    patch_api_session([details_response(info=info)])

    selected = select_completed_history(config, SCAN, HISTORY_ID)

    assert selected.scan_name == expected
    # A naming inconvenience never fails an otherwise valid selection.
    assert selected.history.history_id == HISTORY_ID


def test_no_other_info_field_is_retained(config, patch_api_session):
    patch_api_session(
        [details_response(info={"name": SCAN_NAME, "targets": "10.0.0.7", "uuid": "x"})]
    )

    selected = select_completed_history(config, SCAN, HISTORY_ID)

    rendered = repr(selected)
    assert "10.0.0.7" not in rendered
    assert "targets" not in rendered
    assert selected.scan_name == SCAN_NAME


def test_a_name_is_never_inferred_from_targets_hosts_or_uuid(
    config, patch_api_session
):
    patch_api_session([details_response(info={"uuid": "71ac89ee-e23f"})])

    selected = select_completed_history(config, SCAN, HISTORY_ID)

    assert selected.scan_name is None


# ---------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------


def test_a_successful_acquisition(config, patch_api_session, tmp_path, fake_clock):
    session, result = run(config, patch_api_session, tmp_path, fake_clock)

    assert result.raw_path == output_dir(tmp_path) / f"{STEM}.nessus"
    assert (
        result.manifest_path
        == output_dir(tmp_path) / f"{STEM}.manifest.json"
    )
    assert result.size_bytes == len(VALID_NESSUS_XML)
    assert result.sha256 == DIGEST
    assert result.file_id == "9"
    assert result.history.history_id == 6
    assert result.validation.report_count == 1
    assert session.closed is True


def test_the_pipeline_uses_exactly_the_approved_calls(
    config, patch_api_session, tmp_path, fake_clock
):
    session, _result = run(config, patch_api_session, tmp_path, fake_clock)

    assert session.methods == ["GET", "POST", "GET", "GET"]
    assert session.urls == [
        f"{ENDPOINT}/scans/5",
        f"{ENDPOINT}/scans/5/export",
        f"{ENDPOINT}/scans/5/export/9/status",
        f"{ENDPOINT}/scans/5/export/9/download",
    ]
    assert session.forbidden_calls == []
    assert session.calls[1][2]["json"] == {"format": "nessus", "history_id": 6}


def test_the_committed_bytes_match_the_download_exactly(
    config, patch_api_session, tmp_path, fake_clock
):
    _session, result = run(config, patch_api_session, tmp_path, fake_clock)

    written = result.raw_path.read_bytes()
    assert written == VALID_NESSUS_XML
    assert hashlib.sha256(written).hexdigest() == result.sha256
    assert len(written) == result.size_bytes


def test_the_output_directory_is_created(config, patch_api_session, tmp_path, fake_clock):
    assert not output_dir(tmp_path).exists()

    run(config, patch_api_session, tmp_path, fake_clock)

    assert output_dir(tmp_path).is_dir()


def test_no_part_file_survives_a_success(
    config, patch_api_session, tmp_path, fake_clock
):
    run(config, patch_api_session, tmp_path, fake_clock)

    assert list(output_dir(tmp_path).glob("*.part")) == []
    assert sorted(p.name for p in output_dir(tmp_path).iterdir()) == [
        f"{STEM}.manifest.json",
        f"{STEM}.nessus",
    ]


def test_polling_waits_then_downloads(config, patch_api_session, tmp_path, fake_clock):
    responses = [
        details_response(),
        export_response(),
        status_response("loading"),
        status_response("ready"),
        download_response(),
    ]

    _session, result = run(
        config, patch_api_session, tmp_path, fake_clock, responses=responses
    )

    assert result.polls == 2
    assert fake_clock.sleeps == [2.0]


def test_an_empty_report_is_valid_evidence(
    config, patch_api_session, tmp_path, fake_clock
):
    payload = b"<NessusClientData_v2><Report name='empty'/></NessusClientData_v2>"

    _session, result = run(
        config,
        patch_api_session,
        tmp_path,
        fake_clock,
        responses=happy_path(payload=payload),
    )

    assert result.validation.report_host_count == 0
    assert result.validation.report_item_count == 0
    assert result.raw_path.read_bytes() == payload


# ---------------------------------------------------------------------------
# The manifest sidecar
# ---------------------------------------------------------------------------


def read_manifest(result):
    return json.loads(result.manifest_path.read_text(encoding="utf-8"))


def test_the_manifest_is_written_beside_the_raw_file(
    config, patch_api_session, tmp_path, fake_clock
):
    _session, result = run(config, patch_api_session, tmp_path, fake_clock)
    manifest = read_manifest(result)

    assert result.manifest_path.parent == result.raw_path.parent
    assert manifest["manifest_schema"] == "vulnsight.nessus-export-manifest/1.1"
    assert manifest["manifest_created_utc"] == "2026-08-19T07:40:00Z"
    assert manifest["artefact"]["filename"] == result.raw_path.name


def test_the_manifest_records_the_raw_name_and_the_filename_the_slug(
    config, patch_api_session, tmp_path, fake_clock
):
    responses = happy_path()
    responses[0] = details_response(info={"name": "Weekly / Perimeter Sweep"})
    _session, result = run(
        config, patch_api_session, tmp_path, fake_clock, responses=responses
    )
    manifest = read_manifest(result)

    # The raw provider name survives verbatim...
    assert manifest["scan"]["scan_name"] == "Weekly / Perimeter Sweep"
    # ...while the filename carries only its sanitised slug.
    assert result.raw_path.name == "weekly-perimeter-sweep__scan-5__history-6.nessus"
    assert "/" not in result.raw_path.name


@pytest.mark.parametrize(
    ("info", "expected_stem"),
    [
        ({"name": "synthetic-lab-scan"}, STEM),
        ({"name": "Réseau Été"}, "reseau-ete__scan-5__history-6"),
        ({"name": ""}, FALLBACK_STEM),
        ({"name": None}, FALLBACK_STEM),
        ({"name": 5}, FALLBACK_STEM),
        ({"name": "東京"}, FALLBACK_STEM),
        ({}, FALLBACK_STEM),
        (None, FALLBACK_STEM),
    ],
)
def test_the_filename_falls_back_without_failing_the_export(
    config, patch_api_session, tmp_path, fake_clock, info, expected_stem
):
    responses = happy_path()
    responses[0] = details_response(info=info)

    _session, result = run(
        config, patch_api_session, tmp_path, fake_clock, responses=responses
    )

    assert result.raw_path.name == f"{expected_stem}.nessus"
    assert result.manifest_path.name == f"{expected_stem}.manifest.json"
    assert result.raw_path.read_bytes() == VALID_NESSUS_XML
    assert result.sha256 == DIGEST


def test_a_hostile_scan_name_cannot_escape_the_output_directory(
    config, patch_api_session, tmp_path, fake_clock
):
    responses = happy_path()
    responses[0] = details_response(info={"name": "../../../etc/passwd"})

    _session, result = run(
        config, patch_api_session, tmp_path, fake_clock, responses=responses
    )

    assert result.raw_path.parent == output_dir(tmp_path)
    assert result.raw_path.name == "etc-passwd__scan-5__history-6.nessus"
    assert result.raw_path.is_file()
    # Nothing was written outside the requested directory.
    assert sorted(p.name for p in output_dir(tmp_path).iterdir()) == [
        "etc-passwd__scan-5__history-6.manifest.json",
        "etc-passwd__scan-5__history-6.nessus",
    ]


def test_the_manifest_checksum_and_size_agree_with_the_file(
    config, patch_api_session, tmp_path, fake_clock
):
    _session, result = run(config, patch_api_session, tmp_path, fake_clock)
    manifest = read_manifest(result)
    written = result.raw_path.read_bytes()

    assert manifest["artefact"]["sha256"] == hashlib.sha256(written).hexdigest()
    assert manifest["artefact"]["size_bytes"] == len(written)


def test_the_manifest_records_the_selected_history_verbatim(
    config, patch_api_session, tmp_path, fake_clock
):
    _session, result = run(config, patch_api_session, tmp_path, fake_clock)
    scan = read_manifest(result)["scan"]

    assert scan["scan_id"] == 5
    assert scan["scan_name"] == SCAN_NAME
    assert scan["history_id"] == 6
    assert scan["history_status"] == "completed"
    assert scan["history_creation_date"] == 1_700_000_000
    assert scan["history_uuid"] == "10000006-89ab-cdef-0123-456789abcdef"


def test_the_manifest_records_the_bounded_export_parameters(
    config, patch_api_session, tmp_path, fake_clock
):
    _session, result = run(config, patch_api_session, tmp_path, fake_clock)
    export = read_manifest(result)["export"]

    assert export["request_path"] == "/scans/5/export"
    assert export["request_body"] == {"format": "nessus", "history_id": 6}
    assert export["file_id"] == "9"
    assert export["poll_interval_seconds"] == 2.0
    assert export["poll_timeout_seconds"] == 600.0
    assert export["max_bytes"] == 1_073_741_824


def test_the_manifest_never_carries_a_secret_token_or_finding(
    config, patch_api_session, tmp_path, fake_clock
):
    _session, result = run(config, patch_api_session, tmp_path, fake_clock)
    rendered = result.manifest_path.read_text(encoding="utf-8")

    for forbidden in (
        FAKE_ACCESS_KEY,
        FAKE_SECRET_KEY,
        FAKE_TOKEN,
        "X-ApiKeys",
        *SENSITIVE_MARKERS,
    ):
        assert forbidden not in rendered


def test_unrelated_scan_detail_never_reaches_the_result(
    config, patch_api_session, tmp_path, fake_clock
):
    _session, result = run(config, patch_api_session, tmp_path, fake_clock)

    for marker in SENSITIVE_MARKERS:
        assert marker not in repr(result)


# ---------------------------------------------------------------------------
# Refusals and rollback
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("existing", ["nessus", "manifest.json"])
def test_an_existing_destination_refuses_before_the_export_request(
    config, patch_api_session, tmp_path, fake_clock, existing
):
    """The destination check happens before the POST.

    The filename now depends on the scan name, which arrives with the
    read-only eligibility request, so that one GET necessarily precedes the
    check. Nothing is created, and no export is ever requested.
    """
    directory = output_dir(tmp_path)
    directory.mkdir(parents=True)
    target = directory / f"{STEM}.{existing}"
    target.write_bytes(b"pre-existing evidence")
    session = patch_api_session(happy_path())

    with pytest.raises(EvidenceError) as excinfo:
        acquire_export(
            config,
            SCAN,
            HISTORY_ID,
            directory,
            clock=fake_clock.as_clock(),
        )

    assert excinfo.value.exit_code == 2
    # Exactly one read-only request, and no export request at all.
    assert session.methods == ["GET"]
    assert "POST" not in session.methods
    assert target.read_bytes() == b"pre-existing evidence"
    assert list(directory.glob("*.part")) == []
    assert sorted(p.name for p in directory.iterdir()) == [f"{STEM}.{existing}"]


def test_an_old_style_artefact_is_left_untouched_and_not_migrated(
    config, patch_api_session, tmp_path, fake_clock
):
    """Evidence acquired under the previous naming scheme is never renamed."""
    directory = output_dir(tmp_path)
    directory.mkdir(parents=True)
    old_raw = directory / "nessus_scan-5_history-6.nessus"
    old_manifest = directory / "nessus_scan-5_history-6.manifest.json"
    old_raw.write_bytes(b"earlier acquisition")
    old_manifest.write_bytes(b'{"manifest_schema": "vulnsight.nessus-export-manifest/1.0"}')

    _session, result = run(config, patch_api_session, tmp_path, fake_clock)

    # The old artefacts are still exactly where and what they were...
    assert old_raw.read_bytes() == b"earlier acquisition"
    assert b"1.0" in old_manifest.read_bytes()
    # ...and the new acquisition sits beside them under the new name.
    assert result.raw_path.name == f"{STEM}.nessus"
    assert sorted(p.name for p in directory.iterdir()) == sorted(
        [
            f"{STEM}.manifest.json",
            f"{STEM}.nessus",
            "nessus_scan-5_history-6.manifest.json",
            "nessus_scan-5_history-6.nessus",
        ]
    )


def test_a_rejected_artefact_leaves_nothing_behind(
    config, patch_api_session, tmp_path, fake_clock
):
    responses = happy_path(payload=b'{"error":"expired"}')

    with pytest.raises(XmlValidationError) as excinfo:
        run(config, patch_api_session, tmp_path, fake_clock, responses=responses)

    assert excinfo.value.exit_code == 5
    assert list(output_dir(tmp_path).iterdir()) == []


def test_a_failed_download_leaves_no_part_file(
    config, patch_api_session, tmp_path, fake_clock
):
    responses = [
        details_response(),
        export_response(),
        status_response("ready"),
        FakeResponse(200, payload=None, chunks=[]),
    ]

    with pytest.raises(ExportError):
        run(config, patch_api_session, tmp_path, fake_clock, responses=responses)

    assert list(output_dir(tmp_path).glob("*.part")) == []
    assert list(output_dir(tmp_path).iterdir()) == []


def test_a_provider_export_error_writes_nothing(
    config, patch_api_session, tmp_path, fake_clock
):
    responses = [details_response(), export_response(), status_response("error")]

    with pytest.raises(ExportError) as excinfo:
        run(config, patch_api_session, tmp_path, fake_clock, responses=responses)

    assert excinfo.value.exit_code == 5
    assert list(output_dir(tmp_path).iterdir()) == []


def test_an_ineligible_history_stops_before_the_post(
    config, patch_api_session, tmp_path, fake_clock
):
    responses = [details_response(history_record(6, status="running"))]
    session = patch_api_session(responses)

    with pytest.raises(ExportError) as excinfo:
        acquire_export(
            config,
            SCAN,
            HISTORY_ID,
            output_dir(tmp_path),
            clock=fake_clock.as_clock(),
        )

    assert excinfo.value.exit_code == 2
    assert session.methods == ["GET"]
    assert list(output_dir(tmp_path).iterdir()) == []


def test_a_pre_existing_unrelated_file_is_never_disturbed(
    config, patch_api_session, tmp_path, fake_clock
):
    directory = output_dir(tmp_path)
    directory.mkdir(parents=True)
    bystander = directory / "another-scan__scan-41__history-2.nessus"
    bystander.write_bytes(b"another acquisition")

    run(config, patch_api_session, tmp_path, fake_clock)

    assert bystander.read_bytes() == b"another acquisition"
