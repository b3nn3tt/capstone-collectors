"""Safe structural validation of a downloaded .nessus artefact."""

from __future__ import annotations

import pytest

from vulnsight.nessus.errors import XmlValidationError
from vulnsight.nessus.nessus_xml import NESSUS_ROOT, validate_nessus_file
from conftest import EMPTY_REPORT_NESSUS_XML, VALID_NESSUS_XML


def write(tmp_path, payload: bytes, name: str = "artefact.nessus"):
    path = tmp_path / name
    path.write_bytes(payload)
    return path


# ---------------------------------------------------------------------------
# Accepted documents
# ---------------------------------------------------------------------------


def test_a_valid_export_is_accepted_with_structural_counts(tmp_path):
    result = validate_nessus_file(write(tmp_path, VALID_NESSUS_XML))

    assert result.root == NESSUS_ROOT
    assert result.report_count == 1
    assert result.report_host_count == 1
    assert result.report_item_count == 2


def test_a_completed_scan_with_no_hosts_or_findings_is_valid(tmp_path):
    result = validate_nessus_file(write(tmp_path, EMPTY_REPORT_NESSUS_XML))

    assert result.root == NESSUS_ROOT
    assert result.report_count == 1
    assert result.report_host_count == 0
    assert result.report_item_count == 0


def test_multiple_reports_and_hosts_are_counted(tmp_path):
    payload = (
        b"<NessusClientData_v2>"
        b'<Report name="a"><ReportHost name="h1"><ReportItem/><ReportItem/>'
        b'</ReportHost><ReportHost name="h2"><ReportItem/></ReportHost></Report>'
        b'<Report name="b"><ReportHost name="h3"/></Report>'
        b"</NessusClientData_v2>"
    )

    result = validate_nessus_file(write(tmp_path, payload))

    assert (result.report_count, result.report_host_count, result.report_item_count) == (
        2,
        3,
        3,
    )


def test_validation_does_not_modify_the_file(tmp_path):
    path = write(tmp_path, VALID_NESSUS_XML)
    before = path.read_bytes()
    stat_before = path.stat().st_size

    validate_nessus_file(path)

    assert path.read_bytes() == before
    assert path.stat().st_size == stat_before


# ---------------------------------------------------------------------------
# Rejected documents
# ---------------------------------------------------------------------------


def test_a_wrong_root_element_is_rejected(tmp_path):
    payload = b"<NessusClientData><Report/></NessusClientData>"

    with pytest.raises(XmlValidationError) as excinfo:
        validate_nessus_file(write(tmp_path, payload))

    assert excinfo.value.exit_code == 5
    assert "root element" in excinfo.value.summary


def test_a_document_without_a_report_is_rejected(tmp_path):
    payload = b"<NessusClientData_v2><Policy/></NessusClientData_v2>"

    with pytest.raises(XmlValidationError) as excinfo:
        validate_nessus_file(write(tmp_path, payload))

    assert excinfo.value.exit_code == 5
    assert "no 'Report' element" in excinfo.value.summary


@pytest.mark.parametrize(
    ("payload", "description"),
    [
        (b"<NessusClientData_v2><Report>", "truncated"),
        (b'<?xml version="1.0"?><NessusClientData_v2><Report/>', "unclosed root"),
        (b"not xml at all", "plain text"),
        (b'{"error": "expired"}', "a JSON error body"),
        (b"<html><body>401 Unauthorized</body></html>", "an HTML error page"),
        (b"", "an empty file"),
        (b"<NessusClientData_v2><Report/></Wrong>", "mismatched tags"),
    ],
)
def test_malformed_content_is_rejected(tmp_path, payload, description):
    with pytest.raises(XmlValidationError) as excinfo:
        validate_nessus_file(write(tmp_path, payload))

    assert excinfo.value.exit_code == 5


def test_a_dtd_declaration_is_refused(tmp_path):
    payload = (
        b'<?xml version="1.0"?>\n'
        b"<!DOCTYPE NessusClientData_v2>\n"
        b"<NessusClientData_v2><Report/></NessusClientData_v2>"
    )

    with pytest.raises(XmlValidationError) as excinfo:
        validate_nessus_file(write(tmp_path, payload))

    assert "DTD" in excinfo.value.summary


def test_an_entity_declaration_is_refused(tmp_path):
    payload = (
        b'<?xml version="1.0"?>\n'
        b'<!DOCTYPE NessusClientData_v2 [<!ENTITY boom "aaaaaaaaaa">]>\n'
        b"<NessusClientData_v2><Report>&boom;</Report></NessusClientData_v2>"
    )

    with pytest.raises(XmlValidationError) as excinfo:
        validate_nessus_file(write(tmp_path, payload))

    # The DTD is refused first; either refusal keeps the document out.
    assert excinfo.value.exit_code == 5
    assert "DTD" in excinfo.value.summary or "entity" in excinfo.value.summary


def test_an_external_reference_is_refused(tmp_path):
    payload = (
        b'<?xml version="1.0"?>\n'
        b"<!DOCTYPE NessusClientData_v2 [\n"
        b'  <!ENTITY xxe SYSTEM "file:///etc/passwd">\n'
        b"]>\n"
        b"<NessusClientData_v2><Report>&xxe;</Report></NessusClientData_v2>"
    )

    with pytest.raises(XmlValidationError) as excinfo:
        validate_nessus_file(write(tmp_path, payload))

    assert excinfo.value.exit_code == 5


def test_a_billion_laughs_payload_is_refused(tmp_path):
    payload = (
        b'<?xml version="1.0"?>\n'
        b"<!DOCTYPE lolz [\n"
        b' <!ENTITY lol "lol">\n'
        b' <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;">\n'
        b"]>\n"
        b"<NessusClientData_v2><Report>&lol2;</Report></NessusClientData_v2>"
    )

    with pytest.raises(XmlValidationError) as excinfo:
        validate_nessus_file(write(tmp_path, payload))

    assert excinfo.value.exit_code == 5


def test_rejection_messages_say_nothing_was_committed(tmp_path):
    with pytest.raises(XmlValidationError) as excinfo:
        validate_nessus_file(write(tmp_path, b"broken"))

    assert "Nothing was committed" in excinfo.value.summary
