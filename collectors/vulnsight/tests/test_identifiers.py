"""Scan-identifier validation tests (pure validation; no networking)."""

from __future__ import annotations

import pytest

from vulnsight.nessus.identifiers import (
    KIND_ID,
    KIND_PROVIDER,
    KIND_UUID,
    MAX_IDENTIFIER_LENGTH,
    ScanIdentifierError,
    parse_export_scan_identifier,
    parse_history_identifier,
    parse_scan_identifier,
)

CANONICAL_UUID = "01234567-89ab-cdef-0123-456789abcdef"
UPPERCASE_UUID = "01234567-89AB-CDEF-0123-456789ABCDEF"

#: The identifier the deployed standalone Nessus 10.12 scanner actually
#: returned in the ``uuid`` field of its scan list. It is not a canonical
#: UUID: the final group is 28 hexadecimal characters, not 12.
OBSERVED_PROVIDER_UUID = "01234567-89ab-cdef-0123-456789abcdef0123456789abcdef"


@pytest.mark.parametrize("raw", ["1", "5", "123", "  5  ", "9999999"])
def test_positive_integer_identifiers_are_accepted(raw):
    identifier = parse_scan_identifier(raw)

    assert identifier.kind == KIND_ID
    assert identifier.is_numeric is True
    assert identifier.value == raw.strip()
    assert identifier.numeric_id == int(raw)


@pytest.mark.parametrize("raw", [CANONICAL_UUID, UPPERCASE_UUID])
def test_canonical_uuid_identifiers_are_accepted(raw):
    identifier = parse_scan_identifier(raw)

    assert identifier.kind == KIND_UUID
    assert identifier.is_numeric is False
    assert identifier.value == raw
    assert identifier.numeric_id is None


def test_observed_provider_identifier_is_accepted_verbatim():
    identifier = parse_scan_identifier(OBSERVED_PROVIDER_UUID)

    assert identifier.kind == KIND_PROVIDER
    assert identifier.is_numeric is False
    # The provider value is preserved exactly, never normalised or truncated.
    assert identifier.value == OBSERVED_PROVIDER_UUID


@pytest.mark.parametrize("final_length", [12, 13, 28, 32, 64])
def test_accepted_final_group_lengths(final_length):
    raw = f"71ac89ee-e23f-4daa-c1f2-{'a' * final_length}"

    assert parse_scan_identifier(raw).value == raw


@pytest.mark.parametrize("final_length", [0, 1, 11, 65, 80])
def test_rejected_final_group_lengths(final_length):
    raw = f"71ac89ee-e23f-4daa-c1f2-{'a' * final_length}"

    with pytest.raises(ScanIdentifierError):
        parse_scan_identifier(raw)


def test_overlong_identifier_is_rejected():
    raw = "a" * (MAX_IDENTIFIER_LENGTH + 1)

    with pytest.raises(ScanIdentifierError) as excinfo:
        parse_scan_identifier(raw)

    assert str(MAX_IDENTIFIER_LENGTH) in str(excinfo.value)


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        ("0", "zero"),
        ("-1", "negative integer"),
        ("+7", "signed integer"),
        ("0123", "leading zeroes"),
        ("", "blank"),
        ("   ", "whitespace only"),
        ("../123", "traversal"),
        ("..", "traversal"),
        ("123/../456", "traversal within a path"),
        ("123/history", "slash"),
        ("123\\history", "backslash"),
        ("/scans/123", "absolute path"),
        ("123?limit=1", "query injection"),
        ("123#fragment", "fragment injection"),
        ("123%2f456", "percent encoding"),
        ("5 OR 1=1", "injection with whitespace"),
        ("https://elsewhere.invalid/scans/5", "an absolute URL"),
        ("0123456789abcdef", "unhyphenated hexadecimal"),
        ("01234567-89ab-cdef-0123-456789abcde", "short final group"),
        ("01234567-89ab-cdef-0123-456789abcdeg", "non-hexadecimal characters"),
        ("0123456789ab-cdef-0123-456789abcdef", "misgrouped"),
        ("71ac89ee-e23f-4daa-0d6007eeb92a36ae102af435bbcf", "too few groups"),
        ("71ac89ee-e23f-4daa-c1f2-0d60-07eeb92a36ae102af43", "too many groups"),
        ("synthetic-lab-scan", "a scan name"),
        ("Weekly Lab Sweep", "a scan name with spaces"),
        ("latest", "an implicit selector"),
        ("most-recent", "an implicit selector"),
        ("12.5", "a decimal"),
    ],
)
def test_unacceptable_identifiers_are_rejected(raw, reason):
    with pytest.raises(ScanIdentifierError):
        parse_scan_identifier(raw)


@pytest.mark.parametrize("raw", [None, 123, 1.5, ["5"]])
def test_non_text_identifiers_are_rejected(raw):
    with pytest.raises(ScanIdentifierError):
        parse_scan_identifier(raw)


def test_oversized_integer_is_rejected():
    with pytest.raises(ScanIdentifierError):
        parse_scan_identifier("9" * 30)


def test_rejection_message_names_the_offending_value():
    with pytest.raises(ScanIdentifierError) as excinfo:
        parse_scan_identifier("123/history")

    assert "123/history" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Export identifiers (numeric only)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["1", "5", "123", "  5  "])
def test_export_accepts_a_numeric_scan_id(raw):
    identifier = parse_export_scan_identifier(raw)

    assert identifier.is_numeric is True
    assert identifier.numeric_id == int(raw)


@pytest.mark.parametrize("raw", [CANONICAL_UUID, UPPERCASE_UUID, OBSERVED_PROVIDER_UUID])
def test_export_refuses_a_provider_identifier(raw):
    with pytest.raises(ScanIdentifierError) as excinfo:
        parse_export_scan_identifier(raw)

    assert "numeric scan ID" in str(excinfo.value)


@pytest.mark.parametrize("raw", ["0", "-1", "", "latest", "synthetic-lab-scan", "../5"])
def test_export_rejects_the_same_unsafe_values_as_discovery(raw):
    with pytest.raises(ScanIdentifierError):
        parse_export_scan_identifier(raw)


@pytest.mark.parametrize(
    ("raw", "expected"), [("1", 1), ("6", 6), ("  6  ", 6), ("1234567", 1234567)]
)
def test_history_identifiers_accept_positive_integers(raw, expected):
    assert parse_history_identifier(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "0",
        "-1",
        "+6",
        "06",
        "",
        "   ",
        "6.0",
        "latest",
        "most-recent",
        "../6",
        "6/download",
        "6\\download",
        "6?a=1",
        "6#f",
        "6%2f7",
        "6 OR 1=1",
        CANONICAL_UUID,
        OBSERVED_PROVIDER_UUID,
        "9" * 30,
        "1" * 200,
    ],
)
def test_history_identifiers_reject_everything_else(raw):
    with pytest.raises(ScanIdentifierError):
        parse_history_identifier(raw)


@pytest.mark.parametrize("raw", [None, 6, 1.5, ["6"]])
def test_non_text_history_identifiers_are_rejected(raw):
    with pytest.raises(ScanIdentifierError):
        parse_history_identifier(raw)


def test_history_guidance_names_the_history_id_column():
    with pytest.raises(ScanIdentifierError) as excinfo:
        parse_history_identifier("latest")

    message = str(excinfo.value)
    assert "HISTORY ID" in message
    assert "'latest'" in message


def test_guidance_recommends_the_numeric_scan_id():
    with pytest.raises(ScanIdentifierError) as excinfo:
        parse_scan_identifier("synthetic-lab-scan")

    message = str(excinfo.value)
    assert "positive integer scan ID" in message
    assert "names are not accepted" in message
