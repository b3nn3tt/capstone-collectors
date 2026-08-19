"""Deterministic naming and no-overwrite commit of raw evidence."""

from __future__ import annotations

import re

import pytest

from vulnsight.nessus.errors import EvidenceError
from vulnsight.nessus.evidence import (
    FALLBACK_SLUG,
    MAX_SLUG_LENGTH,
    artefact_stem,
    assert_absent,
    commit,
    discard,
    ensure_directory,
    new_part_path,
    plan_paths,
    rollback,
    safe_scan_slug,
)

MANIFEST_BYTES = b'{\n  "manifest_schema": "test"\n}\n'

#: The only characters a generated filename stem may contain.
STEM_PATTERN = re.compile(r"\A[a-z0-9_-]+\Z")

LIVE_SCAN_NAME = "synthetic-lab-scan"


def make_paths(tmp_path, scan_id: int = 5, history_id: int = 6, scan_name=LIVE_SCAN_NAME):
    directory = tmp_path / "evidence" / "raw" / "nessus"
    ensure_directory(directory)
    return plan_paths(directory, scan_id, history_id, scan_name)


# ---------------------------------------------------------------------------
# The safe slug
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        # Ordinary names.
        ("synthetic-lab-scan", "synthetic-lab-scan"),
        ("Perimeter Scan", "perimeter-scan"),
        ("web01", "web01"),
        # Spaces and repeated punctuation.
        ("  padded  name  ", "padded-name"),
        ("a...b", "a-b"),
        ("a___b", "a-b"),
        ("!!!weekly!!!sweep!!!", "weekly-sweep"),
        # Separators that must never survive.
        ("dir/sub", "dir-sub"),
        ("dir\\sub", "dir-sub"),
        ("..", FALLBACK_SLUG),
        ("../../etc/passwd", "etc-passwd"),
        ("..\\..\\windows\\system32", "windows-system32"),
        # Drive-like and UNC-like text.
        ("C:\\evidence", "c-evidence"),
        ("\\\\server\\share", "server-share"),
        ("//server/share", "server-share"),
        # Query, fragment, escape and address characters.
        ("scan?a=1", "scan-a-1"),
        ("scan#frag", "scan-frag"),
        ("scan%2fetc", "scan-2fetc"),
        ("scan:stream", "scan-stream"),
        ("scan@host", "scan-host"),
        ("a&b", "a-b"),
        ("file.nessus:hidden", "file-nessus-hidden"),
        # Leading and trailing dots and spaces.
        (" .hidden. ", "hidden"),
        ("...", FALLBACK_SLUG),
        # Control characters and newlines.
        ("line1\nline2", "line1-line2"),
        ("tab\there", "tab-here"),
        ("nul\x00byte", "nul-byte"),
        ("\r\n\t", FALLBACK_SLUG),
        # Accented Latin transliteration.
        ("Réseau Été", "reseau-ete"),
        ("Zürich Süd", "zurich-sud"),
        ("naïve café", "naive-cafe"),
        # Entirely non-ASCII text that cannot produce an ASCII slug.
        ("東京スキャン", FALLBACK_SLUG),
        ("Сканирование", FALLBACK_SLUG),
        ("🎯🎯🎯", FALLBACK_SLUG),
        # Windows reserved-looking names.
        ("CON", "con"),
        ("PRN", "prn"),
        ("AUX", "aux"),
        ("NUL", "nul"),
        ("COM1", "com1"),
        ("LPT1", "lpt1"),
        # Blank input.
        ("", FALLBACK_SLUG),
        ("   ", FALLBACK_SLUG),
    ],
)
def test_the_slug_algorithm_is_exact(raw, expected):
    assert safe_scan_slug(raw) == expected


@pytest.mark.parametrize("raw", [None, 5, 1.5, ["a"], {"name": "a"}, True, object()])
def test_a_non_string_name_uses_the_fallback(raw):
    assert safe_scan_slug(raw) == FALLBACK_SLUG


def test_a_very_long_name_is_capped_without_a_trailing_hyphen():
    slug = safe_scan_slug("A" * 200)

    assert len(slug) == MAX_SLUG_LENGTH
    assert slug == "a" * MAX_SLUG_LENGTH


def test_truncation_never_leaves_a_trailing_hyphen():
    # 64 usable characters followed by a separator, so the cut lands on one.
    slug = safe_scan_slug(("x" * (MAX_SLUG_LENGTH - 1)) + " tail")

    assert not slug.endswith("-")
    assert len(slug) <= MAX_SLUG_LENGTH


@pytest.mark.parametrize(
    "raw",
    [
        "dir/sub",
        "..",
        "../../etc/passwd",
        "C:\\evidence",
        "\\\\server\\share",
        "scan:stream",
        "nul\x00byte",
        "line1\nline2",
        " .hidden. ",
        "東京スキャン",
        "A" * 500,
        "",
    ],
)
def test_no_provider_name_can_escape_the_output_directory(tmp_path, raw):
    paths = plan_paths(tmp_path, 5, 6, raw)

    for produced in (paths.raw, paths.manifest):
        assert produced.parent == tmp_path
        assert STEM_PATTERN.match(produced.name.split(".")[0])
        for forbidden in ("/", "\\", "..", ":", "\x00", "\n", " "):
            assert forbidden not in produced.name


def test_the_slug_is_deterministic():
    assert safe_scan_slug("Réseau Été") == safe_scan_slug("Réseau Été")


# ---------------------------------------------------------------------------
# Naming
# ---------------------------------------------------------------------------


def test_names_are_generated_locally_and_deterministically(tmp_path):
    paths = plan_paths(tmp_path, 5, 6, LIVE_SCAN_NAME)

    assert artefact_stem(5, 6, LIVE_SCAN_NAME) == "synthetic-lab-scan__scan-5__history-6"
    assert paths.raw.name == "synthetic-lab-scan__scan-5__history-6.nessus"
    assert paths.manifest.name == "synthetic-lab-scan__scan-5__history-6.manifest.json"
    assert paths.manifest.parent == paths.raw.parent


@pytest.mark.parametrize("scan_name", [None, "", "   ", "...", "東京", 5])
def test_an_unusable_name_falls_back_consistently(tmp_path, scan_name):
    paths = plan_paths(tmp_path, 5, 6, scan_name)

    assert paths.raw.name == "nessus__scan-5__history-6.nessus"
    assert paths.manifest.name == "nessus__scan-5__history-6.manifest.json"


def test_the_stem_only_ever_uses_the_permitted_character_set(tmp_path):
    paths = plan_paths(tmp_path, 5, 6, "Réseau / Été: <weekly> #1")

    stem = paths.raw.name[: -len(".nessus")]
    assert STEM_PATTERN.match(stem)
    assert stem == "reseau-ete-weekly-1__scan-5__history-6"


def test_different_scans_and_histories_stay_distinct(tmp_path):
    names = {
        plan_paths(tmp_path, scan, history, LIVE_SCAN_NAME).raw.name
        for scan, history in ((5, 6), (5, 7), (6, 6), (41, 2))
    }

    assert len(names) == 4


def test_two_names_reducing_to_one_slug_stay_distinct(tmp_path):
    first = plan_paths(tmp_path, 5, 6, "Weekly Sweep")
    second = plan_paths(tmp_path, 9, 6, "weekly/sweep")

    # The slug collides deliberately; the numeric suffix keeps them apart.
    assert first.raw.name.startswith("weekly-sweep__")
    assert second.raw.name.startswith("weekly-sweep__")
    assert first.raw != second.raw


def test_reserved_device_names_are_defused_by_the_identifier_suffix(tmp_path):
    for reserved in ("CON", "PRN", "AUX", "NUL", "COM1", "LPT1"):
        stem = plan_paths(tmp_path, 5, 6, reserved).raw.name.split(".")[0]

        assert stem != reserved.lower()
        assert stem.endswith("__scan-5__history-6")


def test_the_manifest_is_a_sidecar_beside_the_raw_file(tmp_path):
    paths = plan_paths(tmp_path, 41, 7, LIVE_SCAN_NAME)

    assert paths.raw.parent == paths.directory
    assert paths.manifest.parent == paths.directory
    assert paths.manifest.name.startswith(paths.raw.stem)


def test_a_part_file_is_unique_and_inside_the_destination(tmp_path):
    paths = plan_paths(tmp_path, 5, 6, LIVE_SCAN_NAME)

    first = new_part_path(paths)
    second = new_part_path(paths)

    assert first != second
    assert first.parent == paths.directory
    assert first.name.endswith(".part")
    assert first.name.startswith("synthetic-lab-scan__scan-5__history-6.")


# ---------------------------------------------------------------------------
# Directory handling
# ---------------------------------------------------------------------------


def test_the_output_directory_is_created_when_absent(tmp_path):
    directory = tmp_path / "deep" / "raw" / "nessus"
    assert not directory.exists()

    ensure_directory(directory)

    assert directory.is_dir()


def test_an_existing_output_directory_is_reused(tmp_path):
    paths = make_paths(tmp_path)
    keep = paths.directory / "unrelated.txt"
    keep.write_text("keep me", encoding="utf-8")

    ensure_directory(paths.directory)

    assert keep.read_text(encoding="utf-8") == "keep me"


# ---------------------------------------------------------------------------
# No overwrite
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("existing", ["raw", "manifest"])
def test_an_existing_destination_refuses_the_acquisition(tmp_path, existing):
    paths = make_paths(tmp_path)
    target = paths.raw if existing == "raw" else paths.manifest
    target.write_bytes(b"pre-existing")

    with pytest.raises(EvidenceError) as excinfo:
        assert_absent(paths)

    assert excinfo.value.exit_code == 2
    assert "never overwrites" in excinfo.value.summary
    assert target.read_bytes() == b"pre-existing"


def test_absent_destinations_are_accepted(tmp_path):
    paths = make_paths(tmp_path)

    assert assert_absent(paths) is None


# ---------------------------------------------------------------------------
# Commit and rollback
# ---------------------------------------------------------------------------


def test_commit_moves_the_bytes_and_writes_the_manifest(tmp_path):
    paths = make_paths(tmp_path)
    part = new_part_path(paths)
    part.write_bytes(b"<NessusClientData_v2/>")

    created = commit(part, paths, MANIFEST_BYTES)

    assert paths.raw.read_bytes() == b"<NessusClientData_v2/>"
    assert paths.manifest.read_bytes() == MANIFEST_BYTES
    assert not part.exists()
    assert created == (paths.raw, paths.manifest)


def test_commit_leaves_no_part_file_behind(tmp_path):
    paths = make_paths(tmp_path)
    part = new_part_path(paths)
    part.write_bytes(b"<NessusClientData_v2/>")

    commit(part, paths, MANIFEST_BYTES)

    assert list(paths.directory.glob("*.part")) == []


def test_commit_refuses_to_overwrite_a_raw_file_that_appeared(tmp_path):
    paths = make_paths(tmp_path)
    part = new_part_path(paths)
    part.write_bytes(b"new bytes")
    paths.raw.write_bytes(b"existing evidence")

    with pytest.raises(EvidenceError) as excinfo:
        commit(part, paths, MANIFEST_BYTES)

    assert excinfo.value.exit_code == 2
    assert paths.raw.read_bytes() == b"existing evidence"
    assert not paths.manifest.exists()


def test_a_failed_manifest_write_rolls_back_only_this_invocation(tmp_path):
    paths = make_paths(tmp_path)
    bystander = paths.directory / "earlier-acquisition.nessus"
    bystander.write_bytes(b"someone else's evidence")
    paths.manifest.write_bytes(b"a manifest already here")
    part = new_part_path(paths)
    part.write_bytes(b"new bytes")

    with pytest.raises(EvidenceError):
        commit(part, paths, MANIFEST_BYTES)

    # The raw file this invocation created was removed again...
    assert not paths.raw.exists()
    # ...while nothing pre-existing was touched.
    assert bystander.read_bytes() == b"someone else's evidence"
    assert paths.manifest.read_bytes() == b"a manifest already here"


def test_rollback_removes_only_the_named_files(tmp_path):
    paths = make_paths(tmp_path)
    mine = paths.directory / "mine.nessus"
    theirs = paths.directory / "theirs.nessus"
    mine.write_bytes(b"a")
    theirs.write_bytes(b"b")

    rollback([mine])

    assert not mine.exists()
    assert theirs.read_bytes() == b"b"


def test_discard_is_safe_when_the_file_is_absent(tmp_path):
    assert discard(tmp_path / "never-existed.part") is None
    assert discard(None) is None


def test_discard_never_removes_a_directory(tmp_path):
    directory = tmp_path / "keep"
    directory.mkdir()

    discard(directory)

    assert directory.is_dir()
