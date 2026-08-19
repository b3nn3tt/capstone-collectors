"""Documentation links and the acquisition-only boundary.

These are static guards. They read files from the repository and assert no
analytical capability has crept into an acquisition tool.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import vulnsight

PROJECT_ROOT = Path(vulnsight.__file__).resolve().parents[2]
README = PROJECT_ROOT / "README.md"
USER_GUIDE = PROJECT_ROOT / "docs" / "user-guide.md"
CHANGELOG = PROJECT_ROOT / "CHANGELOG.md"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# The user guide and its link
# ---------------------------------------------------------------------------


def test_the_user_guide_exists():
    assert USER_GUIDE.is_file()
    assert USER_GUIDE.stat().st_size > 0


def test_the_readme_links_to_the_user_guide_near_the_top():
    text = read(README)
    head = "\n".join(text.splitlines()[:20])

    assert "docs/user-guide.md" in head, "the guide link must be prominent"


def test_every_readme_link_to_the_guide_resolves():
    text = read(README)

    assert "(docs/user-guide.md)" in text
    for line in text.splitlines():
        if "docs/user-guide.md" not in line:
            continue
        # Strip any in-page anchor before resolving the file itself.
        assert (PROJECT_ROOT / "docs" / "user-guide.md").is_file()


@pytest.mark.parametrize(
    "heading",
    [
        "Purpose and scope",
        "What VulnSight does not do",
        "Prerequisites",
        "Create and activate the environment",
        "Install VulnSight",
        "Create and configure `.env`",
        "Secret handling",
        "TLS verification",
        "Check connectivity",
        "List the visible scans",
        "List the histories of one scan",
        "Export a completed history",
        "Output naming",
        "The acquisition manifest",
        "Verify the artefact independently",
        "No-overwrite behaviour",
        "Exit codes",
        "Troubleshooting",
        "Updating or reinstalling",
        "Evidential and dissertation boundary",
    ],
)
def test_the_user_guide_covers_every_required_section(heading):
    assert heading in read(USER_GUIDE)


def test_the_user_guide_contains_no_real_looking_credentials():
    text = read(USER_GUIDE)

    assert "REPLACE_WITH_YOUR_ACCESS_KEY" in text
    assert "REPLACE_WITH_YOUR_SECRET_KEY" in text
    # A real Nessus key is 64 hexadecimal characters; no such literal appears.
    synthetic_sha256 = (
        "0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef"
    )
    for line in text.splitlines():
        for token in line.split():
            stripped = token.strip("`\"'=,")
            if len(stripped) == 64 and all(c in "0123456789abcdef" for c in stripped):
                # The one permitted 64-hex literal is the published SHA-256.
                assert stripped == synthetic_sha256, stripped


def test_the_user_guide_documents_the_naming_grammar_and_fallback():
    text = read(USER_GUIDE)

    assert "<safe-scan-name>__scan-<SCAN_ID>__history-<HISTORY_ID>" in text
    assert "nessus__scan-<SCAN_ID>__history-<HISTORY_ID>" in text
    assert "Filenames are not evidence selectors" in text
    assert "scan.scan_name" in text


def test_the_user_guide_documents_manifest_1_1_and_historical_1_0():
    text = read(USER_GUIDE)

    assert "vulnsight.nessus-export-manifest/1.1" in text
    assert "1.0" in text
    assert "never" in text and "rewrites" in text


# ---------------------------------------------------------------------------
# The acquisition-only boundary, stated in both documents
# ---------------------------------------------------------------------------


BOUNDARY_CLAIMS = [
    "parse findings",
    "normalise",
    "pseudonymise",
    "KEV",
    "EPSS",
    "Voight-Kampff",
    "C1–C7",
    "contextual adjustments",
    "remediation priority",
]


@pytest.mark.parametrize("claim", BOUNDARY_CLAIMS)
def test_the_readme_states_the_boundary(claim):
    assert claim in read(README)


@pytest.mark.parametrize("claim", BOUNDARY_CLAIMS)
def test_the_user_guide_states_the_boundary(claim):
    assert claim in read(USER_GUIDE)


@pytest.mark.parametrize(
    "handoff",
    [
        "Voight-Kampff ends with raw schema-1.1 JSON",
        "VulnSight ends with raw `.nessus` evidence",
        "MSc artefact begins with validation",
    ],
)
def test_both_documents_state_the_handoff_points(handoff):
    # Emphasis markers are incidental; compare on the prose itself.
    for document in (README, USER_GUIDE):
        assert handoff in read(document).replace("*", "")


def test_the_changelog_records_the_final_sourcing_pass():
    text = read(CHANGELOG)

    assert "## 0.3.1" in text
    assert "vulnsight.nessus-export-manifest/1.1" in text
    assert "docs/user-guide.md" in text
    assert "never renamed" in text
    assert "parked" in text


# ---------------------------------------------------------------------------
# No analytical capability exists in the package
# ---------------------------------------------------------------------------


def package_sources() -> dict[str, str]:
    directory = Path(vulnsight.__file__).parent
    return {
        str(path.relative_to(directory)): path.read_text(encoding="utf-8")
        for path in sorted(directory.rglob("*.py"))
    }


@pytest.mark.parametrize(
    "forbidden",
    [
        "epss",
        "kev",
        "cvss_score_calculation",
        "risk_score",
        "remediation_priority",
        "pseudonym",
        "normalise_finding",
        "normalize_finding",
        "voight",
        "kampff",
        "c1_c7",
        "parse_findings",
        "extract_finding",
        "plugin_output",
    ],
)
def test_no_analytical_or_parsing_capability_is_present(forbidden):
    """VulnSight acquires evidence; it never interprets it."""
    for name, source in package_sources().items():
        assert forbidden not in source.lower(), f"{name} mentions {forbidden}"


def test_report_elements_are_only_ever_counted_never_parsed():
    """``ReportItem`` and ``ReportHost`` appear only as validation counters.

    Structural counts are acquisition evidence that the artefact arrived
    intact. Nothing reads their attributes, children or text.
    """
    sources = package_sources()
    permitted = {"nessus/nessus_xml.py", "nessus/manifest.py"}
    permitted |= {name.replace("/", "\\") for name in permitted}

    for name, source in sources.items():
        lowered = source.lower()
        if "reportitem" in lowered or "reporthost" in lowered:
            assert name in permitted, f"{name} touches report elements"

    xml_source = sources.get("nessus/nessus_xml.py") or sources["nessus\\nessus_xml.py"]
    # The counting target records tag names only: no attribute or text access.
    assert "self.counts[tag] += 1" in xml_source
    assert "attrib[" not in xml_source
    assert ".text" not in xml_source


def test_no_scoring_or_ranking_symbol_is_defined():
    for name, source in package_sources().items():
        lowered = source.lower()
        for symbol in ("def score", "def rank", "def prioritise", "def prioritize"):
            assert symbol not in lowered, f"{name} defines {symbol}"


def test_the_version_is_the_expected_release():
    assert vulnsight.__version__ == "0.3.1"
