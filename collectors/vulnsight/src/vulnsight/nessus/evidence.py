"""Deterministic naming and no-overwrite commit of raw acquisition evidence.

The downloaded bytes are the canonical evidence.  This module decides where
they go, guarantees nothing existing is disturbed, and commits the raw file
and its sidecar manifest together.

Filenames are generated locally and never taken from the server:

* ``<safe-scan-name>__scan-<SCAN_ID>__history-<HISTORY_ID>.nessus``
* ``<safe-scan-name>__scan-<SCAN_ID>__history-<HISTORY_ID>.manifest.json``

The leading component is a mechanically sanitised slug of the provider's scan
name, present purely so that thirteen systems' worth of evidence is legible
in a directory listing.  The numeric identifiers remain authoritative, and the
mechanically generated ``__scan-…__history-…`` suffix keeps two scans apart
even when their names reduce to the same slug.  When no usable name is
available the slug falls back to ``nessus``.

Filenames are a convenience, never an evidence selector: the manifest and the
SHA-256 are what identify an artefact.

Integrity is established by preservation, exclusive creation and checksum
verification.  No claim is made that operating-system read-only attributes
make the evidence immutable; they do not.
"""

from __future__ import annotations

import os
import re
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path

from .client import Outcome
from .errors import EvidenceError

RAW_SUFFIX = ".nessus"
MANIFEST_SUFFIX = ".manifest.json"
PART_SUFFIX = ".part"

#: The slug used when the provider supplies no usable scan name.
FALLBACK_SLUG = "nessus"

#: The longest slug permitted, before the identifier suffix is appended.
MAX_SLUG_LENGTH = 64

_UNSAFE_RUN = re.compile(r"[^a-z0-9]+")
_HYPHEN_RUN = re.compile(r"-{2,}")


def safe_scan_slug(raw: object) -> str:
    """Reduce an untrusted provider scan name to a safe filename component.

    The provider's scan name is untrusted metadata.  It is never interpolated
    into a path as supplied; it is reduced here to a slug that can only ever
    match ``[a-z0-9-]``, so it cannot introduce a directory, an absolute
    path, a drive letter, a UNC prefix, an alternate data stream or a
    traversal component.

    The algorithm is deterministic:

    1. anything that is not a string becomes the fallback;
    2. surrounding whitespace is trimmed;
    3. the text is normalised with NFKD;
    4. accented Latin characters are transliterated to ASCII where the
       decomposition makes that mechanically possible, and anything still
       non-ASCII is dropped;
    5. the text is lowercased;
    6. every run of characters outside ``[a-z0-9]`` becomes a single hyphen;
    7. repeated hyphens are collapsed;
    8. leading and trailing hyphens are stripped;
    9. the result is capped at :data:`MAX_SLUG_LENGTH` characters and any
       trailing hyphen left by that truncation is stripped;
    10. if nothing survives, the fallback is used.

    Because the caller always appends ``__scan-<id>__history-<id>``, a slug
    that collides with a Windows reserved device name such as ``con`` or
    ``lpt1`` cannot produce a reserved filename: the reserved names are
    matched on the whole basename before the first dot, and that basename
    always carries the identifier suffix.
    """
    if not isinstance(raw, str):
        return FALLBACK_SLUG

    text = unicodedata.normalize("NFKD", raw.strip())
    ascii_text = text.encode("ascii", "ignore").decode("ascii").lower()

    slug = _UNSAFE_RUN.sub("-", ascii_text)
    slug = _HYPHEN_RUN.sub("-", slug).strip("-")
    slug = slug[:MAX_SLUG_LENGTH].rstrip("-")

    return slug or FALLBACK_SLUG


def artefact_stem(
    scan_id: int, history_id: int, scan_name: object = None
) -> str:
    """The locally generated basename shared by both output files.

    The numeric identifiers are authoritative; the slug is a human-readable
    convenience placed in front of them.
    """
    return f"{safe_scan_slug(scan_name)}__scan-{scan_id}__history-{history_id}"


@dataclass(frozen=True)
class EvidencePaths:
    """The three paths one acquisition may touch."""

    directory: Path
    raw: Path
    manifest: Path

    @property
    def stem(self) -> str:
        return self.raw.stem


def plan_paths(
    output_dir: Path | str,
    scan_id: int,
    history_id: int,
    scan_name: object = None,
) -> EvidencePaths:
    """Compute the destination paths for one acquisition.

    Both filenames are built from the same stem, so the manifest always sits
    beside the artefact it describes.  Only the file components are derived
    from provider metadata; the directory comes from the user.
    """
    directory = Path(output_dir)
    stem = artefact_stem(scan_id, history_id, scan_name)
    return EvidencePaths(
        directory=directory,
        raw=directory / f"{stem}{RAW_SUFFIX}",
        manifest=directory / f"{stem}{MANIFEST_SUFFIX}",
    )


def ensure_directory(directory: Path | str) -> None:
    """Create the output directory if it does not already exist."""
    target = Path(directory)
    try:
        target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise EvidenceError(
            Outcome.API_ERROR,
            f"The output directory {target} could not be created.",
            f"{type(exc).__name__}: {exc}",
        ) from exc


def assert_absent(paths: EvidencePaths) -> None:
    """Refuse to proceed if either destination already exists.

    This runs before any export request is made, so an existing acquisition
    is never silently replaced and no needless work is asked of the scanner.
    There is no ``--force``: to re-acquire, move the existing evidence aside
    deliberately.
    """
    for existing in (paths.raw, paths.manifest):
        if existing.exists():
            raise EvidenceError(
                Outcome.CONFIGURATION_ERROR,
                f"{existing} already exists. VulnSight never overwrites raw "
                "evidence or a manifest. Move the existing acquisition aside "
                "and run the command again.",
            )


def new_part_path(paths: EvidencePaths) -> Path:
    """A unique temporary path inside the destination directory."""
    return paths.directory / f"{paths.stem}.{uuid.uuid4().hex}{PART_SUFFIX}"


def commit(
    part_path: Path, paths: EvidencePaths, manifest_bytes: bytes
) -> tuple[Path, ...]:
    """Commit the raw artefact and its manifest, or leave nothing behind.

    The downloaded bytes are moved into place rather than rewritten, so the
    committed file is byte-for-byte what arrived.  On Windows ``os.rename``
    is itself a no-overwrite operation; the explicit existence check ahead of
    it gives the same guarantee elsewhere.  The manifest is created with
    ``O_EXCL``, which is exclusive on every supported platform.

    If the second file cannot be created, only files created by this
    invocation are removed.  No pre-existing file is ever deleted or altered.
    """
    created: list[Path] = []
    try:
        if paths.raw.exists():
            raise EvidenceError(
                Outcome.CONFIGURATION_ERROR,
                f"{paths.raw} appeared before the acquisition could be "
                "committed. Nothing was overwritten.",
            )
        os.rename(part_path, paths.raw)
        created.append(paths.raw)

        _write_exclusive(paths.manifest, manifest_bytes)
        created.append(paths.manifest)
    except EvidenceError:
        rollback(created)
        raise
    except OSError as exc:
        rollback(created)
        raise EvidenceError(
            Outcome.API_ERROR,
            "The acquisition could not be committed to "
            f"{paths.directory}. Any file created by this run was removed.",
            f"{type(exc).__name__}: {exc}",
        ) from exc

    return tuple(created)


def _write_exclusive(path: Path, payload: bytes) -> None:
    """Create *path* exclusively and write *payload* to it."""
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    handle_fd = os.open(path, flags, 0o600)
    with os.fdopen(handle_fd, "wb") as handle:
        handle.write(payload)
        handle.flush()
        try:
            os.fsync(handle.fileno())
        except OSError:  # pragma: no cover - platform dependent
            pass


def rollback(created: list[Path] | tuple[Path, ...]) -> None:
    """Remove only the exact files this invocation created."""
    for path in created:
        discard(path)


def discard(path: Path | None) -> None:
    """Remove one specific file if it exists, never a directory or a glob."""
    if path is None:
        return
    try:
        if path.is_file():
            path.unlink()
    except OSError:  # pragma: no cover - best-effort cleanup
        pass
