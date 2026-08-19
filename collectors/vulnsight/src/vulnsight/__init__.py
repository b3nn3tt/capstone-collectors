"""VulnSight — configuration-driven contextual vulnerability prioritisation.

Tranche 0 provided the project scaffold and a Nessus connectivity preflight.
Tranche 1 added read-only scan and history discovery.  Tranche 2 adds explicit
native ``.nessus`` export with an acquisition manifest.  No ``.nessus``
parsing, finding extraction, ingestion or scoring exists yet.

This is the single authoritative version location; ``pyproject.toml`` and the
command-line ``--version`` flag both derive from it.
"""

__version__ = "0.3.1"

__all__ = ["__version__"]
