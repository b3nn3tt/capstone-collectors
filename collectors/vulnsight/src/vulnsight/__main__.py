"""Entry point for ``python -m vulnsight``."""

from __future__ import annotations

from .cli import run

if __name__ == "__main__":  # pragma: no cover - thin process entry point
    run()
