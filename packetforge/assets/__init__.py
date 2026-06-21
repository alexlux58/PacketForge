"""Bundled static assets (icons, etc.)."""

from __future__ import annotations

from pathlib import Path

ASSET_DIR = Path(__file__).resolve().parent


def asset_path(name: str) -> Path:
    """Return the absolute path to a bundled asset file."""
    return ASSET_DIR / name


def icon_path() -> Path:
    """Path to the application icon placeholder."""
    return asset_path("icon.svg")
