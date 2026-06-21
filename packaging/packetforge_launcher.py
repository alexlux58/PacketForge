#!/usr/bin/env python3
"""Bootstrap launcher for `packetforge` when editable .pth files are broken/hidden."""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _venv_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _site_packages(venv_root: Path) -> Path | None:
    lib = venv_root / "lib"
    if not lib.is_dir():
        return None
    matches = sorted(lib.glob("python*/site-packages"))
    return matches[-1] if matches else None


def _project_root_from_metadata(site_packages: Path) -> Path | None:
    for meta in site_packages.glob("packetforge-*.dist-info"):
        direct = meta / "direct_url.json"
        if not direct.is_file():
            continue
        try:
            payload = json.loads(direct.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        url = payload.get("url", "")
        if url.startswith("file://"):
            root = Path(url.removeprefix("file://"))
            if (root / "packetforge" / "main.py").is_file():
                return root
    return None


def project_root() -> Path:
    here = Path(__file__).resolve()

    # Installed copy: .venv/bin/packetforge
    if here.parent.name == "bin" and here.parent.parent.name == ".venv":
        venv_root = here.parent.parent
        site = _site_packages(venv_root)
        if site is not None:
            from_meta = _project_root_from_metadata(site)
            if from_meta is not None:
                return from_meta
        sibling = venv_root.parent
        if (sibling / "packetforge" / "main.py").is_file() and (sibling / "pyproject.toml").is_file():
            return sibling

    # Source checkout: packaging/packetforge_launcher.py
    source_root = here.parent.parent
    if (source_root / "packetforge" / "main.py").is_file() and (source_root / "pyproject.toml").is_file():
        return source_root

    raise SystemExit(
        "Could not locate the PacketForge source tree.\n"
        "From the project directory run: ./scripts/fix_venv.sh"
    )


def main() -> int:
    root = project_root()
    root_text = str(root)
    if root_text not in sys.path:
        sys.path.insert(0, root_text)

    from packetforge.main import main as run_app

    return run_app()


if __name__ == "__main__":
    raise SystemExit(main())
