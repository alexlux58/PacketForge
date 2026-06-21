from __future__ import annotations

import importlib.util
import json
from pathlib import Path


def _load_launcher():
    path = Path(__file__).resolve().parents[1] / "packaging" / "packetforge_launcher.py"
    spec = importlib.util.spec_from_file_location("packetforge_launcher", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_project_root_from_venv_layout() -> None:
    launcher = _load_launcher()
    root = launcher.project_root()
    assert (root / "packetforge" / "main.py").is_file()
    assert (root / "pyproject.toml").is_file()


def test_project_root_from_direct_url(tmp_path: Path) -> None:
    launcher = _load_launcher()
    site = tmp_path / "site-packages"
    meta = site / "packetforge-0.1.0.dist-info"
    meta.mkdir(parents=True)
    project = tmp_path / "project"
    (project / "packetforge").mkdir(parents=True)
    (project / "packetforge" / "main.py").write_text("", encoding="utf-8")
    (meta / "direct_url.json").write_text(
        json.dumps({"url": f"file://{project}"}),
        encoding="utf-8",
    )
    assert launcher._project_root_from_metadata(site) == project
