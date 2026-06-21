from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from packetforge.qt_bootstrap import _pyside6_qt_dir, configure_qt_plugins


def test_pyside6_qt_dir_points_at_plugins_parent() -> None:
    qt_dir = _pyside6_qt_dir()
    if qt_dir is None:
        pytest.skip("PySide6 not installed")
    assert (qt_dir / "plugins" / "platforms").is_dir()


def test_configure_qt_plugins_sets_env(monkeypatch: pytest.MonkeyPatch) -> None:
    qt_dir = _pyside6_qt_dir()
    if qt_dir is None:
        pytest.skip("PySide6 not installed")

    monkeypatch.delenv("QT_PLUGIN_PATH", raising=False)
    monkeypatch.delenv("QT_QPA_PLATFORM_PLUGIN_PATH", raising=False)

    with patch("packetforge.qt_bootstrap._clear_macos_hidden_plugin_flags"):
        configure_qt_plugins()

    assert Path(os.environ["QT_PLUGIN_PATH"]) == qt_dir / "plugins"
    assert Path(os.environ["QT_QPA_PLATFORM_PLUGIN_PATH"]) == qt_dir / "plugins" / "platforms"
