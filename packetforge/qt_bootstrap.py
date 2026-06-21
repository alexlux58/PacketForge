"""Configure PySide6 Qt plugin discovery before QApplication starts."""

from __future__ import annotations

import os
import stat
import sys
from ctypes import CDLL, c_char_p, c_int, c_uint
from ctypes.util import find_library
from pathlib import Path


def _pyside6_qt_dir() -> Path | None:
    try:
        import PySide6
    except ImportError:
        return None
    return Path(PySide6.__file__).resolve().parent / "Qt"


def _clear_macos_hidden_flags(path: Path) -> None:
    """Clear UF_HIDDEN so Qt's plugin scanner can see pip-installed dylibs."""
    hidden_flag = getattr(stat, "UF_HIDDEN", 0x8000)
    libc_path = find_library("c")
    if libc_path is None:
        return
    chflags = CDLL(libc_path).chflags
    chflags.argtypes = [c_char_p, c_uint]
    chflags.restype = c_int

    if path.is_file() or path.is_symlink():
        targets = [path]
    else:
        targets = [entry for entry in path.rglob("*") if entry.is_file()]

    for target in targets:
        try:
            current = os.stat(target, follow_symlinks=False).st_flags
        except OSError:
            continue
        if not (current & hidden_flag):
            continue
        chflags(os.fsencode(str(target)), c_uint(current & ~hidden_flag))


def _clear_macos_hidden_plugin_flags(plugins_dir: Path) -> None:
    if not plugins_dir.is_dir():
        return
    _clear_macos_hidden_flags(plugins_dir)


def configure_qt_plugins() -> None:
    """Make venv-installed PySide6 platform plugins visible to Qt."""
    qt_dir = _pyside6_qt_dir()
    if qt_dir is None:
        return

    plugins_dir = qt_dir / "plugins"
    platforms_dir = plugins_dir / "platforms"
    if not platforms_dir.is_dir():
        return

    if sys.platform == "darwin":
        _clear_macos_hidden_plugin_flags(plugins_dir)

    os.environ.setdefault("QT_PLUGIN_PATH", str(plugins_dir))
    os.environ.setdefault("QT_QPA_PLATFORM_PLUGIN_PATH", str(platforms_dir))

    from PySide6.QtCore import QCoreApplication

    QCoreApplication.setLibraryPaths([str(plugins_dir)])


def cocoa_plugin_hidden() -> bool | None:
    """Return True when macOS marks libqcocoa.dylib hidden (Qt cannot load it)."""
    if sys.platform != "darwin":
        return None
    qt_dir = _pyside6_qt_dir()
    if qt_dir is None:
        return None
    cocoa = qt_dir / "plugins" / "platforms" / "libqcocoa.dylib"
    if not cocoa.is_file():
        return None
    try:
        hidden_flag = getattr(stat, "UF_HIDDEN", 0x8000)
        return bool(os.stat(cocoa).st_flags & hidden_flag)
    except OSError:
        return None
