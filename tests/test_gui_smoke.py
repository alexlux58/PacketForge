"""GUI smoke tests — skipped when Qt platform plugins cannot initialize."""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

pytest.importorskip("PySide6.QtWidgets")


def _gui_runtime_available() -> bool:
    """Return True only when a headless QApplication can start in a subprocess."""
    script = textwrap.dedent(
        """
        from pathlib import Path
        import PySide6
        from PySide6.QtCore import QCoreApplication
        from PySide6.QtWidgets import QApplication

        plugins = str(Path(PySide6.__file__).resolve().parent / "Qt" / "plugins")
        QCoreApplication.setLibraryPaths([plugins])
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        app = QApplication([])
        print("ok")
        app.quit()
        """
    ).lstrip()
    env = os.environ.copy()
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    result = subprocess.run(
        [sys.executable, "-c", "import os\n" + script],
        capture_output=True,
        text=True,
        timeout=20,
        env=env,
    )
    return result.returncode == 0 and "ok" in result.stdout


pytestmark = pytest.mark.skipif(
    not _gui_runtime_available(),
    reason="Qt platform plugins unavailable in this environment",
)


@pytest.fixture(scope="module")
def qapp():
    from pathlib import Path

    import PySide6
    from PySide6.QtCore import QCoreApplication
    from PySide6.QtWidgets import QApplication

    plugins = str(Path(PySide6.__file__).resolve().parent / "Qt" / "plugins")
    QCoreApplication.setLibraryPaths([plugins])
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])
    yield app


def test_main_window_instantiates(qapp) -> None:
    from packetforge.ui.main_window import MainWindow

    window = MainWindow()
    assert window.windowTitle().startswith("PacketForge")
    window.close()


def test_history_tab_lists_runs(qapp, tmp_path) -> None:
    from packetforge.engine.history import DiscoveryHistory
    from packetforge.models.discovery import DiscoveryRun, HostRecord
    from packetforge.ui.state import DiscoveryState
    from packetforge.ui.tabs.history import HistoryTab

    history = DiscoveryHistory(tmp_path)
    run = DiscoveryRun(profile="Balanced", targets="10.0.0.0/24", hosts=[HostRecord(ip="10.0.0.1")])
    history.save(run)

    tab = HistoryTab(DiscoveryState(), history)
    tab.refresh()
    assert "1 saved run" in tab.summary.text()
