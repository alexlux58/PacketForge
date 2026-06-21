"""GUI behaviour tests for the fixes that live in the widgets themselves.

Uses isHidden() (not isVisible()) to check banner state, because the tabs are
never shown on screen and isVisible() also depends on ancestor visibility.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap

import pytest

pytest.importorskip("PySide6.QtWidgets")
pytest.importorskip("scapy")


def _gui_runtime_available() -> bool:
    script = textwrap.dedent(
        """
        import os
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
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=20, env=env
    )
    return result.returncode == 0 and "ok" in result.stdout


pytestmark = pytest.mark.skipif(
    not _gui_runtime_available(),
    reason="Qt platform plugins unavailable in this environment",
)


@pytest.fixture(scope="module")
def qapp():  # type: ignore[no-untyped-def]
    from pathlib import Path

    import PySide6
    from PySide6.QtCore import QCoreApplication
    from PySide6.QtWidgets import QApplication

    plugins = str(Path(PySide6.__file__).resolve().parent / "Qt" / "plugins")
    QCoreApplication.setLibraryPaths([plugins])
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    app = QApplication.instance() or QApplication([])
    yield app


# --- SNMP panel (bug 6) -----------------------------------------------------


def _snmp_widgets(tab):  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QComboBox, QLineEdit, QPushButton

    snmp_tab = tab.tabs.widget(2)  # DNS, DHCP, SNMP, ...
    run = next(b for b in snmp_tab.findChildren(QPushButton) if "Read common OIDs" in b.text())
    community = next(
        e for e in snmp_tab.findChildren(QLineEdit)
        if e.echoMode() == QLineEdit.EchoMode.Password
    )
    version = snmp_tab.findChildren(QComboBox)[0]
    return run, community, version


def test_snmp_panel_requires_community_for_v2c(qapp) -> None:  # type: ignore[no-untyped-def]
    from packetforge.ui.tabs.protocol_troubleshooter import ProtocolTroubleshooterTab

    tab = ProtocolTroubleshooterTab()
    run, community, version = _snmp_widgets(tab)
    version.setCurrentText("v2c")
    community.setText("")
    run.click()
    # Inline validation surfaces a banner and never starts a worker.
    assert not tab.error_banner.isHidden()
    assert not any(worker.isRunning() for worker in tab.workers)


def test_snmp_panel_toggles_fields_by_version(qapp) -> None:  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QLineEdit

    from packetforge.ui.tabs.protocol_troubleshooter import ProtocolTroubleshooterTab

    tab = ProtocolTroubleshooterTab()
    _run, community, version = _snmp_widgets(tab)
    snmp_tab = tab.tabs.widget(2)
    username = next(
        e for e in snmp_tab.findChildren(QLineEdit)
        if "security name" in e.placeholderText()
    )

    version.setCurrentText("v2c")
    assert community.isEnabled() and not username.isEnabled()
    version.setCurrentText("v3")
    assert not community.isEnabled() and username.isEnabled()


# --- Protocol "probe already running" banner (bug 8) ------------------------


def test_busy_banner_auto_dismisses_when_idle(qapp) -> None:  # type: ignore[no-untyped-def]
    from packetforge.errors import ErrorEvent
    from packetforge.models.discovery import ProtocolProbeResult
    from packetforge.ui.tabs.protocol_troubleshooter import ProtocolTroubleshooterTab
    from packetforge.ui.workers import ProtocolWorker

    tab = ProtocolTroubleshooterTab()
    tab._busy_banner_shown = True
    tab.error_banner.show_event(
        ErrorEvent(severity="info", source="Protocol Troubleshooter", operation="probe",
                   message="A probe is already running.")
    )
    assert not tab.error_banner.isHidden()

    worker = ProtocolWorker(lambda: ProtocolProbeResult(protocol="X", target="y"))
    tab._forget(worker)  # nothing running -> stale banner is cleared
    assert tab.error_banner.isHidden()


# --- Fingerprinting prefill + port reuse (bug 5) ----------------------------


def test_fingerprinting_prefills_host_and_reuses_open_ports(qapp) -> None:  # type: ignore[no-untyped-def]
    from packetforge.models.discovery import HostRecord, ServiceRecord
    from packetforge.ui.state import DiscoveryState
    from packetforge.ui.tabs.fingerprinting import FingerprintingTab

    state = DiscoveryState()
    state.upsert(
        HostRecord(
            ip="192.168.4.1",
            services=[
                ServiceRecord(port=22, state="open"),
                ServiceRecord(port=80, state="open"),
                ServiceRecord(port=443, state="closed"),
            ],
        )
    )
    tab = FingerprintingTab(state)
    # Pre-filled from discovery so the user does not retype.
    assert tab.host_combo.currentText() == "192.168.4.1"
    # Only open TCP ports are reused for banner probes.
    assert tab._ports_for("192.168.4.1") == (22, 80)
    assert tab._ports_for("10.9.9.9") is None


# --- layout / discoverability fixes -----------------------------------------


def _buttons(widget) -> set[str]:  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QPushButton

    return {b.text() for b in widget.findChildren(QPushButton)}


def test_ping_lab_controls_scroll_and_buttons_present(qapp) -> None:  # type: ignore[no-untyped-def]
    from PySide6.QtWidgets import QScrollArea

    from packetforge.ui.tabs.ping_lab import PingLabTab

    tab = PingLabTab()
    # The tall form is scrollable so the action buttons can't be clipped off.
    assert tab.findChildren(QScrollArea)
    assert {"Run", "Stop", "Save CSV"} <= _buttons(tab)


def test_packet_builder_exposes_build_and_send(qapp) -> None:  # type: ignore[no-untyped-def]
    from packetforge.presets.storage import PresetStore
    from packetforge.ui.tabs.packet_builder import PacketBuilderTab

    tab = PacketBuilderTab(PresetStore())
    assert {"Build", "Send", "Send and Wait", "Send Multiple"} <= _buttons(tab)


def test_scapy_console_exposes_action_buttons(qapp) -> None:  # type: ignore[no-untyped-def]
    from packetforge.ui.tabs.console import SafeConsoleTab

    tab = SafeConsoleTab()
    assert {"Validate", "Build", "Send"} <= _buttons(tab)


def test_chart_legend_is_opaque_and_readable(qapp) -> None:  # type: ignore[no-untyped-def]
    # Regression: legends used to be transparent and unreadable over bars.
    import pyqtgraph as pg

    from packetforge.ui import charts

    legend = charts._add_legend(pg.PlotWidget())
    assert legend.brush().color().alpha() == 255
    assert legend.labelTextColor().name().lower() == "#e7edf3"
