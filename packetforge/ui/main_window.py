from __future__ import annotations

from PySide6.QtCore import QSettings
from PySide6.QtGui import QAction, QCloseEvent, QIcon, QKeySequence
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QStackedWidget,
    QStatusBar,
    QWidget,
)

from packetforge.assets import icon_path
from packetforge.diagnostics import configure_logging, get_logger
from packetforge.engine.history import DiscoveryHistory
from packetforge.presets.storage import PresetStore
from packetforge.security.privileges import detect_privileges, privilege_status
from packetforge.ui.preferences import AppPreferences
from packetforge.ui.state import DiscoveryState, ObservabilityState, SimulationState
from packetforge.ui.tabs.console import SafeConsoleTab
from packetforge.ui.tabs.dashboard import DashboardTab
from packetforge.ui.tabs.diagnostics import DiagnosticsTab
from packetforge.ui.tabs.discovery_center import DiscoveryCenterTab
from packetforge.ui.tabs.environment import EnvironmentCheckTab
from packetforge.ui.tabs.fingerprinting import FingerprintingTab
from packetforge.ui.tabs.network_map import NetworkMapTab
from packetforge.ui.tabs.observability import ObservabilityTab
from packetforge.ui.tabs.packet_builder import PacketBuilderTab
from packetforge.ui.tabs.ping_lab import PingLabTab
from packetforge.ui.tabs.placeholders import PlaceholderTab
from packetforge.ui.tabs.protocol_troubleshooter import ProtocolTroubleshooterTab
from packetforge.ui.tabs.settings import SettingsTab
from packetforge.ui.tabs.simulation import SimulationTab
from packetforge.ui.widgets.help_dialog import HelpDialog


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.diagnostics = configure_logging()
        get_logger("ui").info("PacketForge main window starting")
        self.settings = QSettings()
        self.prefs = AppPreferences(self.settings)
        self.preset_store = PresetStore()
        self.setWindowTitle("PacketForge")
        icon_file = icon_path()
        if icon_file.exists():
            self.setWindowIcon(QIcon(str(icon_file)))
        self.resize(1440, 900)

        self.sidebar = QListWidget()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(230)
        self.stack = QStackedWidget()

        shell = QWidget()
        layout = QHBoxLayout(shell)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack, 1)
        self.setCentralWidget(shell)

        self.discovery_state = DiscoveryState()
        self.obs_state = ObservabilityState()
        self.simulation_state = SimulationState()
        self.discovery_history = DiscoveryHistory()
        self.dashboard = DashboardTab(self.preset_store)
        self.discovery_center = DiscoveryCenterTab(self.discovery_state)
        self.fingerprinting = FingerprintingTab(self.discovery_state)
        self.network_map = NetworkMapTab(self.discovery_state)
        self.protocol_troubleshooter = ProtocolTroubleshooterTab(self.obs_state)
        self.observability = ObservabilityTab(
            self.discovery_state, self.obs_state, self.discovery_history
        )
        self.ping_lab = PingLabTab(self.obs_state)
        self.packet_builder = PacketBuilderTab(self.preset_store)
        self.console = SafeConsoleTab()
        self.diagnostics_tab = DiagnosticsTab(
            self.diagnostics, config_provider=self._config_snapshot
        )
        self.simulation = SimulationTab(
            self.discovery_state, self.obs_state, self.simulation_state
        )
        self.environment = EnvironmentCheckTab()
        self.capture = PlaceholderTab(
            "Packet Capture",
            "Capture workflows are planned after the first working release. "
            "Use PCAP export from Ping Lab, Packet Builder, or Safe Scapy Console now.",
        )
        self.history = PlaceholderTab(
            "History",
            "Saved run history is planned after the first working release. "
            "Export JSON, CSV, and PCAP files from active tools now.",
        )
        self.settings_tab = SettingsTab(self.prefs)
        self.settings_tab.theme_changed.connect(self.apply_theme)

        for title, widget in [
            ("Dashboard", self.dashboard),
            ("Discovery Center", self.discovery_center),
            ("Fingerprinting", self.fingerprinting),
            ("Network Map", self.network_map),
            ("Protocol Troubleshooter", self.protocol_troubleshooter),
            ("Observability", self.observability),
            ("Ping Lab", self.ping_lab),
            ("Packet Builder", self.packet_builder),
            ("Scapy Console", self.console),
            ("Simulation", self.simulation),
            ("Diagnostics", self.diagnostics_tab),
            ("Environment", self.environment),
            ("Packet Capture", self.capture),
            ("History", self.history),
            ("Settings", self.settings_tab),
        ]:
            item = QListWidgetItem(title)
            self.sidebar.addItem(item)
            self.stack.addWidget(widget)
        self.sidebar.currentRowChanged.connect(self.stack.setCurrentIndex)
        self._select_initial_tab()

        self.dashboard.preset_selected.connect(self.open_preset_in_builder)
        self.packet_builder.status_message.connect(self.show_status)
        self.console.status_message.connect(self.show_status)
        self.diagnostics_tab.status_message.connect(self.show_status)
        self.simulation.status_message.connect(self.show_status)
        self.network_map.status_message.connect(self.show_status)
        self.ping_lab.status_message.connect(self.show_status)
        self.discovery_center.status_message.connect(self.show_status)
        self.simulation_state.changed.connect(self._on_simulation_changed)

        self._create_menu()
        self._create_status_bar()
        self._install_shortcuts()
        self.apply_theme(self.prefs.theme)
        self._restore_window()

    def _create_menu(self) -> None:
        view = self.menuBar().addMenu("&View")
        dark = QAction("Dark Theme", self)
        light = QAction("Light Theme", self)
        dark.triggered.connect(lambda: self.apply_theme("dark"))
        light.triggered.connect(lambda: self.apply_theme("light"))
        view.addAction(dark)
        view.addAction(light)

        help_menu = self.menuBar().addMenu("&Help")
        overview = QAction("PacketForge overview", self)
        overview.triggered.connect(lambda: HelpDialog.show_for("global", self))
        help_menu.addAction(overview)
        this_tab = QAction("This tab", self)
        this_tab.setShortcut(QKeySequence("F1"))
        this_tab.triggered.connect(self._open_help_for_current_tab)
        help_menu.addAction(this_tab)
        help_menu.addSeparator()
        env_check = QAction("Environment Check", self)
        env_check.triggered.connect(self.open_environment_check)
        help_menu.addAction(env_check)

        settings_action = QAction("&Settings...", self)
        settings_action.setShortcut(QKeySequence("Ctrl+,"))
        settings_action.triggered.connect(self.open_settings)
        self.menuBar().addAction(settings_action)

    def _install_shortcuts(self) -> None:
        find_action = QAction("Find in table", self)
        find_action.setShortcut(QKeySequence("Ctrl+F"))
        find_action.triggered.connect(self._focus_current_search)
        self.addAction(find_action)

        copy_action = QAction("Copy selection", self)
        copy_action.setShortcut(QKeySequence("Ctrl+C"))
        copy_action.triggered.connect(self._copy_from_focus)
        self.addAction(copy_action)

    def _focus_current_search(self) -> None:
        widget = self.stack.currentWidget()
        if widget is not None and hasattr(widget, "focus_search"):
            widget.focus_search()

    def _copy_from_focus(self) -> None:
        widget = self.stack.currentWidget()
        if widget is not None and hasattr(widget, "copy_selection"):
            widget.copy_selection()

    def open_settings(self) -> None:
        self.sidebar.setCurrentRow(self.stack.indexOf(self.settings_tab))

    def _open_help_for_current_tab(self) -> None:
        widget = self.stack.currentWidget()
        keys = {
            self.dashboard: "dashboard",
            self.discovery_center: "discovery_center",
            self.fingerprinting: "fingerprinting",
            self.network_map: "network_map",
            self.protocol_troubleshooter: "protocol_troubleshooter",
            self.observability: "observability",
            self.ping_lab: "ping_lab",
            self.packet_builder: "packet_builder",
            self.console: "scapy_console",
            self.simulation: "simulation",
            self.diagnostics: "diagnostics",
            self.environment: "environment",
            self.settings_tab: "settings",
        }
        HelpDialog.show_for(keys.get(widget, "global"), self)

    def _select_initial_tab(self) -> None:
        """Show the Environment Check on first launch, otherwise restore preferences."""
        first_run = self.settings.value("first_run_complete") is None
        if first_run:
            self.environment.refresh()
            self.sidebar.setCurrentRow(self.stack.indexOf(self.environment))
            self.settings.setValue("first_run_complete", True)
        elif self.prefs.remember_last_tab:
            index = self.prefs.last_tab_index
            if 0 <= index < self.sidebar.count():
                self.sidebar.setCurrentRow(index)
            else:
                self.sidebar.setCurrentRow(0)
        else:
            self.sidebar.setCurrentRow(0)

    def open_environment_check(self) -> None:
        self.environment.refresh()
        self.sidebar.setCurrentRow(self.stack.indexOf(self.environment))

    def _create_status_bar(self) -> None:
        bar = QStatusBar()
        self.setStatusBar(bar)
        report = detect_privileges()
        self.interface_label = QLabel("Interface: auto")
        self.privilege_label = QLabel(privilege_status())
        self.raw_label = QLabel(
            "Raw sockets: yes" if report.raw_sockets else "Raw sockets: no (fallbacks active)"
        )
        if report.notes:
            self.raw_label.setToolTip("\n".join(report.notes))
        self.capture_label = QLabel("Capture: idle")
        self.counter_label = QLabel("TX: 0  RX: 0")
        self.simulation_label = QLabel()
        self.simulation_label.setObjectName("SimulationBanner")
        self.simulation_label.setVisible(False)
        bar.addWidget(self.interface_label)
        bar.addWidget(self.simulation_label)
        bar.addPermanentWidget(self.raw_label)
        bar.addPermanentWidget(self.privilege_label)
        bar.addPermanentWidget(self.capture_label)
        bar.addPermanentWidget(self.counter_label)

    def _on_simulation_changed(self, active: bool, scenario_name: str) -> None:
        self.simulation_label.setVisible(active)
        if active:
            self.simulation_label.setText(f"SIMULATION MODE - fake data ({scenario_name})")
            self.setWindowTitle(f"PacketForge - SIMULATION ({scenario_name})")
        else:
            self.setWindowTitle("PacketForge")

    def _config_snapshot(self) -> dict[str, object]:
        """Secret-free configuration summary for the debug bundle."""
        report = detect_privileges()
        return {
            "theme": str(self.settings.value("theme", "dark")),
            "preset_path": str(self.preset_store.path),
            "raw_sockets": report.raw_sockets,
            "platform": report.platform_name,
            "active_tab": self.sidebar.currentItem().text() if self.sidebar.currentItem() else "",
        }

    def open_preset_in_builder(self, preset_id: str) -> None:
        self.packet_builder.load_preset(preset_id)
        self.sidebar.setCurrentRow(self.stack.indexOf(self.packet_builder))

    def show_status(self, message: str) -> None:
        self.statusBar().showMessage(message, self.prefs.status_message_ms)

    def apply_theme(self, theme: str) -> None:
        if theme == "light":
            self.setStyleSheet(LIGHT_THEME)
            self.prefs.theme = "light"
        else:
            self.setStyleSheet(DARK_THEME)
            self.prefs.theme = "dark"

    def _restore_window(self) -> None:
        geometry = self.settings.value("geometry")
        state = self.settings.value("windowState")
        if geometry is not None:
            self.restoreGeometry(geometry)
        if state is not None:
            self.restoreState(state)

    def closeEvent(self, event: QCloseEvent) -> None:
        self.prefs.last_tab_index = self.sidebar.currentRow()
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("windowState", self.saveState())
        super().closeEvent(event)


DARK_THEME = """
QMainWindow, QWidget {
    background: #111418;
    color: #e7edf3;
    font-size: 13px;
}
QMenuBar, QMenu {
    background: #171b21;
    color: #e7edf3;
}
QListWidget#Sidebar {
    background: #171b21;
    border: none;
    padding: 10px;
}
QListWidget#Sidebar::item {
    padding: 11px 12px;
    border-radius: 6px;
}
QListWidget#Sidebar::item:selected {
    background: #285d8f;
}
QGroupBox {
    border: 1px solid #2d3642;
    border-radius: 6px;
    margin-top: 18px;
    padding: 10px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}
QLineEdit, QPlainTextEdit, QSpinBox, QTableWidget, QTreeWidget {
    background: #0d1014;
    color: #e7edf3;
    border: 1px solid #2d3642;
    border-radius: 4px;
    padding: 5px;
}
QComboBox {
    background: #0d1014;
    color: #e7edf3;
    border: 1px solid #2d3642;
    border-radius: 4px;
    padding: 5px 28px 5px 8px;
    min-height: 1.4em;
}
QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 24px;
    border-left: 1px solid #2d3642;
}
QComboBox::down-arrow {
    width: 10px;
    height: 10px;
}
QComboBox QAbstractItemView {
    background: #0d1014;
    color: #e7edf3;
    border: 1px solid #2d3642;
    selection-background-color: #285d8f;
    selection-color: #ffffff;
    outline: 0;
    padding: 2px;
}
QTableWidget {
    alternate-background-color: #151a21;
    gridline-color: #2d3642;
}
QPushButton {
    background: #27313d;
    color: #f6f8fb;
    border: 1px solid #3b4654;
    border-radius: 5px;
    padding: 7px 10px;
    min-height: 24px;
}
QPushButton:hover {
    background: #334150;
}
QTabWidget::pane {
    border: 1px solid #2d3642;
    top: -1px;
}
QTabBar::tab {
    background: #171b21;
    color: #aeb8c3;
    border: 1px solid #2d3642;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    padding: 7px 14px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background: #0d1014;
    color: #e7edf3;
}
QTabBar::tab:hover {
    color: #e7edf3;
}
QLabel#PageTitle {
    font-size: 24px;
    font-weight: 700;
    padding: 10px 10px 2px 10px;
}
QLabel#Muted {
    color: #aeb8c3;
}
QLabel#Error {
    color: #ff8c7a;
}
QLabel#Metric {
    font-size: 16px;
    font-weight: 700;
}
QLabel#SimulationBanner {
    background: #b8860b;
    color: #fff7e0;
    font-weight: 700;
    border: 1px solid #ffcf66;
    border-radius: 5px;
    padding: 6px 10px;
}
QPushButton#HelpButton {
    background: #285d8f;
    color: #ffffff;
    border: 1px solid #3b7cb8;
    border-radius: 14px;
    font-weight: 700;
    font-size: 14px;
    padding: 0;
    min-width: 28px;
    max-width: 28px;
    min-height: 28px;
    max-height: 28px;
}
QPushButton#HelpButton:hover {
    background: #337ab7;
}
"""

LIGHT_THEME = """
QMainWindow, QWidget {
    background: #f7f9fb;
    color: #16202a;
    font-size: 13px;
}
QMenuBar, QMenu {
    background: #ffffff;
    color: #16202a;
}
QListWidget#Sidebar {
    background: #e9eef3;
    border: none;
    padding: 10px;
}
QListWidget#Sidebar::item {
    padding: 11px 12px;
    border-radius: 6px;
}
QListWidget#Sidebar::item:selected {
    background: #2f75b5;
    color: #ffffff;
}
QGroupBox {
    border: 1px solid #cfd8e3;
    border-radius: 6px;
    margin-top: 18px;
    padding: 10px;
}
QGroupBox::title {
    subcontrol-origin: margin;
    left: 10px;
    padding: 0 4px;
}
QLineEdit, QPlainTextEdit, QSpinBox, QTableWidget, QTreeWidget {
    background: #ffffff;
    color: #16202a;
    border: 1px solid #cfd8e3;
    border-radius: 4px;
    padding: 5px;
}
QComboBox {
    background: #ffffff;
    color: #16202a;
    border: 1px solid #cfd8e3;
    border-radius: 4px;
    padding: 5px 28px 5px 8px;
    min-height: 1.4em;
}
QComboBox::drop-down {
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 24px;
    border-left: 1px solid #cfd8e3;
}
QComboBox::down-arrow {
    width: 10px;
    height: 10px;
}
QComboBox QAbstractItemView {
    background: #ffffff;
    color: #16202a;
    border: 1px solid #cfd8e3;
    selection-background-color: #2f75b5;
    selection-color: #ffffff;
    outline: 0;
    padding: 2px;
}
QTableWidget {
    alternate-background-color: #f3f7fb;
    gridline-color: #cfd8e3;
}
QPushButton {
    background: #ffffff;
    color: #16202a;
    border: 1px solid #b7c2cf;
    border-radius: 5px;
    padding: 7px 10px;
    min-height: 24px;
}
QPushButton:hover {
    background: #edf3f8;
}
QTabWidget::pane {
    border: 1px solid #cfd8e3;
    top: -1px;
}
QTabBar::tab {
    background: #e9eef3;
    color: #5f6f80;
    border: 1px solid #cfd8e3;
    border-bottom: none;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
    padding: 7px 14px;
    margin-right: 2px;
}
QTabBar::tab:selected {
    background: #ffffff;
    color: #16202a;
}
QTabBar::tab:hover {
    color: #16202a;
}
QLabel#PageTitle {
    font-size: 24px;
    font-weight: 700;
    padding: 10px 10px 2px 10px;
}
QLabel#Muted {
    color: #5f6f80;
}
QLabel#Error {
    color: #b42318;
}
QLabel#Metric {
    font-size: 16px;
    font-weight: 700;
}
QLabel#SimulationBanner {
    background: #fff3cd;
    color: #7a5b00;
    font-weight: 700;
    border: 1px solid #e0b400;
    border-radius: 5px;
    padding: 6px 10px;
}
QPushButton#HelpButton {
    background: #2f75b5;
    color: #ffffff;
    border: 1px solid #2563a8;
    border-radius: 14px;
    font-weight: 700;
    font-size: 14px;
    padding: 0;
    min-width: 28px;
    max-width: 28px;
    min-height: 28px;
    max-height: 28px;
}
QPushButton#HelpButton:hover {
    background: #3a86c8;
}
"""
