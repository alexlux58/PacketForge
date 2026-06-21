from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from packetforge.diagnostics import get_logger
from packetforge.engine.simulation import build_scenario, list_scenarios
from packetforge.ui.state import DiscoveryState, ObservabilityState, SimulationState
from packetforge.ui.widgets.page_header import PageHeader

_log = get_logger("simulation")


class SimulationTab(QWidget):
    """Load deterministic fake networks so every tool can be tested offline."""

    status_message = Signal(str)

    def __init__(
        self,
        discovery_state: DiscoveryState,
        obs_state: ObservabilityState,
        sim_state: SimulationState,
    ) -> None:
        super().__init__()
        self.discovery_state = discovery_state
        self.obs_state = obs_state
        self.sim_state = sim_state

        root = QVBoxLayout(self)
        root.addWidget(
            PageHeader(
                "Simulation Mode",
                "simulation",
                subtitle=(
                    "Fake network data for demos and UI testing — no packets sent. "
                    "Click i for scope and clearing instructions."
                ),
            )
        )

        self.banner = QLabel()
        self.banner.setObjectName("SimulationBanner")
        self.banner.setWordWrap(True)
        self.banner.setVisible(False)
        root.addWidget(self.banner)

        self.toggle = QCheckBox("Simulation Mode (show simulated data)")
        self.toggle.toggled.connect(self._toggled)
        root.addWidget(self.toggle)

        body = QHBoxLayout()
        root.addLayout(body, 1)

        self.scenarios = QListWidget()
        self.scenarios.setMaximumWidth(280)
        self._scenario_keys: list[str] = []
        for key, name, _description in list_scenarios():
            item = QListWidgetItem(name)
            item.setData(Qt.ItemDataRole.UserRole, key)
            self.scenarios.addItem(item)
            self._scenario_keys.append(key)
        self.scenarios.currentRowChanged.connect(self._show_description)
        body.addWidget(self.scenarios)

        right = QVBoxLayout()
        body.addLayout(right, 1)
        self.description = QPlainTextEdit()
        self.description.setReadOnly(True)
        right.addWidget(self.description, 1)

        buttons = QHBoxLayout()
        load = QPushButton("Load scenario")
        load.clicked.connect(self._load_selected)
        buttons.addWidget(load)
        clear = QPushButton("Clear simulated data")
        clear.clicked.connect(self._clear)
        buttons.addWidget(clear)
        buttons.addStretch(1)
        right.addLayout(buttons)

        if self.scenarios.count():
            self.scenarios.setCurrentRow(0)
        self.sim_state.changed.connect(self._render_banner)
        self._render_banner(self.sim_state.active, self.sim_state.scenario_name)

    def _current_key(self) -> str | None:
        row = self.scenarios.currentRow()
        if 0 <= row < len(self._scenario_keys):
            return self._scenario_keys[row]
        return None

    def _show_description(self, row: int) -> None:
        if 0 <= row < len(self._scenario_keys):
            scenario = build_scenario(self._scenario_keys[row])
            self.description.setPlainText(
                f"{scenario.name}\n\n{scenario.description}\n\n"
                f"Hosts: {scenario.run.host_count}   "
                f"Probes: {len(scenario.probes)}   "
                f"Ping series: {len(scenario.pings)}"
            )

    def _load_selected(self) -> None:
        key = self._current_key()
        if key is None:
            return
        scenario = build_scenario(key)
        self.discovery_state.set_run(scenario.run)
        self.obs_state.load_scenario(scenario.probes, scenario.pings)
        self.sim_state.activate(scenario.key, scenario.name)
        self.toggle.blockSignals(True)
        self.toggle.setChecked(True)
        self.toggle.blockSignals(False)
        _log.info(
            "loaded simulation scenario: %s (%d hosts)", scenario.key, scenario.run.host_count
        )
        self.status_message.emit(f"Simulation: loaded '{scenario.name}' (fake data)")

    def _toggled(self, checked: bool) -> None:
        if checked:
            if not self.sim_state.active:
                self._load_selected()
        elif not self._confirm_clear("Disable simulation mode?"):
            self.toggle.blockSignals(True)
            self.toggle.setChecked(True)
            self.toggle.blockSignals(False)
        else:
            self._clear(skip_confirm=True)

    def _confirm_clear(self, title: str) -> bool:
        if not self.sim_state.active and not self.discovery_state.hosts():
            return True
        reply = QMessageBox.warning(
            self,
            title,
            "This clears all discovery and observability data in the current session, "
            "including real scan results — not just simulated data.\n\nProceed?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        return reply == QMessageBox.StandardButton.Yes

    def _clear(self, *, skip_confirm: bool = False) -> None:
        if not skip_confirm and not self._confirm_clear("Clear simulated data?"):
            return
        self.discovery_state.clear()
        self.obs_state.clear()
        self.sim_state.deactivate()
        self.toggle.blockSignals(True)
        self.toggle.setChecked(False)
        self.toggle.blockSignals(False)
        _log.info("cleared simulated data")
        self.status_message.emit("Simulation: cleared simulated data")

    def _render_banner(self, active: bool, scenario_name: str) -> None:
        self.banner.setVisible(active)
        if active:
            self.banner.setText(
                f"SIMULATION MODE ACTIVE - showing fake data for '{scenario_name}'. "
                "Nothing here was measured from the real network."
            )
