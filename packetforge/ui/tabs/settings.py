from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from packetforge.models.profiles import BUILTIN_PROFILES
from packetforge.ui.preferences import AppPreferences
from packetforge.ui.widgets.interface_combo import defer_populate_interface_combo, tune_combo_box
from packetforge.ui.widgets.page_header import PageHeader
from packetforge.ui.widgets.transmission_form import configure_form_layout


class SettingsTab(QWidget):
    """User preferences persisted via QSettings."""

    preferences_changed = Signal()
    theme_changed = Signal(str)

    def __init__(self, preferences: AppPreferences) -> None:
        super().__init__()
        self.preferences = preferences

        root = QVBoxLayout(self)
        root.addWidget(
            PageHeader(
                "Settings",
                "settings",
                subtitle=(
                    "Local preferences restored on next launch. "
                    "Click i for option descriptions."
                ),
            )
        )

        appearance = QGroupBox("Appearance")
        appearance_form = QFormLayout(appearance)
        configure_form_layout(appearance_form)
        self.theme = QComboBox()
        self.theme.addItems(["dark", "light"])
        self.theme.setCurrentText(self.preferences.theme)
        self.theme.currentTextChanged.connect(self._on_theme)
        appearance_form.addRow("Theme", self.theme)
        root.addWidget(appearance)

        discovery = QGroupBox("Discovery defaults")
        discovery_form = QFormLayout(discovery)
        configure_form_layout(discovery_form)
        self.default_profile = QComboBox()
        self.default_profile.addItems([profile.name for profile in BUILTIN_PROFILES])
        self.default_profile.setCurrentText(self.preferences.default_scan_profile)
        self.default_profile.currentTextChanged.connect(self._save_discovery)
        discovery_form.addRow("Default profile", self.default_profile)

        self.default_interface = tune_combo_box(QComboBox())
        defer_populate_interface_combo(
            self.default_interface,
            selected=self.preferences.default_interface,
        )
        self.default_interface.currentTextChanged.connect(self._save_discovery)
        discovery_form.addRow("Default interface", self.default_interface)
        root.addWidget(discovery)

        ui_box = QGroupBox("UI behaviour")
        ui_form = QFormLayout(ui_box)
        configure_form_layout(ui_form)
        self.remember_tab = QCheckBox("Restore last sidebar tab on launch")
        self.remember_tab.setChecked(self.preferences.remember_last_tab)
        self.remember_tab.toggled.connect(self._save_ui)
        ui_form.addRow(self.remember_tab)

        self.status_ms = QSpinBox()
        self.status_ms.setRange(2000, 30000)
        self.status_ms.setSingleStep(1000)
        self.status_ms.setSuffix(" ms")
        self.status_ms.setValue(self.preferences.status_message_ms)
        self.status_ms.valueChanged.connect(self._save_ui)
        ui_form.addRow("Status message duration", self.status_ms)
        root.addWidget(ui_box)

        root.addStretch(1)

    def _on_theme(self, theme: str) -> None:
        self.preferences.theme = theme
        self.theme_changed.emit(theme)
        self.preferences_changed.emit()

    def _save_discovery(self) -> None:
        self.preferences.default_scan_profile = self.default_profile.currentText()
        self.preferences.default_interface = self.default_interface.currentText()
        self.preferences_changed.emit()

    def _save_ui(self) -> None:
        self.preferences.remember_last_tab = self.remember_tab.isChecked()
        self.preferences.status_message_ms = self.status_ms.value()
        self.preferences_changed.emit()
