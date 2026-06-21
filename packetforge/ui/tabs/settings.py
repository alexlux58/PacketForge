from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QLabel,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from packetforge.engine.interfaces import list_interfaces
from packetforge.models.profiles import BUILTIN_PROFILES
from packetforge.ui.preferences import AppPreferences


class SettingsTab(QWidget):
    """User preferences persisted via QSettings."""

    preferences_changed = Signal()
    theme_changed = Signal(str)

    def __init__(self, preferences: AppPreferences) -> None:
        super().__init__()
        self.preferences = preferences

        root = QVBoxLayout(self)
        title = QLabel("Settings")
        title.setObjectName("PageTitle")
        root.addWidget(title)
        intro = QLabel(
            "Preferences are stored locally. Theme, window layout, and splitter sizes "
            "are restored on the next launch."
        )
        intro.setObjectName("Muted")
        intro.setWordWrap(True)
        root.addWidget(intro)

        appearance = QGroupBox("Appearance")
        appearance_form = QFormLayout(appearance)
        self.theme = QComboBox()
        self.theme.addItems(["dark", "light"])
        self.theme.setCurrentText(self.preferences.theme)
        self.theme.currentTextChanged.connect(self._on_theme)
        appearance_form.addRow("Theme", self.theme)
        root.addWidget(appearance)

        discovery = QGroupBox("Discovery defaults")
        discovery_form = QFormLayout(discovery)
        self.default_profile = QComboBox()
        self.default_profile.addItems([profile.name for profile in BUILTIN_PROFILES])
        self.default_profile.setCurrentText(self.preferences.default_scan_profile)
        self.default_profile.currentTextChanged.connect(self._save_discovery)
        discovery_form.addRow("Default profile", self.default_profile)

        self.default_interface = QComboBox()
        self.default_interface.addItem("")
        self.default_interface.addItems(list_interfaces())
        current_iface = self.preferences.default_interface
        if current_iface:
            self.default_interface.setCurrentText(current_iface)
        self.default_interface.currentTextChanged.connect(self._save_discovery)
        discovery_form.addRow("Default interface", self.default_interface)
        root.addWidget(discovery)

        ui_box = QGroupBox("UI behaviour")
        ui_form = QFormLayout(ui_box)
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
