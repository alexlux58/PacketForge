from __future__ import annotations

from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QComboBox, QSizePolicy

from packetforge.engine.interfaces import list_interfaces


def tune_combo_box(combo: QComboBox) -> QComboBox:
    """Size a combo for form rows without breaking popups on macOS."""
    combo.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
    combo.setMinimumHeight(28)
    combo.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContentsOnFirstShow)
    return combo


def populate_interface_combo(combo: QComboBox, *, selected: str = "") -> None:
    combo.blockSignals(True)
    combo.clear()
    combo.addItem("")
    combo.addItems(list_interfaces())
    if selected:
        combo.setCurrentText(selected)
    combo.blockSignals(False)


def defer_populate_interface_combo(combo: QComboBox, *, selected: str = "") -> None:
    """Fill interface names after the event loop starts (keeps UI responsive)."""
    combo.blockSignals(True)
    combo.clear()
    combo.addItem("")
    combo.setEnabled(False)
    combo.blockSignals(False)

    def load() -> None:
        populate_interface_combo(combo, selected=selected)
        combo.setEnabled(True)

    QTimer.singleShot(0, load)
