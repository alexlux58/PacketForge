from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from packetforge.engine.builder import generate_scapy_code
from packetforge.presets.storage import PresetStore
from packetforge.ui.widgets.page_header import PageHeader


class DashboardTab(QWidget):
    preset_selected = Signal(str)

    def __init__(self, preset_store: PresetStore) -> None:
        super().__init__()
        self.preset_store = preset_store
        self.presets = self.preset_store.all_presets()

        layout = QVBoxLayout(self)
        layout.addWidget(
            PageHeader(
                "PacketForge",
                "dashboard",
                subtitle=(
                    "Authorized packet crafting, ping diagnostics, safe Scapy, and PCAP export."
                ),
            )
        )

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Category", "Preset", "Use", "Layers", "Scapy"])
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(
            3, QHeaderView.ResizeMode.ResizeToContents
        )
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.itemDoubleClicked.connect(self._open_selected_preset)
        layout.addWidget(self.table, 1)

        open_button = QPushButton("Open Selected Preset")
        open_button.clicked.connect(self._open_selected_preset)
        layout.addWidget(open_button, alignment=Qt.AlignmentFlag.AlignRight)
        self.refresh()

    def refresh(self) -> None:
        self.presets = self.preset_store.all_presets()
        self.table.setRowCount(len(self.presets))
        for row, preset in enumerate(self.presets):
            layer_names = " / ".join(layer.kind for layer in preset.packet.layers)
            values = [
                preset.category,
                preset.name,
                preset.use_case,
                layer_names,
                generate_scapy_code(preset.packet),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, preset.id)
                item.setToolTip(value)
                self.table.setItem(row, column, item)

    def _open_selected_preset(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        item = self.table.item(row, 0)
        if item is None:
            return
        self.preset_selected.emit(str(item.data(Qt.ItemDataRole.UserRole)))
