from __future__ import annotations

import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from PySide6.QtCore import QTimer, Signal
from PySide6.QtGui import QColor, QFont, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from packetforge.diagnostics import Diagnostics, build_debug_bundle, get_diagnostics

_LEVELS: list[tuple[str, int]] = [
    ("All", 0),
    ("Debug", logging.DEBUG),
    ("Info", logging.INFO),
    ("Warning", logging.WARNING),
    ("Error", logging.ERROR),
]

_LEVEL_COLORS: dict[str, str] = {
    "DEBUG": "#7f8a97",
    "INFO": "#aeb8c3",
    "WARNING": "#ffcf66",
    "ERROR": "#ff8c7a",
    "CRITICAL": "#ff5a4d",
}

_COLUMNS = ("Time", "Level", "Source", "Message")


class DiagnosticsTab(QWidget):
    """Live debug log, last-packet summary, and a one-click support bundle."""

    status_message = Signal(str)

    def __init__(
        self,
        diagnostics: Diagnostics | None = None,
        config_provider: Callable[[], dict[str, Any]] | None = None,
    ) -> None:
        super().__init__()
        self.diagnostics = diagnostics or get_diagnostics()
        self.config_provider = config_provider
        self._min_level = 0

        root = QVBoxLayout(self)
        title = QLabel("Diagnostics")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        intro = QLabel(
            "Recent operations, exceptions, Scapy/permission errors, and timing. "
            "Logs also stream to a rotating file under ~/.packetforge/logs/."
        )
        intro.setObjectName("Muted")
        intro.setWordWrap(True)
        root.addWidget(intro)

        controls = QHBoxLayout()
        controls.addWidget(QLabel("Level"))
        self.level_combo = QComboBox()
        for label, _value in _LEVELS:
            self.level_combo.addItem(label)
        self.level_combo.setCurrentIndex(0)
        self.level_combo.currentIndexChanged.connect(self._level_changed)
        controls.addWidget(self.level_combo)

        self.auto_refresh = QCheckBox("Auto-refresh")
        self.auto_refresh.setChecked(True)
        controls.addWidget(self.auto_refresh)

        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        controls.addWidget(refresh)

        clear = QPushButton("Clear log")
        clear.clicked.connect(self._clear)
        controls.addWidget(clear)

        controls.addStretch(1)

        copy_bundle = QPushButton("Copy Debug Bundle")
        copy_bundle.clicked.connect(self.copy_debug_bundle)
        controls.addWidget(copy_bundle)

        save_bundle = QPushButton("Save Debug Bundle...")
        save_bundle.clicked.connect(self.save_debug_bundle)
        controls.addWidget(save_bundle)
        root.addLayout(controls)

        self.last_packet = QLabel("Last packet: (none)")
        self.last_packet.setObjectName("Muted")
        self.last_packet.setWordWrap(True)
        root.addWidget(self.last_packet)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.verticalHeader().setVisible(False)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setWordWrap(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setFont(QFont("Menlo", 11))
        root.addWidget(self.table, 1)

        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)
        self._timer.start()
        self.refresh()

    def _level_changed(self, index: int) -> None:
        self._min_level = _LEVELS[index][1]
        self.refresh()

    def _tick(self) -> None:
        if self.auto_refresh.isChecked():
            self.refresh()

    def refresh(self) -> None:
        entries = self.diagnostics.recent(limit=500, min_level=self._min_level)
        self.table.setRowCount(len(entries))
        for row, entry in enumerate(entries):
            source = entry.logger.removeprefix("packetforge.").removeprefix("packetforge")
            values = (entry.time_text, entry.level, source or "app", entry.message)
            color = QColor(_LEVEL_COLORS.get(entry.level, "#aeb8c3"))
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                item.setForeground(color)
                self.table.setItem(row, column, item)
        self.table.scrollToBottom()
        summary = self.diagnostics.last_packet_summary
        self.last_packet.setText(f"Last packet: {summary}" if summary else "Last packet: (none)")

    def _clear(self) -> None:
        self.diagnostics.clear()
        self.refresh()

    def _current_config(self) -> dict[str, Any]:
        if self.config_provider is None:
            return {}
        try:
            return self.config_provider()
        except Exception:  # never let a bad provider break the bundle
            return {}

    def copy_debug_bundle(self) -> None:
        bundle = build_debug_bundle(self._current_config(), diagnostics=self.diagnostics)
        clipboard = QGuiApplication.clipboard()
        if clipboard is not None:
            clipboard.setText(bundle.to_text())
        self.status_message.emit("Debug bundle copied to clipboard.")

    def save_debug_bundle(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Debug Bundle",
            "packetforge-debug.json",
            "JSON (*.json);;Text (*.txt)",
        )
        if not path:
            return
        bundle = build_debug_bundle(self._current_config(), diagnostics=self.diagnostics)
        text = bundle.to_text() if path.lower().endswith(".txt") else bundle.to_json()
        Path(path).write_text(text, encoding="utf-8")
        self.status_message.emit(f"Debug bundle saved to {path}")
