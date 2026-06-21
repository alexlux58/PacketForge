from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from packetforge.engine.environment import (
    CheckResult,
    EnvironmentReport,
    run_environment_checks,
)

_STATUS_TEXT = {"ok": "OK", "warning": "WARN", "fail": "FAIL"}
_STATUS_COLOR = {"ok": "#36c275", "warning": "#e0b400", "fail": "#ff6b5e"}

_COLUMNS = ["Check", "Status", "Detail", "Suggested fix"]


class EnvironmentCheckTab(QWidget):
    """First-run environment screen: Python, Scapy, PySide6, interfaces,
    raw-socket privilege, and a PCAP write self-test."""

    def __init__(self) -> None:
        super().__init__()

        root = QVBoxLayout(self)
        title = QLabel("Environment Check")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        intro = QLabel(
            "PacketForge runs these checks on first launch and whenever you click Re-run. "
            "They never send packets to the network or require elevated privileges."
        )
        intro.setObjectName("Muted")
        intro.setWordWrap(True)
        root.addWidget(intro)

        self.summary = QLabel()
        self.summary.setObjectName("Metric")
        self.summary.setWordWrap(True)
        root.addWidget(self.summary)

        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.table, 1)

        buttons = QHBoxLayout()
        self.rerun_button = QPushButton("Re-run checks")
        self.rerun_button.clicked.connect(self.refresh)
        buttons.addWidget(self.rerun_button)
        buttons.addStretch(1)
        root.addLayout(buttons)

        self.refresh()

    def refresh(self) -> None:
        report = run_environment_checks()
        self._render(report)

    def _render(self, report: EnvironmentReport) -> None:
        self.summary.setText(report.summary())
        self.table.setRowCount(len(report.results))
        for row, result in enumerate(report.results):
            self._set_row(row, result)

    def _set_row(self, row: int, result: CheckResult) -> None:
        name_item = QTableWidgetItem(result.name)
        status_item = QTableWidgetItem(_STATUS_TEXT.get(result.status, result.status.upper()))
        status_item.setForeground(QColor(_STATUS_COLOR.get(result.status, "#e7edf3")))
        status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        detail_item = QTableWidgetItem(result.detail)
        hint_item = QTableWidgetItem(result.hint)
        self.table.setItem(row, 0, name_item)
        self.table.setItem(row, 1, status_item)
        self.table.setItem(row, 2, detail_item)
        self.table.setItem(row, 3, hint_item)
