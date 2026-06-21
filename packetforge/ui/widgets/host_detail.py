from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from packetforge.engine.observability import host_insight, host_report_markdown
from packetforge.models.discovery import HostRecord
from packetforge.models.observability import AnomalyFinding
from packetforge.models.results import PingResult


class HostDetailPanel(QWidget):
    """Read-only host detail drawer: identity, services, fingerprint, latency."""

    export_requested = Signal(str, str)  # format, content

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        header = QHBoxLayout()
        self.title = QLabel("Host detail")
        self.title.setObjectName("Metric")
        header.addWidget(self.title)
        header.addStretch(1)
        self.copy_button = QPushButton("Copy")
        self.copy_button.setToolTip("Copy host report to clipboard")
        self.copy_button.clicked.connect(self._copy_report)
        self.export_button = QPushButton("Export MD")
        self.export_button.setToolTip("Export host report as Markdown")
        self.export_button.clicked.connect(lambda: self._emit_export("markdown"))
        header.addWidget(self.copy_button)
        header.addWidget(self.export_button)
        layout.addLayout(header)

        self.body = QPlainTextEdit()
        self.body.setReadOnly(True)
        self.body.setPlaceholderText(
            "Select a host row or map node to inspect identity, services, "
            "fingerprint evidence, and latency summary."
        )
        layout.addWidget(self.body, 1)
        self._report = ""

    def clear(self) -> None:
        self.title.setText("Host detail")
        self.body.clear()
        self._report = ""

    def show_host(
        self,
        host: HostRecord | None,
        *,
        pings: list[PingResult] | None = None,
        anomalies: list[AnomalyFinding] | None = None,
    ) -> None:
        if host is None:
            self.clear()
            return
        insight = host_insight(host, pings or [], anomalies=anomalies)
        self._report = host_report_markdown(insight)
        label = host.hostname or host.ip
        self.title.setText(f"{label} ({host.ip})")
        self.body.setPlainText(self._report)

    def _copy_report(self) -> None:
        if self._report:
            from PySide6.QtGui import QGuiApplication

            QGuiApplication.clipboard().setText(self._report)

    def _emit_export(self, fmt: str) -> None:
        if self._report:
            self.export_requested.emit(fmt, self._report)
