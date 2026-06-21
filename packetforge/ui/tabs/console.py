from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)
from scapy.packet import Packet

from packetforge.engine.builder import packet_details, packet_hexdump, packet_summary
from packetforge.engine.sender import SendFunction, SendOptions
from packetforge.security.safe_scapy import SafeScapyError, parse_scapy_expression
from packetforge.ui.widgets.error_banner import ErrorBanner
from packetforge.ui.widgets.page_header import PageHeader
from packetforge.ui.widgets.persistent_splitter import PersistentSplitter
from packetforge.ui.widgets.transmission_form import TransmissionControls, build_transmission_group
from packetforge.ui.workers import SendWorker
from packetforge.utils.export import export_packets_to_pcap


class SafeConsoleTab(QWidget):
    status_message = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.packet: Packet | None = None
        self.send_workers: list[SendWorker] = []
        self.tx: TransmissionControls

        root = QVBoxLayout(self)
        root.addWidget(
            PageHeader(
                "Safe Scapy Console",
                "scapy_console",
                subtitle=(
                    "Restricted Scapy expressions only - validate before send. "
                    "Click i for syntax help."
                ),
            )
        )

        self.error_banner = ErrorBanner()
        root.addWidget(self.error_banner)

        splitter = PersistentSplitter(
            Qt.Orientation.Horizontal,
            "splitter/scapy_console",
            default_sizes=[560, 440],
        )
        splitter.addWidget(self._build_editor_panel())
        splitter.addWidget(self._build_output_panel())
        splitter.restore()
        root.addWidget(splitter, 1)

    def _build_editor_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)

        self.expression = QPlainTextEdit(
            'IP(dst="192.168.1.1", ttl=64) / ICMP() / Raw(load=b"PacketForge")'
        )
        self.expression.setFont(QFont("Menlo", 12))
        self.expression.setMinimumHeight(120)
        layout.addWidget(self.expression, 1)

        self.error_label = QLabel()
        self.error_label.setObjectName("Error")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)

        hint = QLabel(
            "Validate checks syntax · Build renders the packet · Send transmits it "
            "(using the Transmission settings on the right). Send and Wait uses sr/sr1."
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        actions = QHBoxLayout()
        for text, callback in [
            ("Validate", self.validate_expression),
            ("Build", self.build_packet),
            ("Send", self.send_once),
            ("Send and Wait", self.send_and_wait),
            ("Save PCAP", self.save_pcap),
        ]:
            button = QPushButton(text)
            button.clicked.connect(callback)
            actions.addWidget(button)
        actions.addStretch(1)
        layout.addLayout(actions)
        return panel

    def _build_output_panel(self) -> QWidget:
        panel = QWidget()
        panel.setMinimumWidth(320)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)

        tx_box, self.tx = build_transmission_group()
        layout.addWidget(tx_box)

        tabs = QTabWidget()
        self.summary = QPlainTextEdit()
        self.summary.setReadOnly(True)
        self.summary.setFont(QFont("Menlo", 12))
        tabs.addTab(self.summary, "Summary")
        self.hex_dump = QPlainTextEdit()
        self.hex_dump.setReadOnly(True)
        self.hex_dump.setFont(QFont("Menlo", 12))
        tabs.addTab(self.hex_dump, "Hex Dump")
        self.show2 = QPlainTextEdit()
        self.show2.setReadOnly(True)
        self.show2.setFont(QFont("Menlo", 12))
        tabs.addTab(self.show2, "show2()")
        layout.addWidget(tabs, 1)
        return panel

    def validate_expression(self) -> None:
        try:
            parse_scapy_expression(self.expression.toPlainText())
        except SafeScapyError as exc:
            self.error_label.setText(str(exc))
            return
        self.error_label.setText("Expression is valid.")

    def build_packet(self) -> Packet | None:
        try:
            self.packet = parse_scapy_expression(self.expression.toPlainText())
        except SafeScapyError as exc:
            self.error_label.setText(str(exc))
            return None
        self.error_label.clear()
        self.summary.setPlainText(packet_summary(self.packet))
        self.hex_dump.setPlainText(packet_hexdump(self.packet))
        self.show2.setPlainText(packet_details(self.packet))
        return self.packet

    def save_pcap(self) -> None:
        packet = self.build_packet()
        if packet is None:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save PCAP", "packetforge-console.pcap", "PCAP (*.pcap)"
        )
        if path:
            export_packets_to_pcap([packet], Path(path))
            self.status_message.emit(f"Saved PCAP to {path}")

    def send_once(self) -> None:
        self._start_send(wait=False)

    def send_and_wait(self) -> None:
        self._start_send(wait=True)

    def _start_send(self, *, wait: bool) -> None:
        self.error_banner.clear()
        packet = self.build_packet()
        if packet is None:
            return
        layer2 = self.tx.send_mode.currentText() == "Layer 2"
        function: SendFunction = (
            "srp1" if wait and layer2 else "sr1" if wait else "sendp" if layer2 else "send"
        )
        options = SendOptions(
            function=function,
            iface=self.tx.interface.currentText() or None,
            count=self.tx.count.value(),
            interval_s=self.tx.interval_ms.value() / 1000,
            timeout_s=self.tx.timeout_ms.value() / 1000,
            retry=self.tx.retry_count.value(),
            verbose=self.tx.verbose.isChecked(),
        )
        worker = SendWorker(packet, options)
        worker.completed.connect(
            lambda result: self.status_message.emit(f"Send completed: {result}")
        )
        worker.error_occurred.connect(
            lambda event: self.error_banner.show_event(
                event, on_retry=lambda: self._start_send(wait=wait)
            )
        )
        worker.finished.connect(lambda: self._forget_worker(worker))
        self.send_workers.append(worker)
        worker.start()

    def _forget_worker(self, worker: SendWorker) -> None:
        if worker in self.send_workers:
            self.send_workers.remove(worker)
