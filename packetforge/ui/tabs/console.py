from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)
from scapy.packet import Packet

from packetforge.engine.builder import packet_details, packet_hexdump, packet_summary
from packetforge.engine.interfaces import list_interfaces
from packetforge.engine.sender import SendFunction, SendOptions
from packetforge.security.safe_scapy import SafeScapyError, parse_scapy_expression
from packetforge.ui.widgets.error_banner import ErrorBanner
from packetforge.ui.workers import SendWorker
from packetforge.utils.export import export_packets_to_pcap


class SafeConsoleTab(QWidget):
    status_message = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        self.packet: Packet | None = None
        self.send_workers: list[SendWorker] = []

        root = QVBoxLayout(self)
        title = QLabel("Safe Scapy Console")
        title.setObjectName("PageTitle")
        root.addWidget(title)

        self.error_banner = ErrorBanner()
        root.addWidget(self.error_banner)

        body = QHBoxLayout()
        root.addLayout(body, 1)

        left = QWidget()
        left_layout = QVBoxLayout(left)
        self.expression = QPlainTextEdit(
            'IP(dst="192.168.1.1", ttl=64) / ICMP() / Raw(load=b"PacketForge")'
        )
        self.expression.setFont(QFont("Menlo", 12))
        left_layout.addWidget(self.expression, 1)
        self.error_label = QLabel()
        self.error_label.setObjectName("Error")
        self.error_label.setWordWrap(True)
        left_layout.addWidget(self.error_label)
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
        left_layout.addLayout(actions)
        body.addWidget(left, 1)

        right = QWidget()
        right_layout = QVBoxLayout(right)
        right_layout.addWidget(self._transmission_box())
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
        right_layout.addWidget(tabs, 1)
        body.addWidget(right, 1)

    def _transmission_box(self) -> QGroupBox:
        box = QGroupBox("Transmission")
        form = QFormLayout(box)
        self.interface = QComboBox()
        self.interface.addItem("")
        self.interface.addItems(list_interfaces())
        self.send_mode = QComboBox()
        self.send_mode.addItems(["Layer 3", "Layer 2"])
        self.count = self._spin(1, 100000, 1)
        self.interval_ms = self._spin(0, 3_600_000, 100)
        self.timeout_ms = self._spin(50, 3_600_000, 1000)
        self.retry_count = self._spin(0, 100, 0)
        self.verbose = QCheckBox()
        form.addRow("Interface", self.interface)
        form.addRow("Send mode", self.send_mode)
        form.addRow("Count", self.count)
        form.addRow("Interval (ms)", self.interval_ms)
        form.addRow("Timeout (ms)", self.timeout_ms)
        form.addRow("Retry", self.retry_count)
        form.addRow("Verbose", self.verbose)
        return box

    def _spin(self, minimum: int, maximum: int, value: int) -> QSpinBox:
        spin = QSpinBox()
        spin.setRange(minimum, maximum)
        spin.setValue(value)
        return spin

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
        layer2 = self.send_mode.currentText() == "Layer 2"
        function: SendFunction = (
            "srp1" if wait and layer2 else "sr1" if wait else "sendp" if layer2 else "send"
        )
        options = SendOptions(
            function=function,
            iface=self.interface.currentText() or None,
            count=self.count.value(),
            interval_s=self.interval_ms.value() / 1000,
            timeout_s=self.timeout_ms.value() / 1000,
            retry=self.retry_count.value(),
            verbose=self.verbose.isChecked(),
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
