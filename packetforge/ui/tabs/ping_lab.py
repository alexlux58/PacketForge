from __future__ import annotations

from pathlib import Path
from typing import Literal, cast

import pyqtgraph as pg
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)
from scapy.packet import Packet

from packetforge.errors import ErrorEvent, report_exception
from packetforge.models.ping import PingConfig
from packetforge.models.results import PingResult, PingSummary
from packetforge.ui.state import ObservabilityState
from packetforge.ui.widgets.data_table import DataTable
from packetforge.ui.widgets.error_banner import ErrorBanner
from packetforge.ui.widgets.interface_combo import defer_populate_interface_combo, tune_combo_box
from packetforge.ui.widgets.page_header import PageHeader
from packetforge.ui.widgets.persistent_splitter import PersistentSplitter
from packetforge.ui.widgets.transmission_form import configure_form_layout, tune_spin_box
from packetforge.ui.workers import PingWorker
from packetforge.utils.export import (
    export_packets_to_pcap,
    export_ping_results_csv,
    export_ping_results_json,
)
from packetforge.utils.formatting import format_ms, format_percent, format_pps
from packetforge.utils.packet_size import ipv4_icmp_size_breakdown

_PING_COLUMNS = [
    "Seq", "RTT", "Reply source", "Reply TTL", "Reply size",
    "Type", "Code", "Timeout", "Duplicate", "Error",
]


class PingLabTab(QWidget):
    status_message = Signal(str)

    def __init__(self, obs_state: ObservabilityState | None = None) -> None:
        super().__init__()
        self.worker: PingWorker | None = None
        self.obs_state = obs_state
        self.results: list[PingResult] = []
        self.captured_packets: list[Packet] = []

        root = QVBoxLayout(self)
        root.addWidget(
            PageHeader(
                "Ping Lab",
                "ping_lab",
                subtitle=(
                    "ICMP echo probes with live RTT charting. "
                    "Click i for help interpreting statistics."
                ),
            )
        )

        self.error_banner = ErrorBanner()
        root.addWidget(self.error_banner)

        top = PersistentSplitter(
            Qt.Orientation.Horizontal,
            "splitter/ping_lab",
            default_sizes=[380, 520],
        )
        root.addWidget(top, 1)
        top.addWidget(self._build_controls())
        top.addWidget(self._build_chart())
        top.restore()

        self.stats_grid = QGridLayout()
        root.addLayout(self.stats_grid)
        self.stat_labels: dict[str, QLabel] = {}
        for index, name in enumerate(
            [
                "Transmitted",
                "Received",
                "Loss",
                "Min",
                "Avg",
                "Max",
                "Median",
                "Stddev",
                "Jitter",
                "P95",
                "Duration",
                "Rate",
                "ICMP errors",
            ]
        ):
            label = QLabel("--")
            label.setObjectName("Metric")
            self.stat_labels[name] = label
            self.stats_grid.addWidget(QLabel(name), index // 7 * 2, index % 7)
            self.stats_grid.addWidget(label, index // 7 * 2 + 1, index % 7)

        self.table = DataTable(
            _PING_COLUMNS,
            empty_message="No ping results yet.",
            empty_hint="Configure destination and click Run.",
        )
        self.table.set_export_handler(self.save_csv)
        self.progress_label = QLabel("Idle")
        self.progress_label.setObjectName("Muted")
        root.addWidget(self.progress_label)
        root.addWidget(self.table, 1)
        self._update_sizes()

    def focus_search(self) -> None:
        self.table.focus_search()

    def copy_selection(self) -> None:
        self.table.copy_selection()

    def _build_controls(self) -> QGroupBox:
        box = QGroupBox("Controls")
        box.setMinimumWidth(340)
        outer = QVBoxLayout(box)
        outer.setContentsMargins(8, 8, 8, 8)

        # Many fields + buttons exceed a short window, so the fields scroll while
        # the action buttons stay pinned and reachable below.
        form_host = QWidget()
        form = QFormLayout(form_host)
        configure_form_layout(form)

        self.destination = QLineEdit("192.168.1.1")
        self.family = tune_combo_box(QComboBox())
        self.family.addItems(["IPv4", "IPv6"])
        self.interface = tune_combo_box(QComboBox())
        defer_populate_interface_combo(self.interface)
        self.source_ip = QLineEdit()

        self.count = tune_spin_box(self._spin(1, 100000, 4))
        self.interval_ms = tune_spin_box(self._spin(10, 3_600_000, 1000))
        self.timeout_ms = tune_spin_box(self._spin(50, 3_600_000, 1000))
        self.ttl = tune_spin_box(self._spin(0, 255, 64))
        self.payload_size = tune_spin_box(self._spin(0, 65507, 56))
        self.dscp = self._spin(0, 63, 0)
        self.ecn = self._spin(0, 3, 0)
        self.icmp_id = self._spin(0, 65535, 0xF00D)
        self.start_sequence = self._spin(0, 65535, 1)
        self.payload_pattern = QLineEdit("PacketForge")
        self.random_payload = QCheckBox()
        self.do_not_fragment = QCheckBox()
        self.resolve_dns = QCheckBox()
        self.resolve_dns.setChecked(True)
        self.record_pcap = QCheckBox()

        self.size_label = QLabel()
        self.size_label.setObjectName("Muted")
        self.payload_size.valueChanged.connect(self._update_sizes)
        self.family.currentTextChanged.connect(self._update_sizes)

        form.addRow("Destination", self.destination)
        form.addRow("Address family", self.family)
        form.addRow("Interface", self.interface)
        form.addRow("Source IP", self.source_ip)
        form.addRow("Count", self.count)
        form.addRow("Interval (ms)", self.interval_ms)
        form.addRow("Timeout (ms)", self.timeout_ms)
        form.addRow("TTL / Hop limit", self.ttl)
        form.addRow("ICMP payload size", self.payload_size)
        form.addRow("DSCP", self.dscp)
        form.addRow("ECN", self.ecn)
        form.addRow("ICMP identifier", self.icmp_id)
        form.addRow("Starting sequence", self.start_sequence)
        form.addRow("Payload pattern", self.payload_pattern)
        form.addRow("Random payload", self.random_payload)
        form.addRow("IPv4 Do Not Fragment", self.do_not_fragment)
        form.addRow("Resolve DNS", self.resolve_dns)
        form.addRow("Record PCAP", self.record_pcap)
        form.addRow("Size breakdown", self.size_label)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setWidget(form_host)
        scroll.setMinimumHeight(150)
        outer.addWidget(scroll, 1)

        run_buttons = QHBoxLayout()
        self.run_button = QPushButton("Run")
        self.stop_button = QPushButton("Stop")
        self.pause_button = QPushButton("Pause")
        self.resume_button = QPushButton("Resume")
        self.clear_button = QPushButton("Clear")
        self.run_again_button = QPushButton("Run Again")
        for button in [
            self.run_button,
            self.stop_button,
            self.pause_button,
            self.resume_button,
            self.clear_button,
            self.run_again_button,
        ]:
            run_buttons.addWidget(button)

        export_buttons = QHBoxLayout()
        self.export_pcap = QPushButton("Save PCAP")
        self.export_csv = QPushButton("Save CSV")
        self.export_json = QPushButton("Save JSON")
        for button in [self.export_pcap, self.export_csv, self.export_json]:
            export_buttons.addWidget(button)

        outer.addLayout(run_buttons)
        outer.addLayout(export_buttons)

        self.run_button.clicked.connect(self.start_ping)
        self.stop_button.clicked.connect(self.stop_ping)
        self.pause_button.clicked.connect(lambda: self.worker.pause() if self.worker else None)
        self.resume_button.clicked.connect(lambda: self.worker.resume() if self.worker else None)
        self.clear_button.clicked.connect(self.clear_results)
        self.run_again_button.clicked.connect(self.start_ping)
        self.export_pcap.clicked.connect(self.save_pcap)
        self.export_csv.clicked.connect(self.save_csv)
        self.export_json.clicked.connect(self.save_json)
        return box

    def _build_chart(self) -> pg.PlotWidget:
        self.plot = pg.PlotWidget()
        self.plot.setLabel("left", "RTT", units="ms")
        self.plot.setLabel("bottom", "ICMP sequence")
        self.plot.showGrid(x=True, y=True, alpha=0.25)
        self.rtt_curve = self.plot.plot([], [], pen=pg.mkPen("#3da5ff", width=2), symbol="o")
        self.avg_curve = self.plot.plot([], [], pen=pg.mkPen("#f5a623", width=2))
        return self.plot

    def _spin(self, minimum: int, maximum: int, value: int) -> QSpinBox:
        spin = QSpinBox()
        spin.setRange(minimum, maximum)
        spin.setValue(value)
        return spin

    def _config(self) -> PingConfig:
        return PingConfig(
            destination=self.destination.text().strip(),
            address_family=cast(Literal["IPv4", "IPv6"], self.family.currentText()),
            interface=self.interface.currentText() or None,
            source_ip=self.source_ip.text().strip() or None,
            count=self.count.value(),
            interval_ms=self.interval_ms.value(),
            timeout_ms=self.timeout_ms.value(),
            ttl=self.ttl.value(),
            payload_size=self.payload_size.value(),
            dscp=self.dscp.value(),
            ecn=self.ecn.value(),
            icmp_id=self.icmp_id.value(),
            start_sequence=self.start_sequence.value(),
            payload_pattern=self.payload_pattern.text(),
            random_payload=self.random_payload.isChecked(),
            do_not_fragment=self.do_not_fragment.isChecked(),
            resolve_dns=self.resolve_dns.isChecked(),
            record_pcap=self.record_pcap.isChecked(),
        )

    def start_ping(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        self.error_banner.clear()
        self.clear_results()
        self.table.begin_bulk_update()
        try:
            config = self._config()
        except Exception as exc:
            self.table.end_bulk_update()
            event = report_exception(exc, source="Ping Lab", operation="configure")
            self.error_banner.show_event(event)
            return
        self.worker = PingWorker(config)
        self.worker.result_ready.connect(self._add_result)
        self.worker.summary_ready.connect(self._update_summary)
        self.worker.completed.connect(self._completed)
        self.worker.error_occurred.connect(self._on_error)
        self.progress_label.setText(f"Pinging {config.destination} ({config.count} probes)...")
        self.status_message.emit(f"Ping started: {config.destination}")
        self.worker.start()

    def _on_error(self, event: ErrorEvent) -> None:
        self.table.end_bulk_update()
        self.error_banner.show_event(event, on_retry=self.start_ping)

    def stop_ping(self) -> None:
        if self.worker:
            self.worker.stop()

    def clear_results(self) -> None:
        self.results.clear()
        self.captured_packets.clear()
        self.table.clear_rows()
        self.rtt_curve.setData([], [])
        self.avg_curve.setData([], [])
        self.progress_label.setText("Idle")
        self._update_summary(PingSummary())

    def _add_result(self, result: PingResult) -> None:
        self.results.append(result)
        row = self.table.insert_row()
        values = [
            str(result.sequence),
            format_ms(result.rtt_ms),
            result.reply_source or "",
            "" if result.reply_ttl is None else str(result.reply_ttl),
            "" if result.reply_size is None else str(result.reply_size),
            "" if result.icmp_type is None else str(result.icmp_type),
            "" if result.icmp_code is None else str(result.icmp_code),
            "yes" if result.timeout else "no",
            "yes" if result.duplicate else "no",
            result.error or "",
        ]
        for column, value in enumerate(values):
            self.table.set_cell(row, column, value)
        self.table.scroll_to_bottom()
        received = len(self.results)
        self.progress_label.setText(
            f"Received {received} / {self.count.value()} replies..."
        )
        self._update_plot()

    def _update_summary(self, summary: PingSummary) -> None:
        updates = {
            "Transmitted": str(summary.transmitted),
            "Received": str(summary.received),
            "Loss": format_percent(summary.loss_percent),
            "Min": format_ms(summary.min_rtt_ms),
            "Avg": format_ms(summary.avg_rtt_ms),
            "Max": format_ms(summary.max_rtt_ms),
            "Median": format_ms(summary.median_rtt_ms),
            "Stddev": format_ms(summary.stddev_rtt_ms),
            "Jitter": format_ms(summary.jitter_ms),
            "P95": format_ms(summary.p95_rtt_ms),
            "Duration": f"{summary.duration_s:.2f} s",
            "Rate": format_pps(summary.effective_pps),
            "ICMP errors": str(summary.icmp_errors),
        }
        for key, value in updates.items():
            self.stat_labels[key].setText(value)

    def _update_plot(self) -> None:
        points = [
            (result.sequence, result.rtt_ms) for result in self.results if result.rtt_ms is not None
        ]
        if not points:
            self.rtt_curve.setData([], [])
            self.avg_curve.setData([], [])
            return
        sequences = [point[0] for point in points]
        rtts = [point[1] for point in points]
        rolling: list[float] = []
        for index in range(len(rtts)):
            window = rtts[max(0, index - 4) : index + 1]
            rolling.append(sum(window) / len(window))
        self.rtt_curve.setData(sequences, rtts)
        self.avg_curve.setData(sequences, rolling)

    def _completed(self, _results: object, packets: object) -> None:
        self.table.end_bulk_update()
        self.table.resize_columns_to_contents()
        self.captured_packets = list(packets) if isinstance(packets, list) else []
        self.progress_label.setText(
            f"Complete — {len(self.results)} result row(s), "
            f"{len(self.captured_packets)} PCAP packet(s)"
        )
        self.status_message.emit(f"Ping finished: {len(self.results)} result(s)")
        if self.obs_state is not None and self.results:
            host = self.destination.text().strip()
            if host:
                self.obs_state.set_pings(host, self.results)

    def _update_sizes(self) -> None:
        if self.family.currentText() != "IPv4":
            self.size_label.setText("IPv6 size preview is shown after packet build.")
            return
        sizes = ipv4_icmp_size_breakdown(self.payload_size.value())
        self.size_label.setText(
            f"payload {sizes.icmp_payload_size} B; IP packet {sizes.ip_packet_size} B; "
            f"Ethernet frame {sizes.ethernet_frame_size_without_fcs} B without FCS / "
            f"{sizes.ethernet_frame_size_with_fcs} B with FCS"
        )

    def save_pcap(self) -> None:
        if not self.captured_packets:
            QMessageBox.information(self, "No packets", "Enable Record PCAP and run a ping first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save PCAP", "ping-results.pcap", "PCAP (*.pcap)"
        )
        if path:
            export_packets_to_pcap(self.captured_packets, Path(path))

    def save_csv(self) -> None:
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "ping-results.csv", "CSV (*.csv)")
        if path:
            export_ping_results_csv(self.results, Path(path))

    def save_json(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save JSON", "ping-results.json", "JSON (*.json)"
        )
        if path:
            export_ping_results_json(self.results, Path(path))
