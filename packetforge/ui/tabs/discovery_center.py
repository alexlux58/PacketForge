from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from packetforge.engine.history import DiscoveryHistory
from packetforge.engine.observability import reachability_breakdown
from packetforge.engine.ports import parse_port_list
from packetforge.engine.targets import parse_targets, preview_targets
from packetforge.errors import ErrorEvent, report_exception
from packetforge.models.discovery import (
    DEFAULT_TCP_PORTS,
    DEFAULT_UDP_PORTS,
    DiscoveryConfig,
    DiscoveryMethod,
    DiscoveryRun,
    HostRecord,
)
from packetforge.models.profiles import BUILTIN_PROFILES, profile_by_name
from packetforge.security.privileges import PRIVILEGED_METHODS, detect_privileges
from packetforge.ui import charts
from packetforge.ui.preferences import AppPreferences
from packetforge.ui.state import DiscoveryState
from packetforge.ui.widgets.data_table import DataTable
from packetforge.ui.widgets.error_banner import ErrorBanner
from packetforge.ui.widgets.form_helpers import add_form_row
from packetforge.ui.widgets.host_detail import HostDetailPanel
from packetforge.ui.widgets.interface_combo import defer_populate_interface_combo, tune_combo_box
from packetforge.ui.widgets.page_header import PageHeader
from packetforge.ui.widgets.persistent_splitter import PersistentSplitter
from packetforge.ui.widgets.transmission_form import configure_form_layout, tune_spin_box
from packetforge.ui.workers import DiscoveryWorker
from packetforge.utils.export import (
    export_hosts_csv,
    export_hosts_json,
    export_hosts_markdown,
    export_packets_to_pcap,
    export_run_json,
)

_METHOD_LABELS: list[tuple[DiscoveryMethod, str]] = [
    ("icmp", "ICMP echo"),
    ("tcp", "TCP connect"),
    ("tcp_syn", "TCP SYN (raw)"),
    ("udp", "UDP probe"),
    ("arp", "ARP (local L2)"),
    ("dns_reverse", "DNS reverse"),
    ("passive", "Passive capture"),
]

_COLUMNS = [
    "IP", "MAC", "Vendor", "Hostname", "Latency", "Open ports",
    "Protocols", "Confidence", "Methods", "Last seen",
]

# Keep identity columns wide enough that full IPs/MACs/hostnames stay readable
# instead of collapsing to "192.168..." after resizeColumnsToContents().
_MIN_COLUMN_WIDTHS: dict[int, int] = {
    0: 140,  # IP
    1: 150,  # MAC
    2: 120,  # Vendor
    3: 160,  # Hostname
    5: 110,  # Open ports
}

_FIELD_TOOLTIPS: dict[str, str] = {
    "Targets": "IP, CIDR, comma list, range, or hostname. Example: 192.168.1.0/24",
    "Interface": "Outbound interface for probes and passive capture. Leave blank for auto.",
    "Profile": "Gentle, Balanced, or Lab Fast — controls probe rate and timeout.",
    "TCP ports": "Comma-separated TCP ports for connect scans.",
    "UDP ports": "Comma-separated UDP ports for UDP probes.",
    "Passive seconds": "How long to listen when passive capture is enabled.",
}


class DiscoveryCenterTab(QWidget):
    status_message = Signal(str)

    def __init__(
        self,
        state: DiscoveryState,
        *,
        history: DiscoveryHistory | None = None,
        preferences: AppPreferences | None = None,
    ) -> None:
        super().__init__()
        self.state = state
        self.worker: DiscoveryWorker | None = None
        self.privileges = detect_privileges()
        self.prefs = preferences or AppPreferences()
        self.history = history or DiscoveryHistory()
        self._row_for_ip: dict[str, int] = {}
        self._last_packets: list[object] = []

        root = QVBoxLayout(self)
        root.addWidget(
            PageHeader(
                "Discovery Center",
                "discovery_center",
                subtitle=(
                    "Authorized networks only. Active discovery sends packets — pick a "
                    "conservative profile. Click i for help interpreting results."
                ),
            )
        )

        self.error_banner = ErrorBanner()
        root.addWidget(self.error_banner)

        body = PersistentSplitter(
            Qt.Orientation.Horizontal,
            "splitter/discovery_main",
            default_sizes=[380, 900],
        )
        root.addWidget(body, 1)
        body.addWidget(self._build_controls())
        body.addWidget(self._build_results_panel())
        body.restore()

        self._mini_timer = QTimer(self)
        self._mini_timer.setSingleShot(True)
        self._mini_timer.setInterval(400)
        self._mini_timer.timeout.connect(self._refresh_mini)

        self.state.hosts_changed.connect(self._sync_from_state)

    def apply_preferences(self) -> None:
        """Refresh discovery defaults after Settings changes."""
        self.profile.setCurrentText(self.prefs.default_scan_profile)
        if self.prefs.default_interface:
            self.interface.setCurrentText(self.prefs.default_interface)

    def _build_results_panel(self) -> QWidget:
        panel = QWidget()
        right = QVBoxLayout(panel)
        right.setContentsMargins(0, 0, 0, 0)

        self.scope_label = QLabel("No scan running.")
        self.scope_label.setObjectName("Metric")
        self.scope_label.setWordWrap(True)
        right.addWidget(self.scope_label)
        self.methods_label = QLabel("")
        self.methods_label.setObjectName("Muted")
        self.methods_label.setWordWrap(True)
        right.addWidget(self.methods_label)

        self.mini_reach = QLabel("Reachability: no hosts yet.")
        self.mini_reach.setObjectName("Muted")
        right.addWidget(self.mini_reach)
        self.mini_holder = QVBoxLayout()
        right.addLayout(self.mini_holder)

        self.host_splitter = PersistentSplitter(
            Qt.Orientation.Horizontal,
            "splitter/discovery_hosts",
            default_sizes=[720, 340],
        )
        table_panel = QWidget()
        table_layout = QVBoxLayout(table_panel)
        table_layout.setContentsMargins(0, 0, 0, 0)
        self.host_table = DataTable(
            _COLUMNS,
            empty_message="No hosts discovered yet.",
            empty_hint="Configure targets and click Start, or load a Simulation scenario.",
            min_column_widths=_MIN_COLUMN_WIDTHS,
        )
        self.host_table.set_export_handler(self.save_csv)
        self.host_table.row_activated.connect(self._show_host_detail)
        self.host_table.table.itemSelectionChanged.connect(self._on_row_selected)
        table_layout.addWidget(self.host_table)
        self.host_detail = HostDetailPanel()
        self.host_detail.export_requested.connect(self._export_host_report)
        self.host_splitter.addWidget(table_panel)
        self.host_splitter.addWidget(self.host_detail)
        right.addWidget(self.host_splitter, 1)
        self.host_splitter.restore()

        self.progress = QProgressBar()
        self.progress.setFormat("%v / %m hosts probed")
        self.progress_label = QLabel("Idle")
        self.progress_label.setObjectName("Muted")
        right.addWidget(self.progress_label)
        right.addWidget(self.progress)
        self.log = QListWidget()
        self.log.setMaximumHeight(140)
        right.addWidget(self.log)
        return panel

    def _build_controls(self) -> QWidget:
        panel = QWidget()
        panel.setMinimumWidth(340)
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)

        box = QGroupBox("Scan setup")
        form = QFormLayout(box)
        configure_form_layout(form)

        self.targets = QLineEdit("192.168.1.0/24")
        self.target_estimate = QLabel("")
        self.target_estimate.setObjectName("Muted")
        self._estimate_timer = QTimer(self)
        self._estimate_timer.setSingleShot(True)
        self._estimate_timer.setInterval(300)
        self._estimate_timer.timeout.connect(self._update_estimate)
        self.targets.textChanged.connect(self._schedule_estimate)

        self.interface = tune_combo_box(QComboBox())
        defer_populate_interface_combo(
            self.interface,
            selected=self.prefs.default_interface,
        )

        self.profile = tune_combo_box(QComboBox())
        self.profile.addItems([profile.name for profile in BUILTIN_PROFILES])
        self.profile.setCurrentText(self.prefs.default_scan_profile)
        self.profile.currentTextChanged.connect(self._update_profile_hint)
        self.profile_hint = QLabel("")
        self.profile_hint.setObjectName("Muted")
        self.profile_hint.setWordWrap(True)

        self.method_boxes: dict[DiscoveryMethod, QCheckBox] = {}
        methods_box = QGroupBox("Methods")
        methods_layout = QVBoxLayout(methods_box)
        for method, label in _METHOD_LABELS:
            checkbox = QCheckBox(label)
            if method in PRIVILEGED_METHODS and not self.privileges.raw_sockets:
                # Grey out raw-socket methods up front so the limitation is visible
                # before starting, not just buried in the logs after the fact.
                checkbox.setText(f"{label} — needs elevation")
                checkbox.setToolTip(
                    "Requires raw sockets. Run with sudo (macOS) or grant cap_net_raw "
                    "(Linux) to enable; disabled because this process is unprivileged."
                )
                checkbox.setChecked(False)
                checkbox.setEnabled(False)
            elif method in {"icmp", "tcp"}:
                checkbox.setChecked(True)
            self.method_boxes[method] = checkbox
            methods_layout.addWidget(checkbox)

        self.tcp_ports = QLineEdit(",".join(str(p) for p in DEFAULT_TCP_PORTS))
        self.udp_ports = QLineEdit(",".join(str(p) for p in DEFAULT_UDP_PORTS))
        self.passive_seconds = tune_spin_box(QSpinBox())
        self.passive_seconds.setRange(1, 600)
        self.passive_seconds.setValue(15)
        self.grab_banners = QCheckBox("Grab service banners")
        self.grab_banners.setChecked(True)
        self.record_pcap = QCheckBox("Record passive PCAP")

        add_form_row(form, "Targets", self.targets, tooltip=_FIELD_TOOLTIPS["Targets"])
        form.addRow("", self.target_estimate)
        self.targets_hint = QLabel("")
        self.targets_hint.setObjectName("Muted")
        self.targets_hint.setWordWrap(True)
        form.addRow("", self.targets_hint)
        add_form_row(form, "Interface", self.interface, tooltip=_FIELD_TOOLTIPS["Interface"])
        add_form_row(form, "Profile", self.profile, tooltip=_FIELD_TOOLTIPS["Profile"])
        form.addRow("", self.profile_hint)
        form.addRow(methods_box)
        add_form_row(form, "TCP ports", self.tcp_ports, tooltip=_FIELD_TOOLTIPS["TCP ports"])
        add_form_row(form, "UDP ports", self.udp_ports, tooltip=_FIELD_TOOLTIPS["UDP ports"])
        add_form_row(
            form,
            "Passive seconds",
            self.passive_seconds,
            tooltip=_FIELD_TOOLTIPS["Passive seconds"],
        )
        form.addRow(self.grab_banners)
        form.addRow(self.record_pcap)

        self.privilege_hint = QLabel(self.privileges.headline)
        self.privilege_hint.setObjectName("Muted")
        self.privilege_hint.setWordWrap(True)
        form.addRow(self.privilege_hint)

        run_buttons = QHBoxLayout()
        self.start_button = QPushButton("Start")
        self.stop_button = QPushButton("Stop")
        self.pause_button = QPushButton("Pause")
        self.resume_button = QPushButton("Resume")
        self.clear_button = QPushButton("Clear")
        for button in (
            self.start_button,
            self.stop_button,
            self.pause_button,
            self.resume_button,
            self.clear_button,
        ):
            run_buttons.addWidget(button)

        export_buttons = QHBoxLayout()
        self.export_csv = QPushButton("Export CSV")
        self.export_json = QPushButton("Export JSON")
        self.export_markdown = QPushButton("Export MD")
        self.export_pcap = QPushButton("Export PCAP")
        for button in (self.export_csv, self.export_json, self.export_markdown, self.export_pcap):
            export_buttons.addWidget(button)

        button_panel = QWidget()
        button_layout = QVBoxLayout(button_panel)
        button_layout.setContentsMargins(0, 0, 0, 0)
        button_layout.setSpacing(6)
        button_layout.addLayout(run_buttons)
        button_layout.addLayout(export_buttons)
        form.addRow(button_panel)

        self.start_button.clicked.connect(self.start_scan)
        self.stop_button.clicked.connect(self.stop_scan)
        self.pause_button.clicked.connect(self.pause_scan)
        self.resume_button.clicked.connect(self.resume_scan)
        self.clear_button.clicked.connect(self.clear)
        self.export_csv.clicked.connect(self.save_csv)
        self.export_json.clicked.connect(self.save_json)
        self.export_markdown.clicked.connect(self.save_markdown)
        self.export_pcap.clicked.connect(self.save_pcap)

        self._update_estimate()
        self._update_profile_hint()
        self.profile.setCurrentText(self.prefs.default_scan_profile)

        layout.addWidget(box)
        layout.addStretch(1)
        return panel

    def focus_search(self) -> None:
        self.host_table.focus_search()

    def _schedule_estimate(self) -> None:
        self._estimate_timer.start()

    def _update_estimate(self) -> None:
        text = self.targets.text().strip()
        if not text:
            self.target_estimate.setText("Enter targets to estimate host count")
            self.target_estimate.setObjectName("Muted")
            self.targets_hint.setText("")
            return
        parsed = preview_targets(text)
        label = f"{parsed.count} target host(s)"
        if parsed.truncated:
            label += " (preview capped)"
        self.target_estimate.setText(label)
        if parsed.count == 0:
            self.target_estimate.setObjectName("Error")
            self.targets_hint.setText("No valid targets parsed. Use IP, CIDR, range, or hostname.")
        else:
            self.target_estimate.setObjectName("Muted")
            self.targets_hint.setText(" ".join(parsed.warnings))

    def _update_profile_hint(self) -> None:
        profile = profile_by_name(self.profile.currentText())
        self.profile_hint.setText(
            f"{profile.description}\nRate: {profile.max_packets_per_second:.0f} pps, "
            f"concurrency {profile.concurrency}, timeout {profile.probe_timeout_ms} ms."
        )

    def _selected_methods(self) -> list[DiscoveryMethod]:
        return [method for method, box in self.method_boxes.items() if box.isChecked()]

    def _parse_ports(self, text: str) -> list[int]:
        return parse_port_list(text)

    def _config(self) -> DiscoveryConfig:
        return DiscoveryConfig(
            targets=self.targets.text().strip(),
            methods=self._selected_methods(),
            profile_name=self.profile.currentText(),
            interface=self.interface.currentText() or None,
            tcp_ports=self._parse_ports(self.tcp_ports.text()),
            udp_ports=self._parse_ports(self.udp_ports.text()),
            passive_seconds=self.passive_seconds.value(),
            grab_banners=self.grab_banners.isChecked(),
            record_pcap=self.record_pcap.isChecked(),
        )

    def start_scan(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        self.error_banner.clear()
        methods = self._selected_methods()
        if not methods:
            self.error_banner.show_event(
                ErrorEvent(
                    severity="warning",
                    source="Discovery Center",
                    operation="configure",
                    message="Select at least one discovery method.",
                    suggested_fix="Enable ICMP, TCP, UDP, ARP, DNS reverse, or passive capture.",
                )
            )
            return
        try:
            config = self._config()
        except Exception as exc:
            event = report_exception(exc, source="Discovery Center", operation="configure")
            self.error_banner.show_event(event)
            return
        parsed = parse_targets(config.targets)
        if parsed.count == 0:
            self.error_banner.show_event(
                ErrorEvent(
                    severity="warning",
                    source="Discovery Center",
                    operation="configure",
                    message="No valid targets to scan.",
                    suggested_fix="Enter a valid IP, CIDR, range, or hostname.",
                )
            )
            return
        self.clear()
        self.host_table.begin_bulk_update()
        self.scope_label.setText(f"Scanning {config.targets} ({parsed.count} host(s))")
        self._update_methods_label(methods)
        self.progress_label.setText("Starting scan...")
        self.status_message.emit(f"Discovery started: {config.targets}")
        self.worker = DiscoveryWorker(config)
        self.worker.host_found.connect(self._on_host)
        self.worker.progress.connect(self._on_progress)
        self.worker.log.connect(self._append_log)
        self.worker.completed.connect(self._on_completed)
        self.worker.failed.connect(self._on_failed)
        self.worker.error_occurred.connect(self._on_error)
        self.worker.start()
        self._append_log(f"Starting {config.profile_name} scan of {config.targets}")

    def stop_scan(self) -> None:
        if self.worker:
            self.worker.stop()
            self._append_log("Stop requested...")

    def pause_scan(self) -> None:
        if self.worker:
            self.worker.pause()
            self._append_log("Paused.")

    def resume_scan(self) -> None:
        if self.worker:
            self.worker.resume()
            self._append_log("Resumed.")

    def clear(self) -> None:
        self.host_table.clear_rows()
        self._row_for_ip.clear()
        self._last_packets = []
        self.progress.setValue(0)
        self.progress_label.setText("Idle")
        self.scope_label.setText("No scan running.")
        self.methods_label.setText("")
        self.log.clear()
        self.host_detail.clear()
        self.state.clear()

    def _update_methods_label(self, methods: list[DiscoveryMethod]) -> None:
        label_map = dict(_METHOD_LABELS)
        running = [label_map.get(method, method) for method in methods]
        parts = [f"Running: {', '.join(running)}"] if running else []
        if not self.privileges.raw_sockets:
            unavailable = [
                label_map[method]
                for method, _ in _METHOD_LABELS
                if method in PRIVILEGED_METHODS
            ]
            parts.append(f"Unavailable without elevation: {', '.join(unavailable)}")
        self.methods_label.setText(" · ".join(parts))

    def _on_host(self, host: HostRecord) -> None:
        # A successful host while the scan is still running means any earlier
        # transient probe error is stale — don't leave a red banner up.
        if self.worker is not None and self.worker.isRunning():
            self.error_banner.clear()
        self.state.upsert(host, notify=False)
        self._render_host(host)
        self._mini_timer.start()

    def _on_progress(self, done: int, total: int) -> None:
        self.progress.setMaximum(total)
        self.progress.setValue(done)
        self.progress_label.setText(f"Probing {done} / {total} targets...")

    def _on_completed(self, run: DiscoveryRun) -> None:
        self.host_table.end_bulk_update()
        self.host_table.resize_columns_to_contents()
        # Capture packets now so PCAP export survives the worker being replaced.
        if self.worker is not None:
            self._last_packets = list(self.worker.captured_packets)
        self.state.set_run(run)
        try:
            self.history.save(run)
        except OSError as exc:
            self._append_log(f"Could not persist run: {exc}")
        self.progress_label.setText(f"Complete — {run.host_count} host(s)")
        self.status_message.emit(f"Discovery finished: {run.host_count} host(s)")
        self._append_log(f"Done. {run.host_count} host(s) discovered.")

    def _on_failed(self, message: str) -> None:
        self.host_table.end_bulk_update()
        self._append_log(f"Scan failed: {message}")

    def _on_error(self, event: ErrorEvent) -> None:
        self.host_table.end_bulk_update()
        self.error_banner.show_event(event, on_retry=self.start_scan)

    def _append_log(self, message: str) -> None:
        self.log.addItem(message)
        self.log.scrollToBottom()

    def _sync_from_state(self) -> None:
        self.host_table.begin_bulk_update()
        self.host_table.clear_rows()
        self._row_for_ip.clear()
        for host in self.state.hosts():
            self._render_host(host)
        self.host_table.end_bulk_update()
        if self.state.hosts():
            self.host_table.resize_columns_to_contents()
        if not self.state.hosts():
            self.host_detail.clear()
            self.progress.setValue(0)
            self.progress_label.setText("Idle")
        self._mini_timer.start()

    def _refresh_mini(self) -> None:
        hosts = self.state.hosts()
        while self.mini_holder.count():
            item = self.mini_holder.takeAt(0)
            widget = item.widget() if item is not None else None
            if widget is not None:
                widget.setParent(None)
        if not hosts:
            self.mini_reach.setText("Reachability: no hosts yet.")
            return
        series = reachability_breakdown(hosts, self.state.last_run)
        counts = dict(zip(series.categories, series.y, strict=True))
        self.mini_reach.setText(
            "Reachability: "
            + ", ".join(f"{name} {int(value)}" for name, value in counts.items())
        )
        chart = charts.bar_chart(series, height=130)
        self.mini_holder.addWidget(chart)

    def _render_host(self, host: HostRecord) -> None:
        row = self._row_for_ip.get(host.ip)
        if row is None:
            row = self.host_table.insert_row()
            self._row_for_ip[host.ip] = row
        values = [
            host.ip,
            host.mac or "",
            host.vendor or "",
            host.hostname or "",
            "" if host.latency_ms is None else f"{host.latency_ms:.1f} ms",
            ",".join(str(p) for p in host.open_ports),
            ",".join(host.protocols),
            f"{host.confidence:.2f}",
            ",".join(host.methods),
            host.last_seen.strftime("%H:%M:%S"),
        ]
        for column, value in enumerate(values):
            self.host_table.set_cell(
                row, column, value, user_data=host.ip if column == 0 else None
            )

    def _show_host_detail(self, ip: str) -> None:
        self.host_detail.show_host(self.state.get(ip))
        self.status_message.emit(f"Inspecting host {ip}")

    def _on_row_selected(self) -> None:
        ip = self.host_table.selected_key()
        if ip:
            self.host_detail.show_host(self.state.get(ip))

    def _export_host_report(self, fmt: str, content: str) -> None:
        if fmt != "markdown":
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export host report", "host-report.md", "Markdown (*.md)"
        )
        if path:
            Path(path).write_text(content, encoding="utf-8")
            self.status_message.emit(f"Saved host report to {path}")

    def _hosts(self) -> list[HostRecord]:
        return self.state.hosts()

    def save_csv(self) -> None:
        hosts = self._hosts()
        if not hosts:
            QMessageBox.information(self, "No hosts", "Run a discovery scan first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save CSV", "discovery.csv", "CSV (*.csv)")
        if path:
            export_hosts_csv(hosts, Path(path))
            self.status_message.emit(f"Exported {len(hosts)} host(s) to CSV")

    def save_json(self) -> None:
        hosts = self._hosts()
        if not hosts:
            QMessageBox.information(self, "No hosts", "Run a discovery scan first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save JSON", "discovery.json", "JSON (*.json)")
        if not path:
            return
        if self.state.last_run is not None:
            export_run_json(self.state.last_run, Path(path))
        else:
            export_hosts_json(hosts, Path(path))

    def save_markdown(self) -> None:
        hosts = self._hosts()
        if not hosts:
            QMessageBox.information(self, "No hosts", "Run a discovery scan first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save Markdown", "discovery.md", "Markdown (*.md)"
        )
        if path:
            export_hosts_markdown(hosts, Path(path), self.state.last_run)
            self.status_message.emit(f"Exported {len(hosts)} host(s) to Markdown")

    def save_pcap(self) -> None:
        packets = self._last_packets or (self.worker.captured_packets if self.worker else [])
        if not packets:
            QMessageBox.information(
                self, "No packets", "Enable passive capture with Record PCAP to collect packets."
            )
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save PCAP", "discovery.pcap", "PCAP (*.pcap)")
        if path:
            export_packets_to_pcap(packets, Path(path))  # type: ignore[arg-type]
