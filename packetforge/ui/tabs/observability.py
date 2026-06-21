from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from packetforge.engine.history import DiscoveryHistory
from packetforge.engine.observability import (
    build_topology,
    compare_runs,
    host_report_markdown,
)
from packetforge.engine.sample_data import sample_baseline_run, sample_run
from packetforge.models.discovery import DiscoveryRun
from packetforge.models.observability import (
    AnomalyFinding,
    HostInsight,
    ObservabilityBundle,
    ProtocolHealthPanel,
    RunComparison,
    TopologyEdge,
    TopologyNode,
)
from packetforge.ui import charts
from packetforge.ui.state import DiscoveryState, ObservabilityState
from packetforge.ui.widgets.page_header import PageHeader
from packetforge.ui.widgets.topology_view import TopologyView
from packetforge.ui.workers import ObservabilityWorker

_SEVERITY_COLOR = {"critical": "#ff6b6b", "warning": "#f5a623", "info": "#3da5ff"}


def _clear_layout(layout: QGridLayout | QVBoxLayout | QHBoxLayout) -> None:
    while layout.count():
        item = layout.takeAt(0)
        if item is None:
            continue
        widget = item.widget()
        if widget is not None:
            widget.setParent(None)


def _chart_card(widget: QWidget, question: str) -> QWidget:
    card = QWidget()
    layout = QVBoxLayout(card)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.addWidget(widget, 1)
    if question:
        hint = QLabel(question)
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)
    return card


class ObservabilityTab(QWidget):
    def __init__(
        self,
        discovery_state: DiscoveryState,
        obs_state: ObservabilityState,
        history: DiscoveryHistory | None = None,
    ) -> None:
        super().__init__()
        self.discovery_state = discovery_state
        self.obs_state = obs_state
        self.history = history or DiscoveryHistory()
        self.bundle = ObservabilityBundle()
        self.worker: ObservabilityWorker | None = None

        self._debounce = QTimer(self)
        self._debounce.setSingleShot(True)
        self._debounce.setInterval(250)
        self._debounce.timeout.connect(self._recompute)

        root = QVBoxLayout(self)
        root.addWidget(
            PageHeader(
                "Observability",
                "observability",
                subtitle=(
                    "Charts from discovery, ping, and protocol data. Load sample data to "
                    "explore without scanning. Click i for tab-by-tab guidance."
                ),
            )
        )

        root.addLayout(self._build_filter_bar())

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self._build_overview_tab()
        self._build_latency_tab()
        self._build_protocols_tab()
        self._build_topology_tab()
        self._build_host_tab()
        self._build_compare_tab()
        self._build_anomalies_tab()

        self.discovery_state.hosts_changed.connect(self._schedule)
        self.obs_state.data_changed.connect(self._schedule)
        self._schedule()

    # -- filter bar ---------------------------------------------------------

    def _build_filter_bar(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.addWidget(QLabel("Subnet:"))
        self.subnet_filter = QComboBox()
        self.subnet_filter.addItem("All subnets", None)
        self.subnet_filter.currentIndexChanged.connect(self._schedule)
        bar.addWidget(self.subnet_filter)

        bar.addWidget(QLabel("Group map by:"))
        self.group_by = QComboBox()
        self.group_by.addItems(["subnet", "protocol"])
        self.group_by.currentIndexChanged.connect(self._render_topology)
        bar.addWidget(self.group_by)

        self.status = QLabel("No data yet.")
        self.status.setObjectName("Muted")
        bar.addWidget(self.status, 1)

        self.sample_button = QPushButton("Load sample data")
        self.sample_button.clicked.connect(self._load_sample)
        bar.addWidget(self.sample_button)

        self.png_button = QPushButton("Export PNG")
        self.png_button.clicked.connect(self._export_png)
        bar.addWidget(self.png_button)

        self.json_button = QPushButton("Export JSON")
        self.json_button.clicked.connect(self._export_json)
        bar.addWidget(self.json_button)

        self.refresh_button = QPushButton("Refresh")
        self.refresh_button.clicked.connect(self._recompute)
        bar.addWidget(self.refresh_button)
        return bar

    # -- tab scaffolding ----------------------------------------------------

    def _scroll(self) -> tuple[QScrollArea, QGridLayout]:
        area = QScrollArea()
        area.setWidgetResizable(True)
        inner = QWidget()
        grid = QGridLayout(inner)
        area.setWidget(inner)
        return area, grid

    def _build_overview_tab(self) -> None:
        area, grid = self._scroll()
        self.overview_grid = grid
        self.tabs.addTab(area, "Discovery overview")

    def _build_latency_tab(self) -> None:
        container = QWidget()
        layout = QHBoxLayout(container)
        self.latency_hosts = QListWidget()
        self.latency_hosts.setSelectionMode(QListWidget.SelectionMode.MultiSelection)
        self.latency_hosts.setMaximumWidth(200)
        self.latency_hosts.itemSelectionChanged.connect(self._render_latency)
        layout.addWidget(self.latency_hosts)
        right, grid = self._scroll()
        self.latency_grid = grid
        layout.addWidget(right, 1)
        self.tabs.addTab(container, "Latency & health")

    def _build_protocols_tab(self) -> None:
        self.protocol_tabs = QTabWidget()
        self.tabs.addTab(self.protocol_tabs, "Protocol health")

    def _build_topology_tab(self) -> None:
        container = QWidget()
        layout = QVBoxLayout(container)
        controls = QHBoxLayout()
        reset = QPushButton("Reset view")
        export_img = QPushButton("Export map image")
        controls.addWidget(reset)
        controls.addWidget(export_img)
        controls.addStretch(1)
        hint = QLabel("Scroll to zoom, drag to pan. Click a node for host detail; an edge for "
                      "evidence.")
        hint.setObjectName("Muted")
        controls.addWidget(hint)
        layout.addLayout(controls)
        self.topology_view = TopologyView()
        reset.clicked.connect(self.topology_view.reset_view)
        export_img.clicked.connect(self._export_topology_image)
        self.topology_view.node_clicked.connect(self._on_node_clicked)
        self.topology_view.edge_clicked.connect(self._on_edge_clicked)
        layout.addWidget(self.topology_view, 1)
        self.topology_detail = QLabel("Select a node or edge to inspect.")
        self.topology_detail.setObjectName("Muted")
        self.topology_detail.setWordWrap(True)
        layout.addWidget(self.topology_detail)
        self.tabs.addTab(container, "Topology")

    def _build_host_tab(self) -> None:
        container = QWidget()
        self.host_tab_widget = container
        layout = QVBoxLayout(container)
        top = QHBoxLayout()
        top.addWidget(QLabel("Host:"))
        self.host_combo = QComboBox()
        self.host_combo.currentIndexChanged.connect(self._render_host_detail)
        top.addWidget(self.host_combo, 1)
        self.host_md_button = QPushButton("Export Markdown")
        self.host_json_button = QPushButton("Export JSON")
        self.host_md_button.clicked.connect(lambda: self._export_host("md"))
        self.host_json_button.clicked.connect(lambda: self._export_host("json"))
        top.addWidget(self.host_md_button)
        top.addWidget(self.host_json_button)
        layout.addLayout(top)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.host_text = QPlainTextEdit()
        self.host_text.setReadOnly(True)
        splitter.addWidget(self.host_text)
        self.host_spark_holder = QWidget()
        self.host_spark_layout = QVBoxLayout(self.host_spark_holder)
        splitter.addWidget(self.host_spark_holder)
        splitter.setSizes([520, 360])
        layout.addWidget(splitter, 1)
        self.tabs.addTab(container, "Host detail")

    def _build_compare_tab(self) -> None:
        container = QWidget()
        layout = QVBoxLayout(container)
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Baseline:"))
        self.baseline_combo = QComboBox()
        controls.addWidget(self.baseline_combo, 1)
        controls.addWidget(QLabel("Candidate:"))
        self.candidate_combo = QComboBox()
        controls.addWidget(self.candidate_combo, 1)
        compare_btn = QPushButton("Compare")
        compare_btn.clicked.connect(self._render_compare)
        controls.addWidget(compare_btn)
        export_btn = QPushButton("Export report")
        export_btn.clicked.connect(self._export_compare)
        controls.addWidget(export_btn)
        layout.addLayout(controls)
        self.compare_text = QPlainTextEdit()
        self.compare_text.setReadOnly(True)
        layout.addWidget(self.compare_text, 1)
        self._last_comparison: RunComparison | None = None
        self.tabs.addTab(container, "Run comparison")

    def _build_anomalies_tab(self) -> None:
        container = QWidget()
        layout = QVBoxLayout(container)
        controls = QHBoxLayout()
        controls.addWidget(QLabel("Min severity:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["info", "warning", "critical"])
        self.severity_filter.currentIndexChanged.connect(self._render_anomalies)
        controls.addWidget(self.severity_filter)
        controls.addStretch(1)
        layout.addLayout(controls)
        area = QScrollArea()
        area.setWidgetResizable(True)
        inner = QWidget()
        self.anomaly_layout = QVBoxLayout(inner)
        self.anomaly_layout.addStretch(1)
        area.setWidget(inner)
        layout.addWidget(area, 1)
        self.tabs.addTab(container, "Anomalies & hints")

    # -- data flow ----------------------------------------------------------

    def _schedule(self) -> None:
        self._debounce.start()

    def _load_sample(self) -> None:
        self.discovery_state.set_run(sample_run())
        self.obs_state.load_sample()

    def _recompute(self) -> None:
        if self.worker is not None and self.worker.isRunning():
            self._schedule()
            return
        hosts = self.discovery_state.hosts()
        subnet = self.subnet_filter.currentData()
        self.status.setText("Aggregating...")
        self.worker = ObservabilityWorker(
            hosts,
            pings=self.obs_state.pings(),
            probes=self.obs_state.probes(),
            run=self.discovery_state.last_run,
            subnet_filter=subnet,
        )
        self.worker.completed.connect(self._on_bundle)
        self.worker.failed.connect(self._on_failed)
        self.worker.start()

    def _on_failed(self, message: str) -> None:
        self.status.setText(f"Aggregation failed: {message}")

    def _on_bundle(self, bundle: ObservabilityBundle) -> None:
        self.bundle = bundle
        self.status.setText(
            f"{bundle.host_count} host(s), {len(bundle.anomalies)} finding(s)"
        )
        self._sync_subnet_filter()
        self._render_overview()
        self._render_latency_hosts()
        self._render_protocols()
        self._render_topology()
        self._render_host_list()
        self._render_run_selectors()
        self._render_anomalies()

    def _sync_subnet_filter(self) -> None:
        existing = {self.subnet_filter.itemData(i) for i in range(self.subnet_filter.count())}
        subnets = {n.subnet for n in self.bundle.topology.nodes if n.subnet}
        for subnet in sorted(subnets):
            if subnet not in existing:
                self.subnet_filter.blockSignals(True)
                self.subnet_filter.addItem(subnet, subnet)
                self.subnet_filter.blockSignals(False)

    # -- overview -----------------------------------------------------------

    def _render_overview(self) -> None:
        _clear_layout(self.overview_grid)
        b = self.bundle
        cards = [
            charts.line_chart([b.timeline], b.timeline.name, height=240, step=True),
            charts.bar_chart(b.reachability, height=240),
            charts.bar_chart(b.protocol_distribution, height=240),
            charts.bar_chart(b.top_talkers, height=240),
            charts.grouped_bar_chart(b.subnet_coverage, "Subnet coverage", height=240),
            charts.bar_chart(b.confidence_distribution, height=240),
        ]
        questions = [
            b.timeline.question,
            b.reachability.question,
            b.protocol_distribution.question,
            b.top_talkers.question,
            "Per subnet: discovered vs responsive vs unresolved (no reverse DNS).",
            b.confidence_distribution.question,
        ]
        for index, (widget, question) in enumerate(zip(cards, questions, strict=True)):
            self.overview_grid.addWidget(_chart_card(widget, question), index // 2, index % 2)
        heatmap = charts.heatmap_widget(b.port_heatmap, height=300)
        self.overview_grid.addWidget(
            _chart_card(heatmap, b.port_heatmap.question), 3, 0, 1, 2
        )

    # -- latency ------------------------------------------------------------

    def _render_latency_hosts(self) -> None:
        previous = {i.text() for i in self.latency_hosts.selectedItems()}
        self.latency_hosts.blockSignals(True)
        self.latency_hosts.clear()
        for host in sorted(self.bundle.latency_by_host):
            item = QListWidgetItem(host)
            self.latency_hosts.addItem(item)
            if host in previous or not previous:
                item.setSelected(True)
        self.latency_hosts.blockSignals(False)
        self._render_latency()

    def _render_latency(self) -> None:
        _clear_layout(self.latency_grid)
        selected = [i.text() for i in self.latency_hosts.selectedItems()]
        b = self.bundle
        if not selected:
            self.latency_grid.addWidget(
                QLabel("Select host(s) with ping data, or run a ping in Ping Lab."), 0, 0
            )
            return
        rtt_series = [b.latency_by_host[h] for h in selected if h in b.latency_by_host]
        rtt_series += [b.rolling_by_host[h] for h in selected if h in b.rolling_by_host]
        jitter_series = [b.jitter_by_host[h] for h in selected if h in b.jitter_by_host]
        loss_series = [b.loss_by_host[h] for h in selected if h in b.loss_by_host]
        first = selected[0]
        hist = b.latency_histogram_by_host.get(first)

        self.latency_grid.addWidget(
            _chart_card(
                charts.line_chart(rtt_series, "RTT + rolling average", height=240),
                "Compare hosts side by side. Rolling average reveals the underlying trend.",
            ),
            0, 0,
        )
        self.latency_grid.addWidget(
            _chart_card(
                charts.line_chart(jitter_series, "Jitter (sample-to-sample)", height=240),
                "Spikes here mean inconsistent latency, which hurts voice/video.",
            ),
            0, 1,
        )
        self.latency_grid.addWidget(
            _chart_card(
                charts.line_chart(loss_series, "Packet loss timeline", height=200, step=True),
                "1 = lost probe. Clusters indicate intermittent outages.",
            ),
            1, 0,
        )
        if hist is not None:
            self.latency_grid.addWidget(
                _chart_card(charts.histogram_chart(hist, height=200), hist.question), 1, 1
            )
        self.latency_grid.addWidget(self._latency_table(selected), 2, 0, 1, 2)

    def _latency_table(self, hosts: list[str]) -> QWidget:
        table = QTableWidget()
        columns = ["Host", "Samples", "Min ms", "Avg ms", "Max ms", "Jitter ms", "Loss %"]
        table.setColumnCount(len(columns))
        table.setHorizontalHeaderLabels(columns)
        rows = [(h, self.bundle.latency_summary_by_host.get(h)) for h in hosts]
        table.setRowCount(len(rows))
        for row, (host, summary) in enumerate(rows):
            values = [
                host,
                str(summary.samples) if summary else "-",
                _fmt(summary.min_ms) if summary else "-",
                _fmt(summary.avg_ms) if summary else "-",
                _fmt(summary.max_ms) if summary else "-",
                _fmt(summary.jitter_ms) if summary else "-",
                f"{summary.loss_percent:.0f}" if summary else "-",
            ]
            for col, value in enumerate(values):
                table.setItem(row, col, QTableWidgetItem(value))
        table.setMaximumHeight(180)
        return table

    # -- protocols ----------------------------------------------------------

    def _render_protocols(self) -> None:
        current = self.protocol_tabs.currentIndex()
        self.protocol_tabs.clear()
        for panel in self.bundle.protocol_panels:
            self.protocol_tabs.addTab(self._protocol_panel_widget(panel), panel.protocol)
        if 0 <= current < self.protocol_tabs.count():
            self.protocol_tabs.setCurrentIndex(current)

    def _protocol_panel_widget(self, panel: ProtocolHealthPanel) -> QWidget:
        widget = QWidget()
        layout = QVBoxLayout(widget)
        if panel.is_empty:
            empty = QLabel(
                f"No {panel.protocol} data yet. Run a {panel.protocol} probe in the "
                "Protocol Troubleshooter."
            )
            empty.setObjectName("Muted")
            empty.setWordWrap(True)
            layout.addWidget(empty)
            layout.addStretch(1)
            return widget
        if panel.headline:
            head = QLabel(panel.headline)
            layout.addWidget(head)
        for note in panel.notes:
            note_label = QLabel(note)
            note_label.setObjectName("Muted")
            note_label.setWordWrap(True)
            layout.addWidget(note_label)
        if panel.series:
            chart_row = QHBoxLayout()
            for series in panel.series:
                card = _chart_card(charts.bar_chart(series, height=220), series.question)
                chart_row.addWidget(card)
            layout.addLayout(chart_row)
        if panel.table_rows:
            layout.addWidget(self._panel_table(panel))
        layout.addStretch(1)
        return widget

    def _panel_table(self, panel: ProtocolHealthPanel) -> QWidget:
        table = QTableWidget()
        table.setColumnCount(len(panel.table_columns))
        table.setHorizontalHeaderLabels(panel.table_columns)
        table.setRowCount(len(panel.table_rows))
        for row, cells in enumerate(panel.table_rows):
            for col, value in enumerate(cells):
                table.setItem(row, col, QTableWidgetItem(str(value)))
        table.resizeColumnsToContents()
        return table

    # -- topology -----------------------------------------------------------

    def _render_topology(self) -> None:
        group_by = self.group_by.currentText()
        hosts = self.discovery_state.hosts()
        subnet = self.subnet_filter.currentData()
        if subnet:
            from packetforge.engine.observability import _subnet_of

            hosts = [h for h in hosts if (h.subnet or _subnet_of(h.ip)) == subnet]
        graph = build_topology(hosts, group_by=group_by)
        self.topology_view.set_graph(graph)
        self.topology_view.reset_view()

    def _on_node_clicked(self, node: TopologyNode) -> None:
        insight = self.bundle.host_insights.get(node.ip or "")
        if insight is not None:
            self._select_host(node.ip or "")
            self.topology_detail.setText(
                f"Selected {node.label} ({node.ip}). Opened in Host detail tab."
            )
        else:
            self.topology_detail.setText(f"Selected {node.label} ({node.ip}).")

    def _on_edge_clicked(self, edge: TopologyEdge) -> None:
        evidence = "; ".join(edge.evidence) or "no additional evidence"
        self.topology_detail.setText(f"Edge [{edge.kind}] {edge.label}: {evidence}")

    # -- host detail --------------------------------------------------------

    def _render_host_list(self) -> None:
        current = self.host_combo.currentText()
        self.host_combo.blockSignals(True)
        self.host_combo.clear()
        for ip in sorted(self.bundle.host_insights):
            insight = self.bundle.host_insights[ip]
            label = f"{ip} ({insight.hostname})" if insight.hostname else ip
            self.host_combo.addItem(label, ip)
        index = self.host_combo.findData(current) if current else -1
        if index >= 0:
            self.host_combo.setCurrentIndex(index)
        self.host_combo.blockSignals(False)
        self._render_host_detail()

    def _select_host(self, ip: str) -> None:
        index = self.host_combo.findData(ip)
        if index >= 0:
            self.host_combo.setCurrentIndex(index)
            host_tab = self.tabs.indexOf(self.host_tab_widget)
            if host_tab >= 0:
                self.tabs.setCurrentIndex(host_tab)

    def _current_insight(self) -> HostInsight | None:
        ip = self.host_combo.currentData()
        return self.bundle.host_insights.get(ip) if ip else None

    def _render_host_detail(self) -> None:
        _clear_layout(self.host_spark_layout)
        insight = self._current_insight()
        if insight is None:
            self.host_text.setPlainText("No host selected.")
            return
        self.host_text.setPlainText(host_report_markdown(insight))
        spark_label = QLabel("Latency sparkline (recent RTT samples)")
        spark_label.setObjectName("Muted")
        self.host_spark_layout.addWidget(spark_label)
        self.host_spark_layout.addWidget(charts.sparkline(insight.sparkline))
        if insight.anomalies:
            self.host_spark_layout.addWidget(QLabel("Findings:"))
            for finding in insight.anomalies:
                self.host_spark_layout.addWidget(_anomaly_card(finding))
        self.host_spark_layout.addStretch(1)

    def _export_host(self, fmt: str) -> None:
        insight = self._current_insight()
        if insight is None:
            QMessageBox.information(self, "No host", "Select a host first.")
            return
        if fmt == "md":
            path, _ = QFileDialog.getSaveFileName(
                self, "Export host report", f"{insight.ip}.md", "Markdown (*.md)"
            )
            content = host_report_markdown(insight)
        else:
            path, _ = QFileDialog.getSaveFileName(
                self, "Export host report", f"{insight.ip}.json", "JSON (*.json)"
            )
            content = insight.model_dump_json(indent=2)
        if path:
            Path(path).write_text(content, encoding="utf-8")

    # -- run comparison -----------------------------------------------------

    def _available_runs(self) -> list[tuple[str, DiscoveryRun]]:
        runs: list[tuple[str, DiscoveryRun]] = []
        if self.discovery_state.last_run is not None:
            runs.append(("Current live run", self.discovery_state.last_run))
        runs.append(("Sample (current)", sample_run()))
        runs.append(("Sample (baseline)", sample_baseline_run()))
        for run in self.history.list_runs():
            runs.append((f"Saved: {run.label}", run))
        return runs

    def _render_run_selectors(self) -> None:
        runs = self._available_runs()
        self._runs = runs
        for combo in (self.baseline_combo, self.candidate_combo):
            current = combo.currentIndex()
            combo.blockSignals(True)
            combo.clear()
            for label, _run in runs:
                combo.addItem(label)
            combo.blockSignals(False)
            if 0 <= current < combo.count():
                combo.setCurrentIndex(current)
        if self.baseline_combo.count() >= 2 and self.baseline_combo.currentIndex() == 0:
            # Default to comparing baseline-sample against current-sample for a useful demo.
            for index, (label, _run) in enumerate(runs):
                if label == "Sample (baseline)":
                    self.baseline_combo.setCurrentIndex(index)
                if label == "Sample (current)":
                    self.candidate_combo.setCurrentIndex(index)

    def _render_compare(self) -> None:
        runs = getattr(self, "_runs", [])
        if not runs:
            return
        baseline = runs[self.baseline_combo.currentIndex()][1]
        candidate = runs[self.candidate_combo.currentIndex()][1]
        comparison = compare_runs(baseline, candidate)
        self._last_comparison = comparison
        self.compare_text.setPlainText(_comparison_report(comparison))

    def _export_compare(self) -> None:
        if self._last_comparison is None:
            QMessageBox.information(self, "No comparison", "Run a comparison first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export comparison", "run-comparison.md", "Markdown (*.md);;JSON (*.json)"
        )
        if not path:
            return
        if path.endswith(".json"):
            content = self._last_comparison.model_dump_json(indent=2)
        else:
            content = _comparison_report(self._last_comparison)
        Path(path).write_text(content, encoding="utf-8")

    # -- anomalies ----------------------------------------------------------

    def _render_anomalies(self) -> None:
        _clear_layout(self.anomaly_layout)
        min_rank = {"info": 2, "warning": 1, "critical": 0}[self.severity_filter.currentText()]
        shown = [a for a in self.bundle.anomalies if a.rank <= min_rank]
        if not shown:
            empty = QLabel("No findings at this severity. Nothing notable detected.")
            empty.setObjectName("Muted")
            self.anomaly_layout.addWidget(empty)
        for finding in shown:
            self.anomaly_layout.addWidget(_anomaly_card(finding))
        self.anomaly_layout.addStretch(1)

    # -- exports ------------------------------------------------------------

    def _export_png(self) -> None:
        widget = self.tabs.currentWidget()
        path, _ = QFileDialog.getSaveFileName(
            self, "Export view as PNG", "observability.png", "PNG (*.png)"
        )
        if path:
            widget.grab().save(path)

    def _export_json(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export observability data", "observability.json", "JSON (*.json)"
        )
        if path:
            Path(path).write_text(self.bundle.model_dump_json(indent=2), encoding="utf-8")

    def _export_topology_image(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export topology image", "topology.png", "PNG (*.png)"
        )
        if path and not self.topology_view.export_image(path):
            QMessageBox.information(self, "Empty map", "Discover or load hosts first.")


def _fmt(value: float | None) -> str:
    return f"{value:.2f}" if value is not None else "-"


def _anomaly_card(finding: AnomalyFinding) -> QWidget:
    frame = QFrame()
    frame.setFrameShape(QFrame.Shape.StyledPanel)
    color = _SEVERITY_COLOR.get(finding.severity, "#3da5ff")
    frame.setStyleSheet(
        f"QFrame {{ border-left: 4px solid {color}; border-radius: 4px; "
        "background: #1b2129; padding: 6px; }"
    )
    layout = QVBoxLayout(frame)
    header = QLabel(f"[{finding.severity.upper()}] {finding.title}")
    header.setStyleSheet(f"color: {color}; font-weight: 600;")
    header.setWordWrap(True)
    layout.addWidget(header)
    detail = QLabel(finding.detail)
    detail.setObjectName("Muted")
    detail.setWordWrap(True)
    layout.addWidget(detail)
    if finding.evidence:
        evidence = QLabel("Evidence: " + "; ".join(finding.evidence))
        evidence.setObjectName("Muted")
        evidence.setWordWrap(True)
        layout.addWidget(evidence)
    confidence = QLabel(f"confidence ~{finding.confidence * 100:.0f}%")
    confidence.setObjectName("Muted")
    layout.addWidget(confidence)
    return frame


def _comparison_report(comparison: RunComparison) -> str:
    lines = [
        "# Run comparison",
        f"Baseline: {comparison.baseline_label}",
        f"Candidate: {comparison.candidate_label}",
        "",
        f"Summary: {comparison.summary}",
        "",
        "## Added hosts",
    ]
    if comparison.added_hosts:
        lines += [f"- {ip}" for ip in comparison.added_hosts]
    else:
        lines.append("- none")
    lines += ["", "## Removed hosts"]
    if comparison.removed_hosts:
        lines += [f"- {ip}" for ip in comparison.removed_hosts]
    else:
        lines.append("- none")
    lines += ["", "## Port changes"]
    if comparison.port_changes:
        for pc in comparison.port_changes:
            lines.append(f"- {pc.host}: opened {pc.opened or '-'}, closed {pc.closed or '-'}")
    else:
        lines.append("- none")
    lines += ["", "## Capability changes"]
    if comparison.capability_changes:
        for host, changes in comparison.capability_changes.items():
            lines.append(f"- {host}: {', '.join(changes)}")
    else:
        lines.append("- none")
    lines += ["", "## Latency deltas"]
    if comparison.latency_deltas:
        for delta in comparison.latency_deltas:
            lines.append(
                f"- {delta.host}: {delta.before_ms} -> {delta.after_ms} ms "
                f"(delta {delta.delta_ms})"
            )
    else:
        lines.append("- none")
    lines += ["", "## Fingerprint confidence changes"]
    if comparison.confidence_changes:
        for cc in comparison.confidence_changes:
            lines.append(
                f"- {cc.host}: {cc.before:.2f} -> {cc.after:.2f} (delta {cc.delta:+.2f})"
            )
    else:
        lines.append("- none")
    return "\n".join(lines)
