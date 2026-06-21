from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from packetforge.engine.observability import build_topology, detect_anomalies
from packetforge.models.observability import (
    AnomalyFinding,
    TopologyEdge,
    TopologyGraph,
    TopologyNode,
)
from packetforge.ui.state import DiscoveryState
from packetforge.ui.widgets.host_detail import HostDetailPanel
from packetforge.ui.widgets.page_header import PageHeader
from packetforge.ui.widgets.persistent_splitter import PersistentSplitter
from packetforge.ui.widgets.topology_view import TopologyView


class NetworkMapTab(QWidget):
    status_message = Signal(str)

    def __init__(self, state: DiscoveryState) -> None:
        super().__init__()
        self.state = state
        self.graph = TopologyGraph()
        self._anomalies: list[AnomalyFinding] = []

        root = QVBoxLayout(self)
        root.addWidget(
            PageHeader(
                "Network Map",
                "network_map",
                subtitle=(
                    "Interactive topology from discovered hosts. Scroll to zoom, drag to pan. "
                    "Click i for help with grouping, edges, and clearing the map."
                ),
            )
        )

        controls = QHBoxLayout()
        root.addLayout(controls)
        controls.addWidget(QLabel("Group by:"))
        self.group_by = QComboBox()
        self.group_by.addItems(["subnet", "protocol"])
        self.group_by.currentIndexChanged.connect(self.rebuild)
        controls.addWidget(self.group_by)
        self.refresh_button = QPushButton("Rebuild map")
        self.reset_button = QPushButton("Reset view")
        self.reset_button.setToolTip("Reset zoom and pan on the current map.")
        self.clear_button = QPushButton("Clear map")
        self.clear_button.setToolTip(
            "Remove all discovered hosts from the map and shared discovery state."
        )
        self.export_json_button = QPushButton("Export JSON")
        self.export_image_button = QPushButton("Export image")
        controls.addWidget(self.refresh_button)
        controls.addWidget(self.reset_button)
        controls.addWidget(self.clear_button)
        controls.addWidget(self.export_json_button)
        controls.addWidget(self.export_image_button)
        controls.addStretch(1)
        self.summary = QLabel("No hosts yet.")
        self.summary.setObjectName("Muted")
        controls.addWidget(self.summary)

        self.splitter = PersistentSplitter(
            Qt.Orientation.Horizontal,
            "splitter/network_map",
            default_sizes=[900, 380],
        )
        self.view = TopologyView()
        self.splitter.addWidget(self.view)
        self.host_detail = HostDetailPanel()
        self.splitter.addWidget(self.host_detail)
        root.addWidget(self.splitter, 1)
        self.splitter.restore()

        self.edge_detail = QLabel("")
        self.edge_detail.setObjectName("Muted")
        self.edge_detail.setWordWrap(True)
        root.addWidget(self.edge_detail)

        self.refresh_button.clicked.connect(self.rebuild)
        self.reset_button.clicked.connect(self.view.reset_view)
        self.clear_button.clicked.connect(self.clear_map)
        self.export_json_button.clicked.connect(self.export_json)
        self.export_image_button.clicked.connect(self.export_image)
        self.view.node_clicked.connect(self._show_node)
        self.view.edge_clicked.connect(self._show_edge)
        self.state.hosts_changed.connect(self.rebuild)
        self.rebuild()

    def rebuild(self) -> None:
        hosts = self.state.hosts()
        scan_targets = self.state.last_run.targets if self.state.last_run else None
        self.graph = build_topology(
            hosts, group_by=self.group_by.currentText(), scan_targets=scan_targets
        )
        self._anomalies = detect_anomalies(hosts)
        self.view.set_graph(self.graph)
        self.view.reset_view()
        if hosts:
            self.summary.setText(
                f"{len(self.graph.groups)} group(s), {len(hosts)} host(s), "
                f"{len(self.graph.edges)} edge(s)"
            )
        else:
            self.summary.setText("No hosts yet — run Discovery or load Simulation data.")
            self.host_detail.clear()
            self.edge_detail.setText("")

    def clear_map(self) -> None:
        if not self.state.hosts():
            self.view.reset_view()
            self.host_detail.clear()
            self.edge_detail.setText("")
            self.status_message.emit("Network map is already empty.")
            return
        answer = QMessageBox.question(
            self,
            "Clear network map",
            "Remove all discovered hosts from the map?\n\n"
            "This also clears Discovery Center and Fingerprinting host lists.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        self.state.clear()
        self.status_message.emit("Network map cleared.")

    def _show_node(self, node: TopologyNode) -> None:
        host = self.state.get(node.ip or "")
        findings = [a for a in self._anomalies if a.host == (node.ip or "")]
        self.host_detail.show_host(host, anomalies=findings)
        self.edge_detail.setText("")
        if host is not None:
            self.status_message.emit(f"Map: inspecting {host.ip}")

    def _show_edge(self, edge: TopologyEdge) -> None:
        lines = [
            f"Edge: {edge.label or edge.kind}",
            f"Type: {edge.kind}",
            "Evidence:",
            *[f"- {item}" for item in (edge.evidence or ["no additional evidence"])],
        ]
        self.edge_detail.setText("\n".join(lines))
        self.status_message.emit(f"Map: edge {edge.kind}")

    def export_json(self) -> None:
        if not self.graph.nodes:
            QMessageBox.information(self, "Empty map", "Discover hosts first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export map JSON", "network-map.json", "JSON (*.json)"
        )
        if path:
            Path(path).write_text(self.graph.model_dump_json(indent=2), encoding="utf-8")
            self.status_message.emit(f"Exported map JSON to {path}")

    def export_image(self) -> None:
        if not self.graph.nodes:
            QMessageBox.information(self, "Empty map", "Discover hosts first.")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export map image", "network-map.png", "PNG (*.png)"
        )
        if path:
            self.view.export_image(path)
            self.status_message.emit(f"Exported map image to {path}")
