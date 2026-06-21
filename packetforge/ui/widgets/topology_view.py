from __future__ import annotations

from PySide6.QtCore import QRectF, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QImage, QMouseEvent, QPainter, QPen, QWheelEvent
from PySide6.QtWidgets import (
    QGraphicsItem,
    QGraphicsLineItem,
    QGraphicsRectItem,
    QGraphicsScene,
    QGraphicsView,
)

from packetforge.models.observability import TopologyEdge, TopologyGraph, TopologyNode

_GROUP_COLOR = QColor("#285d8f")
_HOST_COLOR = QColor("#27313d")
_GATEWAY_COLOR = QColor("#8f6b28")
_EDGE_COLOR = QColor("#3b4654")
_ARP_COLOR = QColor("#36c275")
_PASSIVE_COLOR = QColor("#b48cff")
_TEXT_COLOR = QColor("#e7edf3")
_SUB_COLOR = QColor("#aeb8c3")

_EDGE_COLORS = {
    "arp": _ARP_COLOR,
    "passive": _PASSIVE_COLOR,
    "protocol": QColor("#f5a623"),
    "ttl": QColor("#22b8cf"),
}


class TopologyView(QGraphicsView):
    """Interactive topology graph with zoom, pan, and click-to-inspect.

    Emits ``node_clicked`` / ``edge_clicked`` so containers can show a host
    detail drawer or edge evidence without knowing about the rendering details.
    """

    node_clicked = Signal(object)
    edge_clicked = Signal(object)

    def __init__(self) -> None:
        self._scene = QGraphicsScene()
        super().__init__(self._scene)
        self.setRenderHint(QPainter.RenderHint.Antialiasing)
        self.setDragMode(QGraphicsView.DragMode.ScrollHandDrag)
        self.setTransformationAnchor(QGraphicsView.ViewportAnchor.AnchorUnderMouse)
        self._payloads: dict[int, TopologyNode | TopologyEdge] = {}
        self.graph = TopologyGraph()

    # -- rendering ----------------------------------------------------------

    def set_graph(self, graph: TopologyGraph) -> None:
        self.graph = graph
        self._draw()

    def _draw(self) -> None:
        self._scene.clear()
        self._payloads.clear()
        positions: dict[str, tuple[float, float]] = {}
        group_x = 20.0
        host_x = 340.0
        row_height = 60.0
        row = 0

        for group in self.graph.groups:
            members = [n for n in self.graph.nodes if n.kind == "host" or n.kind == "gateway"]
            members = [n for n in members if n.group == group]
            group_node = next(
                (n for n in self.graph.nodes if n.id == f"group:{group}"), None
            )
            block_top = row * row_height
            mid = block_top + max(0, (len(members) - 1)) * row_height / 2
            if group_node is not None:
                positions[group_node.id] = (group_x, mid)
                self._add_node(group_node, group_x, mid, _GROUP_COLOR, width=230)
            for member in sorted(members, key=lambda n: n.ip or n.label):
                y = row * row_height
                color = _GATEWAY_COLOR if member.is_gateway else _HOST_COLOR
                positions[member.id] = (host_x, y)
                self._add_node(member, host_x, y, color, width=280)
                row += 1
            if not members:
                row += 1

        for edge in self.graph.edges:
            if edge.source in positions and edge.target in positions:
                self._add_edge(edge, positions)

        rect = self._scene.itemsBoundingRect()
        self._scene.setSceneRect(rect.adjusted(-40, -40, 40, 40))

    def _add_node(
        self, node: TopologyNode, x: float, y: float, color: QColor, *, width: float
    ) -> None:
        rect_item = QGraphicsRectItem(QRectF(x, y, width, 30))
        rect_item.setPen(QPen(color.lighter(150)))
        rect_item.setBrush(QBrush(color))
        rect_item.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        rect_item.setZValue(2)
        if node.kind in {"host", "gateway"}:
            rect_item.setToolTip(_node_tooltip(node))
        self._scene.addItem(rect_item)
        self._payloads[id(rect_item)] = node

        suffix = "  [gw]" if node.is_gateway else ""
        text = self._scene.addText(f"{node.label}{suffix}")
        text.setDefaultTextColor(_TEXT_COLOR)
        text.setPos(x + 6, y + 5)
        text.setZValue(3)

        sub_parts: list[str] = []
        if node.badges:
            sub_parts.append(" ".join(node.badges[:5]))
        if node.open_ports:
            sub_parts.append("ports " + ",".join(str(p) for p in node.open_ports[:8]))
        if sub_parts:
            sub = self._scene.addText("  ".join(sub_parts))
            sub.setDefaultTextColor(_SUB_COLOR)
            sub.setPos(x + 6, y + 30)
            sub.setScale(0.8)
            sub.setZValue(3)

    def _add_edge(
        self, edge: TopologyEdge, positions: dict[str, tuple[float, float]]
    ) -> None:
        sx, sy = positions[edge.source]
        tx, ty = positions[edge.target]
        color = _EDGE_COLORS.get(edge.kind, _EDGE_COLOR)
        pen = QPen(color)
        pen.setWidth(2 if edge.kind == "arp" else 1)
        if edge.kind == "passive":
            pen.setStyle(Qt.PenStyle.DashLine)
        line = QGraphicsLineItem(sx + 230, sy + 15, tx, ty + 15)
        line.setPen(pen)
        line.setZValue(1)
        line.setToolTip(_edge_tooltip(edge))
        self._scene.addItem(line)
        self._payloads[id(line)] = edge
        if edge.label:
            label = self._scene.addText(edge.label)
            label.setDefaultTextColor(color)
            label.setScale(0.7)
            label.setPos((sx + 230 + tx) / 2 - 10, (sy + ty) / 2 + 2)
            label.setZValue(1)

    # -- interaction --------------------------------------------------------

    def wheelEvent(self, event: QWheelEvent) -> None:
        factor = 1.15 if event.angleDelta().y() > 0 else 1 / 1.15
        self.scale(factor, factor)

    def mousePressEvent(self, event: QMouseEvent) -> None:
        item = self.itemAt(event.position().toPoint())
        payload = self._payloads.get(id(item)) if item is not None else None
        if isinstance(payload, TopologyNode) and payload.kind in {"host", "gateway"}:
            self.node_clicked.emit(payload)
        elif isinstance(payload, TopologyEdge):
            self.edge_clicked.emit(payload)
        super().mousePressEvent(event)

    def reset_view(self) -> None:
        self.resetTransform()
        if self.graph.nodes:
            self.fitInView(self._scene.itemsBoundingRect(), Qt.AspectRatioMode.KeepAspectRatio)

    def export_image(self, path: str) -> bool:
        if not self.graph.nodes:
            return False
        rect = self._scene.sceneRect()
        image = QImage(
            int(rect.width()) or 800, int(rect.height()) or 600, QImage.Format.Format_ARGB32
        )
        image.fill(QColor("#111418"))
        painter = QPainter(image)
        self._scene.render(painter)
        painter.end()
        return bool(image.save(path))


def _node_tooltip(node: TopologyNode) -> str:
    lines = [f"<b>{node.label}</b>", f"IP: {node.ip or 'n/a'}"]
    if node.subnet:
        lines.append(f"Subnet: {node.subnet}")
    if node.is_gateway:
        lines.append("Possible gateway/router")
    if node.badges:
        lines.append("Services: " + ", ".join(node.badges))
    if node.open_ports:
        lines.append("Open ports: " + ", ".join(str(p) for p in node.open_ports))
    lines.append("Click to open host detail")
    return "<br>".join(lines)


def _edge_tooltip(edge: TopologyEdge) -> str:
    lines = [f"<b>{edge.label or edge.kind}</b>"]
    lines.extend(edge.evidence or ["no additional evidence"])
    lines.append("Click for supporting evidence")
    return "<br>".join(lines)
