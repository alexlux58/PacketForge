from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Literal

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)
from scapy.packet import Packet

from packetforge.engine.builder import (
    PacketBuildError,
    build_packet,
    generate_scapy_code,
    packet_details,
    packet_hexdump,
    packet_summary,
)
from packetforge.engine.sender import SendFunction, SendOptions
from packetforge.models.packet import (
    ICMPLayer,
    IPv4Layer,
    PacketConfig,
    RawLayer,
    TcpFlag,
    TCPLayer,
    UDPLayer,
    default_ping_packet,
)
from packetforge.models.preset import Preset, PresetCategory
from packetforge.presets.storage import PresetStore
from packetforge.security.safe_scapy import SafeScapyError, parse_scapy_expression
from packetforge.ui.widgets.form_helpers import add_form_row
from packetforge.ui.widgets.page_header import PageHeader
from packetforge.ui.widgets.persistent_splitter import PersistentSplitter
from packetforge.ui.widgets.transmission_form import TransmissionControls, build_transmission_group
from packetforge.ui.workers import SendWorker
from packetforge.utils.export import export_packets_to_pcap, load_packets_from_pcap

BuilderLayer = IPv4Layer | ICMPLayer | TCPLayer | UDPLayer | RawLayer
IPv4Flag = Literal["DF", "MF"]

_FIELD_TOOLTIPS: dict[str, str] = {
    "Source": "IPv4 source address. Leave default to let the OS choose.",
    "Destination": "IPv4 destination address for this packet.",
    "TTL": "Time-to-live (hop limit). Decrements at each router; at 0 the packet is dropped.",
    "DSCP": "Differentiated Services Code Point (6 bits). Marks traffic class for QoS.",
    "ECN": "Explicit Congestion Notification (0-3). 1/2 mark congestion without dropping.",
    "Identification": "IPv4 ID field. Auto assigns a value when set to auto.",
    "Flags": "DF (Don't Fragment) prevents downstream fragmentation.",
    "Fragment offset": "Offset of this fragment in the datagram (units of 8 bytes).",
    "Options": "Raw IPv4 options string passed to Scapy when supported.",
    "ICMP Type": "ICMP message type (8=echo request, 0=echo reply).",
    "ICMP Code": "ICMP sub-code; usually 0 for echo.",
    "ICMP Identifier": "Echo identifier used to match replies. Auto picks one if unset.",
    "ICMP Sequence": "Echo sequence number incremented per probe.",
    "TCP Source port": "Source TCP port (0 lets the OS assign ephemeral).",
    "TCP Destination port": "Destination TCP port on the target host.",
    "TCP Sequence": "Initial TCP sequence number for this segment.",
    "TCP Acknowledgment": "Acknowledgment number if ACK flag is set.",
    "TCP Flags": "Standard TCP control flags (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR).",
    "TCP Window": "Receive window size advertised in this segment.",
    "UDP Source port": "Source UDP port.",
    "UDP Destination port": "Destination UDP port.",
    "Raw mode": "Payload encoding: UTF-8 text, hex bytes, repeated byte, or random fill.",
    "Interface": "Outbound interface for L2 send or capture binding.",
    "Send mode": "Layer 3 (IP) send vs Layer 2 (Ethernet) sendp.",
    "Count": "Number of times to transmit the built packet.",
    "Interval (ms)": "Delay between repeated transmissions.",
    "Timeout (ms)": "Wait time when using send-and-wait (sr/sr1).",
    "Retry": "Retransmit count for send-and-wait operations.",
    "Verbose": "Ask Scapy to print send/receive details to the log.",
}


class PacketBuilderTab(QWidget):
    status_message = Signal(str)

    def __init__(self, preset_store: PresetStore) -> None:
        super().__init__()
        self.preset_store = preset_store
        self.presets = self.preset_store.all_presets()
        self.config = default_ping_packet()
        self.send_workers: list[SendWorker] = []
        self._setting_code = False
        self.tx: TransmissionControls

        root = QVBoxLayout(self)
        root.addWidget(
            PageHeader(
                "Packet Builder",
                "packet_builder",
                subtitle=(
                    "Visual layer editor with live Scapy code. "
                    "Click i for build and send workflow."
                ),
            )
        )

        splitter = PersistentSplitter(
            Qt.Orientation.Horizontal,
            "splitter/packet_builder",
            default_sizes=[260, 420, 520],
        )
        root.addWidget(splitter, 1)
        splitter.addWidget(self._scroll(self._left_panel()))
        splitter.addWidget(self._editor_panel())
        splitter.addWidget(self._preview_panel())
        splitter.restore()

        self._refresh_presets()
        self._rebuild_layer_forms()
        self._refresh_preview()

    def _scroll(self, widget: QWidget) -> QScrollArea:
        """Wrap a tall panel so its controls stay reachable on short windows."""
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.Shape.NoFrame)
        area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        area.setWidget(widget)
        return area

    def _left_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)

        preset_box = QGroupBox("Presets")
        preset_layout = QVBoxLayout(preset_box)
        self.preset_combo = QComboBox()
        self.preset_combo.currentIndexChanged.connect(self._preset_changed)
        preset_layout.addWidget(self.preset_combo)
        self.preset_description = QLabel()
        self.preset_description.setWordWrap(True)
        self.preset_description.setObjectName("Muted")
        preset_layout.addWidget(self.preset_description)

        preset_buttons = QHBoxLayout()
        duplicate = QPushButton("Duplicate")
        delete = QPushButton("Delete")
        export = QPushButton("Export")
        import_button = QPushButton("Import")
        duplicate.clicked.connect(self.duplicate_preset)
        delete.clicked.connect(self.delete_preset)
        export.clicked.connect(self.export_presets)
        import_button.clicked.connect(self.import_presets)
        for button in [duplicate, delete, export, import_button]:
            preset_buttons.addWidget(button)
        preset_layout.addLayout(preset_buttons)
        layout.addWidget(preset_box)

        add_box = QGroupBox("Add Layer")
        add_layout = QVBoxLayout(add_box)
        for name, callback in [
            ("IPv4", lambda: self.add_layer(IPv4Layer())),
            ("ICMP", lambda: self.add_layer(ICMPLayer())),
            ("TCP", lambda: self.add_layer(TCPLayer())),
            ("UDP", lambda: self.add_layer(UDPLayer())),
            ("Raw", lambda: self.add_layer(RawLayer())),
        ]:
            button = QPushButton(name)
            button.clicked.connect(callback)
            add_layout.addWidget(button)
        layout.addWidget(add_box)

        tx_box, self.tx = build_transmission_group(tooltips=_FIELD_TOOLTIPS)
        layout.addWidget(tx_box)
        layout.addStretch(1)
        return panel

    def _editor_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        self.error_label = QLabel()
        self.error_label.setObjectName("Error")
        self.error_label.setWordWrap(True)
        layout.addWidget(self.error_label)
        self.layer_area = QScrollArea()
        self.layer_area.setWidgetResizable(True)
        self.layer_container = QWidget()
        self.layer_layout = QVBoxLayout(self.layer_container)
        self.layer_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.layer_area.setWidget(self.layer_container)
        layout.addWidget(self.layer_area, 1)

        hint = QLabel(
            "Build previews the packet. Send transmits it using the Transmission "
            "settings on the left (interface, count, Layer 3/2). Send and Wait uses sr/sr1."
        )
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        layout.addWidget(hint)

        # Two rows: primary build/send actions on top, file/preset actions below,
        # so wide labels do not overflow a narrow panel and get clipped.
        primary = QHBoxLayout()
        for text, callback in [
            ("Build", self._refresh_preview),
            ("Send", self.send_once),
            ("Send and Wait", self.send_and_wait),
            ("Send Multiple", self.send_multiple),
        ]:
            button = QPushButton(text)
            button.clicked.connect(callback)
            primary.addWidget(button)
        layout.addLayout(primary)

        secondary = QHBoxLayout()
        for text, callback in [
            ("Save PCAP", self.save_pcap),
            ("Load PCAP", self.load_pcap),
            ("Save Preset", self.save_current_preset),
            ("Copy Scapy Code", self.copy_code),
            ("Clear", self.clear_builder),
        ]:
            button = QPushButton(text)
            button.clicked.connect(callback)
            secondary.addWidget(button)
        layout.addLayout(secondary)
        return panel

    def _preview_panel(self) -> QWidget:
        tabs = QTabWidget()

        self.layer_tree = QTreeWidget()
        self.layer_tree.setHeaderLabels(["Layer / Field", "Value"])
        tabs.addTab(self.layer_tree, "Layer Tree")

        code_panel = QWidget()
        code_layout = QVBoxLayout(code_panel)
        self.code_editor = QPlainTextEdit()
        self.code_editor.setFont(QFont("Menlo", 12))
        self.code_editor.setTabChangesFocus(False)
        code_layout.addWidget(self.code_editor, 1)
        apply_code = QPushButton("Apply Scapy Code")
        apply_code.clicked.connect(self.apply_code)
        code_layout.addWidget(apply_code, alignment=Qt.AlignmentFlag.AlignRight)
        tabs.addTab(code_panel, "Scapy Code")

        self.hex_dump = QPlainTextEdit()
        self.hex_dump.setReadOnly(True)
        self.hex_dump.setFont(QFont("Menlo", 12))
        tabs.addTab(self.hex_dump, "Hex Dump")

        self.summary = QPlainTextEdit()
        self.summary.setReadOnly(True)
        self.summary.setFont(QFont("Menlo", 12))
        tabs.addTab(self.summary, "Summary")
        return tabs

    def _spin(self, minimum: int, maximum: int, value: int) -> QSpinBox:
        spin = QSpinBox()
        spin.setRange(minimum, maximum)
        spin.setValue(value)
        return spin

    def _refresh_presets(self, select_id: str | None = None) -> None:
        self.presets = self.preset_store.all_presets()
        self.preset_combo.blockSignals(True)
        self.preset_combo.clear()
        for preset in self.presets:
            label = f"{preset.category}: {preset.name}"
            self.preset_combo.addItem(label, preset.id)
        if select_id is not None:
            index = self.preset_combo.findData(select_id)
            if index >= 0:
                self.preset_combo.setCurrentIndex(index)
        self.preset_combo.blockSignals(False)
        self._update_preset_description()

    def _preset_changed(self) -> None:
        preset_id = self.preset_combo.currentData()
        if preset_id:
            self.load_preset(str(preset_id))

    def load_preset(self, preset_id: str) -> None:
        preset = next((candidate for candidate in self.presets if candidate.id == preset_id), None)
        if preset is None:
            return
        self.config = preset.packet.model_copy(deep=True)
        index = self.preset_combo.findData(preset_id)
        if index >= 0 and self.preset_combo.currentIndex() != index:
            self.preset_combo.blockSignals(True)
            self.preset_combo.setCurrentIndex(index)
            self.preset_combo.blockSignals(False)
        self._update_preset_description()
        self._rebuild_layer_forms()
        self._refresh_preview()

    def _update_preset_description(self) -> None:
        preset_id = self.preset_combo.currentData()
        preset = next((candidate for candidate in self.presets if candidate.id == preset_id), None)
        self.preset_description.setText(
            "" if preset is None else f"{preset.description}\n\n{preset.use_case}"
        )

    def add_layer(self, layer: BuilderLayer) -> None:
        layers = list(self.config.layers)
        names = [existing.kind for existing in layers]
        if layer.kind == "IPv4" and "IPv4" in names:
            self._show_error("This first release supports one IPv4 layer per packet.")
            return
        if layer.kind in {"ICMP", "TCP", "UDP"} and any(
            name in names for name in {"ICMP", "TCP", "UDP"}
        ):
            self._show_error("Remove the current transport layer before adding another one.")
            return
        if layer.kind == "Raw" and "Raw" in names:
            self._show_error("This packet already has a Raw payload.")
            return
        if layer.kind == "IPv4":
            layers.insert(0, layer)
        elif layer.kind == "Raw":
            layers.append(layer)
        else:
            raw_index = names.index("Raw") if "Raw" in names else len(layers)
            layers.insert(raw_index, layer)
        self._set_layers(layers)

    def _set_layers(self, layers: list[BuilderLayer]) -> None:
        try:
            self.config = PacketConfig(
                name=self.config.name,
                description=self.config.description,
                layers=layers,
            )
        except Exception as exc:
            self._show_error(str(exc))
            return
        self.error_label.clear()
        self._rebuild_layer_forms()
        self._refresh_preview()

    def _rebuild_layer_forms(self) -> None:
        while self.layer_layout.count():
            item = self.layer_layout.takeAt(0)
            if item is None:
                continue
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        for index, layer in enumerate(self.config.layers):
            self.layer_layout.addWidget(self._layer_group(index, layer))
        self.layer_layout.addStretch(1)

    def _layer_group(
        self,
        index: int,
        layer: BuilderLayer,
    ) -> QGroupBox:
        group = QGroupBox(f"{index + 1}. {layer.kind}")
        outer = QVBoxLayout(group)
        buttons = QHBoxLayout()
        up = QPushButton("Up")
        down = QPushButton("Down")
        remove = QPushButton("Remove")
        up.clicked.connect(lambda: self.move_layer(index, -1))
        down.clicked.connect(lambda: self.move_layer(index, 1))
        remove.clicked.connect(lambda: self.remove_layer(index))
        buttons.addWidget(up)
        buttons.addWidget(down)
        buttons.addWidget(remove)
        outer.addLayout(buttons)

        form = QFormLayout()
        outer.addLayout(form)
        if isinstance(layer, IPv4Layer):
            self._ipv4_form(form, layer)
        elif isinstance(layer, ICMPLayer):
            self._icmp_form(form, layer)
        elif isinstance(layer, TCPLayer):
            self._tcp_form(form, layer)
        elif isinstance(layer, UDPLayer):
            self._udp_form(form, layer)
        elif isinstance(layer, RawLayer):
            self._raw_form(form, layer)
        return group

    def _ipv4_form(self, form: QFormLayout, layer: IPv4Layer) -> None:
        add_form_row(
            form,
            "Source",
            self._line(layer.src or "", lambda value: self._assign(layer, "src", value or None)),
            tooltip=_FIELD_TOOLTIPS["Source"],
        )
        add_form_row(
            form,
            "Destination",
            self._line(layer.dst, lambda value: self._assign(layer, "dst", value)),
            tooltip=_FIELD_TOOLTIPS["Destination"],
        )
        add_form_row(
            form,
            "TTL",
            self._spin_field(0, 255, layer.ttl, lambda value: self._assign(layer, "ttl", value)),
            tooltip=_FIELD_TOOLTIPS["TTL"],
        )
        add_form_row(
            form,
            "DSCP",
            self._spin_field(0, 63, layer.dscp, lambda value: self._assign(layer, "dscp", value)),
            tooltip=_FIELD_TOOLTIPS["DSCP"],
        )
        add_form_row(
            form,
            "ECN",
            self._spin_field(0, 3, layer.ecn, lambda value: self._assign(layer, "ecn", value)),
            tooltip=_FIELD_TOOLTIPS["ECN"],
        )
        add_form_row(
            form,
            "Identification",
            self._optional_spin(
                0,
                65535,
                layer.identification,
                lambda value: self._assign(layer, "identification", value),
            ),
            tooltip=_FIELD_TOOLTIPS["Identification"],
        )
        df = QCheckBox("DF")
        df.setChecked("DF" in layer.flags)
        df.stateChanged.connect(
            lambda state: self._set_ipv4_df(layer, state == Qt.CheckState.Checked.value)
        )
        add_form_row(form, "Flags", df, tooltip=_FIELD_TOOLTIPS["Flags"])
        add_form_row(
            form,
            "Fragment offset",
            self._spin_field(
                0,
                8191,
                layer.fragment_offset,
                lambda value: self._assign(layer, "fragment_offset", value),
            ),
            tooltip=_FIELD_TOOLTIPS["Fragment offset"],
        )
        add_form_row(
            form,
            "Options",
            self._line(layer.options, lambda value: self._assign(layer, "options", value)),
            tooltip=_FIELD_TOOLTIPS["Options"],
        )

    def _icmp_form(self, form: QFormLayout, layer: ICMPLayer) -> None:
        add_form_row(
            form,
            "Type",
            self._spin_field(
                0, 255, layer.icmp_type, lambda value: self._assign(layer, "icmp_type", value)
            ),
            tooltip=_FIELD_TOOLTIPS["ICMP Type"],
        )
        add_form_row(
            form,
            "Code",
            self._spin_field(0, 255, layer.code, lambda value: self._assign(layer, "code", value)),
            tooltip=_FIELD_TOOLTIPS["ICMP Code"],
        )
        add_form_row(
            form,
            "Identifier",
            self._optional_spin(
                0, 65535, layer.identifier, lambda value: self._assign(layer, "identifier", value)
            ),
            tooltip=_FIELD_TOOLTIPS["ICMP Identifier"],
        )
        add_form_row(
            form,
            "Sequence",
            self._spin_field(
                0, 65535, layer.sequence, lambda value: self._assign(layer, "sequence", value)
            ),
            tooltip=_FIELD_TOOLTIPS["ICMP Sequence"],
        )

    def _tcp_form(self, form: QFormLayout, layer: TCPLayer) -> None:
        add_form_row(
            form,
            "Source port",
            self._spin_field(
                0, 65535, layer.sport, lambda value: self._assign(layer, "sport", value)
            ),
            tooltip=_FIELD_TOOLTIPS["TCP Source port"],
        )
        add_form_row(
            form,
            "Destination port",
            self._spin_field(
                0, 65535, layer.dport, lambda value: self._assign(layer, "dport", value)
            ),
            tooltip=_FIELD_TOOLTIPS["TCP Destination port"],
        )
        add_form_row(
            form,
            "Sequence",
            self._spin_field(
                0, 2**31 - 1, layer.seq, lambda value: self._assign(layer, "seq", value)
            ),
            tooltip=_FIELD_TOOLTIPS["TCP Sequence"],
        )
        add_form_row(
            form,
            "Acknowledgment",
            self._spin_field(
                0, 2**31 - 1, layer.ack, lambda value: self._assign(layer, "ack", value)
            ),
            tooltip=_FIELD_TOOLTIPS["TCP Acknowledgment"],
        )
        flags = QWidget()
        flag_layout = QHBoxLayout(flags)
        flag_layout.setContentsMargins(0, 0, 0, 0)
        tcp_flags: tuple[TcpFlag, ...] = ("F", "S", "R", "P", "A", "U", "E", "C")
        for flag in tcp_flags:
            checkbox = QCheckBox(flag)
            checkbox.setChecked(flag in layer.flags)
            checkbox.stateChanged.connect(lambda _state, flag=flag: self._set_tcp_flag(layer, flag))
            flag_layout.addWidget(checkbox)
        add_form_row(form, "Flags", flags, tooltip=_FIELD_TOOLTIPS["TCP Flags"])
        add_form_row(
            form,
            "Window",
            self._spin_field(
                0, 65535, layer.window, lambda value: self._assign(layer, "window", value)
            ),
            tooltip=_FIELD_TOOLTIPS["TCP Window"],
        )

    def _udp_form(self, form: QFormLayout, layer: UDPLayer) -> None:
        add_form_row(
            form,
            "Source port",
            self._spin_field(
                0, 65535, layer.sport, lambda value: self._assign(layer, "sport", value)
            ),
            tooltip=_FIELD_TOOLTIPS["UDP Source port"],
        )
        add_form_row(
            form,
            "Destination port",
            self._spin_field(
                0, 65535, layer.dport, lambda value: self._assign(layer, "dport", value)
            ),
            tooltip=_FIELD_TOOLTIPS["UDP Destination port"],
        )

    def _raw_form(self, form: QFormLayout, layer: RawLayer) -> None:
        mode = QComboBox()
        mode.addItems(["text", "hex", "repeated", "random"])
        mode.setCurrentText(layer.mode)
        mode.currentTextChanged.connect(lambda value: self._assign(layer, "mode", value))
        add_form_row(form, "Mode", mode, tooltip=_FIELD_TOOLTIPS["Raw mode"])
        form.addRow(
            "UTF-8 text", self._line(layer.text, lambda value: self._assign(layer, "text", value))
        )
        form.addRow(
            "Hex", self._line(layer.hex_data, lambda value: self._assign(layer, "hex_data", value))
        )
        form.addRow(
            "Repeated byte",
            self._spin_field(
                0, 255, layer.byte_value, lambda value: self._assign(layer, "byte_value", value)
            ),
        )
        form.addRow(
            "Length",
            self._spin_field(
                0, 65535, layer.length, lambda value: self._assign(layer, "length", value)
            ),
        )

    def _line(self, value: str, callback: Callable[[str], None]) -> QLineEdit:
        line = QLineEdit(value)
        line.textChanged.connect(callback)
        return line

    def _spin_field(
        self, minimum: int, maximum: int, value: int, callback: Callable[[int], None]
    ) -> QSpinBox:
        spin = self._spin(minimum, maximum, value)
        spin.valueChanged.connect(callback)
        return spin

    def _optional_spin(
        self,
        minimum: int,
        maximum: int,
        value: int | None,
        callback: Callable[[int | None], None],
    ) -> QSpinBox:
        spin = self._spin(minimum - 1, maximum, minimum - 1 if value is None else value)
        spin.setSpecialValueText("auto")
        spin.valueChanged.connect(lambda number: callback(None if number < minimum else number))
        return spin

    def _assign(self, layer: object, field: str, value: object) -> None:
        try:
            setattr(layer, field, value)
            self.error_label.clear()
            self._refresh_preview()
        except Exception as exc:
            self._show_error(str(exc))

    def _set_ipv4_df(self, layer: IPv4Layer, enabled: bool) -> None:
        flags: list[IPv4Flag] = [flag for flag in layer.flags if flag != "DF"]
        if enabled:
            flags.append("DF")
        self._assign(layer, "flags", flags)

    def _set_tcp_flag(self, layer: TCPLayer, flag: TcpFlag) -> None:
        sender = self.sender()
        if not isinstance(sender, QCheckBox):
            return
        flags: list[TcpFlag]
        flags = [existing for existing in layer.flags if existing != flag]
        if sender.isChecked():
            flags.append(flag)
        self._assign(layer, "flags", flags)

    def move_layer(self, index: int, direction: int) -> None:
        target = index + direction
        if target < 0 or target >= len(self.config.layers):
            return
        layers = list(self.config.layers)
        layers[index], layers[target] = layers[target], layers[index]
        self._set_layers(layers)

    def remove_layer(self, index: int) -> None:
        layers = list(self.config.layers)
        del layers[index]
        self._set_layers(layers)

    def clear_builder(self) -> None:
        self.config = PacketConfig(name="Untitled packet", layers=[])
        self._rebuild_layer_forms()
        self._refresh_preview()

    def _refresh_preview(self) -> None:
        try:
            code = generate_scapy_code(self.config)
            self._setting_code = True
            self.code_editor.setPlainText(code)
            self._setting_code = False
            self._populate_layer_tree()
            packet = build_packet(self.config) if self.config.layers else None
            if packet is None:
                self.hex_dump.clear()
                self.summary.clear()
                return
            self.hex_dump.setPlainText(packet_hexdump(packet))
            self.summary.setPlainText(f"{packet_summary(packet)}\n\n{packet_details(packet)}")
            self.error_label.clear()
        except Exception as exc:
            self._show_error(str(exc))

    def _populate_layer_tree(self) -> None:
        self.layer_tree.clear()
        for layer in self.config.layers:
            root = QTreeWidgetItem([layer.kind, ""])
            data = layer.model_dump()
            for key, value in data.items():
                if key != "kind":
                    root.addChild(QTreeWidgetItem([key, str(value)]))
            self.layer_tree.addTopLevelItem(root)
            root.setExpanded(True)

    def apply_code(self) -> None:
        try:
            packet = parse_scapy_expression(self.code_editor.toPlainText())
        except SafeScapyError as exc:
            self._show_error(str(exc))
            return
        self.hex_dump.setPlainText(packet_hexdump(packet))
        self.summary.setPlainText(f"{packet_summary(packet)}\n\n{packet_details(packet)}")
        self.error_label.setText(
            "Scapy code validated. Builder fields remain the source of visual edits."
        )

    def _current_packet_from_code(self) -> Packet:
        try:
            return parse_scapy_expression(self.code_editor.toPlainText())
        except SafeScapyError as exc:
            raise PacketBuildError(str(exc)) from exc

    def save_pcap(self) -> None:
        try:
            packet = self._current_packet_from_code()
        except PacketBuildError as exc:
            self._show_error(str(exc))
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Save PCAP", "packetforge.pcap", "PCAP (*.pcap)"
        )
        if path:
            export_packets_to_pcap([packet], Path(path))
            self.status_message.emit(f"Saved PCAP to {path}")

    def load_pcap(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Load PCAP", "", "PCAP (*.pcap *.pcapng)")
        if not path:
            return
        packets = load_packets_from_pcap(Path(path))
        self.summary.setPlainText("\n".join(packet.summary() for packet in packets))
        self.status_message.emit(f"Loaded {len(packets)} packets from {path}")

    def save_current_preset(self) -> None:
        name, ok = QInputDialog.getText(self, "Save Preset", "Preset name:", text=self.config.name)
        if not ok or not name.strip():
            return
        description, ok = QInputDialog.getMultiLineText(
            self,
            "Save Preset",
            "Description:",
            self.config.description,
        )
        if not ok:
            return
        category = self._category_for_current_packet()
        preset = Preset(
            name=name.strip(),
            category=category,
            description=description.strip() or "Custom PacketForge preset.",
            use_case="Custom lab packet.",
            packet=PacketConfig(
                name=name.strip(),
                description=description.strip(),
                layers=list(self.config.layers),
            ),
            builtin=False,
        )
        self.preset_store.upsert(preset)
        self._refresh_presets(select_id=preset.id)
        self.status_message.emit(f"Saved preset '{preset.name}'")

    def duplicate_preset(self) -> None:
        preset = self._selected_preset()
        if preset is None:
            return
        clone = preset.duplicate()
        self.preset_store.upsert(clone)
        self._refresh_presets(select_id=clone.id)

    def delete_preset(self) -> None:
        preset = self._selected_preset()
        if preset is None or preset.builtin:
            QMessageBox.information(self, "Built-in preset", "Built-in presets cannot be deleted.")
            return
        if self.preset_store.delete(preset.id):
            self._refresh_presets()

    def export_presets(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Presets", "packetforge-presets.json", "JSON (*.json)"
        )
        if path:
            self.preset_store.export_json(self.preset_store.load_custom(), Path(path))

    def import_presets(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Import Presets", "", "JSON (*.json)")
        if path:
            imported = self.preset_store.import_json(Path(path))
            self._refresh_presets(select_id=imported[0].id if imported else None)

    def copy_code(self) -> None:
        QApplication.clipboard().setText(self.code_editor.toPlainText())
        self.status_message.emit("Copied Scapy code to clipboard")

    def send_once(self) -> None:
        self._start_send(self._send_options(wait=False, count=1))

    def send_and_wait(self) -> None:
        self._start_send(self._send_options(wait=True, count=1))

    def send_multiple(self) -> None:
        self._start_send(self._send_options(wait=False, count=self.tx.count.value()))

    def _send_options(self, *, wait: bool, count: int) -> SendOptions:
        layer2 = self.tx.send_mode.currentText() == "Layer 2"
        function: SendFunction = (
            "srp1" if wait and layer2 else "sr1" if wait else "sendp" if layer2 else "send"
        )
        return SendOptions(
            function=function,
            iface=self.tx.interface.currentText() or None,
            count=count,
            interval_s=self.tx.interval_ms.value() / 1000,
            timeout_s=self.tx.timeout_ms.value() / 1000,
            retry=self.tx.retry_count.value(),
            verbose=self.tx.verbose.isChecked(),
        )

    def _start_send(self, options: SendOptions) -> None:
        try:
            packet = self._current_packet_from_code()
        except PacketBuildError as exc:
            self._show_error(str(exc))
            return
        worker = SendWorker(packet, options)
        worker.completed.connect(
            lambda result: self.status_message.emit(f"Send completed: {result}")
        )
        worker.failed.connect(lambda message: self._show_error(f"Send failed: {message}"))
        worker.finished.connect(lambda: self._forget_worker(worker))
        self.send_workers.append(worker)
        worker.start()

    def _forget_worker(self, worker: SendWorker) -> None:
        if worker in self.send_workers:
            self.send_workers.remove(worker)

    def _selected_preset(self) -> Preset | None:
        preset_id = self.preset_combo.currentData()
        return next((preset for preset in self.presets if preset.id == preset_id), None)

    def _category_for_current_packet(self) -> PresetCategory:
        names = {layer.kind for layer in self.config.layers}
        if "ICMP" in names:
            return "ICMP"
        if "TCP" in names:
            return "TCP"
        if "UDP" in names:
            return "UDP"
        if "Raw" in names:
            return "Raw"
        return "Diagnostic"

    def _show_error(self, message: str) -> None:
        self.error_label.setText(message)
