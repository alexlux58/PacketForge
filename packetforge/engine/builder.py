from __future__ import annotations

import secrets
from collections.abc import Iterable
from typing import Any, cast

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.packet import Packet, Raw
from scapy.utils import hexdump

from packetforge.models.packet import (
    ICMPLayer,
    IPv4Layer,
    LayerConfig,
    PacketConfig,
    RawLayer,
    TCPLayer,
    UDPLayer,
)


class PacketBuildError(ValueError):
    """Raised when a PacketConfig cannot be converted into a Scapy packet."""


def build_packet(config: PacketConfig) -> Packet:
    packet: Packet | None = None
    for layer in config.layers:
        scapy_layer = build_layer(layer)
        packet = scapy_layer if packet is None else packet / scapy_layer
    if packet is None:
        raise PacketBuildError("packet must contain at least one layer")
    return packet


def build_packets(configs: Iterable[PacketConfig]) -> list[Packet]:
    return [build_packet(config) for config in configs]


def build_layer(layer: LayerConfig) -> Packet:
    if isinstance(layer, IPv4Layer):
        kwargs: dict[str, Any] = {
            "dst": layer.dst,
            "ttl": layer.ttl,
            "tos": layer.tos,
            "frag": layer.fragment_offset,
        }
        if layer.src:
            kwargs["src"] = layer.src
        if layer.identification is not None:
            kwargs["id"] = layer.identification
        if layer.flags:
            kwargs["flags"] = "+".join(layer.flags)
        if layer.options:
            kwargs["options"] = layer.options
        return cast(Packet, IP(**kwargs))
    if isinstance(layer, ICMPLayer):
        kwargs = {"type": layer.icmp_type, "code": layer.code, "seq": layer.sequence}
        if layer.identifier is not None:
            kwargs["id"] = layer.identifier
        return cast(Packet, ICMP(**kwargs))
    if isinstance(layer, TCPLayer):
        return cast(
            Packet,
            TCP(
                sport=layer.sport,
                dport=layer.dport,
                seq=layer.seq,
                ack=layer.ack,
                flags=layer.scapy_flags,
                window=layer.window,
            ),
        )
    if isinstance(layer, UDPLayer):
        return cast(Packet, UDP(sport=layer.sport, dport=layer.dport))
    if isinstance(layer, RawLayer):
        return cast(Packet, Raw(load=payload_bytes(layer)))
    raise PacketBuildError(f"unsupported layer type: {type(layer).__name__}")


def payload_bytes(layer: RawLayer) -> bytes:
    if layer.mode == "text":
        return layer.text.encode()
    if layer.mode == "hex":
        return bytes.fromhex(layer.hex_data)
    if layer.mode == "repeated":
        return bytes([layer.byte_value]) * layer.length
    if layer.mode == "random":
        return secrets.token_bytes(layer.length)
    raise PacketBuildError(f"unsupported raw payload mode: {layer.mode}")


def generate_scapy_code(config: PacketConfig) -> str:
    if not config.layers:
        return "# Add a layer to generate Scapy code."
    expressions = [_layer_expression(layer) for layer in config.layers]
    if len(expressions) == 1:
        return expressions[0]
    return " / \\\n    ".join(expressions)


def packet_hexdump(packet: Packet) -> str:
    return str(hexdump(packet, dump=True))


def packet_summary(packet: Packet) -> str:
    return str(packet.summary())


def packet_details(packet: Packet) -> str:
    try:
        return str(packet.show2(dump=True) or "")
    except Exception:
        return str(packet.show(dump=True) or "")


def _layer_expression(layer: LayerConfig) -> str:
    if isinstance(layer, IPv4Layer):
        kwargs: list[tuple[str, Any]] = [("dst", layer.dst), ("ttl", layer.ttl), ("tos", layer.tos)]
        if layer.src:
            kwargs.insert(0, ("src", layer.src))
        if layer.identification is not None:
            kwargs.append(("id", layer.identification))
        if layer.flags:
            kwargs.append(("flags", "+".join(layer.flags)))
        if layer.fragment_offset:
            kwargs.append(("frag", layer.fragment_offset))
        if layer.options:
            kwargs.append(("options", layer.options))
        return f"IP({_format_kwargs(kwargs)})"
    if isinstance(layer, ICMPLayer):
        kwargs = [("type", layer.icmp_type), ("code", layer.code), ("seq", layer.sequence)]
        if layer.identifier is not None:
            kwargs.append(("id", layer.identifier))
        return f"ICMP({_format_kwargs(kwargs)})"
    if isinstance(layer, TCPLayer):
        kwargs = [
            ("sport", layer.sport),
            ("dport", layer.dport),
            ("seq", layer.seq),
            ("ack", layer.ack),
            ("flags", layer.scapy_flags),
            ("window", layer.window),
        ]
        return f"TCP({_format_kwargs(kwargs)})"
    if isinstance(layer, UDPLayer):
        return f"UDP({_format_kwargs([('sport', layer.sport), ('dport', layer.dport)])})"
    if isinstance(layer, RawLayer):
        return f"Raw(load={payload_bytes(layer)!r})"
    raise PacketBuildError(f"unsupported layer type: {type(layer).__name__}")


def _format_kwargs(items: list[tuple[str, Any]]) -> str:
    return ", ".join(f"{key}={value!r}" for key, value in items)
