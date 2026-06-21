from __future__ import annotations

import pytest

pytest.importorskip("pydantic")
pytest.importorskip("scapy")

from pydantic import ValidationError

from packetforge.engine.builder import (
    PacketBuildError,
    build_layer,
    build_packet,
    generate_scapy_code,
    packet_details,
    packet_summary,
    payload_bytes,
)
from packetforge.models.packet import (
    ICMPLayer,
    IPv4Layer,
    PacketConfig,
    RawLayer,
    TCPLayer,
    UDPLayer,
)


def test_build_packet_requires_at_least_one_layer() -> None:
    with pytest.raises(PacketBuildError):
        build_packet(PacketConfig(layers=[]))


def test_layer_validation_rejects_two_ipv4_layers() -> None:
    with pytest.raises(ValidationError):
        PacketConfig(layers=[IPv4Layer(), IPv4Layer()])


def test_layer_validation_rejects_two_transport_layers() -> None:
    with pytest.raises(ValidationError):
        PacketConfig(layers=[IPv4Layer(), TCPLayer(), UDPLayer()])


def test_layer_validation_rejects_transport_before_ip() -> None:
    with pytest.raises(ValidationError):
        PacketConfig(layers=[TCPLayer(), IPv4Layer()])


def test_layer_validation_requires_raw_to_be_last() -> None:
    with pytest.raises(ValidationError):
        PacketConfig(layers=[IPv4Layer(), RawLayer(), ICMPLayer()])


def test_layer_field_bounds_are_enforced() -> None:
    with pytest.raises(ValidationError):
        IPv4Layer(ttl=999)
    with pytest.raises(ValidationError):
        TCPLayer(dport=70000)
    with pytest.raises(ValidationError):
        ICMPLayer(code=-1)


def test_tcp_flags_are_deduplicated_in_order() -> None:
    layer = TCPLayer(flags=["S", "A", "S", "A"])
    assert layer.flags == ["S", "A"]
    assert layer.scapy_flags == "SA"


def test_hex_raw_layer_rejects_invalid_hex() -> None:
    with pytest.raises(ValidationError):
        RawLayer(mode="hex", hex_data="zz")


def test_hex_raw_layer_normalizes_whitespace() -> None:
    layer = RawLayer(mode="hex", hex_data="DE AD BE EF")
    assert layer.hex_data == "deadbeef"
    assert payload_bytes(layer) == b"\xde\xad\xbe\xef"


def test_payload_bytes_modes() -> None:
    assert payload_bytes(RawLayer(mode="text", text="hi")) == b"hi"
    assert payload_bytes(RawLayer(mode="repeated", byte_value=65, length=3)) == b"AAA"
    assert len(payload_bytes(RawLayer(mode="random", length=16))) == 16


def test_build_layer_for_each_supported_type() -> None:
    assert build_layer(IPv4Layer(dst="203.0.113.5")).summary()
    assert build_layer(ICMPLayer()).summary()
    assert build_layer(TCPLayer(dport=443, flags=["S"])).summary()
    assert build_layer(UDPLayer(dport=53)).summary()
    assert build_layer(RawLayer(text="abc")).summary()


def test_build_packet_stacks_layers_and_renders() -> None:
    config = PacketConfig(
        layers=[
            IPv4Layer(dst="198.51.100.7", ttl=42),
            UDPLayer(sport=5000, dport=53),
            RawLayer(text="ping"),
        ]
    )
    packet = build_packet(config)
    assert "IP" in packet_summary(packet)
    assert "UDP" in packet_summary(packet)
    assert packet_details(packet)


def test_generate_scapy_code_empty_config() -> None:
    assert "Add a layer" in generate_scapy_code(PacketConfig(layers=[]))


def test_generate_scapy_code_for_full_stack() -> None:
    config = PacketConfig(
        layers=[
            IPv4Layer(dst="203.0.113.1", ttl=7, dscp=46, flags=["DF"], identification=22),
            TCPLayer(sport=1234, dport=80, flags=["S", "A"]),
        ]
    )
    code = generate_scapy_code(config)
    assert "IP(" in code
    assert "tos=184" in code  # dscp 46 << 2
    assert "flags='DF'" in code
    assert "id=22" in code
    assert "TCP(" in code
    assert "flags='SA'" in code
    assert " / \\" in code  # multi-layer join


def test_generate_scapy_code_single_layer_has_no_join() -> None:
    code = generate_scapy_code(PacketConfig(layers=[IPv4Layer(dst="10.0.0.1")]))
    assert code.startswith("IP(")
    assert "/" not in code


def test_raw_payload_code_uses_repr_bytes() -> None:
    code = generate_scapy_code(PacketConfig(layers=[RawLayer(mode="text", text="PacketForge")]))
    assert "Raw(load=b'PacketForge')" in code
