import pytest

pytest.importorskip("pydantic")
pytest.importorskip("scapy")

from packetforge.engine.builder import build_packet, generate_scapy_code, packet_hexdump
from packetforge.models.packet import ICMPLayer, IPv4Layer, PacketConfig, RawLayer


def test_builder_creates_ipv4_icmp_raw_packet_and_code() -> None:
    config = PacketConfig(
        name="test",
        layers=[
            IPv4Layer(dst="203.0.113.1", ttl=7, dscp=46, flags=["DF"]),
            ICMPLayer(identifier=123, sequence=9),
            RawLayer(text="PacketForge"),
        ],
    )

    packet = build_packet(config)
    code = generate_scapy_code(config)

    assert packet.summary()
    assert "IP(" in code
    assert "tos=184" in code
    assert "flags='DF'" in code
    assert packet_hexdump(packet)
