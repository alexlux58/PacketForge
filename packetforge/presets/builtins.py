from __future__ import annotations

from packetforge.models.packet import (
    ICMPLayer,
    IPv4Layer,
    LayerConfig,
    PacketConfig,
    RawLayer,
    TCPLayer,
    UDPLayer,
)
from packetforge.models.preset import Preset, PresetCategory


def builtin_presets() -> list[Preset]:
    return [
        _preset(
            "icmp-standard-ipv4-ping",
            "Standard IPv4 ping",
            "ICMP",
            "A normal IPv4 ICMP echo request with a short text payload.",
            "Baseline reachability and latency checks.",
            [IPv4Layer(dst="192.168.1.1"), ICMPLayer(), RawLayer(text="PacketForge")],
        ),
        _preset(
            "icmp-small-payload",
            "Small-payload ping",
            "ICMP",
            "ICMP echo with a one-byte payload.",
            "Confirm connectivity with minimal packet size.",
            [IPv4Layer(dst="192.168.1.1"), ICMPLayer(), RawLayer(text="x")],
        ),
        _preset(
            "icmp-large-payload",
            "Large-payload ping",
            "ICMP",
            "ICMP echo with a 1400-byte repeated payload.",
            "Exercise MTU and path behavior without fragmentation on common Ethernet links.",
            [
                IPv4Layer(dst="192.168.1.1"),
                ICMPLayer(),
                RawLayer(mode="repeated", byte_value=65, length=1400),
            ],
        ),
        _preset(
            "icmp-df",
            "Do-not-fragment ping",
            "ICMP",
            "IPv4 ICMP echo request with the DF bit set.",
            "Validate path MTU and firewall handling for non-fragmentable packets.",
            [IPv4Layer(dst="192.168.1.1", flags=["DF"]), ICMPLayer(), RawLayer(text="DF test")],
        ),
        _preset(
            "icmp-mtu-discovery",
            "MTU discovery test",
            "Diagnostic",
            "Large ICMP echo with DF set and a 1472-byte payload.",
            "Probe whether a path supports a 1500-byte IPv4 packet.",
            [
                IPv4Layer(dst="192.168.1.1", flags=["DF"]),
                ICMPLayer(),
                RawLayer(mode="repeated", byte_value=77, length=1472),
            ],
        ),
        _preset(
            "icmp-custom-ttl",
            "Custom TTL ping",
            "ICMP",
            "ICMP echo request with a low TTL.",
            "Investigate hop limits and traceroute-style behavior.",
            [IPv4Layer(dst="8.8.8.8", ttl=4), ICMPLayer(), RawLayer(text="ttl")],
        ),
        _preset(
            "icmp-custom-dscp",
            "Custom DSCP ping",
            "ICMP",
            "ICMP echo request marked with DSCP 46.",
            "Validate QoS marking and policy treatment.",
            [IPv4Layer(dst="192.168.1.1", dscp=46), ICMPLayer(), RawLayer(text="qos")],
        ),
        _preset(
            "tcp-syn-probe",
            "TCP SYN probe",
            "TCP",
            "IPv4 TCP SYN packet to port 443.",
            "Check whether a TCP service appears reachable without completing a connection.",
            [IPv4Layer(dst="192.168.1.1"), TCPLayer(dport=443, flags=["S"])],
        ),
        _preset(
            "tcp-ack-probe",
            "TCP ACK probe",
            "TCP",
            "IPv4 TCP ACK packet to port 443.",
            "Firewall policy validation for established-flow handling.",
            [IPv4Layer(dst="192.168.1.1"), TCPLayer(dport=443, flags=["A"])],
        ),
        _preset(
            "tcp-rst",
            "TCP RST packet",
            "TCP",
            "IPv4 TCP reset packet.",
            "Test reset handling in a controlled lab.",
            [IPv4Layer(dst="192.168.1.1"), TCPLayer(dport=80, flags=["R"])],
        ),
        _preset(
            "udp-port-probe",
            "UDP port probe",
            "UDP",
            "IPv4 UDP packet to port 53.",
            "Validate UDP reachability or ICMP unreachable behavior.",
            [IPv4Layer(dst="192.168.1.1"), UDPLayer(dport=53), RawLayer(text="PacketForge")],
        ),
        _preset(
            "udp-custom-payload",
            "Custom UDP payload",
            "UDP",
            "IPv4 UDP packet with editable UTF-8 payload.",
            "Send application-like bytes to a UDP listener in a lab.",
            [IPv4Layer(dst="192.168.1.1"), UDPLayer(dport=9999), RawLayer(text="hello")],
        ),
        _preset(
            "raw-ip-payload",
            "Custom raw payload",
            "Raw",
            "IPv4 packet carrying raw bytes directly after the IP header.",
            "Experiment with protocol numbers and payload bytes in controlled environments.",
            [IPv4Layer(dst="192.168.1.1"), RawLayer(mode="hex", hex_data="de ad be ef")],
        ),
    ]


def _preset(
    preset_id: str,
    name: str,
    category: PresetCategory,
    description: str,
    use_case: str,
    layers: list[LayerConfig],
) -> Preset:
    return Preset(
        id=preset_id,
        name=name,
        category=category,
        description=description,
        use_case=use_case,
        packet=PacketConfig(name=name, description=description, layers=layers),
        builtin=True,
    )
