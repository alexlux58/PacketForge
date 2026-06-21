from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PacketSizeBreakdown:
    icmp_payload_size: int
    ip_header_size: int
    icmp_header_size: int
    ip_packet_size: int
    ethernet_header_size: int
    ethernet_frame_size_without_fcs: int
    ethernet_frame_size_with_fcs: int


def ipv4_icmp_size_breakdown(payload_size: int) -> PacketSizeBreakdown:
    if payload_size < 0:
        raise ValueError("payload size cannot be negative")
    ip_header = 20
    icmp_header = 8
    ethernet_header = 14
    ip_packet_size = payload_size + ip_header + icmp_header
    ethernet_without_fcs = ip_packet_size + ethernet_header
    return PacketSizeBreakdown(
        icmp_payload_size=payload_size,
        ip_header_size=ip_header,
        icmp_header_size=icmp_header,
        ip_packet_size=ip_packet_size,
        ethernet_header_size=ethernet_header,
        ethernet_frame_size_without_fcs=ethernet_without_fcs,
        ethernet_frame_size_with_fcs=ethernet_without_fcs + 4,
    )
