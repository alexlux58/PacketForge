from packetforge.utils.packet_size import ipv4_icmp_size_breakdown


def test_ipv4_icmp_size_breakdown_distinguishes_payload_ip_and_ethernet() -> None:
    sizes = ipv4_icmp_size_breakdown(32)

    assert sizes.icmp_payload_size == 32
    assert sizes.ip_packet_size == 60
    assert sizes.ethernet_frame_size_without_fcs == 74
    assert sizes.ethernet_frame_size_with_fcs == 78
