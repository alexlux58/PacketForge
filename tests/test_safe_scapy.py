import pytest

pytest.importorskip("scapy")

from packetforge.security.safe_scapy import SafeScapyError, parse_scapy_expression


def test_safe_scapy_builds_packet_expression() -> None:
    packet = parse_scapy_expression('IP(dst="192.0.2.1") / ICMP() / Raw(load=b"x")')

    assert packet.summary()


def test_safe_scapy_rejects_unapproved_calls() -> None:
    with pytest.raises(SafeScapyError):
        parse_scapy_expression('__import__("os").system("id")')


def test_safe_scapy_rejects_attribute_traversal() -> None:
    with pytest.raises(SafeScapyError):
        parse_scapy_expression("IP().__class__")
