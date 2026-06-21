from __future__ import annotations

import pytest

pytest.importorskip("scapy")

from packetforge.security.safe_scapy import (
    SafeScapyError,
    parse_scapy_expression,
    validate_scapy_expression,
)


@pytest.mark.parametrize(
    "expression",
    [
        'IP(dst="192.0.2.1")',
        'IP(dst="192.0.2.1") / TCP(dport=80, flags="S")',
        'Ether() / IP() / UDP() / DNS(qd=DNSQR(qname="example.com"))',
        'IP(dst="192.0.2.1", ttl=-1)',  # negative numbers allowed
        'IP(options=[("k", 1)])',  # lists/tuples allowed
        'ARP(pdst="192.0.2.0/24")',
    ],
)
def test_allowed_expressions_build(expression: str) -> None:
    packet = parse_scapy_expression(expression)
    assert packet.summary()
    assert validate_scapy_expression(expression).ok


@pytest.mark.parametrize(
    "expression",
    [
        '__import__("os").system("id")',  # unapproved call / name
        "IP().__class__",  # attribute access
        "open('x')",  # unapproved class
        "eval('1')",  # unapproved class
        "IP() + ICMP()",  # only '/' allowed
        "IP() - ICMP()",  # only '/' allowed
        "5",  # not a packet
        '"hello"',  # not a packet
        "IP() / 5",  # '/' on non-packet
        "lambda: IP()",  # lambda rejected
        "packets[0]",  # subscript rejected
        "IP(dst=DST)",  # bare name as value rejected
        "IP(",  # syntax error
    ],
)
def test_rejected_expressions_raise(expression: str) -> None:
    with pytest.raises(SafeScapyError):
        parse_scapy_expression(expression)
    result = validate_scapy_expression(expression)
    assert not result.ok
    assert result.message


def test_star_args_and_kwargs_are_rejected() -> None:
    with pytest.raises(SafeScapyError):
        parse_scapy_expression("IP(**{'dst': '10.0.0.1'})")


def test_method_call_on_packet_is_rejected() -> None:
    with pytest.raises(SafeScapyError):
        parse_scapy_expression('IP().build()')


def test_validate_returns_friendly_message_for_valid() -> None:
    result = validate_scapy_expression('IP(dst="192.0.2.1") / ICMP()')
    assert result.ok
    assert "valid" in result.message.lower()
