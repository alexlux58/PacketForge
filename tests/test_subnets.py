import pytest

pytest.importorskip("pydantic")

from packetforge.engine.subnets import (
    containing_network,
    parse_scan_networks,
    subnet_for_ip,
)


def test_parse_scan_networks_only_keeps_cidrs() -> None:
    nets = parse_scan_networks("192.168.4.0/22, 10.0.0.1, host.lab, 10.0.0.5-9")
    assert [str(n) for n in nets] == ["192.168.4.0/22"]


def test_parse_scan_networks_handles_multiple_and_bad_tokens() -> None:
    nets = parse_scan_networks("192.168.4.0/22 10.0.0.0/8 999.0.0.0/8")
    assert [str(n) for n in nets] == ["192.168.4.0/22", "10.0.0.0/8"]


def test_subnet_for_ip_uses_scanned_prefix_not_24() -> None:
    nets = parse_scan_networks("192.168.4.0/22")
    # Both .4.x and .5.x fall inside the scanned /22 and must NOT collapse to /24.
    assert subnet_for_ip("192.168.4.10", nets) == "192.168.4.0/22"
    assert subnet_for_ip("192.168.5.10", nets) == "192.168.4.0/22"


def test_subnet_for_ip_falls_back_to_24_outside_scan() -> None:
    nets = parse_scan_networks("192.168.4.0/22")
    assert subnet_for_ip("10.0.0.5", nets) == "10.0.0.0/24"
    assert subnet_for_ip("10.0.0.5") == "10.0.0.0/24"


def test_subnet_for_ip_prefers_most_specific_network() -> None:
    nets = parse_scan_networks("10.0.0.0/8 10.1.2.0/24")
    assert subnet_for_ip("10.1.2.3", nets) == "10.1.2.0/24"


def test_subnet_for_ip_invalid_returns_none() -> None:
    assert subnet_for_ip("not-an-ip") is None


def test_containing_network_handles_version_mismatch() -> None:
    nets = parse_scan_networks("192.168.4.0/22")
    assert containing_network("2001:db8::1", nets) is None
