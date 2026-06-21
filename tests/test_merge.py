import pytest

pytest.importorskip("pydantic")

from packetforge.engine.merge import (
    compute_confidence,
    merge_host,
    merge_host_list,
    merge_service,
    merge_services,
    upsert_host,
)
from packetforge.models.discovery import HostRecord, ServiceRecord


def test_merge_service_prefers_more_definitive_state() -> None:
    filtered = ServiceRecord(port=80, state="filtered")
    open_state = ServiceRecord(port=80, state="open", banner="nginx")
    merged = merge_service(filtered, open_state)
    assert merged.state == "open"
    assert merged.banner == "nginx"


def test_merge_service_keeps_existing_banner_if_incoming_missing() -> None:
    have_banner = ServiceRecord(port=22, state="open", banner="OpenSSH")
    no_banner = ServiceRecord(port=22, state="open")
    merged = merge_service(have_banner, no_banner)
    assert merged.banner == "OpenSSH"


def test_merge_services_unions_by_port_and_protocol() -> None:
    existing = [ServiceRecord(port=80, protocol="tcp", state="open")]
    incoming = [
        ServiceRecord(port=80, protocol="tcp", state="filtered"),
        ServiceRecord(port=53, protocol="udp", state="open"),
    ]
    merged = merge_services(existing, incoming)
    assert len(merged) == 2
    http = next(s for s in merged if s.port == 80)
    assert http.state == "open"


def test_merge_host_unions_methods_and_fills_fields() -> None:
    first = HostRecord(ip="10.0.0.1", methods=["icmp"], latency_ms=12.0)
    second = HostRecord(
        ip="10.0.0.1",
        mac="aa:bb:cc:dd:ee:ff",
        hostname="gw.lab",
        methods=["arp"],
        services=[ServiceRecord(port=443, state="open")],
    )
    merged = merge_host(first, second)
    assert set(merged.methods) == {"icmp", "arp"}
    assert merged.mac == "aa:bb:cc:dd:ee:ff"
    assert merged.hostname == "gw.lab"
    assert merged.open_ports == [443]
    assert merged.latency_ms == 12.0


def test_confidence_increases_with_evidence() -> None:
    sparse = HostRecord(ip="10.0.0.2", methods=["tcp"])
    rich = HostRecord(
        ip="10.0.0.2",
        methods=["tcp", "icmp", "arp"],
        mac="aa:bb:cc:dd:ee:ff",
        hostname="host.lab",
        services=[ServiceRecord(port=22, state="open")],
    )
    assert compute_confidence(rich) > compute_confidence(sparse)
    assert 0.0 <= compute_confidence(rich) <= 1.0


def test_merge_host_list_groups_by_ip() -> None:
    hosts = [
        HostRecord(ip="10.0.0.1", methods=["icmp"]),
        HostRecord(ip="10.0.0.1", methods=["tcp"]),
        HostRecord(ip="10.0.0.2", methods=["arp"]),
    ]
    merged = merge_host_list(hosts)
    assert len(merged) == 2
    first = next(h for h in merged if h.ip == "10.0.0.1")
    assert set(first.methods) == {"icmp", "tcp"}


def test_upsert_host_updates_index_in_place() -> None:
    index: dict[str, HostRecord] = {}
    upsert_host(index, HostRecord(ip="10.0.0.3", methods=["icmp"]))
    upsert_host(index, HostRecord(ip="10.0.0.3", methods=["tcp"]))
    assert len(index) == 1
    assert set(index["10.0.0.3"].methods) == {"icmp", "tcp"}
