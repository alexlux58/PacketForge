from pathlib import Path

import pytest

pytest.importorskip("pydantic")

from packetforge.engine.history import DiscoveryHistory, compare_runs
from packetforge.engine.topology import build_map, looks_like_gateway
from packetforge.models.discovery import DiscoveryRun, HostRecord, ServiceRecord


def _run_with(hosts: list[HostRecord]) -> DiscoveryRun:
    return DiscoveryRun(profile="Balanced", targets="10.0.0.0/24", hosts=hosts)


def test_history_save_list_load_delete(tmp_path: Path) -> None:
    history = DiscoveryHistory(tmp_path)
    run = _run_with([HostRecord(ip="10.0.0.1", methods=["icmp"])])
    history.save(run)

    runs = history.list_runs()
    assert len(runs) == 1
    loaded = history.load(run.id)
    assert loaded is not None
    assert loaded.hosts[0].ip == "10.0.0.1"
    assert history.delete(run.id) is True
    assert history.list_runs() == []


def test_compare_runs_detects_changes() -> None:
    baseline = _run_with(
        [
            HostRecord(ip="10.0.0.1", services=[ServiceRecord(port=22, state="open")]),
            HostRecord(ip="10.0.0.2"),
        ]
    )
    candidate = _run_with(
        [
            HostRecord(
                ip="10.0.0.1",
                services=[
                    ServiceRecord(port=22, state="open"),
                    ServiceRecord(port=80, state="open"),
                ],
            ),
            HostRecord(ip="10.0.0.3"),
        ]
    )
    comparison = compare_runs(baseline, candidate)
    assert comparison.added_hosts == ["10.0.0.3"]
    assert comparison.removed_hosts == ["10.0.0.2"]
    assert comparison.common_hosts == ["10.0.0.1"]
    assert comparison.changed_ports["10.0.0.1"]["opened"] == [80]


def test_build_map_groups_by_subnet_and_flags_gateway() -> None:
    hosts = [
        HostRecord(ip="192.168.1.1", mac="aa:bb:cc:dd:ee:ff"),
        HostRecord(ip="192.168.1.50", services=[ServiceRecord(port=80, state="open", name="http")]),
    ]
    network_map = build_map(hosts)
    assert "192.168.1.0/24" in network_map.subnets
    gateway_nodes = [node for node in network_map.nodes if node.is_gateway]
    assert any(node.ip == "192.168.1.1" for node in gateway_nodes)
    assert len(network_map.edges) >= 2


def test_looks_like_gateway_heuristic() -> None:
    assert looks_like_gateway(HostRecord(ip="10.0.0.1")) is True
    assert looks_like_gateway(HostRecord(ip="10.0.0.254")) is True
    assert looks_like_gateway(HostRecord(ip="10.0.0.73")) is False
    assert looks_like_gateway(HostRecord(ip="10.0.0.73", is_gateway_candidate=True)) is True
