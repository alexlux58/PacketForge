from __future__ import annotations

import csv
import json
from collections.abc import Callable

import pytest

pytest.importorskip("pydantic")
pytest.importorskip("scapy")

from packetforge.engine.builder import build_packet
from packetforge.models.discovery import DiscoveryRun, HostRecord
from packetforge.models.packet import ICMPLayer, IPv4Layer, PacketConfig, RawLayer
from packetforge.models.results import PingResult
from packetforge.utils.export import (
    export_hosts_csv,
    export_hosts_json,
    export_packets_to_pcap,
    export_ping_results_csv,
    export_ping_results_json,
    export_run_json,
    load_packets_from_pcap,
)


def _sample_packet() -> object:
    config = PacketConfig(
        layers=[
            IPv4Layer(dst="198.51.100.9", ttl=55),
            ICMPLayer(sequence=7),
            RawLayer(text="roundtrip"),
        ]
    )
    return build_packet(config)


def test_pcap_export_then_import_roundtrips(tmp_path) -> None:  # type: ignore[no-untyped-def]
    packet = _sample_packet()
    path = tmp_path / "out.pcap"
    export_packets_to_pcap([packet], path)
    assert path.exists()

    loaded = load_packets_from_pcap(path)
    assert len(loaded) == 1
    assert bytes(loaded[0]) == bytes(packet)


def test_pcap_export_rejects_empty_packet_list(tmp_path) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(ValueError, match="no packets"):
        export_packets_to_pcap([], tmp_path / "empty.pcap")


def test_ping_results_json_roundtrip(
    tmp_path, make_ping_results: Callable[..., list[PingResult]]
) -> None:  # type: ignore[no-untyped-def]
    results = make_ping_results([5.0, None, 7.5])
    path = tmp_path / "pings.json"
    export_ping_results_json(results, path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert len(data) == 3
    assert data[0]["rtt_ms"] == 5.0
    assert data[1]["timeout"] is True


def test_ping_results_csv_has_header_and_rows(
    tmp_path, make_ping_results: Callable[..., list[PingResult]]
) -> None:  # type: ignore[no-untyped-def]
    results = make_ping_results([5.0, 6.0])
    path = tmp_path / "pings.csv"
    export_ping_results_csv(results, path)
    rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))
    assert len(rows) == 2
    assert "rtt_ms" in rows[0]
    assert "sequence" in rows[0]


def test_ping_results_csv_empty_writes_empty_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "empty.csv"
    export_ping_results_csv([], path)
    assert path.read_text(encoding="utf-8") == ""


def test_hosts_csv_includes_known_columns(
    tmp_path, make_host: Callable[..., HostRecord]
) -> None:  # type: ignore[no-untyped-def]
    hosts = [make_host("10.0.0.1"), make_host("10.0.0.2", hostname="server")]
    path = tmp_path / "hosts.csv"
    export_hosts_csv(hosts, path)
    rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))
    assert {"ip", "mac", "hostname", "open_ports", "confidence"} <= set(rows[0])
    assert rows[1]["hostname"] == "server"


def test_hosts_json_roundtrip(
    tmp_path, make_host: Callable[..., HostRecord]
) -> None:  # type: ignore[no-untyped-def]
    path = tmp_path / "hosts.json"
    export_hosts_json([make_host("10.0.0.5")], path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data[0]["ip"] == "10.0.0.5"


def test_run_json_is_valid_and_reloadable(
    tmp_path, make_host: Callable[..., HostRecord]
) -> None:  # type: ignore[no-untyped-def]
    run = DiscoveryRun(profile="Balanced", targets="10.0.0.0/30", hosts=[make_host("10.0.0.1")])
    path = tmp_path / "run.json"
    export_run_json(run, path)
    reloaded = DiscoveryRun.model_validate_json(path.read_text(encoding="utf-8"))
    assert reloaded.id == run.id
    assert reloaded.host_count == 1
