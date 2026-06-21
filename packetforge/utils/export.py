from __future__ import annotations

import csv
import json
from collections.abc import Iterable
from pathlib import Path

from scapy.all import rdpcap, wrpcap
from scapy.packet import Packet

from packetforge.models.discovery import DiscoveryRun, HostRecord
from packetforge.models.results import PingResult


def export_packets_to_pcap(packets: Iterable[Packet], path: str | Path) -> None:
    packet_list = list(packets)
    if not packet_list:
        raise ValueError("no packets to export")
    wrpcap(str(path), packet_list)


def load_packets_from_pcap(path: str | Path) -> list[Packet]:
    return list(rdpcap(str(path)))


def export_ping_results_json(results: Iterable[PingResult], path: str | Path) -> None:
    data = [result.model_dump(mode="json") for result in results]
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def export_ping_results_csv(results: Iterable[PingResult], path: str | Path) -> None:
    rows = [result.model_dump(mode="json") for result in results]
    if not rows:
        Path(path).write_text("", encoding="utf-8")
        return
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def _host_row(host: HostRecord) -> dict[str, str]:
    open_ports = ",".join(str(port) for port in host.open_ports)
    fingerprint = host.fingerprint.summary if host.fingerprint else ""
    return {
        "ip": host.ip,
        "mac": host.mac or "",
        "vendor": host.vendor or "",
        "hostname": host.hostname or "",
        "latency_ms": "" if host.latency_ms is None else f"{host.latency_ms:.2f}",
        "open_ports": open_ports,
        "protocols": ",".join(host.protocols),
        "methods": ",".join(host.methods),
        "confidence": f"{host.confidence:.2f}",
        "gateway_candidate": "yes" if host.is_gateway_candidate else "no",
        "subnet": host.subnet or "",
        "fingerprint": fingerprint,
        "last_seen": host.last_seen.isoformat(),
    }


def export_hosts_csv(hosts: Iterable[HostRecord], path: str | Path) -> None:
    rows = [_host_row(host) for host in hosts]
    fieldnames = list(_host_row(HostRecord(ip="0.0.0.0")))
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def export_run_json(run: DiscoveryRun, path: str | Path) -> None:
    Path(path).write_text(run.model_dump_json(indent=2), encoding="utf-8")


def export_hosts_json(hosts: Iterable[HostRecord], path: str | Path) -> None:
    data = [host.model_dump(mode="json") for host in hosts]
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
