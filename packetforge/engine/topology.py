from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from pydantic import BaseModel, Field

from packetforge.models.discovery import HostRecord


class MapNode(BaseModel):
    id: str
    label: str
    kind: str  # "subnet" | "gateway" | "host"
    ip: str | None = None
    subnet: str | None = None
    badges: list[str] = Field(default_factory=list)
    open_ports: list[int] = Field(default_factory=list)
    is_gateway: bool = False


class MapEdge(BaseModel):
    source: str
    target: str
    kind: str = "subnet"  # "subnet" | "arp" | "passive"


class NetworkMap(BaseModel):
    nodes: list[MapNode] = Field(default_factory=list)
    edges: list[MapEdge] = Field(default_factory=list)
    subnets: list[str] = Field(default_factory=list)


def looks_like_gateway(host: HostRecord) -> bool:
    if host.is_gateway_candidate:
        return True
    try:
        addr = ipaddress.ip_address(host.ip)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        last_octet = int(addr) & 0xFF
        return last_octet in {1, 254}
    return False


def _subnet_of(host: HostRecord) -> str:
    if host.subnet:
        return host.subnet
    try:
        addr = ipaddress.ip_address(host.ip)
    except ValueError:
        return "unknown"
    if isinstance(addr, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{host.ip}/24", strict=False))
    return str(ipaddress.ip_network(f"{host.ip}/64", strict=False))


def _badges(host: HostRecord) -> list[str]:
    badges: list[str] = list(host.protocols)
    for service in host.services:
        if service.state == "open" and service.name and service.name not in badges:
            badges.append(service.name)
    return badges[:8]


def build_map(hosts: Iterable[HostRecord]) -> NetworkMap:
    grouped: dict[str, list[HostRecord]] = {}
    for host in hosts:
        grouped.setdefault(_subnet_of(host), []).append(host)

    nodes: list[MapNode] = []
    edges: list[MapEdge] = []
    for subnet in sorted(grouped):
        subnet_id = f"subnet:{subnet}"
        members = grouped[subnet]
        nodes.append(
            MapNode(
                id=subnet_id,
                label=f"{subnet} ({len(members)})",
                kind="subnet",
                subnet=subnet,
            )
        )
        for host in sorted(members, key=lambda h: h.ip):
            is_gw = looks_like_gateway(host)
            host_id = f"host:{host.ip}"
            label = host.hostname or host.ip
            nodes.append(
                MapNode(
                    id=host_id,
                    label=label,
                    kind="gateway" if is_gw else "host",
                    ip=host.ip,
                    subnet=subnet,
                    badges=_badges(host),
                    open_ports=host.open_ports,
                    is_gateway=is_gw,
                )
            )
            if host.mac:
                edge_kind = "arp"
            elif "passive" in host.methods:
                edge_kind = "passive"
            else:
                edge_kind = "subnet"
            edges.append(MapEdge(source=subnet_id, target=host_id, kind=edge_kind))
    return NetworkMap(nodes=nodes, edges=edges, subnets=sorted(grouped))
