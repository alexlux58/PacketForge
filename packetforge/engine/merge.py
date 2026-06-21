from __future__ import annotations

from collections.abc import Iterable

from packetforge.models.discovery import HostRecord, PortState, ServiceRecord

# Higher number == more definitive observation; wins on conflict.
_STATE_RANK: dict[PortState, int] = {
    "unknown": 0,
    "open|filtered": 1,
    "filtered": 2,
    "closed": 3,
    "open": 4,
}


def _better_state(left: PortState, right: PortState) -> PortState:
    return left if _STATE_RANK[left] >= _STATE_RANK[right] else right


def merge_service(existing: ServiceRecord, incoming: ServiceRecord) -> ServiceRecord:
    return ServiceRecord(
        port=existing.port,
        protocol=existing.protocol,
        state=_better_state(existing.state, incoming.state),
        name=incoming.name or existing.name,
        banner=incoming.banner or existing.banner,
        last_seen=max(existing.last_seen, incoming.last_seen),
    )


def merge_services(
    existing: Iterable[ServiceRecord], incoming: Iterable[ServiceRecord]
) -> list[ServiceRecord]:
    merged: dict[tuple[int, str], ServiceRecord] = {}
    for service in existing:
        merged[service.key] = service
    for service in incoming:
        current = merged.get(service.key)
        merged[service.key] = service if current is None else merge_service(current, service)
    return sorted(merged.values(), key=lambda s: (s.protocol, s.port))


def _union[T](left: Iterable[T], right: Iterable[T]) -> list[T]:
    seen: dict[T, None] = {}
    for value in (*left, *right):
        seen.setdefault(value, None)
    return list(seen)


def compute_confidence(host: HostRecord) -> float:
    score = 0.0
    if host.methods:
        score += 0.3 + min(0.3, 0.15 * (len(set(host.methods)) - 1))
    if host.mac:
        score += 0.1
    if host.hostname:
        score += 0.1
    if any(service.state == "open" for service in host.services):
        score += 0.15
    if host.fingerprint is not None:
        score += 0.2 * host.fingerprint.confidence
    return round(min(1.0, score), 3)


def merge_host(existing: HostRecord, incoming: HostRecord) -> HostRecord:
    latencies = [v for v in (existing.latency_ms, incoming.latency_ms) if v is not None]
    merged = HostRecord(
        ip=existing.ip,
        mac=incoming.mac or existing.mac,
        vendor=incoming.vendor or existing.vendor,
        hostname=incoming.hostname or existing.hostname,
        latency_ms=min(latencies) if latencies else None,
        services=merge_services(existing.services, incoming.services),
        protocols=_union(existing.protocols, incoming.protocols),
        methods=_union(existing.methods, incoming.methods),
        is_gateway_candidate=existing.is_gateway_candidate or incoming.is_gateway_candidate,
        subnet=incoming.subnet or existing.subnet,
        fingerprint=incoming.fingerprint or existing.fingerprint,
        first_seen=min(existing.first_seen, incoming.first_seen),
        last_seen=max(existing.last_seen, incoming.last_seen),
    )
    merged.confidence = compute_confidence(merged)
    return merged


def merge_host_list(hosts: Iterable[HostRecord]) -> list[HostRecord]:
    merged: dict[str, HostRecord] = {}
    for host in hosts:
        current = merged.get(host.ip)
        merged[host.ip] = host if current is None else merge_host(current, host)
    return sorted(merged.values(), key=lambda h: _ip_sort_key(h.ip))


def upsert_host(index: dict[str, HostRecord], incoming: HostRecord) -> HostRecord:
    """Merge ``incoming`` into ``index`` in place and return the stored record."""
    current = index.get(incoming.ip)
    merged = incoming if current is None else merge_host(current, incoming)
    if current is None:
        merged.confidence = compute_confidence(merged)
    index[incoming.ip] = merged
    return merged


def _ip_sort_key(ip: str) -> tuple[int, ...]:
    import ipaddress

    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, *(ord(char) for char in ip[:16]))
