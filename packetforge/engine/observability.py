from __future__ import annotations

import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass

from packetforge.engine.statistics import calculate_ping_summary
from packetforge.engine.subnets import (
    IPNetwork,
    containing_network,
    parse_scan_networks,
    subnet_for_ip,
)
from packetforge.engine.targets import parse_targets
from packetforge.models.discovery import (
    DiscoveryRun,
    HostRecord,
    ProtocolProbeResult,
    TransportProtocol,
)
from packetforge.models.observability import (
    AnomalyFinding,
    ChartSeries,
    ConfidenceChange,
    HeatmapMatrix,
    HostInsight,
    LatencyDelta,
    LatencySummary,
    ObservabilityBundle,
    PortChange,
    ProtocolHealthPanel,
    RunComparison,
    TopologyEdge,
    TopologyGraph,
    TopologyNode,
)
from packetforge.models.results import PingResult

PingsByHost = dict[str, list[PingResult]]


@dataclass(frozen=True)
class AnomalyThresholds:
    dns_latency_ms: float = 200.0
    ntp_offset_ms: float = 100.0
    rtt_avg_ms: float = 150.0
    loss_percent: float = 20.0
    rtt_outlier_factor: float = 3.0
    snmp_error_min: float = 1.0


# ---------------------------------------------------------------------------
# Discovery overview aggregations
# ---------------------------------------------------------------------------


def discovery_timeline(hosts: Sequence[HostRecord]) -> ChartSeries:
    """Cumulative hosts discovered over time (relative seconds from first sighting)."""
    series = ChartSeries(
        name="Hosts discovered",
        kind="step",
        x_label="seconds since first host",
        y_label="cumulative hosts",
        question="How quickly are hosts being found? Plateaus mean the scan is winding down.",
    )
    if not hosts:
        return series
    ordered = sorted(hosts, key=lambda h: h.first_seen)
    start = ordered[0].first_seen
    for index, host in enumerate(ordered, start=1):
        series.x.append(max(0.0, (host.first_seen - start).total_seconds()))
        series.y.append(float(index))
    return series


def protocol_distribution(hosts: Sequence[HostRecord]) -> ChartSeries:
    """Count of open services / observed protocols across all hosts (bar)."""
    counts: dict[str, int] = {}
    for host in hosts:
        for service in host.services:
            if service.state == "open":
                label = service.name or f"{service.port}/{service.protocol}"
                counts[label] = counts.get(label, 0) + 1
        for protocol in host.protocols:
            counts[protocol] = counts.get(protocol, 0) + 1
    ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
    return ChartSeries(
        name="Service / protocol distribution",
        kind="bar",
        categories=[name for name, _ in ranked],
        x=[float(i) for i in range(len(ranked))],
        y=[float(count) for _, count in ranked],
        y_label="hosts",
        question="Which services dominate this network? Outliers may be unexpected exposure.",
    )


def classify_reachability(host: HostRecord) -> str:
    if host.latency_ms is not None or host.open_ports or {"icmp", "arp"} & set(host.methods):
        return "reachable"
    if any(service.state in {"filtered", "open|filtered"} for service in host.services):
        return "filtered"
    return "unknown"


def reachability_breakdown(
    hosts: Sequence[HostRecord], run: DiscoveryRun | None = None
) -> ChartSeries:
    buckets = {"reachable": 0, "filtered": 0, "unreachable": 0, "unknown": 0}
    for host in hosts:
        buckets[classify_reachability(host)] += 1
    if run is not None and run.targets:
        scanned = parse_targets(run.targets).count
        unreachable = max(0, scanned - len(hosts))
        buckets["unreachable"] = unreachable
    categories = ["reachable", "filtered", "unreachable", "unknown"]
    return ChartSeries(
        name="Reachability",
        kind="bar",
        categories=categories,
        x=[float(i) for i in range(len(categories))],
        y=[float(buckets[name]) for name in categories],
        y_label="hosts",
        question="What share of targets actually responded vs. filtered/silent?",
    )


def top_talkers(hosts: Sequence[HostRecord], limit: int = 10) -> ChartSeries:
    responsive = [h for h in hosts if h.latency_ms is not None]
    responsive.sort(key=lambda h: h.latency_ms or 0.0)
    top = responsive[:limit]
    return ChartSeries(
        name="Most responsive hosts",
        kind="bar",
        categories=[h.hostname or h.ip for h in top],
        x=[float(i) for i in range(len(top))],
        y=[h.latency_ms or 0.0 for h in top],
        y_label="latency",
        unit="ms",
        question="Which hosts answer fastest? Useful for picking healthy reference nodes.",
    )


def subnet_coverage(hosts: Sequence[HostRecord]) -> list[ChartSeries]:
    grouped: dict[str, list[HostRecord]] = {}
    for host in hosts:
        grouped.setdefault(host.subnet or _subnet_of(host.ip), []).append(host)
    subnets = sorted(grouped)
    x = [float(i) for i in range(len(subnets))]
    discovered = [float(len(grouped[s])) for s in subnets]
    responsive = [
        float(sum(1 for h in grouped[s] if classify_reachability(h) == "reachable"))
        for s in subnets
    ]
    unresolved = [float(sum(1 for h in grouped[s] if not h.hostname)) for s in subnets]
    question = "Per subnet: how many hosts found, how many responsive, how many unresolved?"
    return [
        ChartSeries(
            name="Discovered", kind="bar", categories=subnets, x=x, y=discovered,
            y_label="hosts", color="#3da5ff", question=question,
        ),
        ChartSeries(
            name="Responsive", kind="bar", categories=subnets, x=x, y=responsive,
            y_label="hosts", color="#36c275", question=question,
        ),
        ChartSeries(
            name="Unresolved (no DNS)", kind="bar", categories=subnets, x=x, y=unresolved,
            y_label="hosts", color="#f5a623", question=question,
        ),
    ]


_STATE_INTENSITY: dict[str, float] = {
    "open": 1.0,
    "open|filtered": 0.6,
    "filtered": 0.4,
    "closed": 0.15,
    "unknown": 0.0,
}


def port_heatmap(hosts: Sequence[HostRecord], max_hosts: int = 40) -> HeatmapMatrix:
    """Host x port intensity map. Bright cells = open ports worth investigating."""
    host_subset = [h for h in hosts if h.services][:max_hosts]
    port_keys: dict[tuple[int, TransportProtocol], str] = {}
    for host in host_subset:
        for service in host.services:
            label = f"{service.port} {service.name}" if service.name else str(service.port)
            port_keys[(service.port, service.protocol)] = label
    ordered_ports = sorted(port_keys, key=lambda key: key[0])
    columns = [port_keys[key] for key in ordered_ports]
    rows = [h.hostname or h.ip for h in host_subset]
    values: list[list[float]] = []
    for host in host_subset:
        by_key: dict[tuple[int, TransportProtocol], str] = {
            (s.port, s.protocol): s.state for s in host.services
        }
        row = [_STATE_INTENSITY.get(by_key.get(key, "unknown"), 0.0) for key in ordered_ports]
        values.append(row)
    return HeatmapMatrix(
        rows=rows,
        columns=columns,
        values=values,
        title="Open port heatmap",
        row_label="host",
        col_label="port / service",
        question="Where are the open ports concentrated? Bright columns = common exposure.",
    )


def confidence_distribution(hosts: Sequence[HostRecord]) -> ChartSeries:
    edges = [0.0, 0.2, 0.4, 0.6, 0.8, 1.01]
    labels = ["0-20%", "20-40%", "40-60%", "60-80%", "80-100%"]
    counts = [0] * len(labels)
    for host in hosts:
        if host.fingerprint is None:
            continue
        value = host.fingerprint.confidence
        for index in range(len(labels)):
            if edges[index] <= value < edges[index + 1]:
                counts[index] += 1
                break
    return ChartSeries(
        name="Fingerprint confidence",
        kind="bar",
        categories=labels,
        x=[float(i) for i in range(len(labels))],
        y=[float(c) for c in counts],
        y_label="hosts",
        question="How trustworthy are the OS guesses? A left-skew means weak evidence.",
    )


# ---------------------------------------------------------------------------
# Latency / packet health
# ---------------------------------------------------------------------------


def _ping_points(results: Sequence[PingResult]) -> tuple[list[float], list[float]]:
    points = [(r.send_timestamp, r.rtt_ms) for r in results if r.rtt_ms is not None]
    if not points:
        return [], []
    start = min(ts for ts, _ in points)
    xs = [ts - start for ts, _ in points]
    ys = [rtt for _, rtt in points if rtt is not None]
    return xs, ys


def latency_series(host: str, results: Sequence[PingResult]) -> ChartSeries:
    xs, ys = _ping_points(results)
    return ChartSeries(
        name=f"RTT {host}",
        kind="line",
        x=xs,
        y=ys,
        x_label="seconds",
        y_label="RTT",
        unit="ms",
        color="#3da5ff",
        question="Is latency to this host stable, climbing, or spiking?",
    )


def rolling_average(host: str, results: Sequence[PingResult], window: int = 5) -> ChartSeries:
    xs, ys = _ping_points(results)
    rolled: list[float] = []
    for index in range(len(ys)):
        chunk = ys[max(0, index - window + 1) : index + 1]
        rolled.append(sum(chunk) / len(chunk))
    return ChartSeries(
        name=f"Rolling avg {host}",
        kind="line",
        x=xs,
        y=rolled,
        x_label="seconds",
        y_label="RTT",
        unit="ms",
        color="#f5a623",
        question="Smoothed trend that hides single-sample noise.",
    )


def jitter_series(host: str, results: Sequence[PingResult]) -> ChartSeries:
    _xs, ys = _ping_points(results)
    jitter = [0.0]
    for index in range(1, len(ys)):
        jitter.append(abs(ys[index] - ys[index - 1]))
    return ChartSeries(
        name=f"Jitter {host}",
        kind="line",
        x=[float(i) for i in range(len(jitter))],
        y=jitter,
        x_label="sample",
        y_label="jitter",
        unit="ms",
        color="#b48cff",
        question="How much does RTT vary sample-to-sample? High jitter hurts real-time apps.",
    )


def loss_timeline(host: str, results: Sequence[PingResult]) -> ChartSeries:
    y = [1.0 if r.timeout else 0.0 for r in results]
    return ChartSeries(
        name=f"Loss {host}",
        kind="step",
        x=[float(i) for i in range(len(y))],
        y=y,
        x_label="sequence",
        y_label="lost",
        color="#ff6b6b",
        question="When did packets drop? Clusters indicate intermittent outages.",
    )


def latency_histogram(values: Sequence[float], bucket_ms: float = 10.0) -> ChartSeries:
    series = ChartSeries(
        name="RTT histogram",
        kind="histogram",
        x_label="RTT bucket",
        y_label="count",
        unit="ms",
        question="What is the typical RTT, and is the distribution bimodal (two paths)?",
    )
    clean = [v for v in values if v is not None]
    if not clean or bucket_ms <= 0:
        return series
    top = max(clean)
    bucket_count = int(top // bucket_ms) + 1
    counts = [0] * bucket_count
    for value in clean:
        index = min(bucket_count - 1, int(value // bucket_ms))
        counts[index] += 1
    series.x = [i * bucket_ms for i in range(bucket_count)]
    series.y = [float(c) for c in counts]
    series.categories = [
        f"{int(i * bucket_ms)}-{int((i + 1) * bucket_ms)}" for i in range(bucket_count)
    ]
    return series


def latency_summary(results: Sequence[PingResult]) -> LatencySummary:
    if not results:
        return LatencySummary()
    summary = calculate_ping_summary(results)
    return LatencySummary(
        samples=summary.transmitted,
        min_ms=summary.min_rtt_ms,
        avg_ms=summary.avg_rtt_ms,
        max_ms=summary.max_rtt_ms,
        jitter_ms=summary.jitter_ms,
        loss_percent=summary.loss_percent,
    )


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------


def _subnet_of(ip: str, scan_networks: Sequence[IPNetwork] = ()) -> str:
    return subnet_for_ip(ip, scan_networks) or "unknown"


def _looks_like_gateway(host: HostRecord) -> bool:
    if host.is_gateway_candidate:
        return True
    try:
        addr = ipaddress.ip_address(host.ip)
    except ValueError:
        return False
    return isinstance(addr, ipaddress.IPv4Address) and (int(addr) & 0xFF) in {1, 254}


def _node_badges(host: HostRecord) -> list[str]:
    badges: list[str] = []
    seen: set[str] = set()
    open_names = [s.name for s in host.services if s.state == "open" and s.name]
    for token in (*host.protocols, *open_names):
        if token and token not in seen:
            seen.add(token)
            badges.append(token)
    return badges[:8]


def _group_key(host: HostRecord, group_by: str, scan_networks: Sequence[IPNetwork] = ()) -> str:
    if group_by == "protocol":
        names = sorted({s.name for s in host.services if s.state == "open" and s.name})
        return names[0] if names else "no-service"
    # Prefer the network the user actually scanned so a /22 scan is not mislabeled
    # as /24. ``host.subnet`` already carries the scanned prefix for fresh runs;
    # ``scan_networks`` re-derives it for hosts loaded without a subnet.
    scoped = containing_network(host.ip, scan_networks)
    if scoped is not None:
        return str(scoped)
    return host.subnet or _subnet_of(host.ip)


def build_topology(
    hosts: Sequence[HostRecord],
    group_by: str = "subnet",
    *,
    scan_targets: str | None = None,
) -> TopologyGraph:
    scan_networks = parse_scan_networks(scan_targets) if scan_targets else []
    grouped: dict[str, list[HostRecord]] = {}
    for host in hosts:
        grouped.setdefault(_group_key(host, group_by, scan_networks), []).append(host)
    groups = sorted(grouped)
    nodes: list[TopologyNode] = []
    edges: list[TopologyEdge] = []
    for group in groups:
        group_id = f"group:{group}"
        members = grouped[group]
        nodes.append(
            TopologyNode(
                id=group_id,
                label=f"{group} ({len(members)})",
                kind="group" if group_by != "subnet" else "subnet",
                group=group,
            )
        )
        for host in sorted(members, key=lambda h: h.ip):
            host_id = f"host:{host.ip}"
            is_gw = _looks_like_gateway(host)
            nodes.append(
                TopologyNode(
                    id=host_id,
                    label=host.hostname or host.ip,
                    kind="gateway" if is_gw else "host",
                    ip=host.ip,
                    subnet=host.subnet or _subnet_of(host.ip),
                    group=group,
                    badges=_node_badges(host),
                    open_ports=host.open_ports,
                    is_gateway=is_gw,
                    confidence=host.confidence,
                )
            )
            edges.append(_edge_for_host(group_id, host_id, host))
    return TopologyGraph(nodes=nodes, edges=edges, groups=groups, grouped_by=group_by)


def _edge_for_host(group_id: str, host_id: str, host: HostRecord) -> TopologyEdge:
    evidence: list[str] = []
    kind = "subnet"
    label = "subnet member"
    if host.mac:
        kind = "arp"
        label = "ARP"
        evidence.append(f"ARP reply from {host.mac}")
    elif "passive" in host.methods:
        kind = "passive"
        label = "passive"
        evidence.append("seen in passive capture")
    if host.latency_ms is not None:
        evidence.append(f"ICMP/TCP latency {host.latency_ms:.1f} ms")
    if "dns_reverse" in host.methods and host.hostname:
        evidence.append(f"reverse DNS -> {host.hostname}")
    return TopologyEdge(source=group_id, target=host_id, kind=kind, label=label, evidence=evidence)


# ---------------------------------------------------------------------------
# Run comparison
# ---------------------------------------------------------------------------


def compare_runs(baseline: DiscoveryRun, candidate: DiscoveryRun) -> RunComparison:
    base = {h.ip: h for h in baseline.hosts}
    cand = {h.ip: h for h in candidate.hosts}
    base_ips, cand_ips = set(base), set(cand)
    common = sorted(base_ips & cand_ips)

    port_changes: list[PortChange] = []
    capability_changes: dict[str, list[str]] = {}
    latency_deltas: list[LatencyDelta] = []
    confidence_changes: list[ConfidenceChange] = []

    for ip in common:
        before, after = base[ip], cand[ip]
        opened = sorted(set(after.open_ports) - set(before.open_ports))
        closed = sorted(set(before.open_ports) - set(after.open_ports))
        if opened or closed:
            port_changes.append(PortChange(host=ip, opened=opened, closed=closed))

        changes = _capability_changes(before, after)
        if changes:
            capability_changes[ip] = changes

        if before.latency_ms is not None or after.latency_ms is not None:
            delta = None
            if before.latency_ms is not None and after.latency_ms is not None:
                delta = round(after.latency_ms - before.latency_ms, 2)
            latency_deltas.append(
                LatencyDelta(
                    host=ip, before_ms=before.latency_ms, after_ms=after.latency_ms, delta_ms=delta
                )
            )

        before_conf = before.fingerprint.confidence if before.fingerprint else 0.0
        after_conf = after.fingerprint.confidence if after.fingerprint else 0.0
        if abs(after_conf - before_conf) >= 0.01:
            confidence_changes.append(
                ConfidenceChange(
                    host=ip,
                    before=round(before_conf, 3),
                    after=round(after_conf, 3),
                    delta=round(after_conf - before_conf, 3),
                )
            )

    return RunComparison(
        baseline_label=baseline.label,
        candidate_label=candidate.label,
        added_hosts=sorted(cand_ips - base_ips),
        removed_hosts=sorted(base_ips - cand_ips),
        common_hosts=common,
        port_changes=port_changes,
        capability_changes=capability_changes,
        latency_deltas=latency_deltas,
        confidence_changes=confidence_changes,
    )


def _capability_changes(before: HostRecord, after: HostRecord) -> list[str]:
    before_caps = _capabilities(before)
    after_caps = _capabilities(after)
    changes: list[str] = []
    for cap in sorted(after_caps - before_caps):
        changes.append(f"+ {cap}")
    for cap in sorted(before_caps - after_caps):
        changes.append(f"- {cap}")
    return changes


def _capabilities(host: HostRecord) -> set[str]:
    caps = set(host.protocols)
    for service in host.services:
        if service.state == "open" and service.name:
            caps.add(service.name)
    return caps


# ---------------------------------------------------------------------------
# Anomaly detection
# ---------------------------------------------------------------------------


def detect_anomalies(
    hosts: Sequence[HostRecord],
    probes: Sequence[ProtocolProbeResult] | None = None,
    pings: PingsByHost | None = None,
    thresholds: AnomalyThresholds | None = None,
) -> list[AnomalyFinding]:
    thresholds = thresholds or AnomalyThresholds()
    probes = probes or []
    pings = pings or {}
    findings: list[AnomalyFinding] = []

    for host in hosts:
        findings.extend(_host_anomalies(host))
    findings.extend(_probe_anomalies(probes, thresholds))
    findings.extend(_ping_anomalies(pings, thresholds))

    findings.sort(key=lambda f: (f.rank, -f.confidence))
    return findings


def _host_anomalies(host: HostRecord) -> list[AnomalyFinding]:
    findings: list[AnomalyFinding] = []
    methods = set(host.methods)
    if "arp" in methods and "icmp" not in methods and host.latency_ms is None:
        findings.append(
            AnomalyFinding(
                id=f"arp-no-icmp:{host.ip}",
                category="reachability",
                severity="info",
                title=f"{host.ip} answers ARP but not ICMP",
                detail="Host is present at layer 2 but did not reply to ICMP echo. "
                "It may have a host firewall blocking ping, which is common and not "
                "necessarily a fault.",
                evidence=[f"methods: {', '.join(sorted(methods))}", "no ICMP latency recorded"],
                host=host.ip,
                confidence=0.6,
            )
        )
    if _looks_like_gateway(host) and "arp" in methods:
        evidence = [f"address ends in .{int(ipaddress.ip_address(host.ip)) & 0xFF}"]
        if host.mac:
            evidence.append(f"ARP MAC {host.mac}")
        if host.fingerprint and host.fingerprint.best_guess:
            evidence.append(f"fingerprint: {host.fingerprint.summary}")
        findings.append(
            AnomalyFinding(
                id=f"gateway:{host.ip}",
                category="topology",
                severity="info",
                title=f"{host.ip} is a possible router/gateway",
                detail="Address position plus ARP presence suggest a gateway. Confirm with "
                "the routing table before relying on this.",
                evidence=evidence,
                host=host.ip,
                confidence=0.5,
            )
        )
    return findings


def _probe_anomalies(
    probes: Sequence[ProtocolProbeResult], thresholds: AnomalyThresholds
) -> list[AnomalyFinding]:
    findings: list[AnomalyFinding] = []
    for probe in probes:
        base = probe.protocol.split("-")[0].upper()
        if base == "DNS" and probe.latency_ms is not None and (
            probe.latency_ms > thresholds.dns_latency_ms
        ):
            resolver = probe.detail.get("resolver", probe.target)
            findings.append(
                AnomalyFinding(
                    id=f"dns-latency:{resolver}:{probe.target}",
                    category="dns",
                    severity="warning",
                    title=f"High DNS latency on resolver {resolver}",
                    detail=f"Query took {probe.latency_ms:.0f} ms "
                    f"(threshold {thresholds.dns_latency_ms:.0f} ms).",
                    evidence=[probe.summary, f"resolver {resolver}"],
                    confidence=0.7,
                )
            )
        if base == "SMTP" and probe.detail.get("starttls") == "no":
            findings.append(
                AnomalyFinding(
                    id=f"smtp-starttls:{probe.target}",
                    category="smtp",
                    severity="warning",
                    title=f"SMTP STARTTLS missing on {probe.target}",
                    detail="The server did not advertise STARTTLS, so mail may transit in "
                    "cleartext. Verify whether TLS is expected here.",
                    evidence=[probe.detail.get("banner", probe.summary)],
                    host=probe.target.split(":")[0],
                    confidence=0.75,
                )
            )
        if base == "NTP":
            offset = _to_float(probe.detail.get("offset_ms"))
            if offset is not None and abs(offset) > thresholds.ntp_offset_ms:
                findings.append(
                    AnomalyFinding(
                        id=f"ntp-offset:{probe.target}",
                        category="ntp",
                        severity="warning",
                        title=f"NTP offset exceeds threshold on {probe.target}",
                        detail=f"Clock offset {offset:.1f} ms exceeds "
                        f"{thresholds.ntp_offset_ms:.0f} ms; clients syncing here may drift.",
                        evidence=[probe.summary],
                        host=probe.target,
                        confidence=0.7,
                    )
                )
        if base == "SNMP":
            findings.extend(_snmp_error_anomaly(probe, thresholds))
    return findings


def _snmp_error_anomaly(
    probe: ProtocolProbeResult, thresholds: AnomalyThresholds
) -> list[AnomalyFinding]:
    findings: list[AnomalyFinding] = []
    for key, raw in probe.detail.items():
        lowered = key.lower()
        if "error" not in lowered and "discard" not in lowered:
            continue
        value = _to_float(raw)
        if value is not None and value >= thresholds.snmp_error_min:
            findings.append(
                AnomalyFinding(
                    id=f"snmp-errors:{probe.target}:{key}",
                    category="snmp",
                    severity="warning",
                    title=f"SNMP interface errors on {probe.target}",
                    detail=f"{key} = {raw}. Rising error/discard counters often indicate "
                    "duplex mismatch, cabling, or congestion.",
                    evidence=[f"{key}={raw}"],
                    host=probe.target,
                    confidence=0.65,
                )
            )
    return findings


def _ping_anomalies(
    pings: PingsByHost, thresholds: AnomalyThresholds
) -> list[AnomalyFinding]:
    findings: list[AnomalyFinding] = []
    for host, results in pings.items():
        if not results:
            continue
        summary = calculate_ping_summary(results)
        if summary.loss_percent > thresholds.loss_percent:
            findings.append(
                AnomalyFinding(
                    id=f"loss:{host}",
                    category="latency",
                    severity="critical" if summary.loss_percent > 50 else "warning",
                    title=f"Packet loss to {host} is {summary.loss_percent:.0f}%",
                    detail=f"{summary.transmitted - summary.received} of {summary.transmitted} "
                    "probes were lost.",
                    evidence=[f"loss {summary.loss_percent:.0f}%"],
                    host=host,
                    confidence=0.85,
                )
            )
        if summary.avg_rtt_ms is not None and summary.avg_rtt_ms > thresholds.rtt_avg_ms:
            findings.append(
                AnomalyFinding(
                    id=f"rtt-avg:{host}",
                    category="latency",
                    severity="warning",
                    title=f"High average RTT to {host}",
                    detail=f"Average RTT {summary.avg_rtt_ms:.0f} ms exceeds "
                    f"{thresholds.rtt_avg_ms:.0f} ms.",
                    evidence=[f"avg {summary.avg_rtt_ms:.0f} ms", f"max {summary.max_rtt_ms} ms"],
                    host=host,
                    confidence=0.7,
                )
            )
        findings.extend(_rtt_outlier_anomaly(host, results, summary.avg_rtt_ms, thresholds))
        if summary.duplicate_replies:
            findings.append(
                AnomalyFinding(
                    id=f"dup:{host}",
                    category="latency",
                    severity="info",
                    title=f"Duplicate replies from {host}",
                    detail=f"{summary.duplicate_replies} duplicate ICMP replies; can indicate "
                    "a routing loop or misconfigured load balancer.",
                    evidence=[f"{summary.duplicate_replies} duplicates"],
                    host=host,
                    confidence=0.6,
                )
            )
        if summary.icmp_errors:
            findings.append(
                AnomalyFinding(
                    id=f"icmp-err:{host}",
                    category="latency",
                    severity="info",
                    title=f"ICMP errors observed for {host}",
                    detail=f"{summary.icmp_errors} ICMP error replies (e.g. unreachable/TTL).",
                    evidence=[f"{summary.icmp_errors} ICMP errors"],
                    host=host,
                    confidence=0.6,
                )
            )
    return findings


def _rtt_outlier_anomaly(
    host: str,
    results: Sequence[PingResult],
    avg: float | None,
    thresholds: AnomalyThresholds,
) -> list[AnomalyFinding]:
    if avg is None or avg <= 0:
        return []
    cutoff = avg * thresholds.rtt_outlier_factor
    outliers = [r.rtt_ms for r in results if r.rtt_ms is not None and r.rtt_ms > cutoff]
    if not outliers:
        return []
    return [
        AnomalyFinding(
            id=f"rtt-outlier:{host}",
            category="latency",
            severity="info",
            title=f"RTT spikes to {host}",
            detail=f"{len(outliers)} sample(s) exceeded {thresholds.rtt_outlier_factor:.0f}x the "
            f"average ({avg:.0f} ms). Peak {max(outliers):.0f} ms.",
            evidence=[f"{len(outliers)} spikes", f"peak {max(outliers):.0f} ms"],
            host=host,
            confidence=0.6,
        )
    ]


def _to_float(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Host insight
# ---------------------------------------------------------------------------


def host_insight(
    host: HostRecord,
    results: Sequence[PingResult] | None = None,
    anomalies: Sequence[AnomalyFinding] | None = None,
) -> HostInsight:
    results = results or []
    summary = latency_summary(results)
    _xs, ys = _ping_points(results)
    services = [
        f"{s.port}/{s.protocol} {s.state}" + (f" {s.name}" if s.name else "")
        for s in sorted(host.services, key=lambda s: s.port)
    ]
    fp = host.fingerprint
    findings = [a for a in (anomalies or []) if a.host == host.ip]
    return HostInsight(
        ip=host.ip,
        hostname=host.hostname,
        mac=host.mac,
        vendor=host.vendor,
        subnet=host.subnet or _subnet_of(host.ip),
        methods=list(host.methods),
        last_seen=host.last_seen,
        is_gateway_candidate=_looks_like_gateway(host),
        services=services,
        fingerprint_summary=fp.summary if fp else "no fingerprint evidence",
        fingerprint_confidence=fp.confidence if fp else 0.0,
        fingerprint_evidence=[f"{s.name}: {s.interpretation}" for s in fp.signals] if fp else [],
        latency=summary,
        sparkline=ys[-40:],
        protocol_findings=list(host.protocols),
        anomalies=findings,
    )


def host_report_markdown(insight: HostInsight) -> str:
    lines = [
        f"# Host report: {insight.ip}",
        "",
        "## Identity",
        f"- IP: {insight.ip}",
        f"- Hostname: {insight.hostname or 'n/a'}",
        f"- MAC: {insight.mac or 'n/a'}",
        f"- Vendor: {insight.vendor or 'n/a'}",
        f"- Subnet: {insight.subnet or 'n/a'}",
        f"- Discovery methods: {', '.join(insight.methods) or 'n/a'}",
        f"- Last seen: {insight.last_seen.isoformat() if insight.last_seen else 'n/a'}",
        f"- Gateway candidate: {'yes' if insight.is_gateway_candidate else 'no'}",
        "",
        "## Services",
    ]
    if insight.services:
        lines.extend(f"- {service}" for service in insight.services)
    else:
        lines.append("- none")
    lines += [
        "",
        "## Fingerprint",
        f"- Summary: {insight.fingerprint_summary}",
        f"- Confidence: {insight.fingerprint_confidence * 100:.0f}%",
    ]
    lines.extend(f"- {item}" for item in insight.fingerprint_evidence)
    lat = insight.latency
    lines += [
        "",
        "## Latency",
        f"- Samples: {lat.samples}",
        f"- Min/Avg/Max: {lat.min_ms} / {lat.avg_ms} / {lat.max_ms} ms",
        f"- Jitter: {lat.jitter_ms} ms",
        f"- Loss: {lat.loss_percent:.0f}%",
        "",
        "## Findings",
    ]
    if insight.anomalies:
        for finding in insight.anomalies:
            lines.append(f"- [{finding.severity}] {finding.title}: {finding.detail}")
    else:
        lines.append("- none")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Protocol health panels
# ---------------------------------------------------------------------------

_PROTOCOL_ORDER = ["DNS", "DHCP", "SNMP", "SMTP", "NTP", "BGP", "OSPF", "STP"]


def build_protocol_panels(probes: Sequence[ProtocolProbeResult]) -> list[ProtocolHealthPanel]:
    grouped: dict[str, list[ProtocolProbeResult]] = {name: [] for name in _PROTOCOL_ORDER}
    for probe in probes:
        base = probe.protocol.split("-")[0].upper()
        grouped.setdefault(base, []).append(probe)
    return [
        _dns_panel(grouped["DNS"]),
        _dhcp_panel(grouped["DHCP"]),
        _snmp_panel(grouped["SNMP"]),
        _smtp_panel(grouped["SMTP"]),
        _ntp_panel(grouped["NTP"]),
        _bgp_panel(grouped["BGP"]),
        _passive_panel("OSPF", grouped["OSPF"]),
        _passive_panel("STP", grouped["STP"]),
    ]


def _dns_panel(probes: Sequence[ProtocolProbeResult]) -> ProtocolHealthPanel:
    panel = ProtocolHealthPanel(protocol="DNS")
    if not probes:
        return panel
    by_resolver: dict[str, list[float]] = {}
    rcodes: dict[str, int] = {}
    rows: list[list[str]] = []
    for probe in probes:
        resolver = probe.detail.get("resolver", probe.target)
        if probe.latency_ms is not None:
            by_resolver.setdefault(resolver, []).append(probe.latency_ms)
        rcode = probe.detail.get("rcode", "?")
        rcodes[rcode] = rcodes.get(rcode, 0) + 1
        rows.append(
            [
                probe.detail.get("qname", probe.target),
                probe.detail.get("qtype", "?"),
                rcode,
                probe.detail.get("answers", str(len(probe.records))),
                f"{probe.latency_ms:.1f}" if probe.latency_ms is not None else "-",
            ]
        )
    resolvers = sorted(by_resolver)
    panel.series.append(
        ChartSeries(
            name="Query latency by resolver",
            kind="bar",
            categories=resolvers,
            x=[float(i) for i in range(len(resolvers))],
            y=[sum(v) / len(v) for v in (by_resolver[r] for r in resolvers)],
            y_label="latency",
            unit="ms",
            question="Which resolver is slowest? Compare against a known-good resolver.",
        )
    )
    rcode_names = sorted(rcodes)
    panel.series.append(
        ChartSeries(
            name="Response codes",
            kind="bar",
            categories=rcode_names,
            x=[float(i) for i in range(len(rcode_names))],
            y=[float(rcodes[name]) for name in rcode_names],
            y_label="responses",
            question="Are responses NOERROR, or are SERVFAIL/REFUSED showing up?",
        )
    )
    panel.table_columns = ["Name", "Type", "RCODE", "Answers", "Latency ms"]
    panel.table_rows = rows
    panel.headline = f"{len(probes)} query/queries across {len(resolvers)} resolver(s)"
    return panel


def _dhcp_panel(probes: Sequence[ProtocolProbeResult]) -> ProtocolHealthPanel:
    panel = ProtocolHealthPanel(protocol="DHCP")
    if not probes:
        return panel
    msg_counts: dict[str, int] = {}
    rows: list[list[str]] = []
    servers: set[str] = set()
    for probe in probes:
        if probe.detail.get("server"):
            servers.add(probe.detail["server"])
        for record in probe.records:
            kind = record.split()[0] if record else "?"
            msg_counts[kind] = msg_counts.get(kind, 0) + 1
            rows.append([probe.target, record])
        for key in ("offered_ip", "server", "message_type"):
            if key in probe.detail:
                rows.append([probe.target, f"{key}={probe.detail[key]}"])
    names = sorted(msg_counts)
    if names:
        panel.series.append(
            ChartSeries(
                name="DHCP message types",
                kind="bar",
                categories=names,
                x=[float(i) for i in range(len(names))],
                y=[float(msg_counts[n]) for n in names],
                y_label="messages",
                question="Is the DHCP conversation completing (DISCOVER/OFFER/REQUEST/ACK)?",
            )
        )
    panel.table_columns = ["Source", "Observation"]
    panel.table_rows = rows
    panel.notes = [f"server identities: {', '.join(sorted(servers))}"] if servers else []
    panel.headline = f"{len(probes)} DHCP observation(s)"
    return panel


def _snmp_panel(probes: Sequence[ProtocolProbeResult]) -> ProtocolHealthPanel:
    panel = ProtocolHealthPanel(protocol="SNMP")
    if not probes:
        return panel
    rows: list[list[str]] = []
    counters: dict[str, float] = {}
    for probe in probes:
        for key, value in probe.detail.items():
            rows.append([probe.target, key, value])
            numeric = _to_float(value)
            if numeric is not None and ("error" in key.lower() or "discard" in key.lower()):
                counters[f"{probe.target}:{key}"] = numeric
    if counters:
        names = sorted(counters)
        panel.series.append(
            ChartSeries(
                name="Interface errors / discards",
                kind="bar",
                categories=names,
                x=[float(i) for i in range(len(names))],
                y=[counters[n] for n in names],
                y_label="count",
                question="Are error/discard counters non-zero or climbing?",
            )
        )
    panel.table_columns = ["Device", "OID / field", "Value"]
    panel.table_rows = rows
    panel.headline = f"{len(probes)} SNMP device(s)"
    return panel


def _smtp_panel(probes: Sequence[ProtocolProbeResult]) -> ProtocolHealthPanel:
    panel = ProtocolHealthPanel(protocol="SMTP")
    if not probes:
        return panel
    rows: list[list[str]] = []
    targets: list[str] = []
    latencies: list[float] = []
    for probe in probes:
        starttls = probe.detail.get("starttls", "?")
        rows.append(
            [
                probe.target,
                probe.detail.get("banner", "")[:60],
                starttls,
                str(len(probe.records)),
            ]
        )
        if probe.latency_ms is not None:
            targets.append(probe.target)
            latencies.append(probe.latency_ms)
    if latencies:
        panel.series.append(
            ChartSeries(
                name="SMTP response latency",
                kind="bar",
                categories=targets,
                x=[float(i) for i in range(len(targets))],
                y=latencies,
                y_label="latency",
                unit="ms",
                question="Which mail servers are slow to answer EHLO?",
            )
        )
    panel.table_columns = ["Server", "Banner", "STARTTLS", "Capabilities"]
    panel.table_rows = rows
    missing = [r[0] for r in rows if r[2] == "no"]
    panel.notes = [f"STARTTLS missing on: {', '.join(missing)}"] if missing else []
    panel.headline = f"{len(probes)} SMTP server(s)"
    return panel


def _ntp_panel(probes: Sequence[ProtocolProbeResult]) -> ProtocolHealthPanel:
    panel = ProtocolHealthPanel(protocol="NTP")
    if not probes:
        return panel
    targets: list[str] = []
    offsets: list[float] = []
    delays: list[float] = []
    strata: dict[str, int] = {}
    rows: list[list[str]] = []
    for probe in probes:
        offset = _to_float(probe.detail.get("offset_ms"))
        delay = _to_float(probe.detail.get("delay_ms"))
        stratum = probe.detail.get("stratum", "?")
        strata[stratum] = strata.get(stratum, 0) + 1
        targets.append(probe.target)
        offsets.append(offset or 0.0)
        delays.append(delay or 0.0)
        rows.append(
            [probe.target, stratum, probe.detail.get("offset_ms", "-"),
             probe.detail.get("delay_ms", "-")]
        )
    panel.series.append(
        ChartSeries(
            name="Offset by server",
            kind="bar",
            categories=targets,
            x=[float(i) for i in range(len(targets))],
            y=offsets,
            y_label="offset",
            unit="ms",
            question="Is any server's clock offset large enough to matter?",
        )
    )
    panel.series.append(
        ChartSeries(
            name="Delay by server",
            kind="bar",
            categories=targets,
            x=[float(i) for i in range(len(targets))],
            y=delays,
            y_label="delay",
            unit="ms",
            question="Round-trip delay to each time source.",
        )
    )
    panel.table_columns = ["Server", "Stratum", "Offset ms", "Delay ms"]
    panel.table_rows = rows
    panel.notes = [f"stratum distribution: {dict(sorted(strata.items()))}"]
    panel.headline = f"{len(probes)} NTP server(s)"
    return panel


def _bgp_panel(probes: Sequence[ProtocolProbeResult]) -> ProtocolHealthPanel:
    panel = ProtocolHealthPanel(protocol="BGP")
    if not probes:
        return panel
    rows = [
        [
            probe.target,
            "reachable" if probe.success else "unreachable",
            probe.detail.get("tcp_179", "?"),
            probe.detail.get("peer_reply", "-"),
        ]
        for probe in probes
    ]
    panel.table_columns = ["Peer", "TCP/179", "Port state", "OPEN reply"]
    panel.table_rows = rows
    panel.headline = f"{len(probes)} BGP peer(s)"
    return panel


def _passive_panel(name: str, probes: Sequence[ProtocolProbeResult]) -> ProtocolHealthPanel:
    panel = ProtocolHealthPanel(protocol=name)
    if not probes:
        return panel
    rows: list[list[str]] = []
    identities: set[str] = set()
    total = 0
    for probe in probes:
        for key in ("routers", "roots"):
            if probe.detail.get(key):
                identities.add(probe.detail[key])
        for record in probe.records:
            rows.append([probe.target, record])
            total += 1
    panel.table_columns = ["Interface", "Observation"]
    panel.table_rows = rows
    if identities:
        label = "neighbors" if name == "OSPF" else "root/bridge"
        panel.notes = [f"{label}: {', '.join(sorted(identities))}"]
    panel.headline = f"{total} {name} observation(s)"
    return panel


# ---------------------------------------------------------------------------
# Bundle
# ---------------------------------------------------------------------------


def build_bundle(
    hosts: Sequence[HostRecord],
    *,
    pings: PingsByHost | None = None,
    probes: Sequence[ProtocolProbeResult] | None = None,
    run: DiscoveryRun | None = None,
    thresholds: AnomalyThresholds | None = None,
    subnet_filter: str | None = None,
    host_filter: str | None = None,
) -> ObservabilityBundle:
    pings = pings or {}
    probes = list(probes or [])
    if subnet_filter:
        hosts = [h for h in hosts if (h.subnet or _subnet_of(h.ip)) == subnet_filter]
    if host_filter:
        hosts = [h for h in hosts if h.ip == host_filter or h.hostname == host_filter]

    anomalies = detect_anomalies(hosts, probes, pings, thresholds)
    bundle = ObservabilityBundle(
        host_count=len(hosts),
        timeline=discovery_timeline(hosts),
        protocol_distribution=protocol_distribution(hosts),
        reachability=reachability_breakdown(hosts, run),
        top_talkers=top_talkers(hosts),
        subnet_coverage=subnet_coverage(hosts),
        port_heatmap=port_heatmap(hosts),
        confidence_distribution=confidence_distribution(hosts),
        topology=build_topology(hosts, scan_targets=run.targets if run else None),
        protocol_panels=build_protocol_panels(probes),
        anomalies=anomalies,
    )
    for host, results in pings.items():
        bundle.latency_by_host[host] = latency_series(host, results)
        bundle.rolling_by_host[host] = rolling_average(host, results)
        bundle.jitter_by_host[host] = jitter_series(host, results)
        bundle.loss_by_host[host] = loss_timeline(host, results)
        _xs, ys = _ping_points(results)
        bundle.latency_histogram_by_host[host] = latency_histogram(ys)
        bundle.latency_summary_by_host[host] = latency_summary(results)
    for record_host in hosts:
        bundle.host_insights[record_host.ip] = host_insight(
            record_host, pings.get(record_host.ip, []), anomalies
        )
    return bundle
