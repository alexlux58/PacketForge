from datetime import UTC, datetime, timedelta

import pytest

pytest.importorskip("pydantic")

from packetforge.engine.observability import (
    AnomalyThresholds,
    build_bundle,
    build_topology,
    compare_runs,
    confidence_distribution,
    detect_anomalies,
    discovery_timeline,
    latency_histogram,
    port_heatmap,
    reachability_breakdown,
)
from packetforge.models.discovery import (
    DiscoveryRun,
    FingerprintEvidence,
    HostRecord,
    OsGuess,
    ProtocolProbeResult,
    ServiceRecord,
)
from packetforge.models.results import PingResult

_BASE = datetime(2026, 6, 20, 21, 0, 0, tzinfo=UTC)


def _host(ip: str, seconds: int = 0, **kwargs: object) -> HostRecord:
    return HostRecord(ip=ip, first_seen=_BASE + timedelta(seconds=seconds), **kwargs)  # type: ignore[arg-type]


# --- timeline ---------------------------------------------------------------


def test_discovery_timeline_is_cumulative_in_relative_seconds() -> None:
    hosts = [_host("10.0.0.1", 0), _host("10.0.0.2", 5), _host("10.0.0.3", 12)]
    series = discovery_timeline(hosts)
    assert series.x == [0.0, 5.0, 12.0]
    assert series.y == [1.0, 2.0, 3.0]


def test_discovery_timeline_empty() -> None:
    assert discovery_timeline([]).is_empty


# --- heatmap ----------------------------------------------------------------


def test_port_heatmap_matrix_shape_and_intensity() -> None:
    hosts = [
        _host("10.0.0.1", services=[ServiceRecord(port=22, state="open", name="ssh")]),
        _host(
            "10.0.0.2",
            services=[
                ServiceRecord(port=22, state="filtered", name="ssh"),
                ServiceRecord(port=80, state="open", name="http"),
            ],
        ),
    ]
    matrix = port_heatmap(hosts)
    assert matrix.rows == ["10.0.0.1", "10.0.0.2"]
    assert matrix.columns == ["22 ssh", "80 http"]
    # host1: ssh open=1.0, http absent=0.0
    assert matrix.values[0] == [1.0, 0.0]
    # host2: ssh filtered=0.4, http open=1.0
    assert matrix.values[1] == [0.4, 1.0]


def test_port_heatmap_empty_without_services() -> None:
    assert port_heatmap([_host("10.0.0.1")]).is_empty


# --- histogram --------------------------------------------------------------


def test_latency_histogram_buckets() -> None:
    series = latency_histogram([5.0, 12.0, 14.0, 23.0], bucket_ms=10.0)
    assert series.x == [0.0, 10.0, 20.0]
    assert series.y == [1.0, 2.0, 1.0]
    assert series.categories == ["0-10", "10-20", "20-30"]


def test_latency_histogram_empty_and_bad_bucket() -> None:
    assert latency_histogram([]).is_empty
    assert latency_histogram([1.0, 2.0], bucket_ms=0).is_empty


# --- reachability + confidence ---------------------------------------------


def test_reachability_breakdown_classification() -> None:
    hosts = [
        _host("10.0.0.1", latency_ms=2.0),  # reachable
        _host("10.0.0.2", methods=["arp"], mac="aa:bb:cc:dd:ee:ff"),  # reachable (arp)
        _host("10.0.0.3", services=[ServiceRecord(port=445, state="filtered")]),  # filtered
        _host("10.0.0.4", methods=["dns_reverse"], hostname="x"),  # unknown
    ]
    series = reachability_breakdown(hosts)
    mapping = dict(zip(series.categories, series.y, strict=True))
    assert mapping["reachable"] == 2.0
    assert mapping["filtered"] == 1.0
    assert mapping["unknown"] == 1.0


def test_reachability_unreachable_uses_scanned_total() -> None:
    hosts = [_host("192.168.1.1", latency_ms=1.0)]
    run = DiscoveryRun(targets="192.168.1.0/30")  # 2 usable hosts
    series = reachability_breakdown(hosts, run)
    mapping = dict(zip(series.categories, series.y, strict=True))
    assert mapping["unreachable"] == 1.0


def test_confidence_distribution_buckets() -> None:
    hosts = [
        _host("10.0.0.1", fingerprint=FingerprintEvidence(host="10.0.0.1", confidence=0.1)),
        _host("10.0.0.2", fingerprint=FingerprintEvidence(host="10.0.0.2", confidence=0.85)),
        _host("10.0.0.3"),  # no fingerprint -> ignored
    ]
    series = confidence_distribution(hosts)
    mapping = dict(zip(series.categories, series.y, strict=True))
    assert mapping["0-20%"] == 1.0
    assert mapping["80-100%"] == 1.0


# --- topology ---------------------------------------------------------------


def test_build_topology_nodes_and_edges() -> None:
    hosts = [
        _host("192.168.1.1", mac="aa:bb:cc:00:00:01", subnet="192.168.1.0/24"),
        _host(
            "192.168.1.50",
            subnet="192.168.1.0/24",
            methods=["passive"],
            services=[ServiceRecord(port=80, state="open", name="http")],
        ),
    ]
    graph = build_topology(hosts)
    assert "192.168.1.0/24" in graph.groups
    gateway = next(n for n in graph.nodes if n.ip == "192.168.1.1")
    assert gateway.is_gateway is True
    host_node = next(n for n in graph.nodes if n.ip == "192.168.1.50")
    assert "http" in host_node.badges
    arp_edge = next(e for e in graph.edges if e.target == "host:192.168.1.1")
    assert arp_edge.kind == "arp"
    assert any("ARP" in item for item in arp_edge.evidence)
    passive_edge = next(e for e in graph.edges if e.target == "host:192.168.1.50")
    assert passive_edge.kind == "passive"


def test_build_topology_group_by_protocol() -> None:
    hosts = [
        _host("10.0.0.1", services=[ServiceRecord(port=80, state="open", name="http")]),
        _host("10.0.0.2", services=[ServiceRecord(port=22, state="open", name="ssh")]),
    ]
    graph = build_topology(hosts, group_by="protocol")
    assert graph.grouped_by == "protocol"
    assert "http" in graph.groups
    assert "ssh" in graph.groups


# --- run comparison ---------------------------------------------------------


def _run(hosts: list[HostRecord], label_id: str) -> DiscoveryRun:
    return DiscoveryRun(id=label_id, hosts=hosts)


def test_compare_runs_reports_all_deltas() -> None:
    baseline = _run(
        [
            HostRecord(
                ip="10.0.0.1",
                latency_ms=5.0,
                services=[ServiceRecord(port=22, state="open", name="ssh")],
                fingerprint=FingerprintEvidence(
                    host="10.0.0.1", confidence=0.4,
                    os_guesses=[OsGuess(family="Linux", confidence=0.4)],
                ),
            ),
            HostRecord(ip="10.0.0.9"),  # will be removed
        ],
        "base",
    )
    candidate = _run(
        [
            HostRecord(
                ip="10.0.0.1",
                latency_ms=9.0,
                services=[
                    ServiceRecord(port=22, state="open", name="ssh"),
                    ServiceRecord(port=443, state="open", name="https"),
                ],
                fingerprint=FingerprintEvidence(
                    host="10.0.0.1", confidence=0.7,
                    os_guesses=[OsGuess(family="Linux", confidence=0.7)],
                ),
            ),
            HostRecord(ip="10.0.0.20"),  # added
        ],
        "cand",
    )
    comparison = compare_runs(baseline, candidate)
    assert comparison.added_hosts == ["10.0.0.20"]
    assert comparison.removed_hosts == ["10.0.0.9"]
    assert comparison.common_hosts == ["10.0.0.1"]

    port_change = comparison.port_changes[0]
    assert port_change.host == "10.0.0.1"
    assert port_change.opened == [443]
    assert port_change.closed == []

    assert comparison.capability_changes["10.0.0.1"] == ["+ https"]

    delta = comparison.latency_deltas[0]
    assert delta.delta_ms == pytest.approx(4.0)

    conf = comparison.confidence_changes[0]
    assert conf.delta == pytest.approx(0.3, abs=1e-6)


# --- anomalies --------------------------------------------------------------


def test_dns_latency_anomaly_respects_threshold() -> None:
    fast = ProtocolProbeResult(
        protocol="DNS", target="example.com", latency_ms=50.0,
        detail={"resolver": "1.1.1.1"},
    )
    slow = ProtocolProbeResult(
        protocol="DNS", target="example.com", latency_ms=300.0,
        detail={"resolver": "8.8.8.8"},
    )
    thresholds = AnomalyThresholds(dns_latency_ms=200.0)
    none_found = detect_anomalies([], [fast], thresholds=thresholds)
    assert not any(a.category == "dns" for a in none_found)
    found = detect_anomalies([], [slow], thresholds=thresholds)
    dns = next(a for a in found if a.category == "dns")
    assert dns.severity == "warning"
    assert "8.8.8.8" in dns.title


def test_smtp_starttls_anomaly() -> None:
    probe = ProtocolProbeResult(
        protocol="SMTP", target="legacy:25", detail={"starttls": "no", "banner": "220 legacy"}
    )
    findings = detect_anomalies([], [probe])
    assert any(a.category == "smtp" and "STARTTLS" in a.title for a in findings)


def test_ntp_offset_anomaly_threshold() -> None:
    probe = ProtocolProbeResult(
        protocol="NTP", target="t", detail={"offset_ms": "180.0", "stratum": "3"}
    )
    ok = detect_anomalies([], [probe], thresholds=AnomalyThresholds(ntp_offset_ms=500.0))
    assert not any(a.category == "ntp" for a in ok)
    bad = detect_anomalies([], [probe], thresholds=AnomalyThresholds(ntp_offset_ms=100.0))
    assert any(a.category == "ntp" for a in bad)


def test_arp_without_icmp_anomaly() -> None:
    host = HostRecord(ip="10.0.0.5", methods=["arp"], mac="aa:bb:cc:dd:ee:ff")
    findings = detect_anomalies([host])
    assert any("ARP but not ICMP" in a.title for a in findings)


def test_packet_loss_anomaly_severity() -> None:
    results = [
        PingResult(sequence=i, send_timestamp=float(i), timeout=(i % 2 == 0)) for i in range(10)
    ]
    findings = detect_anomalies([], pings={"10.0.0.7": results})
    loss = next(a for a in findings if a.id.startswith("loss:"))
    assert loss.severity == "critical"
    assert loss.host == "10.0.0.7"


def test_anomalies_sorted_by_severity() -> None:
    host = HostRecord(ip="10.0.0.5", methods=["arp"], mac="aa:bb:cc:dd:ee:ff")
    loss_results = [
        PingResult(sequence=i, send_timestamp=float(i), timeout=(i < 8)) for i in range(10)
    ]
    findings = detect_anomalies([host], pings={"10.0.0.7": loss_results})
    ranks = [f.rank for f in findings]
    assert ranks == sorted(ranks)


# --- bundle -----------------------------------------------------------------


def test_build_bundle_subnet_filter() -> None:
    hosts = [
        _host("192.168.1.1", subnet="192.168.1.0/24", latency_ms=1.0),
        _host("10.0.0.1", subnet="10.0.0.0/24", latency_ms=1.0),
    ]
    bundle = build_bundle(hosts, subnet_filter="10.0.0.0/24")
    assert bundle.host_count == 1
    assert "10.0.0.1" in bundle.host_insights
