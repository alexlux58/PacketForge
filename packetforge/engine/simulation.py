"""Local simulation mode: deterministic fake networks for demos and dev.

Every scenario populates the *same* Pydantic models that real scans produce
(:class:`HostRecord`, :class:`ServiceRecord`, :class:`FingerprintEvidence`,
:class:`ProtocolProbeResult`, :class:`PingResult`, :class:`DiscoveryRun`), so the
discovery table, protocol panels, observability charts, and reports behave
exactly as they would against a live network - just without sending a packet.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from packetforge.engine.sample_data import (
    sample_baseline_run,
    sample_pings,
    sample_probes,
    sample_run,
)
from packetforge.models.discovery import (
    DiscoveryRun,
    FingerprintEvidence,
    FingerprintSignal,
    HostRecord,
    OsGuess,
    ProtocolProbeResult,
    ServiceRecord,
)
from packetforge.models.results import PingResult

_BASE = datetime(2026, 6, 20, 21, 0, 0, tzinfo=UTC)


@dataclass(frozen=True)
class SimulatedScenario:
    """A complete, self-contained fake dataset for one situation."""

    key: str
    name: str
    description: str
    run: DiscoveryRun
    pings: dict[str, list[PingResult]] = field(default_factory=dict)
    probes: list[ProtocolProbeResult] = field(default_factory=list)
    baseline: DiscoveryRun | None = None


# --------------------------------------------------------------------------- #
# Small deterministic builders (mirror the shapes used by the real engine)
# --------------------------------------------------------------------------- #
def _at(seconds: int) -> datetime:
    return _BASE + timedelta(seconds=seconds)


def _fingerprint(host: str, family: str, confidence: float) -> FingerprintEvidence:
    return FingerprintEvidence(
        host=host,
        confidence=confidence,
        os_guesses=[OsGuess(family=family, confidence=confidence, rationale="simulated evidence")],
        signals=[
            FingerprintSignal(name="TTL/hop limit", value="64", interpretation=f"{family} TTL"),
            FingerprintSignal(name="TCP window size", value="64240", interpretation="modern stack"),
        ],
    )


def _ping_train(
    host: str,
    base_rtt: float,
    *,
    count: int = 40,
    jitter: float = 1.5,
    loss_at: set[int] | None = None,
    spike_at: dict[int, float] | None = None,
) -> list[PingResult]:
    loss_at = loss_at or set()
    spike_at = spike_at or {}
    results: list[PingResult] = []
    start = _BASE.timestamp()
    for seq in range(count):
        ts = start + seq
        if seq in loss_at:
            results.append(PingResult(sequence=seq, send_timestamp=ts, timeout=True))
            continue
        wobble = jitter * (1 if seq % 2 == 0 else -1) * ((seq % 5) / 5.0)
        rtt = max(0.1, base_rtt + wobble + spike_at.get(seq, 0.0))
        results.append(
            PingResult(
                sequence=seq,
                send_timestamp=ts,
                receive_timestamp=ts + rtt / 1000.0,
                rtt_ms=round(rtt, 2),
                reply_source=host,
                reply_ttl=64,
            )
        )
    return results


def _run(key: str, name: str, targets: str, hosts: list[HostRecord]) -> DiscoveryRun:
    return DiscoveryRun(
        id=f"sim-{key}",
        profile="Simulation",
        targets=targets,
        methods=["icmp", "tcp", "arp", "dns_reverse"],
        started_at=_BASE,
        finished_at=_BASE + timedelta(seconds=40),
        hosts=hosts,
        notes=f"Simulated scenario: {name}",
    )


# --------------------------------------------------------------------------- #
# Scenarios
# --------------------------------------------------------------------------- #
def _home_lan() -> SimulatedScenario:
    net = "192.168.0.0/24"
    hosts = [
        HostRecord(
            ip="192.168.0.1", mac="b8:27:eb:00:00:01", hostname="router.home",
            latency_ms=1.1, methods=["arp", "icmp", "tcp"], protocols=["dns"],
            services=[
                ServiceRecord(port=53, protocol="udp", state="open", name="dns"),
                ServiceRecord(port=80, state="open", name="http"),
                ServiceRecord(port=443, state="open", name="https"),
            ],
            is_gateway_candidate=True, subnet=net, confidence=0.86,
            fingerprint=_fingerprint("192.168.0.1", "Network device", 0.6),
            first_seen=_at(0), last_seen=_at(30),
        ),
        HostRecord(
            ip="192.168.0.10", mac="3c:22:fb:00:00:0a", hostname="macbook.home",
            latency_ms=2.4, methods=["arp", "icmp", "tcp"],
            services=[ServiceRecord(port=22, state="open", name="ssh")],
            subnet=net, confidence=0.72,
            fingerprint=_fingerprint("192.168.0.10", "macOS", 0.7),
            first_seen=_at(3), last_seen=_at(31),
        ),
        HostRecord(
            ip="192.168.0.21", mac="a4:83:e7:00:00:15", hostname="iphone.home",
            latency_ms=6.0, methods=["arp", "icmp"], subnet=net, confidence=0.55,
            fingerprint=_fingerprint("192.168.0.21", "iOS", 0.5),
            first_seen=_at(6), last_seen=_at(32),
        ),
        HostRecord(
            ip="192.168.0.30", mac="dc:a6:32:00:00:1e", hostname="smarttv.home",
            latency_ms=9.0, methods=["arp", "icmp", "tcp"],
            services=[ServiceRecord(port=8008, state="open", name="cast")],
            subnet=net, confidence=0.58, first_seen=_at(9), last_seen=_at(33),
        ),
        HostRecord(
            ip="192.168.0.40", mac="00:11:32:00:00:28", hostname="printer.home",
            latency_ms=12.0, methods=["arp", "tcp"],
            services=[
                ServiceRecord(port=631, state="open", name="ipp"),
                ServiceRecord(port=9100, state="open", name="jetdirect"),
            ],
            subnet=net, confidence=0.6, first_seen=_at(12), last_seen=_at(34),
        ),
    ]
    pings = {
        "192.168.0.1": _ping_train("192.168.0.1", 1.1, jitter=0.3),
        "192.168.0.10": _ping_train("192.168.0.10", 2.4, jitter=0.6),
    }
    probes = [
        ProtocolProbeResult(
            protocol="DNS", target="example.com", success=True,
            summary="NOERROR - 1 record in 9.0 ms", latency_ms=9.0,
            detail={"resolver": "192.168.0.1:53", "qname": "example.com", "qtype": "A",
                    "rcode": "NOERROR", "answers": "1", "flags": "QR,RD,RA"},
            records=["example.com -> 93.184.216.34"],
        ),
        ProtocolProbeResult(
            protocol="DHCP", target="eth0", success=True,
            summary="observed 2 DHCP message(s) passively",
            records=["DISCOVER from 3c:22:fb:00:00:0a", "ACK from b8:27:eb:00:00:01"],
            detail={"server": "192.168.0.1"},
        ),
    ]
    return SimulatedScenario(
        key="home_lan",
        name="Small home LAN",
        description="A healthy 5-device home network behind a single consumer router.",
        run=_run("home_lan", "Small home LAN", net, hosts),
        pings=pings,
        probes=probes,
    )


def _enterprise() -> SimulatedScenario:
    return SimulatedScenario(
        key="enterprise",
        name="Enterprise subnet",
        description="A multi-subnet enterprise network with mixed OSes, routers, and services "
        "(reuses the full observability demo dataset, including a baseline run to diff).",
        run=sample_run(),
        pings=sample_pings(),
        probes=sample_probes(),
        baseline=sample_baseline_run(),
    )


def _dns_issue() -> SimulatedScenario:
    net = "10.10.0.0/24"
    hosts = [
        HostRecord(
            ip="10.10.0.1", mac="aa:bb:cc:10:00:01", hostname="gw.corp",
            latency_ms=1.5, methods=["arp", "icmp", "tcp"], is_gateway_candidate=True,
            services=[ServiceRecord(port=443, state="open", name="https")],
            subnet=net, confidence=0.8, first_seen=_at(0), last_seen=_at(20),
        ),
        HostRecord(
            ip="10.10.0.53", mac="aa:bb:cc:10:00:35", hostname="dns-primary.corp",
            latency_ms=2.0, methods=["arp", "icmp", "tcp"], protocols=["dns"],
            services=[ServiceRecord(port=53, protocol="udp", state="open", name="dns")],
            subnet=net, confidence=0.82,
            fingerprint=_fingerprint("10.10.0.53", "Linux", 0.7),
            first_seen=_at(2), last_seen=_at(21),
        ),
        HostRecord(
            ip="10.10.0.54", mac="aa:bb:cc:10:00:36", hostname="dns-secondary.corp",
            latency_ms=2.2, methods=["arp", "icmp", "tcp"], protocols=["dns"],
            services=[ServiceRecord(port=53, protocol="udp", state="open", name="dns")],
            subnet=net, confidence=0.8, first_seen=_at(4), last_seen=_at(22),
        ),
    ]
    probes = [
        ProtocolProbeResult(
            protocol="DNS", target="intranet.corp", success=True,
            summary="NOERROR - 1 record in 6.0 ms", latency_ms=6.0,
            detail={"resolver": "10.10.0.53:53", "qname": "intranet.corp", "qtype": "A",
                    "rcode": "NOERROR", "answers": "1", "flags": "QR,RD,RA"},
            records=["intranet.corp -> 10.10.5.20"],
        ),
        ProtocolProbeResult(
            protocol="DNS", target="intranet.corp", success=True,
            summary="NOERROR - 1 record in 680.0 ms", latency_ms=680.0,
            detail={"resolver": "10.10.0.54:53", "qname": "intranet.corp", "qtype": "A",
                    "rcode": "NOERROR", "answers": "1", "flags": "QR,RD,RA"},
            records=["intranet.corp -> 10.10.5.20"],
        ),
        ProtocolProbeResult(
            protocol="DNS", target="ext.example.com", success=False,
            summary="SERVFAIL - 0 record(s) in 510.0 ms", latency_ms=510.0,
            detail={"resolver": "10.10.0.54:53", "qname": "ext.example.com", "qtype": "A",
                    "rcode": "SERVFAIL", "answers": "0", "flags": "QR,RD,RA"},
            warnings=["Resolver returned SERVFAIL; upstream forwarder may be unreachable."],
        ),
    ]
    return SimulatedScenario(
        key="dns_issue",
        name="DNS issue",
        description="Two resolvers where the secondary is slow (680 ms) and intermittently "
        "returns SERVFAIL - classic split-resolver latency problem.",
        run=_run("dns_issue", "DNS issue", net, hosts),
        probes=probes,
    )


def _dhcp_issue() -> SimulatedScenario:
    net = "172.16.4.0/24"
    hosts = [
        HostRecord(
            ip="172.16.4.1", mac="00:50:56:00:00:01", hostname="dhcp.corp",
            latency_ms=1.8, methods=["arp", "icmp", "tcp"], is_gateway_candidate=True,
            subnet=net, confidence=0.8, first_seen=_at(0), last_seen=_at(20),
        ),
        HostRecord(
            ip="172.16.4.66", mac="00:0c:29:00:00:42", hostname=None,
            latency_ms=3.0, methods=["arp"], subnet=net, confidence=0.4,
            first_seen=_at(5), last_seen=_at(22),
        ),
    ]
    probes = [
        ProtocolProbeResult(
            protocol="DHCP", target="eth0", success=False,
            summary="rogue DHCP suspected: 2 servers offered leases",
            records=[
                "DISCOVER from 00:0c:29:00:00:42",
                "OFFER 172.16.4.120 from 172.16.4.1 (authoritative)",
                "OFFER 172.16.4.201 from 172.16.4.66 (unexpected)",
            ],
            detail={"servers": "172.16.4.1, 172.16.4.66", "authoritative": "172.16.4.1"},
            warnings=[
                "Two DHCP servers answered on the same segment; 172.16.4.66 is not the "
                "sanctioned server. Investigate a possible rogue/misconfigured DHCP service.",
            ],
        ),
    ]
    return SimulatedScenario(
        key="dhcp_issue",
        name="DHCP issue",
        description="A rogue DHCP server answers alongside the real one, handing out leases "
        "from the wrong scope.",
        run=_run("dhcp_issue", "DHCP issue", net, hosts),
        probes=probes,
    )


def _high_latency() -> SimulatedScenario:
    net = "10.20.0.0/24"
    hosts = [
        HostRecord(
            ip="10.20.0.1", mac="aa:bb:cc:20:00:01", hostname="wan-edge",
            latency_ms=2.0, methods=["arp", "icmp", "tcp"], is_gateway_candidate=True,
            subnet=net, confidence=0.8, first_seen=_at(0), last_seen=_at(40),
        ),
        HostRecord(
            ip="10.20.0.80", hostname="app-remote", latency_ms=210.0,
            methods=["icmp", "tcp"],
            services=[ServiceRecord(port=443, state="open", name="https")],
            subnet=net, confidence=0.6,
            fingerprint=_fingerprint("10.20.0.80", "Linux", 0.55),
            first_seen=_at(4), last_seen=_at(41),
        ),
    ]
    pings = {
        "10.20.0.1": _ping_train("10.20.0.1", 2.0, jitter=0.5),
        "10.20.0.80": _ping_train(
            "10.20.0.80", 210.0, jitter=55.0,
            loss_at={5, 6, 7, 17, 18, 29, 30, 31, 32},
            spike_at={12: 400.0, 24: 650.0},
        ),
    }
    return SimulatedScenario(
        key="high_latency",
        name="High latency / jitter issue",
        description="A remote host with ~210 ms average RTT, heavy jitter, periodic loss, and "
        "two large spikes - triggers latency, loss, and RTT-outlier findings.",
        run=_run("high_latency", "High latency / jitter issue", net, hosts),
        pings=pings,
    )


def _smtp_no_starttls() -> SimulatedScenario:
    net = "10.30.0.0/24"
    hosts = [
        HostRecord(
            ip="10.30.0.25", mac="aa:bb:cc:30:00:19", hostname="legacy-mail",
            latency_ms=5.0, methods=["arp", "icmp", "tcp"], protocols=["smtp"],
            services=[
                ServiceRecord(port=25, state="open", name="smtp", banner="220 legacy-mail ESMTP"),
            ],
            subnet=net, confidence=0.7,
            fingerprint=_fingerprint("10.30.0.25", "Linux", 0.6),
            first_seen=_at(0), last_seen=_at(20),
        ),
    ]
    probes = [
        ProtocolProbeResult(
            protocol="SMTP", target="10.30.0.25:25", success=True,
            summary="banner received; 3 EHLO capabilities; STARTTLS not advertised",
            latency_ms=38.0,
            detail={"banner": "220 legacy-mail ESMTP Postfix", "starttls": "no"},
            records=["PIPELINING", "SIZE 10240000", "8BITMIME"],
            warnings=["No STARTTLS advertised; this server may accept cleartext mail."],
        ),
    ]
    return SimulatedScenario(
        key="smtp_no_starttls",
        name="SMTP STARTTLS missing",
        description="A mail server that does not advertise STARTTLS, so mail can transit in "
        "cleartext.",
        run=_run("smtp_no_starttls", "SMTP STARTTLS missing", net, hosts),
        probes=probes,
    )


def _snmp_errors() -> SimulatedScenario:
    net = "10.40.0.0/24"
    hosts = [
        HostRecord(
            ip="10.40.0.1", mac="aa:bb:cc:40:00:01", hostname="dist-switch",
            latency_ms=1.6, methods=["arp", "icmp", "tcp"], protocols=["snmp"],
            is_gateway_candidate=True,
            services=[ServiceRecord(port=161, protocol="udp", state="open", name="snmp")],
            subnet=net, confidence=0.85,
            fingerprint=_fingerprint("10.40.0.1", "Network device", 0.62),
            first_seen=_at(0), last_seen=_at(20),
        ),
    ]
    probes = [
        ProtocolProbeResult(
            protocol="SNMP", target="10.40.0.1", success=True,
            summary="6 OID value(s) returned in 18.0 ms", latency_ms=18.0,
            detail={
                "sysName": "dist-switch", "sysDescr": "Lab Switch OS 3.1",
                "sysUpTime": "9981200", "ifInErrors": "1843",
                "ifOutDiscards": "266", "ifInDiscards": "57",
            },
        ),
    ]
    return SimulatedScenario(
        key="snmp_errors",
        name="SNMP interface errors",
        description="A switch reporting high and rising ifInErrors / ifOutDiscards counters - "
        "often a duplex mismatch, bad cable, or congestion.",
        run=_run("snmp_errors", "SNMP interface errors", net, hosts),
        probes=probes,
    )


def _ntp_drift() -> SimulatedScenario:
    net = "10.50.0.0/24"
    hosts = [
        HostRecord(
            ip="10.50.0.123", mac="aa:bb:cc:50:00:7b", hostname="ntp.corp",
            latency_ms=4.0, methods=["arp", "icmp", "tcp"], protocols=["ntp"],
            services=[ServiceRecord(port=123, protocol="udp", state="open", name="ntp")],
            subnet=net, confidence=0.7,
            fingerprint=_fingerprint("10.50.0.123", "Linux", 0.6),
            first_seen=_at(0), last_seen=_at(20),
        ),
    ]
    probes = [
        ProtocolProbeResult(
            protocol="NTP", target="10.50.0.123", success=True,
            summary="stratum 4, offset 264.00 ms, delay 12.00 ms", latency_ms=12.0,
            detail={"stratum": "4", "offset_ms": "264.00", "delay_ms": "12.00",
                    "ref_id": "LOCL", "poll": "10"},
        ),
    ]
    return SimulatedScenario(
        key="ntp_drift",
        name="NTP clock drift",
        description="An NTP server whose clock offset (264 ms) far exceeds the safe threshold; "
        "clients syncing here will drift.",
        run=_run("ntp_drift", "NTP clock drift", net, hosts),
        probes=probes,
    )


def _gateway_discovery() -> SimulatedScenario:
    net = "192.168.50.0/24"
    hosts = [
        HostRecord(
            ip="192.168.50.1", mac="00:1b:0d:00:00:01", hostname=None,
            latency_ms=None, methods=["arp"],  # answers ARP but not ICMP
            protocols=["ospf"], is_gateway_candidate=True,
            services=[ServiceRecord(port=179, state="open", name="bgp")],
            subnet=net, confidence=0.7,
            fingerprint=_fingerprint("192.168.50.1", "Network device", 0.58),
            first_seen=_at(0), last_seen=_at(20),
        ),
        HostRecord(
            ip="192.168.50.254", mac="00:1b:0d:00:00:fe", hostname="hsrp-standby",
            latency_ms=None, methods=["arp"], is_gateway_candidate=True,
            subnet=net, confidence=0.65, first_seen=_at(2), last_seen=_at(21),
        ),
        HostRecord(
            ip="192.168.50.20", mac="00:1b:0d:00:00:14", hostname="server-a",
            latency_ms=3.0, methods=["arp", "icmp", "tcp"],
            services=[ServiceRecord(port=22, state="open", name="ssh")],
            subnet=net, confidence=0.74,
            fingerprint=_fingerprint("192.168.50.20", "Linux", 0.7),
            first_seen=_at(4), last_seen=_at(22),
        ),
    ]
    probes = [
        ProtocolProbeResult(
            protocol="OSPF", target="eth0", success=True,
            summary="observed 3 OSPF packet(s) from 2 router(s)",
            detail={"routers": "192.168.50.1, 192.168.50.254"},
            records=[
                "Hello from RID 192.168.50.1 area 0.0.0.0",
                "Hello from RID 192.168.50.254 area 0.0.0.0",
                "Hello from RID 192.168.50.1 area 0.0.0.0",
            ],
        ),
        ProtocolProbeResult(
            protocol="BGP", target="192.168.50.1:179", success=True,
            summary="TCP/179 reachable in 2.0 ms (reachability only)", latency_ms=2.0,
            detail={"tcp_179": "open"},
        ),
    ]
    return SimulatedScenario(
        key="gateway_discovery",
        name="Router / gateway discovery",
        description="Two first-hop routers (active + standby) that answer ARP but not ICMP, "
        "plus OSPF/BGP evidence - exercises gateway and ARP-without-ICMP detection.",
        run=_run("gateway_discovery", "Router / gateway discovery", net, hosts),
        probes=probes,
    )


_BUILDERS: dict[str, Callable[[], SimulatedScenario]] = {
    "home_lan": _home_lan,
    "enterprise": _enterprise,
    "dns_issue": _dns_issue,
    "dhcp_issue": _dhcp_issue,
    "high_latency": _high_latency,
    "smtp_no_starttls": _smtp_no_starttls,
    "snmp_errors": _snmp_errors,
    "ntp_drift": _ntp_drift,
    "gateway_discovery": _gateway_discovery,
}


def scenario_keys() -> list[str]:
    return list(_BUILDERS)


def list_scenarios() -> list[tuple[str, str, str]]:
    """Return ``(key, name, description)`` triples in display order."""
    scenarios = [build_scenario(key) for key in _BUILDERS]
    return [(s.key, s.name, s.description) for s in scenarios]


def build_scenario(key: str) -> SimulatedScenario:
    try:
        builder = _BUILDERS[key]
    except KeyError as exc:
        raise KeyError(f"unknown simulation scenario: {key!r}") from exc
    return builder()
