from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

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


@dataclass
class SampleData:
    """A self-contained, deterministic dataset for demoing observability."""

    run: DiscoveryRun
    pings: dict[str, list[PingResult]] = field(default_factory=dict)
    probes: list[ProtocolProbeResult] = field(default_factory=list)


def _fingerprint(host: str, family: str, confidence: float) -> FingerprintEvidence:
    return FingerprintEvidence(
        host=host,
        confidence=confidence,
        os_guesses=[OsGuess(family=family, confidence=confidence, rationale="sample evidence")],
        signals=[
            FingerprintSignal(name="TTL/hop limit", value="64", interpretation=f"{family} TTL"),
            FingerprintSignal(name="TCP window size", value="64240", interpretation="modern stack"),
        ],
    )


def sample_hosts() -> list[HostRecord]:
    hosts: list[HostRecord] = []

    def at(seconds: int) -> datetime:
        return _BASE + timedelta(seconds=seconds)

    hosts.append(
        HostRecord(
            ip="192.168.1.1",
            mac="aa:bb:cc:00:00:01",
            hostname="gw.lab",
            latency_ms=1.2,
            methods=["arp", "icmp", "tcp"],
            protocols=["snmp"],
            services=[
                ServiceRecord(port=53, protocol="udp", state="open", name="dns"),
                ServiceRecord(port=80, state="open", name="http"),
                ServiceRecord(port=161, protocol="udp", state="open", name="snmp"),
                ServiceRecord(port=443, state="open", name="https"),
            ],
            is_gateway_candidate=True,
            subnet="192.168.1.0/24",
            confidence=0.82,
            fingerprint=_fingerprint("192.168.1.1", "Network device", 0.55),
            first_seen=at(0),
            last_seen=at(30),
        )
    )
    hosts.append(
        HostRecord(
            ip="192.168.1.10",
            mac="aa:bb:cc:00:00:0a",
            hostname="dns1.lab",
            latency_ms=3.4,
            methods=["arp", "icmp", "tcp"],
            services=[
                ServiceRecord(
                    port=22, state="open", name="ssh", banner="SSH-2.0-OpenSSH_8.9 Ubuntu"
                ),
                ServiceRecord(port=53, protocol="udp", state="open", name="dns"),
            ],
            subnet="192.168.1.0/24",
            confidence=0.78,
            fingerprint=_fingerprint("192.168.1.10", "Linux", 0.82),
            first_seen=at(2),
            last_seen=at(31),
        )
    )
    hosts.append(
        HostRecord(
            ip="192.168.1.20",
            mac="aa:bb:cc:00:00:14",
            hostname="mail.lab",
            latency_ms=5.1,
            methods=["arp", "icmp", "tcp"],
            services=[
                ServiceRecord(port=25, state="open", name="smtp", banner="220 mail.lab ESMTP"),
                ServiceRecord(port=587, state="open", name="submission"),
            ],
            subnet="192.168.1.0/24",
            confidence=0.7,
            fingerprint=_fingerprint("192.168.1.20", "Linux", 0.66),
            first_seen=at(5),
            last_seen=at(33),
        )
    )
    hosts.append(
        HostRecord(
            ip="192.168.1.25",
            mac="aa:bb:cc:00:00:19",
            hostname=None,
            latency_ms=None,
            methods=["arp"],
            services=[ServiceRecord(port=445, state="filtered", name="smb")],
            subnet="192.168.1.0/24",
            confidence=0.35,
            first_seen=at(8),
            last_seen=at(34),
        )
    )
    hosts.append(
        HostRecord(
            ip="192.168.1.50",
            hostname="ws-50.lab",
            latency_ms=12.0,
            methods=["icmp", "tcp"],
            services=[
                ServiceRecord(port=135, state="open", name="msrpc"),
                ServiceRecord(port=139, state="open", name="netbios"),
                ServiceRecord(port=445, state="open", name="smb"),
                ServiceRecord(port=3389, state="open", name="rdp"),
            ],
            subnet="192.168.1.0/24",
            confidence=0.74,
            fingerprint=_fingerprint("192.168.1.50", "Windows", 0.71),
            first_seen=at(11),
            last_seen=at(35),
        )
    )
    hosts.append(
        HostRecord(
            ip="192.168.1.77",
            hostname=None,
            latency_ms=88.0,
            methods=["icmp"],
            subnet="192.168.1.0/24",
            confidence=0.4,
            first_seen=at(15),
            last_seen=at(36),
        )
    )
    hosts.append(
        HostRecord(
            ip="10.0.0.1",
            mac="aa:bb:cc:10:00:01",
            hostname="edge-rtr",
            latency_ms=2.0,
            methods=["arp", "tcp"],
            protocols=["bgp", "ospf"],
            services=[
                ServiceRecord(port=179, state="open", name="bgp"),
                ServiceRecord(port=22, state="open", name="ssh", banner="SSH-2.0-Cisco-1.25"),
            ],
            is_gateway_candidate=True,
            subnet="10.0.0.0/24",
            confidence=0.8,
            fingerprint=_fingerprint("10.0.0.1", "Network device", 0.6),
            first_seen=at(18),
            last_seen=at(37),
        )
    )
    hosts.append(
        HostRecord(
            ip="10.0.0.5",
            mac="aa:bb:cc:10:00:05",
            hostname="ntp.lab",
            latency_ms=4.0,
            methods=["arp", "icmp", "tcp"],
            services=[ServiceRecord(port=123, protocol="udp", state="open", name="ntp")],
            subnet="10.0.0.0/24",
            confidence=0.62,
            fingerprint=_fingerprint("10.0.0.5", "Linux", 0.5),
            first_seen=at(21),
            last_seen=at(38),
        )
    )
    return hosts


def sample_run() -> DiscoveryRun:
    hosts = sample_hosts()
    return DiscoveryRun(
        id="sample-run-current",
        profile="Balanced",
        targets="192.168.1.0/24 10.0.0.0/24",
        methods=["icmp", "tcp", "arp", "dns_reverse"],
        started_at=_BASE,
        finished_at=_BASE + timedelta(seconds=40),
        hosts=hosts,
        notes="Sample data for observability demo.",
    )


def sample_baseline_run() -> DiscoveryRun:
    """An earlier run, so run-comparison has something to diff against."""
    hosts = [h.model_copy(deep=True) for h in sample_hosts()]
    by_ip = {h.ip: h for h in hosts}
    # Mail server previously had no submission port and lower confidence.
    mail = by_ip["192.168.1.20"]
    mail.services = [ServiceRecord(port=25, state="open", name="smtp")]
    if mail.fingerprint:
        mail.fingerprint.confidence = 0.5
    # Windows workstation previously did not expose RDP.
    ws = by_ip["192.168.1.50"]
    ws.services = [s for s in ws.services if s.port != 3389]
    ws.latency_ms = 9.0
    # A host that has since disappeared.
    hosts.append(
        HostRecord(
            ip="192.168.1.200",
            hostname="old-printer",
            latency_ms=20.0,
            methods=["icmp"],
            services=[ServiceRecord(port=9100, state="open", name="jetdirect")],
            subnet="192.168.1.0/24",
            confidence=0.5,
        )
    )
    # 192.168.1.77 was not present before.
    hosts = [h for h in hosts if h.ip != "192.168.1.77"]
    return DiscoveryRun(
        id="sample-run-baseline",
        profile="Balanced",
        targets="192.168.1.0/24 10.0.0.0/24",
        started_at=_BASE - timedelta(hours=2),
        finished_at=_BASE - timedelta(hours=2) + timedelta(seconds=42),
        hosts=hosts,
        notes="Earlier sample baseline run.",
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
        rtt = base_rtt + wobble + spike_at.get(seq, 0.0)
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


def sample_pings() -> dict[str, list[PingResult]]:
    return {
        "192.168.1.1": _ping_train("192.168.1.1", 1.2, jitter=0.4),
        "192.168.1.10": _ping_train("192.168.1.10", 3.4, jitter=1.0, spike_at={17: 60.0}),
        "192.168.1.77": _ping_train(
            "192.168.1.77", 90.0, jitter=15.0, loss_at={3, 4, 11, 19, 27, 28}
        ),
        "10.0.0.5": _ping_train("10.0.0.5", 4.0, jitter=1.2),
    }


def sample_probes() -> list[ProtocolProbeResult]:
    probes: list[ProtocolProbeResult] = []
    probes.append(
        ProtocolProbeResult(
            protocol="DNS", target="example.com", success=True,
            summary="NOERROR - 1 record in 8.0 ms", latency_ms=8.0,
            detail={"resolver": "192.168.1.10:53", "qname": "example.com", "qtype": "A",
                    "rcode": "NOERROR", "answers": "1", "flags": "QR,RD,RA"},
            records=["example.com -> 93.184.216.34"],
        )
    )
    probes.append(
        ProtocolProbeResult(
            protocol="DNS", target="example.com", success=True,
            summary="NOERROR - 1 record in 240.0 ms", latency_ms=240.0,
            detail={"resolver": "8.8.8.8:53", "qname": "example.com", "qtype": "A",
                    "rcode": "NOERROR", "answers": "1", "flags": "QR,RD,RA"},
            records=["example.com -> 93.184.216.34"],
        )
    )
    probes.append(
        ProtocolProbeResult(
            protocol="DHCP", target="eth0", success=True,
            summary="observed 3 DHCP message(s) passively",
            records=["DISCOVER from aa:bb:cc:00:00:50", "OFFER from aa:bb:cc:00:00:01",
                     "ACK from aa:bb:cc:00:00:01"],
            detail={"server": "192.168.1.1"},
        )
    )
    probes.append(
        ProtocolProbeResult(
            protocol="SNMP", target="192.168.1.1", success=True,
            summary="4 OID value(s) returned in 15.0 ms", latency_ms=15.0,
            detail={"sysName": "gw.lab", "sysDescr": "Lab Router OS 1.2",
                    "sysUpTime": "1180400", "ifInErrors": "42", "ifOutDiscards": "0"},
        )
    )
    probes.append(
        ProtocolProbeResult(
            protocol="SMTP", target="mail.lab:25", success=True,
            summary="banner received; 5 EHLO capabilities; STARTTLS available", latency_ms=22.0,
            detail={"banner": "220 mail.lab ESMTP Postfix", "starttls": "yes"},
            records=["PIPELINING", "SIZE 10240000", "STARTTLS", "8BITMIME", "DSN"],
        )
    )
    probes.append(
        ProtocolProbeResult(
            protocol="SMTP", target="legacy.lab:25", success=True,
            summary="banner received; 3 caps; STARTTLS not advertised", latency_ms=45.0,
            detail={"banner": "220 legacy.lab ESMTP", "starttls": "no"},
            records=["PIPELINING", "SIZE 5120000", "8BITMIME"],
            warnings=["No STARTTLS advertised; this server may accept cleartext."],
        )
    )
    probes.append(
        ProtocolProbeResult(
            protocol="NTP", target="10.0.0.5", success=True,
            summary="stratum 3, offset 4.20 ms, delay 8.10 ms", latency_ms=8.1,
            detail={"stratum": "3", "offset_ms": "4.20", "delay_ms": "8.10"},
        )
    )
    probes.append(
        ProtocolProbeResult(
            protocol="NTP", target="time.bad.lab", success=True,
            summary="stratum 4, offset 180.00 ms, delay 30.00 ms", latency_ms=30.0,
            detail={"stratum": "4", "offset_ms": "180.00", "delay_ms": "30.00"},
        )
    )
    probes.append(
        ProtocolProbeResult(
            protocol="BGP", target="10.0.0.1:179", success=True,
            summary="TCP/179 reachable in 2.0 ms (reachability only)", latency_ms=2.0,
            detail={"tcp_179": "open"},
        )
    )
    probes.append(
        ProtocolProbeResult(
            protocol="OSPF", target="eth1", success=True,
            summary="observed 2 OSPF packet(s) from 1 router(s)",
            detail={"routers": "10.0.0.1"},
            records=[
                "Hello from RID 10.0.0.1 area 0.0.0.0",
                "Hello from RID 10.0.0.1 area 0.0.0.0",
            ],
        )
    )
    probes.append(
        ProtocolProbeResult(
            protocol="STP", target="eth0", success=True,
            summary="observed 1 BPDU(s); 1 root bridge(s)",
            detail={"roots": "32768/aa:bb:cc:00:00:01"},
            records=["root 32768/aa:bb:cc:00:00:01 cost 0 bridge 32768/aa:bb:cc:00:00:01"],
        )
    )
    return probes


def sample_data() -> SampleData:
    return SampleData(run=sample_run(), pings=sample_pings(), probes=sample_probes())
