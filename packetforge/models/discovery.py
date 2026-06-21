from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

DiscoveryMethod = Literal[
    "icmp",
    "tcp",
    "tcp_syn",
    "udp",
    "arp",
    "dns_reverse",
    "passive",
]

PortState = Literal["open", "closed", "filtered", "open|filtered", "unknown"]
TransportProtocol = Literal["tcp", "udp"]


def _now() -> datetime:
    return datetime.now(tz=UTC)


class ServiceRecord(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    port: int = Field(ge=0, le=65535)
    protocol: TransportProtocol = "tcp"
    state: PortState = "unknown"
    name: str | None = None
    banner: str | None = None
    last_seen: datetime = Field(default_factory=_now)

    @property
    def key(self) -> tuple[int, TransportProtocol]:
        return (self.port, self.protocol)


class FingerprintSignal(BaseModel):
    """A single observed fingerprinting signal and how it was interpreted."""

    model_config = ConfigDict(validate_assignment=True)

    name: str
    value: str
    interpretation: str = ""
    source: DiscoveryMethod | Literal["fingerprint", "passive", "service"] = "fingerprint"
    weight: float = Field(default=1.0, ge=0.0, le=10.0)


class OsGuess(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    family: str
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = ""


class FingerprintEvidence(BaseModel):
    """Aggregated fingerprint evidence for a single host.

    PacketForge never claims an exact OS. It reports ranked "likely" families
    with an explicit confidence score and the raw signals behind them.
    """

    model_config = ConfigDict(validate_assignment=True)

    host: str
    signals: list[FingerprintSignal] = Field(default_factory=list)
    os_guesses: list[OsGuess] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    updated_at: datetime = Field(default_factory=_now)

    @property
    def best_guess(self) -> OsGuess | None:
        return self.os_guesses[0] if self.os_guesses else None

    @property
    def summary(self) -> str:
        guess = self.best_guess
        if guess is None or guess.confidence < 0.2:
            return "insufficient evidence"
        qualifier = "likely" if guess.confidence < 0.75 else "very likely"
        return f"{qualifier} {guess.family} ({guess.confidence * 100:.0f}%)"


class HostRecord(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    ip: str
    mac: str | None = None
    vendor: str | None = None
    hostname: str | None = None
    latency_ms: float | None = None
    services: list[ServiceRecord] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    methods: list[DiscoveryMethod] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    is_gateway_candidate: bool = False
    subnet: str | None = None
    fingerprint: FingerprintEvidence | None = None
    first_seen: datetime = Field(default_factory=_now)
    last_seen: datetime = Field(default_factory=_now)

    @property
    def open_ports(self) -> list[int]:
        return sorted(s.port for s in self.services if s.state == "open")


class ProtocolProbeResult(BaseModel):
    """Result of a single protocol troubleshooter probe.

    Safe by construction: probes are read-only by default and any active or
    lab-only behaviour is recorded in ``warnings`` and gated upstream.
    """

    model_config = ConfigDict(validate_assignment=True)

    protocol: str
    target: str
    success: bool = False
    summary: str = ""
    detail: dict[str, str] = Field(default_factory=dict)
    records: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    latency_ms: float | None = None
    lab_mode: bool = False
    timestamp: datetime = Field(default_factory=_now)


DEFAULT_TCP_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 995, 3389, 8080,
)
DEFAULT_UDP_PORTS: tuple[int, ...] = (53, 67, 123, 137, 161, 500)


def _default_methods() -> list[DiscoveryMethod]:
    return ["icmp", "tcp"]


class DiscoveryConfig(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    targets: str = "192.168.1.0/24"
    methods: list[DiscoveryMethod] = Field(default_factory=_default_methods)
    profile_name: str = "Balanced"
    interface: str | None = None
    tcp_ports: list[int] = Field(default_factory=lambda: list(DEFAULT_TCP_PORTS))
    udp_ports: list[int] = Field(default_factory=lambda: list(DEFAULT_UDP_PORTS))
    resolve_hostnames: bool = True
    grab_banners: bool = True
    passive_seconds: int = Field(default=15, ge=1, le=600)
    record_pcap: bool = False
    max_targets: int = Field(default=4096, ge=1, le=65536)


class DiscoveryRun(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    profile: str = "Balanced"
    targets: str = ""
    methods: list[DiscoveryMethod] = Field(default_factory=list)
    interface: str | None = None
    started_at: datetime = Field(default_factory=_now)
    finished_at: datetime | None = None
    hosts: list[HostRecord] = Field(default_factory=list)
    notes: str = ""

    @property
    def host_count(self) -> int:
        return len(self.hosts)

    @property
    def label(self) -> str:
        stamp = self.started_at.strftime("%Y-%m-%d %H:%M:%S")
        return f"{stamp} - {self.profile} - {self.host_count} hosts"
