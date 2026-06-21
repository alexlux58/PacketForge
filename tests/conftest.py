"""Shared, deterministic fixtures for PacketForge's test-suite.

Nothing here touches the live network or requires elevated privileges. Scapy
``send``/``sr``/``sr1``/``sniff`` calls are always mocked by the individual
tests using the fakes provided below.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from typing import Any

import pytest

pytest.importorskip("pydantic")
pytest.importorskip("scapy")

from packetforge.models.discovery import (
    FingerprintEvidence,
    HostRecord,
    OsGuess,
    ServiceRecord,
)
from packetforge.models.results import PingResult


# --------------------------------------------------------------------------- #
# Fake hosts / services / fingerprints
# --------------------------------------------------------------------------- #
@pytest.fixture
def make_service() -> Callable[..., ServiceRecord]:
    def _make(port: int = 80, **kwargs: Any) -> ServiceRecord:
        defaults: dict[str, Any] = {
            "protocol": "tcp",
            "state": "open",
            "name": "http",
        }
        defaults.update(kwargs)
        return ServiceRecord(port=port, **defaults)

    return _make


@pytest.fixture
def make_fingerprint() -> Callable[..., FingerprintEvidence]:
    def _make(host: str = "10.0.0.1", *, family: str = "Linux", confidence: float = 0.6,
              ) -> FingerprintEvidence:
        return FingerprintEvidence(
            host=host,
            os_guesses=[OsGuess(family=family, confidence=confidence, rationale="ttl=64")],
            confidence=confidence,
        )

    return _make


@pytest.fixture
def make_host(make_service: Callable[..., ServiceRecord]) -> Callable[..., HostRecord]:
    def _make(ip: str = "10.0.0.1", **kwargs: Any) -> HostRecord:
        defaults: dict[str, Any] = {
            "methods": ["tcp"],
            "latency_ms": 4.2,
            "subnet": "10.0.0.0/24",
        }
        defaults.update(kwargs)
        if "services" not in defaults:
            defaults["services"] = [make_service()]
        return HostRecord(ip=ip, **defaults)

    return _make


# --------------------------------------------------------------------------- #
# Fake ping results
# --------------------------------------------------------------------------- #
@pytest.fixture
def make_ping_result() -> Callable[..., PingResult]:
    def _make(sequence: int = 1, *, rtt_ms: float | None = 5.0, **kwargs: Any) -> PingResult:
        send_ts = kwargs.pop("send_timestamp", float(sequence))
        if rtt_ms is None:
            kwargs.setdefault("timeout", True)
            return PingResult(sequence=sequence, send_timestamp=send_ts, **kwargs)
        kwargs.setdefault("receive_timestamp", send_ts + rtt_ms / 1000.0)
        kwargs.setdefault("reply_source", "10.0.0.1")
        kwargs.setdefault("reply_ttl", 64)
        kwargs.setdefault("icmp_type", 0)
        return PingResult(sequence=sequence, send_timestamp=send_ts, rtt_ms=rtt_ms, **kwargs)

    return _make


@pytest.fixture
def make_ping_results(
    make_ping_result: Callable[..., PingResult],
) -> Callable[[Sequence[float | None]], list[PingResult]]:
    def _make(rtts: Sequence[float | None]) -> list[PingResult]:
        return [make_ping_result(index + 1, rtt_ms=rtt) for index, rtt in enumerate(rtts)]

    return _make


# --------------------------------------------------------------------------- #
# Fake probe replies (wire bytes) and timeout/error injection
# --------------------------------------------------------------------------- #
@pytest.fixture
def dns_response_bytes() -> Callable[..., bytes]:
    def _make(name: str = "example.com", addr: str = "93.184.216.34") -> bytes:
        from scapy.layers.dns import DNS, DNSQR, DNSRR

        response = DNS(
            id=0x1234,
            qr=1,
            rd=1,
            ra=1,
            rcode=0,
            qd=DNSQR(qname=name, qtype=1),
            an=DNSRR(rrname=name, type=1, rdata=addr, ttl=300),
        )
        return bytes(response)

    return _make


@pytest.fixture
def ntp_response_bytes() -> Callable[..., bytes]:
    def _make(stratum: int = 2) -> bytes:
        from scapy.layers.ntp import NTP

        # recv/sent expressed in NTP seconds (post-2036-safe small offset is fine).
        response = NTP(version=4, mode=4, stratum=stratum, recv=3_900_000_000,
                       sent=3_900_000_000)
        return bytes(response)

    return _make


@pytest.fixture
def snmp_response_bytes() -> Callable[..., bytes]:
    def _make(community: str = "public", sys_name: str = "router1") -> bytes:
        from scapy.asn1.asn1 import ASN1_OID, ASN1_STRING
        from scapy.layers.snmp import SNMP, SNMPresponse, SNMPvarbind

        varbind = SNMPvarbind(
            oid=ASN1_OID("1.3.6.1.2.1.1.5.0"),
            value=ASN1_STRING(sys_name.encode()),
        )
        response = SNMP(community=community, PDU=SNMPresponse(varbindlist=[varbind]))
        return bytes(response)

    return _make


class FakeTCPSocket:
    """A minimal stand-in for ``socket.create_connection`` results."""

    def __init__(self, recv_chunks: Iterable[bytes] | None = None) -> None:
        self._recv: list[bytes] = list(recv_chunks or [])
        self.sent = b""
        self.closed = False
        self.timeout: float | None = None

    def __enter__(self) -> FakeTCPSocket:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def settimeout(self, timeout: float | None) -> None:
        self.timeout = timeout

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, _size: int = 4096) -> bytes:
        return self._recv.pop(0) if self._recv else b""

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_tcp_socket() -> type[FakeTCPSocket]:
    return FakeTCPSocket


# --------------------------------------------------------------------------- #
# Qt (headless) and diagnostics helpers
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def qt_app() -> Any:
    qtcore = pytest.importorskip("PySide6.QtCore")
    return qtcore.QCoreApplication.instance() or qtcore.QCoreApplication([])


@pytest.fixture
def diagnostics() -> Any:
    """A fresh Diagnostics instance with its ring handler attached to the logger."""
    import logging

    from packetforge.diagnostics import LOGGER_NAME, Diagnostics

    diag = Diagnostics(capacity=100)
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    diag.ring.setLevel(logging.DEBUG)
    logger.addHandler(diag.ring)
    try:
        yield diag
    finally:
        logger.removeHandler(diag.ring)
