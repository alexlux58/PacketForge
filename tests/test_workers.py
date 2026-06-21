from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

pytest.importorskip("pydantic")
pytest.importorskip("scapy")
pytest.importorskip("PySide6")

from packetforge.engine import discovery, ping_engine, sender
from packetforge.engine.sender import SendOptions
from packetforge.models.discovery import (
    DiscoveryConfig,
    FingerprintEvidence,
    HostRecord,
    ProtocolProbeResult,
)
from packetforge.models.observability import ObservabilityBundle
from packetforge.models.packet import IPv4Layer, PacketConfig
from packetforge.models.ping import PingConfig
from packetforge.ui import workers
from packetforge.ui.workers import (
    DiscoveryWorker,
    FingerprintWorker,
    ObservabilityWorker,
    PingWorker,
    ProtocolWorker,
    SendWorker,
)

pytestmark = pytest.mark.usefixtures("qt_app")


def _packet() -> Any:
    from packetforge.engine.builder import build_packet

    return build_packet(PacketConfig(layers=[IPv4Layer(dst="192.0.2.1")]))


# --------------------------------------------------------------------------- #
# PingWorker
# --------------------------------------------------------------------------- #
def test_ping_worker_success_emits_results(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ping_engine, "sr1", lambda *a, **k: None)  # all timeouts, no network
    worker = PingWorker(PingConfig(destination="192.0.2.1", count=2, interval_ms=10))
    results: list[Any] = []
    summaries: list[Any] = []
    completed: list[tuple[Any, Any]] = []
    worker.result_ready.connect(results.append)
    worker.summary_ready.connect(summaries.append)
    worker.completed.connect(lambda r, p: completed.append((r, p)))

    worker.run()

    assert len(results) == 2
    assert len(summaries) == 2
    assert len(completed) == 1
    assert len(completed[0][0]) == 2


def test_ping_worker_cancel_stops_early(monkeypatch: pytest.MonkeyPatch) -> None:
    worker = PingWorker(PingConfig(destination="192.0.2.1", count=10, interval_ms=10))

    def stop_then_timeout(*_a: Any, **_k: Any) -> None:
        worker.stop()  # request cancel after the first probe
        return None

    monkeypatch.setattr(ping_engine, "sr1", stop_then_timeout)
    completed: list[tuple[Any, Any]] = []
    worker.completed.connect(lambda r, p: completed.append((r, p)))

    worker.run()

    assert completed
    assert len(completed[0][0]) == 1  # cancelled after the first result


def test_ping_worker_failure_emits_failed(monkeypatch: pytest.MonkeyPatch) -> None:
    worker = PingWorker(PingConfig(destination="192.0.2.1", count=1))

    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("kaboom")

    monkeypatch.setattr(worker.engine, "run", boom)
    failures: list[str] = []
    events: list[Any] = []
    worker.failed.connect(failures.append)
    worker.error_occurred.connect(events.append)

    worker.run()

    # The GUI only ever sees the safe summary - never the raw exception text.
    assert failures
    assert "kaboom" not in failures[0]
    assert events and events[0].category == "unknown"
    assert "kaboom" in events[0].traceback  # full detail is preserved for logging


# --------------------------------------------------------------------------- #
# SendWorker
# --------------------------------------------------------------------------- #
def test_send_worker_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sender, "send", lambda *a, **k: "sent-1")
    worker = SendWorker(_packet(), SendOptions(function="send"))
    completed: list[Any] = []
    worker.completed.connect(completed.append)

    worker.run()

    assert completed == ["sent-1"]


def test_send_worker_permission_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(*_a: Any, **_k: Any) -> Any:
        raise PermissionError("need root")

    monkeypatch.setattr(sender, "send", denied)
    worker = SendWorker(_packet(), SendOptions(function="send"))
    failures: list[str] = []
    events: list[Any] = []
    worker.failed.connect(failures.append)
    worker.error_occurred.connect(events.append)

    worker.run()

    assert failures
    assert "permission" in failures[0].lower()
    assert events and events[0].category == "permission_denied"


def test_send_worker_records_last_packet_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    from packetforge.diagnostics import get_diagnostics

    monkeypatch.setattr(sender, "send", lambda *a, **k: None)
    worker = SendWorker(_packet(), SendOptions(function="send"))
    worker.run()
    assert get_diagnostics().last_packet_summary is not None


# --------------------------------------------------------------------------- #
# DiscoveryWorker
# --------------------------------------------------------------------------- #
def test_discovery_worker_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        discovery, "_tcp_connect", lambda *a, **k: ("open", None, 2.0)
    )
    config = DiscoveryConfig(
        targets="10.0.0.1", methods=["tcp"], tcp_ports=[80], resolve_hostnames=False
    )
    worker = DiscoveryWorker(config)
    completed: list[Any] = []
    worker.completed.connect(completed.append)

    worker.run()

    # host_found is emitted from a pool thread (queued); the completed run is authoritative.
    assert completed
    assert completed[0].host_count == 1
    assert completed[0].hosts[0].ip == "10.0.0.1"


def test_discovery_worker_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    worker = DiscoveryWorker(DiscoveryConfig())

    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("discovery boom")

    monkeypatch.setattr(worker.engine, "run", boom)
    failures: list[str] = []
    events: list[Any] = []
    worker.failed.connect(failures.append)
    worker.error_occurred.connect(events.append)

    worker.run()

    assert failures
    assert "discovery boom" not in failures[0]
    assert events and events[0].source == "Discovery Center"


# --------------------------------------------------------------------------- #
# FingerprintWorker
# --------------------------------------------------------------------------- #
def test_fingerprint_worker_success(monkeypatch: pytest.MonkeyPatch) -> None:
    evidence = FingerprintEvidence(host="10.0.0.1")
    monkeypatch.setattr(workers, "fingerprint_host", lambda *a, **k: evidence)
    worker = FingerprintWorker("10.0.0.1")
    completed: list[Any] = []
    worker.completed.connect(completed.append)

    worker.run()

    assert completed == [evidence]


def test_fingerprint_worker_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: Any, **_k: Any) -> Any:
        raise RuntimeError("fp boom")

    monkeypatch.setattr(workers, "fingerprint_host", boom)
    worker = FingerprintWorker("10.0.0.1")
    failures: list[str] = []
    events: list[Any] = []
    worker.failed.connect(failures.append)
    worker.error_occurred.connect(events.append)

    worker.run()

    assert failures
    assert "fp boom" not in failures[0]
    assert events and events[0].source == "Fingerprinting"


# --------------------------------------------------------------------------- #
# ProtocolWorker
# --------------------------------------------------------------------------- #
def test_protocol_worker_success() -> None:
    result = ProtocolProbeResult(protocol="DNS", target="example.com", success=True)
    worker = ProtocolWorker(lambda: result)
    completed: list[Any] = []
    worker.completed.connect(completed.append)

    worker.run()

    assert completed == [result]


def test_protocol_worker_failure() -> None:
    def boom() -> ProtocolProbeResult:
        raise RuntimeError("probe boom")

    worker = ProtocolWorker(boom)
    failures: list[str] = []
    events: list[Any] = []
    worker.failed.connect(failures.append)
    worker.error_occurred.connect(events.append)

    worker.run()

    assert failures
    assert "probe boom" not in failures[0]
    assert events and events[0].source == "Protocol Troubleshooter"


# --------------------------------------------------------------------------- #
# ObservabilityWorker
# --------------------------------------------------------------------------- #
def test_observability_worker_builds_bundle(
    make_host: Callable[..., HostRecord],
) -> None:
    worker = ObservabilityWorker([make_host("10.0.0.1"), make_host("10.0.0.2")])
    completed: list[Any] = []
    worker.completed.connect(completed.append)

    worker.run()

    assert len(completed) == 1
    assert isinstance(completed[0], ObservabilityBundle)
    assert completed[0].host_count == 2
