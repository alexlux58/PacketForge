from __future__ import annotations

from collections.abc import Callable, Sequence

from PySide6.QtCore import QThread, Signal
from scapy.packet import Packet

from packetforge.diagnostics import get_diagnostics, get_logger
from packetforge.engine.discovery import DiscoveryEngine
from packetforge.engine.fingerprint_probe import fingerprint_host
from packetforge.engine.observability import AnomalyThresholds, PingsByHost, build_bundle
from packetforge.engine.ping_engine import PingEngine
from packetforge.engine.sender import SendOptions, send_packet
from packetforge.engine.statistics import calculate_ping_summary
from packetforge.errors import report_exception
from packetforge.models.discovery import (
    DiscoveryConfig,
    DiscoveryRun,
    FingerprintEvidence,
    HostRecord,
    ProtocolProbeResult,
)
from packetforge.models.ping import PingConfig
from packetforge.models.results import PingResult

_log = get_logger("workers")


class PingWorker(QThread):
    result_ready = Signal(object)
    summary_ready = Signal(object)
    completed = Signal(object, object)
    failed = Signal(str)
    error_occurred = Signal(object)

    def __init__(self, config: PingConfig) -> None:
        super().__init__()
        self.config = config
        self.engine = PingEngine()
        self.results: list[PingResult] = []

    def run(self) -> None:
        _log.info(
            "ping started: dst=%s count=%d iface=%s",
            self.config.destination,
            self.config.count,
            self.config.interface or "default",
        )
        try:
            self.results = []

            def handle_result(result: PingResult) -> None:
                self.results.append(result)
                self.result_ready.emit(result)
                self.summary_ready.emit(calculate_ping_summary(self.results))

            self.engine.run(self.config, handle_result)
            _log.info("ping finished: %d reply/result row(s)", len(self.results))
            self.completed.emit(self.results, self.engine.captured_packets)
        except Exception as exc:
            event = report_exception(exc, source="Ping Lab", operation="ping", logger=_log)
            self.error_occurred.emit(event)
            self.failed.emit(event.message)

    def stop(self) -> None:
        self.engine.stop()

    def pause(self) -> None:
        self.engine.pause()

    def resume(self) -> None:
        self.engine.resume()


class SendWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)
    error_occurred = Signal(object)

    def __init__(self, packet: Packet, options: SendOptions) -> None:
        super().__init__()
        self.packet = packet
        self.options = options

    def run(self) -> None:
        try:
            summary = str(self.packet.summary())
        except Exception:
            summary = "<unrenderable packet>"
        get_diagnostics().set_last_packet_summary(summary)
        _log.info("send started: %s via %s", summary, self.options.function)
        try:
            result = send_packet(self.packet, self.options)
            _log.info("send finished: %s", summary)
            self.completed.emit(result)
        except Exception as exc:
            event = report_exception(exc, source="Scapy Console", operation="send", logger=_log)
            self.error_occurred.emit(event)
            self.failed.emit(event.message)


class DiscoveryWorker(QThread):
    host_found = Signal(object)
    progress = Signal(int, int)
    log = Signal(str)
    completed = Signal(object)
    failed = Signal(str)
    error_occurred = Signal(object)

    def __init__(self, config: DiscoveryConfig) -> None:
        super().__init__()
        self.config = config
        self.engine = DiscoveryEngine()

    def run(self) -> None:
        _log.info(
            "discovery started: targets=%r methods=%s",
            self.config.targets,
            ",".join(self.config.methods),
        )
        try:
            run = self.engine.run(
                self.config,
                on_host=self.host_found.emit,
                on_progress=self.progress.emit,
                on_log=self.log.emit,
            )
            _log.info("discovery finished: %d host(s)", len(run.hosts))
            self.completed.emit(run)
        except Exception as exc:
            event = report_exception(
                exc, source="Discovery Center", operation="discovery", logger=_log
            )
            self.error_occurred.emit(event)
            self.failed.emit(event.message)

    def stop(self) -> None:
        self.engine.stop()

    def pause(self) -> None:
        self.engine.pause()

    def resume(self) -> None:
        self.engine.resume()

    @property
    def captured_packets(self) -> list[object]:
        return self.engine.captured_packets


class FingerprintWorker(QThread):
    completed = Signal(object)
    failed = Signal(str)
    error_occurred = Signal(object)

    def __init__(
        self,
        host: str,
        *,
        interface: str | None = None,
        raw_ok: bool = False,
        ports: tuple[int, ...] | None = None,
    ) -> None:
        super().__init__()
        self.host = host
        self.interface = interface
        self.raw_ok = raw_ok
        self.ports = ports

    def run(self) -> None:
        _log.info("fingerprint started: host=%s raw_ok=%s", self.host, self.raw_ok)
        try:
            kwargs: dict[str, object] = {"interface": self.interface, "raw_ok": self.raw_ok}
            if self.ports:
                kwargs["ports"] = self.ports
            evidence: FingerprintEvidence = fingerprint_host(self.host, **kwargs)  # type: ignore[arg-type]
            _log.info("fingerprint finished: host=%s", self.host)
            self.completed.emit(evidence)
        except Exception as exc:
            event = report_exception(
                exc, source="Fingerprinting", operation="fingerprint", logger=_log
            )
            self.error_occurred.emit(event)
            self.failed.emit(event.message)


class ProtocolWorker(QThread):
    """Runs any callable that returns a ProtocolProbeResult off the main thread."""

    completed = Signal(object)
    failed = Signal(str)
    error_occurred = Signal(object)

    def __init__(self, task: Callable[[], ProtocolProbeResult]) -> None:
        super().__init__()
        self.task = task

    def run(self) -> None:
        try:
            result: ProtocolProbeResult = self.task()
            _log.info(
                "protocol probe finished: %s %s (success=%s)",
                result.protocol,
                result.target,
                result.success,
            )
            self.completed.emit(result)
        except Exception as exc:
            event = report_exception(
                exc, source="Protocol Troubleshooter", operation="probe", logger=_log
            )
            self.error_occurred.emit(event)
            self.failed.emit(event.message)


class ObservabilityWorker(QThread):
    """Builds the observability aggregation bundle off the GUI thread."""

    completed = Signal(object)
    failed = Signal(str)
    error_occurred = Signal(object)

    def __init__(
        self,
        hosts: Sequence[HostRecord],
        *,
        pings: PingsByHost | None = None,
        probes: Sequence[ProtocolProbeResult] | None = None,
        run: DiscoveryRun | None = None,
        thresholds: AnomalyThresholds | None = None,
        subnet_filter: str | None = None,
        host_filter: str | None = None,
    ) -> None:
        super().__init__()
        self._hosts = list(hosts)
        self._pings = pings or {}
        self._probes = list(probes or [])
        self._run = run
        self._thresholds = thresholds
        self._subnet_filter = subnet_filter
        self._host_filter = host_filter

    def run(self) -> None:
        try:
            bundle = build_bundle(
                self._hosts,
                pings=self._pings,
                probes=self._probes,
                run=self._run,
                thresholds=self._thresholds,
                subnet_filter=self._subnet_filter,
                host_filter=self._host_filter,
            )
            self.completed.emit(bundle)
        except Exception as exc:
            event = report_exception(
                exc, source="Observability", operation="aggregate", logger=_log
            )
            self.error_occurred.emit(event)
            self.failed.emit(event.message)
