from __future__ import annotations

from PySide6.QtCore import QObject, Signal

from packetforge.engine.merge import upsert_host
from packetforge.models.discovery import DiscoveryRun, HostRecord, ProtocolProbeResult
from packetforge.models.results import PingResult


class DiscoveryState(QObject):
    """Shared, in-memory store of discovered hosts across tabs.

    Discovery Center writes here; Fingerprinting and Network Map read from it so
    the user does not have to re-scan when moving between tools.
    """

    hosts_changed = Signal()

    def __init__(self) -> None:
        super().__init__()
        self._hosts: dict[str, HostRecord] = {}
        self.last_run: DiscoveryRun | None = None

    def upsert(self, host: HostRecord, *, notify: bool = True) -> HostRecord:
        merged = upsert_host(self._hosts, host)
        if notify:
            self.hosts_changed.emit()
        return merged

    def set_run(self, run: DiscoveryRun) -> None:
        self.last_run = run
        self._hosts = {host.ip: host for host in run.hosts}
        self.hosts_changed.emit()

    def clear(self) -> None:
        self._hosts.clear()
        self.last_run = None
        self.hosts_changed.emit()

    def hosts(self) -> list[HostRecord]:
        return sorted(self._hosts.values(), key=lambda h: h.ip)

    def get(self, ip: str) -> HostRecord | None:
        return self._hosts.get(ip)


class ObservabilityState(QObject):
    """Shared store of protocol probe results and ping trains for observability.

    The Protocol Troubleshooter and Ping Lab push results here so the
    Observability tab can chart them without re-running anything.
    """

    data_changed = Signal()

    def __init__(self) -> None:
        super().__init__()
        self._probes: list[ProtocolProbeResult] = []
        self._pings: dict[str, list[PingResult]] = {}

    def add_probe(self, result: ProtocolProbeResult) -> None:
        self._probes.append(result)
        self.data_changed.emit()

    def set_pings(self, host: str, results: list[PingResult]) -> None:
        if results:
            self._pings[host] = list(results)
            self.data_changed.emit()

    def probes(self) -> list[ProtocolProbeResult]:
        return list(self._probes)

    def pings(self) -> dict[str, list[PingResult]]:
        return {host: list(results) for host, results in self._pings.items()}

    def load_sample(self) -> None:
        from packetforge.engine.sample_data import sample_data

        data = sample_data()
        self._probes = list(data.probes)
        self._pings = dict(data.pings)
        self.data_changed.emit()

    def load_scenario(
        self,
        probes: list[ProtocolProbeResult],
        pings: dict[str, list[PingResult]],
    ) -> None:
        """Replace probe/ping data with a simulated scenario's data."""
        self._probes = list(probes)
        self._pings = {host: list(results) for host, results in pings.items()}
        self.data_changed.emit()

    def clear(self) -> None:
        self._probes.clear()
        self._pings.clear()
        self.data_changed.emit()


class SimulationState(QObject):
    """Tracks whether the GUI is showing simulated (fake) data.

    Tabs and the main window listen to :attr:`changed` so they can show a clear
    'simulation' indicator whenever data did not come from the real network.
    """

    changed = Signal(bool, str)

    def __init__(self) -> None:
        super().__init__()
        self.active = False
        self.scenario_key: str | None = None
        self.scenario_name: str = ""

    def activate(self, scenario_key: str, scenario_name: str) -> None:
        self.active = True
        self.scenario_key = scenario_key
        self.scenario_name = scenario_name
        self.changed.emit(True, scenario_name)

    def deactivate(self) -> None:
        self.active = False
        self.scenario_key = None
        self.scenario_name = ""
        self.changed.emit(False, "")
