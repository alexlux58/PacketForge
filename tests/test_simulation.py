from __future__ import annotations

import pytest

pytest.importorskip("pydantic")
pytest.importorskip("scapy")

from packetforge.engine import discovery
from packetforge.engine.discovery import DiscoveryEngine
from packetforge.engine.merge import upsert_host
from packetforge.engine.observability import build_bundle, detect_anomalies
from packetforge.engine.simulation import (
    SimulatedScenario,
    build_scenario,
    list_scenarios,
    scenario_keys,
)
from packetforge.models.discovery import (
    DiscoveryConfig,
    DiscoveryRun,
    FingerprintEvidence,
    HostRecord,
    ProtocolProbeResult,
    ServiceRecord,
)
from packetforge.models.observability import ObservabilityBundle
from packetforge.models.results import PingResult
from packetforge.utils.export import export_run_json

EXPECTED_KEYS = {
    "home_lan",
    "enterprise",
    "dns_issue",
    "dhcp_issue",
    "high_latency",
    "smtp_no_starttls",
    "snmp_errors",
    "ntp_drift",
    "gateway_discovery",
}


def _all_scenarios() -> list[SimulatedScenario]:
    return [build_scenario(key) for key in scenario_keys()]


def test_all_required_scenarios_exist() -> None:
    assert set(scenario_keys()) >= EXPECTED_KEYS
    triples = list_scenarios()
    assert {key for key, _name, _desc in triples} == set(scenario_keys())
    for _key, name, description in triples:
        assert name and description


def test_unknown_scenario_raises() -> None:
    with pytest.raises(KeyError):
        build_scenario("does-not-exist")


@pytest.mark.parametrize("key", sorted(EXPECTED_KEYS))
def test_scenarios_populate_the_real_models(key: str) -> None:
    scenario = build_scenario(key)
    assert isinstance(scenario.run, DiscoveryRun)
    assert scenario.run.hosts, f"{key} should discover at least one host"
    for host in scenario.run.hosts:
        assert isinstance(host, HostRecord)
        for service in host.services:
            assert isinstance(service, ServiceRecord)
        if host.fingerprint is not None:
            assert isinstance(host.fingerprint, FingerprintEvidence)
    for probe in scenario.probes:
        assert isinstance(probe, ProtocolProbeResult)
    for results in scenario.pings.values():
        assert results
        for result in results:
            assert isinstance(result, PingResult)


@pytest.mark.parametrize("key", sorted(EXPECTED_KEYS))
def test_scenario_run_serializes_like_a_real_run(key: str, tmp_path) -> None:  # type: ignore[no-untyped-def]
    scenario = build_scenario(key)
    path = tmp_path / f"{key}.json"
    export_run_json(scenario.run, path)
    reloaded = DiscoveryRun.model_validate_json(path.read_text(encoding="utf-8"))
    assert reloaded.host_count == scenario.run.host_count


@pytest.mark.parametrize("key", sorted(EXPECTED_KEYS))
def test_scenarios_feed_observability_bundle(key: str) -> None:
    scenario = build_scenario(key)
    bundle = build_bundle(
        scenario.run.hosts,
        pings=scenario.pings,
        probes=scenario.probes,
        run=scenario.run,
    )
    assert isinstance(bundle, ObservabilityBundle)
    assert bundle.host_count == scenario.run.host_count


def _categories(scenario: SimulatedScenario) -> set[str]:
    findings = detect_anomalies(scenario.run.hosts, scenario.probes, scenario.pings)
    return {finding.category for finding in findings}


def test_dns_issue_flags_dns_latency() -> None:
    assert "dns" in _categories(build_scenario("dns_issue"))


def test_high_latency_flags_latency() -> None:
    assert "latency" in _categories(build_scenario("high_latency"))


def test_smtp_scenario_flags_starttls() -> None:
    assert "smtp" in _categories(build_scenario("smtp_no_starttls"))


def test_snmp_scenario_flags_interface_errors() -> None:
    assert "snmp" in _categories(build_scenario("snmp_errors"))


def test_ntp_scenario_flags_offset() -> None:
    assert "ntp" in _categories(build_scenario("ntp_drift"))


def test_gateway_scenario_flags_topology_and_reachability() -> None:
    categories = _categories(build_scenario("gateway_discovery"))
    assert "topology" in categories  # possible gateway
    assert "reachability" in categories  # ARP but no ICMP


def test_enterprise_includes_baseline_for_comparison() -> None:
    scenario = build_scenario("enterprise")
    assert scenario.baseline is not None
    assert isinstance(scenario.baseline, DiscoveryRun)


# --------------------------------------------------------------------------- #
# The central guarantee: simulated and real data are the *same* model types.
# --------------------------------------------------------------------------- #
def test_simulated_and_real_paths_share_models(monkeypatch: pytest.MonkeyPatch) -> None:
    # Real discovery path (sockets mocked, no live network / privileges).
    monkeypatch.setattr(discovery, "_tcp_connect", lambda *a, **k: ("open", "nginx", 2.0))
    real_run = DiscoveryEngine().run(
        DiscoveryConfig(
            targets="10.0.0.1",
            methods=["tcp"],
            tcp_ports=[80],
            resolve_hostnames=False,
        )
    )

    sim_run = build_scenario("home_lan").run

    # Identical container and element model classes.
    assert type(real_run) is type(sim_run) is DiscoveryRun
    assert type(real_run.hosts[0]) is type(sim_run.hosts[0]) is HostRecord

    # Both flow through the same merge, bundle, and export code paths.
    index: dict[str, HostRecord] = {}
    for host in (*real_run.hosts, *sim_run.hosts):
        assert isinstance(upsert_host(index, host), HostRecord)

    for run in (real_run, sim_run):
        bundle = build_bundle(run.hosts, run=run)
        assert isinstance(bundle, ObservabilityBundle)


def test_observability_state_load_scenario_round_trips(qt_app) -> None:  # type: ignore[no-untyped-def]
    from packetforge.ui.state import DiscoveryState, ObservabilityState, SimulationState

    scenario = build_scenario("high_latency")
    discovery_state = DiscoveryState()
    obs_state = ObservabilityState()
    sim_state = SimulationState()

    discovery_state.set_run(scenario.run)
    obs_state.load_scenario(scenario.probes, scenario.pings)
    sim_state.activate(scenario.key, scenario.name)

    assert len(discovery_state.hosts()) == scenario.run.host_count
    assert obs_state.probes() == scenario.probes
    assert obs_state.pings().keys() == scenario.pings.keys()
    assert sim_state.active is True
    assert sim_state.scenario_name == scenario.name

    sim_state.deactivate()
    assert sim_state.active is False
