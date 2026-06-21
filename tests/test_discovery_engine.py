from __future__ import annotations

from typing import Any

import pytest

pytest.importorskip("pydantic")
pytest.importorskip("scapy")

from packetforge.engine import discovery
from packetforge.engine.discovery import (
    DiscoveryEngine,
    _reverse_dns,
    _tcp_connect,
    _udp_probe,
    service_name,
)
from packetforge.models.discovery import DiscoveryConfig
from packetforge.security.privileges import PrivilegeReport


class _FakeUDPSocket:
    def __init__(self, behavior: str) -> None:
        self._behavior = behavior

    def settimeout(self, _t: float) -> None:
        pass

    def sendto(self, _data: bytes, _addr: tuple[str, int]) -> None:
        pass

    def recvfrom(self, _size: int) -> tuple[bytes, tuple[str, int]]:
        if self._behavior == "open":
            return b"\x00", ("10.0.0.1", 53)
        if self._behavior == "timeout":
            raise TimeoutError
        raise ConnectionRefusedError

    def close(self) -> None:
        pass


# --------------------------------------------------------------------------- #
# Socket-level helpers (mocked, never touch the network)
# --------------------------------------------------------------------------- #
def test_tcp_connect_open_with_banner(monkeypatch: pytest.MonkeyPatch, fake_tcp_socket) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(
        discovery.socket,
        "create_connection",
        lambda *a, **k: fake_tcp_socket([b"SSH-2.0-OpenSSH_9\r\n"]),
    )
    state, banner, rtt = _tcp_connect("10.0.0.1", 22, 0.5, grab_banner=True)
    assert state == "open"
    assert banner == "SSH-2.0-OpenSSH_9"
    assert rtt is not None and rtt >= 0


def test_tcp_connect_refused_is_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def _refuse(*_a: Any, **_k: Any) -> Any:
        raise ConnectionRefusedError

    monkeypatch.setattr(discovery.socket, "create_connection", _refuse)
    assert _tcp_connect("10.0.0.1", 22, 0.5, grab_banner=False) == ("closed", None, None)


def test_tcp_connect_timeout_is_filtered(monkeypatch: pytest.MonkeyPatch) -> None:
    def _timeout(*_a: Any, **_k: Any) -> Any:
        raise TimeoutError("timed out")

    monkeypatch.setattr(discovery.socket, "create_connection", _timeout)
    assert _tcp_connect("10.0.0.1", 22, 0.5, grab_banner=False) == ("filtered", None, None)


@pytest.mark.parametrize(
    ("behavior", "expected"),
    [("open", "open"), ("timeout", "open|filtered"), ("refused", "closed")],
)
def test_udp_probe_states(
    monkeypatch: pytest.MonkeyPatch, behavior: str, expected: str
) -> None:
    monkeypatch.setattr(discovery.socket, "socket", lambda *a, **k: _FakeUDPSocket(behavior))
    assert _udp_probe("10.0.0.1", 53, 0.2) == expected


def test_reverse_dns_success_and_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        discovery.socket, "gethostbyaddr", lambda _ip: ("host.lab", [], ["10.0.0.1"])
    )
    assert _reverse_dns("10.0.0.1") == "host.lab"

    def _fail(_ip: str) -> Any:
        raise OSError

    monkeypatch.setattr(discovery.socket, "gethostbyaddr", _fail)
    assert _reverse_dns("10.0.0.1") is None


def test_service_name_lookup() -> None:
    assert service_name(22) == "ssh"
    assert service_name(443) == "https"
    assert service_name(64999) is None


# --------------------------------------------------------------------------- #
# Engine orchestration (helpers mocked)
# --------------------------------------------------------------------------- #
def test_run_tcp_discovery_records_and_merges(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_tcp(ip: str, port: int, _timeout: float, *, grab_banner: bool):  # type: ignore[no-untyped-def]
        if port == 80:
            return "open", "nginx", 3.0
        return "closed", None, None

    monkeypatch.setattr(discovery, "_tcp_connect", fake_tcp)

    engine = DiscoveryEngine()
    config = DiscoveryConfig(
        targets="10.0.0.1-10.0.0.3",
        methods=["tcp"],
        tcp_ports=[80, 443],
        profile_name="Lab Fast",
        resolve_hostnames=False,
        grab_banners=False,
    )

    found: list[str] = []
    progress: list[tuple[int, int]] = []
    logs: list[str] = []
    run = engine.run(
        config,
        on_host=lambda h: found.append(h.ip),
        on_progress=lambda done, total: progress.append((done, total)),
        on_log=logs.append,
    )

    assert [h.ip for h in run.hosts] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert all(h.methods == ["tcp"] for h in run.hosts)
    assert run.hosts[0].open_ports == [80]
    assert set(found) == {"10.0.0.1", "10.0.0.2", "10.0.0.3"}
    assert progress[-1] == (3, 3)
    assert run.finished_at is not None
    assert any("Discovery finished" in line for line in logs)


def test_run_tcp_syn_discovery_records_raw_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        discovery,
        "detect_privileges",
        lambda: PrivilegeReport(
            is_root=True, raw_sockets=True, platform_name="Test", notes=[]
        ),
    )

    def fake_syn(_ip: str, port: int, _timeout: float, _iface: str | None):  # type: ignore[no-untyped-def]
        if port == 22:
            return "closed", 2.5
        if port == 443:
            return "open", 3.5
        return "filtered", None

    monkeypatch.setattr(discovery, "_tcp_syn_probe", fake_syn)

    engine = DiscoveryEngine()
    config = DiscoveryConfig(
        targets="10.0.0.10",
        methods=["tcp_syn"],
        tcp_ports=[22, 443, 8443],
        profile_name="Gentle",
        resolve_hostnames=False,
    )
    run = engine.run(config)

    assert run.host_count == 1
    host = run.hosts[0]
    assert host.methods == ["tcp_syn"]
    assert host.latency_ms == 2.5
    assert [(service.port, service.state) for service in host.services] == [
        (22, "closed"),
        (443, "open"),
    ]
    assert host.open_ports == [443]


def test_tcp_syn_without_raw_sockets_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        discovery,
        "detect_privileges",
        lambda: PrivilegeReport(
            is_root=False, raw_sockets=False, platform_name="Test", notes=[]
        ),
    )
    monkeypatch.setattr(
        discovery,
        "_tcp_syn_probe",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("syn should be skipped")),
    )
    logs: list[str] = []
    run = DiscoveryEngine().run(
        DiscoveryConfig(targets="10.0.0.1", methods=["tcp_syn"], resolve_hostnames=False),
        on_log=logs.append,
    )

    assert run.hosts == []
    assert any("tcp syn" in line.lower() and "raw sockets" in line.lower() for line in logs)


def test_icmp_without_raw_sockets_is_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        discovery,
        "detect_privileges",
        lambda: PrivilegeReport(
            is_root=False, raw_sockets=False, platform_name="Test", notes=[]
        ),
    )
    # If ICMP were attempted it would call _icmp_echo; make that explode to prove it is skipped.
    monkeypatch.setattr(
        discovery,
        "_icmp_echo",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("icmp should be skipped")),
    )
    engine = DiscoveryEngine()
    config = DiscoveryConfig(
        targets="10.0.0.1",
        methods=["icmp"],
        resolve_hostnames=False,
    )
    logs: list[str] = []
    run = engine.run(config, on_log=logs.append)
    assert run.hosts == []
    assert any("raw sockets" in line.lower() for line in logs)


def test_stop_mid_scan_short_circuits_remaining_ports(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    engine = DiscoveryEngine()

    # Stop as soon as the first port is probed; remaining ports must be skipped.
    def stop_after_first(_ip: str, port: int, _timeout: float, *, grab_banner: bool):  # type: ignore[no-untyped-def]
        calls.append(port)
        engine.stop()
        return "open", None, 1.0

    monkeypatch.setattr(discovery, "_tcp_connect", stop_after_first)
    config = DiscoveryConfig(
        targets="10.0.0.1",
        methods=["tcp"],
        tcp_ports=[80, 443, 8080],
        resolve_hostnames=False,
    )
    engine.run(config)
    assert calls == [80]
