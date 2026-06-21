from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

pytest.importorskip("pydantic")
pytest.importorskip("scapy")

from packetforge.engine.protocols import bgp, dns, ntp, smtp, snmp


# --------------------------------------------------------------------------- #
# DNS
# --------------------------------------------------------------------------- #
def test_dns_resolve_parses_answer(
    monkeypatch: pytest.MonkeyPatch, dns_response_bytes: Callable[..., bytes]
) -> None:
    monkeypatch.setattr(dns, "udp_query", lambda *a, **k: dns_response_bytes("example.com"))
    result = dns.resolve(dns.DnsQuery(name="example.com", qtype="A"))
    assert result.success
    assert result.detail["rcode"] == "NOERROR"
    assert result.records
    assert result.latency_ms is not None


def test_dns_resolve_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def _timeout(*_a: Any, **_k: Any) -> bytes:
        raise TimeoutError

    monkeypatch.setattr(dns, "udp_query", _timeout)
    result = dns.resolve(dns.DnsQuery(name="example.com"))
    assert not result.success
    assert "no response" in result.summary


def test_dns_resolve_socket_error(monkeypatch: pytest.MonkeyPatch) -> None:
    def _oserror(*_a: Any, **_k: Any) -> bytes:
        raise OSError("network unreachable")

    monkeypatch.setattr(dns, "udp_query", _oserror)
    result = dns.resolve(dns.DnsQuery(name="example.com"))
    assert not result.success
    assert "socket error" in result.summary


# --------------------------------------------------------------------------- #
# NTP
# --------------------------------------------------------------------------- #
def test_ntp_probe_parses_stratum(
    monkeypatch: pytest.MonkeyPatch, ntp_response_bytes: Callable[..., bytes]
) -> None:
    monkeypatch.setattr(ntp, "udp_query", lambda *a, **k: ntp_response_bytes(stratum=3))
    result = ntp.probe(ntp.NtpProbe(host="10.0.0.1"))
    assert result.success
    assert result.detail["stratum"] == "3"
    assert result.latency_ms is not None


def test_ntp_probe_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def _timeout(*_a: Any, **_k: Any) -> bytes:
        raise TimeoutError

    monkeypatch.setattr(ntp, "udp_query", _timeout)
    result = ntp.probe(ntp.NtpProbe(host="10.0.0.1"))
    assert not result.success
    assert "no NTP response" in result.summary


# --------------------------------------------------------------------------- #
# SNMP
# --------------------------------------------------------------------------- #
def test_snmp_v2c_parses_varbinds(
    monkeypatch: pytest.MonkeyPatch, snmp_response_bytes: Callable[..., bytes]
) -> None:
    monkeypatch.setattr(
        snmp, "udp_query", lambda *a, **k: snmp_response_bytes(sys_name="core-router")
    )
    result = snmp.get(snmp.SnmpProbe(host="10.0.0.1", version="v2c", community="public"))
    assert result.success
    assert result.detail.get("sysName") == "core-router"


def test_snmp_v2c_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def _timeout(*_a: Any, **_k: Any) -> bytes:
        raise TimeoutError

    monkeypatch.setattr(snmp, "udp_query", _timeout)
    result = snmp.get(snmp.SnmpProbe(host="10.0.0.1", version="v2c", community="public"))
    assert not result.success
    assert "no SNMP response" in result.summary


# --------------------------------------------------------------------------- #
# SMTP
# --------------------------------------------------------------------------- #
_EHLO_WITH_TLS = (
    b"250-mail.example.com\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 SIZE 10240000\r\n"
)
_EHLO_NO_TLS = b"250-mail.example.com\r\n250-PIPELINING\r\n250 SIZE 10240000\r\n"


def test_smtp_probe_detects_starttls(monkeypatch: pytest.MonkeyPatch, fake_tcp_socket) -> None:  # type: ignore[no-untyped-def]
    sock = fake_tcp_socket([b"220 mail.example.com ESMTP\r\n", _EHLO_WITH_TLS])
    monkeypatch.setattr(smtp.socket, "create_connection", lambda *a, **k: sock)
    result = smtp.probe(smtp.SmtpProbe(host="10.0.0.1"))
    assert result.success
    assert result.detail["starttls"] == "yes"
    assert "STARTTLS" in result.records
    assert result.warnings == []


def test_smtp_probe_warns_when_no_starttls(  # type: ignore[no-untyped-def]
    monkeypatch: pytest.MonkeyPatch, fake_tcp_socket
) -> None:
    sock = fake_tcp_socket([b"220 mail.example.com ESMTP\r\n", _EHLO_NO_TLS])
    monkeypatch.setattr(smtp.socket, "create_connection", lambda *a, **k: sock)
    result = smtp.probe(smtp.SmtpProbe(host="10.0.0.1"))
    assert result.detail["starttls"] == "no"
    assert result.warnings


def test_smtp_probe_connection_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fail(*_a: Any, **_k: Any) -> Any:
        raise OSError("connection refused")

    monkeypatch.setattr(smtp.socket, "create_connection", _fail)
    result = smtp.probe(smtp.SmtpProbe(host="10.0.0.1"))
    assert not result.success
    assert "connection failed" in result.summary


# --------------------------------------------------------------------------- #
# BGP
# --------------------------------------------------------------------------- #
def test_bgp_reachability_only(monkeypatch: pytest.MonkeyPatch, fake_tcp_socket) -> None:  # type: ignore[no-untyped-def]
    monkeypatch.setattr(bgp.socket, "create_connection", lambda *a, **k: fake_tcp_socket())
    result = bgp.probe(bgp.BgpProbe(host="192.0.2.1", lab_mode=False))
    assert result.success
    assert result.detail["tcp_179"] == "open"
    assert result.warnings  # nudges towards lab mode
    assert result.lab_mode is False


def test_bgp_connection_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    def _refuse(*_a: Any, **_k: Any) -> Any:
        raise ConnectionRefusedError

    monkeypatch.setattr(bgp.socket, "create_connection", _refuse)
    result = bgp.probe(bgp.BgpProbe(host="192.0.2.1"))
    assert not result.success
    assert "refused" in result.summary


def test_bgp_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    def _unreach(*_a: Any, **_k: Any) -> Any:
        raise OSError("no route to host")

    monkeypatch.setattr(bgp.socket, "create_connection", _unreach)
    result = bgp.probe(bgp.BgpProbe(host="192.0.2.1"))
    assert not result.success
    assert "unreachable" in result.summary
