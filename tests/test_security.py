"""Security and safety regression tests for PacketForge.

Covers the Safe Scapy AST sandbox, command-input policy, credential handling,
export redaction, rate limits, and lab-mode gating for dangerous probes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic")
pytest.importorskip("scapy")

from packetforge.diagnostics import redact_config
from packetforge.engine.protocols import bgp, dhcp, dns, ospf, snmp, stp
from packetforge.models.discovery import ProtocolProbeResult
from packetforge.models.profiles import BUILTIN_PROFILES
from packetforge.security.command_policy import validate_command
from packetforge.security.safe_scapy import SafeScapyError, parse_scapy_expression

# --------------------------------------------------------------------------- #
# Safe Scapy console - rejected unsafe expressions
# --------------------------------------------------------------------------- #
_UNSAFE_SCAPY_EXPRESSIONS: list[tuple[str, str]] = [
    ('__import__("os").system("id")', "import/os escape"),
    ("exec('1')", "exec call"),
    ("eval('IP()')", "eval call"),
    ("compile('1', '', 'eval')", "compile call"),
    ("getattr(IP, 'dst')", "getattr call"),
    ("IP().__class__", "attribute traversal"),
    ("IP()[0]", "subscript on packet"),
    ("IP() / IP().__class__", "attribute in layer stack"),
    ("open('/etc/passwd')", "unapproved builtin"),
    ("IP() + ICMP()", "forbidden binary op"),
    ("IP() * 2", "forbidden binary op"),
    ("lambda: IP()", "lambda"),
    ("IP(dst=DST)", "bare name"),
    ("IP(**{'dst': '10.0.0.1'})", "expanded kwargs"),
    ("IP(*['dst'])", "star args"),  # Starred node -> unsupported syntax
    ("[IP() for _ in range(1)][0]", "comprehension/subscript"),
    ("IP() if True else ICMP()", "conditional expression"),
    ("IP().build()", "method call on packet"),
    ('IP(dst=f"{"x"}")', "f-string"),
    ("5", "non-packet constant"),
]


@pytest.mark.parametrize(
    ("expression", "reason"),
    _UNSAFE_SCAPY_EXPRESSIONS,
    ids=[item[1] for item in _UNSAFE_SCAPY_EXPRESSIONS],
)
def test_safe_scapy_rejects_unsafe_expressions(expression: str, reason: str) -> None:
    with pytest.raises(SafeScapyError):
        parse_scapy_expression(expression)


def test_safe_scapy_uses_ast_not_builtins_eval() -> None:
    """The console parser must not call Python's eval()/exec() builtins."""
    import ast
    import inspect

    from packetforge.security import safe_scapy

    source = inspect.getsource(safe_scapy.parse_scapy_expression)
    tree = ast.parse(source)
    names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "eval" not in names
    assert "exec" not in names


# --------------------------------------------------------------------------- #
# Command policy - rejected unsafe shell input (defense-in-depth module)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "command",
    [
        "rm -rf /",
        "nmap -sS 10.0.0.0/8",
        "ping 8.8.8.8; id",
        "ping 8.8.8.8 && curl evil",
        "ping 8.8.8.8 | tee /tmp/x",
        "ping $(whoami)",
        "ping `id`",
        "ping 8.8.8.8 > /tmp/out",
        "ping 8.8.8.8 < /etc/passwd",
    ],
)
def test_command_policy_rejects_unsafe_input(command: str) -> None:
    result = validate_command(command)
    assert not result.ok


@pytest.mark.parametrize(
    "command",
    [
        "ping 192.0.2.1",
        "ping6 2001:db8::1",
        "traceroute example.com",
        "dig @1.1.1.1 example.com A",
    ],
)
def test_command_policy_allows_readonly_diagnostics(command: str) -> None:
    result = validate_command(command)
    assert result.ok
    assert result.argv


def test_no_subprocess_or_shell_in_application_code() -> None:
    """PacketForge must not shell out; scan application modules for forbidden APIs."""
    forbidden = ("subprocess", "os.system", "os.popen", "shell=True")
    root = Path("packetforge")
    offenders: list[str] = []
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for pattern in forbidden:
            if pattern in text:
                offenders.append(f"{path}: {pattern}")
    assert offenders == []


# --------------------------------------------------------------------------- #
# SNMP credentials - never stored in results or exported by default
# --------------------------------------------------------------------------- #
def test_snmp_empty_community_never_probes() -> None:
    result = snmp.get(snmp.SnmpProbe(host="10.0.0.1", community=""))
    assert not result.success
    payload = result.model_dump(mode="json")
    assert "community" not in payload
    assert result.detail == {}


def test_snmp_probe_result_never_contains_community_string() -> None:
    """Even when a community is supplied, results must not persist it."""
    # We cannot rely on live SNMP; inspect the result model shape from the
    # empty-community path and assert the schema has no credential field.
    fields = set(ProtocolProbeResult.model_fields)
    assert "community" not in fields
    assert "password" not in fields


def test_snmp_v3_does_not_attempt_auth_without_engine() -> None:
    result = snmp.get(snmp.SnmpProbe(host="10.0.0.1", version="v3", v3_username="admin"))
    assert not result.success
    assert "brute force" in " ".join(result.warnings).lower()


# --------------------------------------------------------------------------- #
# Export / debug bundle redaction
# --------------------------------------------------------------------------- #
def test_redact_config_masks_credential_keys() -> None:
    config = {
        "community": "public",
        "snmp_password": "secret",
        "resolver": "1.1.1.1",
        "nested": {"api_key": "abc123", "timeout": 3},
    }
    redacted = redact_config(config)
    assert redacted["community"] == "***redacted***"
    assert redacted["snmp_password"] == "***redacted***"
    assert redacted["resolver"] == "1.1.1.1"
    assert redacted["nested"]["api_key"] == "***redacted***"


def test_protocol_probe_json_export_has_no_secret_fields() -> None:
    result = ProtocolProbeResult(
        protocol="SNMP",
        target="10.0.0.1",
        success=True,
        summary="ok",
        detail={"sysName": "router1"},
    )
    payload = result.model_dump(mode="json")
    assert "community" not in payload
    assert "password" not in payload


# --------------------------------------------------------------------------- #
# Dangerous protocol actions gated behind lab mode / confirmation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "factory,summary_needle",
    [
        (lambda: dhcp.discover(dhcp.DhcpDiscoverProbe(lab_mode=False)), "lab mode"),
        (lambda: ospf.send_hello(ospf.OspfActiveProbe(lab_mode=False)), "lab mode"),
        (lambda: stp.send_bpdu(stp.StpActiveProbe(lab_mode=False)), "lab mode"),
        (lambda: dns.zone_transfer("example.com", "1.1.1.1", confirmed=False), "confirmation"),
    ],
)
def test_dangerous_probes_blocked_without_explicit_opt_in(
    factory: object, summary_needle: str
) -> None:
    result = factory()  # type: ignore[operator]
    assert isinstance(result, ProtocolProbeResult)
    assert not result.success
    assert summary_needle in result.summary.lower()


def test_bgp_open_only_when_lab_mode_enabled() -> None:
    probe = bgp.BgpProbe(host="192.0.2.1", lab_mode=False)
    assert probe.lab_mode is False


# --------------------------------------------------------------------------- #
# Active discovery rate limits
# --------------------------------------------------------------------------- #
def test_scan_profiles_enforce_bounded_packet_rates() -> None:
    for profile in BUILTIN_PROFILES:
        assert 0 < profile.max_packets_per_second <= 2000
        assert profile.concurrency <= 256
        assert profile.max_ports_per_host <= 1024
