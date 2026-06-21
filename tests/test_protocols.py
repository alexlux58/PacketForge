import pytest

pytest.importorskip("pydantic")
pytest.importorskip("scapy")

from packetforge.engine.protocols import bgp, dhcp, dns, ntp, ospf, smtp, snmp, stp
from packetforge.models.discovery import ProtocolProbeResult


def test_protocol_probe_result_safe_defaults() -> None:
    result = ProtocolProbeResult(protocol="TEST", target="example")
    assert result.success is False
    assert result.lab_mode is False
    assert result.warnings == []
    assert result.detail == {}
    assert result.records == []


def test_dns_qtypes_cover_required_records() -> None:
    for qtype in ("A", "AAAA", "PTR", "MX", "TXT", "NS", "SOA"):
        assert qtype in dns.QTYPES


def test_dns_reverse_pointer() -> None:
    assert dns.reverse_pointer("8.8.8.8") == "8.8.8.8.in-addr.arpa"
    assert dns.reverse_pointer("2001:db8::1").endswith("ip6.arpa")


def test_dns_query_defaults_disable_zone_transfer() -> None:
    query = dns.DnsQuery(name="example.com")
    assert query.allow_zone_transfer is False


def test_dns_unsupported_record_type_is_rejected() -> None:
    result = dns.resolve(dns.DnsQuery(name="x", qtype="ANY"))
    assert result.success is False
    assert "unsupported" in result.summary


def test_zone_transfer_requires_confirmation() -> None:
    result = dns.zone_transfer("lab.example", "10.0.0.53", confirmed=False)
    assert result.success is False
    assert "confirmation required" in result.summary
    assert result.warnings


def test_snmp_never_guesses_community() -> None:
    result = snmp.get(snmp.SnmpProbe(host="10.0.0.1", version="v2c", community=""))
    assert result.success is False
    assert "never guesses" in result.summary.lower()


def test_snmp_v3_reports_unsupported_without_sending() -> None:
    result = snmp.get(snmp.SnmpProbe(host="10.0.0.1", version="v3", v3_username="ro"))
    assert result.success is False
    assert "v3" in result.summary.lower()
    assert any("brute force" in warning.lower() for warning in result.warnings)


def test_dhcp_discover_blocked_without_lab_mode() -> None:
    result = dhcp.discover(dhcp.DhcpDiscoverProbe(lab_mode=False))
    assert result.success is False
    assert "lab mode required" in result.summary.lower()
    assert result.lab_mode is False


def test_ospf_hello_blocked_without_lab_mode() -> None:
    result = ospf.send_hello(ospf.OspfActiveProbe(lab_mode=False))
    assert result.success is False
    assert "lab mode required" in result.summary.lower()


def test_stp_bpdu_blocked_without_lab_mode() -> None:
    result = stp.send_bpdu(stp.StpActiveProbe(lab_mode=False))
    assert result.success is False
    assert "lab mode required" in result.summary.lower()


def test_bgp_probe_defaults_to_reachability_only() -> None:
    assert bgp.BgpProbe(host="192.0.2.1").lab_mode is False


def test_snmp_common_oids_are_read_only_system_group() -> None:
    assert snmp.COMMON_OIDS["sysName"] == "1.3.6.1.2.1.1.5.0"
    assert snmp.COMMON_OIDS["sysDescr"].startswith("1.3.6.1.2.1.1.1")


def test_ntp_unix_delta_constant() -> None:
    assert ntp.NTP_UNIX_DELTA == 2_208_988_800


def test_smtp_capability_parsing() -> None:
    block = "250-mail.example.com\r\n250-PIPELINING\r\n250-STARTTLS\r\n250 SIZE 10240000\r\n"
    caps = smtp._parse_capabilities(block)
    assert "STARTTLS" in caps
    assert "PIPELINING" in caps
