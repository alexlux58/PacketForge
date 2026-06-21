from __future__ import annotations

import time
from dataclasses import dataclass, field

from packetforge.engine.protocols import udp_query
from packetforge.models.discovery import ProtocolProbeResult

# Standard read-only SNMPv2-MIB / IF-MIB OIDs. Read-only by design.
COMMON_OIDS: dict[str, str] = {
    "sysDescr": "1.3.6.1.2.1.1.1.0",
    "sysObjectID": "1.3.6.1.2.1.1.2.0",
    "sysUpTime": "1.3.6.1.2.1.1.3.0",
    "sysContact": "1.3.6.1.2.1.1.4.0",
    "sysName": "1.3.6.1.2.1.1.5.0",
    "sysLocation": "1.3.6.1.2.1.1.6.0",
    "ifNumber": "1.3.6.1.2.1.2.1.0",
}


@dataclass
class SnmpProbe:
    host: str
    version: str = "v2c"  # "v2c" or "v3"
    community: str = ""  # user-supplied; never guessed
    v3_username: str = ""
    port: int = 161
    timeout_s: float = 3.0
    oids: dict[str, str] = field(default_factory=lambda: dict(COMMON_OIDS))


def get(config: SnmpProbe) -> ProtocolProbeResult:
    if config.version == "v3":
        return _v3_unsupported(config)
    if not config.community:
        return ProtocolProbeResult(
            protocol="SNMP",
            target=config.host,
            success=False,
            summary="no community string supplied (PacketForge never guesses communities)",
            warnings=["Provide the read-only community you are authorized to use."],
        )
    return _get_v2c(config)


def _get_v2c(config: SnmpProbe) -> ProtocolProbeResult:
    from scapy.asn1.asn1 import ASN1_OID
    from scapy.layers.snmp import SNMP, SNMPget, SNMPvarbind

    varbinds = [SNMPvarbind(oid=ASN1_OID(oid)) for oid in config.oids.values()]
    request = SNMP(community=config.community, PDU=SNMPget(varbindlist=varbinds))
    start = time.perf_counter()
    try:
        raw = udp_query(bytes(request), config.host, config.port, config.timeout_s)
    except TimeoutError:
        return ProtocolProbeResult(
            protocol="SNMP",
            target=config.host,
            success=False,
            summary=f"no SNMP response within {config.timeout_s:.1f}s "
            "(wrong community, ACL, or host down)",
        )
    except OSError as exc:
        return ProtocolProbeResult(
            protocol="SNMP", target=config.host, success=False, summary=f"socket error: {exc}"
        )
    latency = (time.perf_counter() - start) * 1000
    response = SNMP(raw)
    values = _parse_varbinds(response, config.oids)
    return ProtocolProbeResult(
        protocol="SNMP",
        target=config.host,
        success=bool(values),
        summary=f"{len(values)} OID value(s) returned in {latency:.1f} ms"
        if values
        else "no values returned",
        detail=values,
        latency_ms=latency,
    )


def _parse_varbinds(response: object, oids: dict[str, str]) -> dict[str, str]:
    by_oid = {oid: label for label, oid in oids.items()}
    values: dict[str, str] = {}
    try:
        varbinds = response.PDU.varbindlist  # type: ignore[attr-defined]
    except AttributeError:
        return values
    for vb in varbinds or []:
        oid = str(getattr(vb.oid, "val", vb.oid))
        label = by_oid.get(oid, oid)
        raw_value = getattr(vb, "value", None)
        values[label] = _stringify(getattr(raw_value, "val", raw_value))
    return values


def _stringify(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1", errors="replace")
    return str(value)


def _v3_unsupported(config: SnmpProbe) -> ProtocolProbeResult:
    return ProtocolProbeResult(
        protocol="SNMP",
        target=config.host,
        success=False,
        summary="SNMPv3 user-based security is not implemented in this build",
        detail={"username": config.v3_username or "(none)"},
        warnings=[
            "SNMPv3 auth/priv requires a dedicated engine; use authorized v2c here, "
            "or an external v3 tool. PacketForge will never brute force credentials.",
        ],
    )
