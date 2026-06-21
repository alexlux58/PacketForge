from __future__ import annotations

import socket
import struct
import time
from dataclasses import dataclass

from packetforge.engine.protocols import udp_query
from packetforge.models.discovery import ProtocolProbeResult

# qtype name -> numeric code. Restricted to safe, read-only record lookups.
QTYPES: dict[str, int] = {
    "A": 1,
    "AAAA": 28,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "NS": 2,
    "SOA": 6,
    "CNAME": 5,
}

DNS_RCODES: dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


@dataclass
class DnsQuery:
    name: str
    qtype: str = "A"
    resolver: str = "1.1.1.1"
    port: int = 53
    timeout_s: float = 3.0
    allow_zone_transfer: bool = False


def reverse_pointer(ip: str) -> str:
    """Return the in-addr.arpa / ip6.arpa name for an address."""
    import ipaddress

    return ipaddress.ip_address(ip).reverse_pointer


def resolve(query: DnsQuery) -> ProtocolProbeResult:
    qtype = query.qtype.upper()
    if qtype not in QTYPES:
        return ProtocolProbeResult(
            protocol="DNS",
            target=query.name,
            success=False,
            summary=f"unsupported record type: {query.qtype}",
        )
    qname = query.name
    if qtype == "PTR" and _looks_like_ip(qname):
        qname = reverse_pointer(qname)

    from scapy.layers.dns import DNS, DNSQR

    request = DNS(rd=1, qd=DNSQR(qname=qname, qtype=QTYPES[qtype]))
    start = time.perf_counter()
    try:
        raw = udp_query(bytes(request), query.resolver, query.port, query.timeout_s)
    except TimeoutError:
        return ProtocolProbeResult(
            protocol="DNS",
            target=query.name,
            success=False,
            summary=f"no response from resolver {query.resolver} within {query.timeout_s:.1f}s",
        )
    except OSError as exc:
        return ProtocolProbeResult(
            protocol="DNS", target=query.name, success=False, summary=f"socket error: {exc}"
        )
    latency = (time.perf_counter() - start) * 1000
    response = DNS(raw)
    rcode = int(getattr(response, "rcode", 0))
    records = _extract_answers(response)
    detail = {
        "resolver": f"{query.resolver}:{query.port}",
        "qname": qname,
        "qtype": qtype,
        "rcode": DNS_RCODES.get(rcode, str(rcode)),
        "answers": str(int(getattr(response, "ancount", 0))),
        "flags": _flags(response),
    }
    return ProtocolProbeResult(
        protocol="DNS",
        target=query.name,
        success=rcode == 0 and bool(records),
        summary=f"{DNS_RCODES.get(rcode, rcode)} - {len(records)} record(s) in {latency:.1f} ms",
        detail=detail,
        records=records,
        latency_ms=latency,
    )


def zone_transfer(name: str, resolver: str, *, confirmed: bool, port: int = 53,
                  timeout_s: float = 5.0) -> ProtocolProbeResult:
    """Attempt an AXFR. Only runs when the caller passes ``confirmed=True``.

    This is an authorized-use diagnostic; it never runs implicitly.
    """
    if not confirmed:
        return ProtocolProbeResult(
            protocol="DNS-AXFR",
            target=name,
            success=False,
            summary="zone transfer not attempted (explicit confirmation required)",
            warnings=["AXFR can expose full zone data; only test zones you are authorized to."],
        )
    from scapy.layers.dns import DNS, DNSQR

    request = DNS(qd=DNSQR(qname=name, qtype=252))  # 252 = AXFR
    payload = bytes(request)
    framed = struct.pack(">H", len(payload)) + payload
    try:
        with socket.create_connection((resolver, port), timeout=timeout_s) as sock:
            sock.sendall(framed)
            sock.settimeout(timeout_s)
            data = sock.recv(65535)
    except OSError as exc:
        return ProtocolProbeResult(
            protocol="DNS-AXFR",
            target=name,
            success=False,
            summary=f"zone transfer failed/refused: {exc}",
            warnings=["A refusal here is the normal, secure default for most servers."],
        )
    records: list[str] = []
    if len(data) > 2:
        response = DNS(data[2:])
        records = _extract_answers(response)
    return ProtocolProbeResult(
        protocol="DNS-AXFR",
        target=name,
        success=bool(records),
        summary=f"AXFR returned {len(records)} record(s)",
        records=records,
        warnings=["Server allowed a zone transfer; verify this is intended."],
    )


def _extract_answers(response: object) -> list[str]:
    records: list[str] = []
    ancount = int(getattr(response, "ancount", 0))
    for index in range(ancount):
        try:
            rr = response.an[index]  # type: ignore[attr-defined]
        except (AttributeError, IndexError, TypeError):
            break
        rrname = _decode(getattr(rr, "rrname", b""))
        rdata = getattr(rr, "rdata", "")
        records.append(f"{rrname} -> {_decode(rdata)}")
    return records


def _decode(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("latin-1", errors="replace").rstrip(".")
    return str(value).rstrip(".")


def _flags(response: object) -> str:
    flags = []
    for attr in ("qr", "aa", "tc", "rd", "ra"):
        if int(getattr(response, attr, 0)):
            flags.append(attr.upper())
    return ",".join(flags)


def _looks_like_ip(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
