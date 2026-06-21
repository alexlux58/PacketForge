from __future__ import annotations

import threading
from dataclasses import dataclass

from packetforge.models.discovery import ProtocolProbeResult

_DHCP_MESSAGE_TYPES: dict[int, str] = {
    1: "DISCOVER",
    2: "OFFER",
    3: "REQUEST",
    4: "DECLINE",
    5: "ACK",
    6: "NAK",
    7: "RELEASE",
    8: "INFORM",
}


@dataclass
class DhcpPassiveProbe:
    interface: str | None = None
    seconds: int = 20


@dataclass
class DhcpDiscoverProbe:
    interface: str | None = None
    timeout_s: float = 6.0
    lab_mode: bool = False


def observe(
    config: DhcpPassiveProbe, stop_event: threading.Event | None = None
) -> ProtocolProbeResult:  # pragma: no cover - requires raw sockets
    """Passively watch for DHCP traffic. Sends nothing."""
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.sendrecv import sniff

    stop = stop_event or threading.Event()
    try:
        packets = sniff(
            iface=config.interface,
            filter="udp and (port 67 or port 68)",
            timeout=config.seconds,
            store=True,
            stop_filter=lambda _pkt: stop.is_set(),
        )
    except Exception as exc:
        return ProtocolProbeResult(
            protocol="DHCP",
            target=config.interface or "default",
            success=False,
            summary=f"passive capture unavailable: {exc}",
        )
    records: list[str] = []
    for pkt in packets:
        if pkt.haslayer(BOOTP):
            msg_type = _message_type(pkt[DHCP]) if pkt.haslayer(DHCP) else "?"
            records.append(f"{msg_type} from {pkt[BOOTP].chaddr[:6].hex(':')}")
    return ProtocolProbeResult(
        protocol="DHCP",
        target=config.interface or "default",
        success=bool(records),
        summary=f"observed {len(records)} DHCP message(s) passively",
        records=records,
    )


def discover(
    config: DhcpDiscoverProbe,
) -> ProtocolProbeResult:  # pragma: no cover - requires raw sockets
    """Active DHCP Discover. Only runs in explicit lab mode; broadcasts a request."""
    if not config.lab_mode:
        return ProtocolProbeResult(
            protocol="DHCP",
            target=config.interface or "broadcast",
            success=False,
            summary="DHCP Discover not sent (lab mode required)",
            warnings=[
                "Active DHCP Discover broadcasts to the whole segment and can disturb "
                "DHCP servers. Enable Lab mode only on networks you own.",
            ],
        )
    from scapy.layers.dhcp import BOOTP, DHCP
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    from scapy.sendrecv import srp1
    from scapy.volatile import RandInt

    discover_pkt = (
        Ether(dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=b"\x00\x11\x22\x33\x44\x55", xid=int(RandInt()))
        / DHCP(options=[("message-type", "discover"), "end"])
    )
    warnings = ["Lab mode: broadcast a DHCP Discover. Use only on networks you own."]
    try:
        reply = srp1(
            discover_pkt, iface=config.interface, timeout=config.timeout_s, verbose=False
        )
    except Exception as exc:
        return ProtocolProbeResult(
            protocol="DHCP",
            target=config.interface or "broadcast",
            success=False,
            summary=f"DHCP Discover failed: {exc}",
            lab_mode=True,
            warnings=warnings,
        )
    if reply is None or not reply.haslayer(BOOTP):
        return ProtocolProbeResult(
            protocol="DHCP",
            target=config.interface or "broadcast",
            success=False,
            summary="no DHCP offer received",
            lab_mode=True,
            warnings=warnings,
        )
    offer = reply[BOOTP]
    detail = {
        "offered_ip": str(offer.yiaddr),
        "server": str(offer.siaddr),
        "message_type": _message_type(reply[DHCP]) if reply.haslayer(DHCP) else "?",
    }
    return ProtocolProbeResult(
        protocol="DHCP",
        target=config.interface or "broadcast",
        success=True,
        summary=f"offer {detail['offered_ip']} from server {detail['server']}",
        detail=detail,
        lab_mode=True,
        warnings=warnings,
    )


def _message_type(dhcp_layer: object) -> str:
    for option in getattr(dhcp_layer, "options", []):
        if isinstance(option, tuple) and option[0] == "message-type":
            return _DHCP_MESSAGE_TYPES.get(int(option[1]), str(option[1]))
    return "?"
