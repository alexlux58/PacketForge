from __future__ import annotations

import threading
from dataclasses import dataclass

from packetforge.models.discovery import ProtocolProbeResult

_OSPF_TYPES: dict[int, str] = {
    1: "Hello",
    2: "DBD",
    3: "LSR",
    4: "LSU",
    5: "LSAck",
}


@dataclass
class OspfPassiveProbe:
    interface: str | None = None
    seconds: int = 30


@dataclass
class OspfActiveProbe:
    interface: str | None = None
    area: str = "0.0.0.0"
    router_id: str = "10.255.255.1"
    lab_mode: bool = False


def observe(
    config: OspfPassiveProbe, stop_event: threading.Event | None = None
) -> ProtocolProbeResult:  # pragma: no cover - requires raw sockets
    """Passively decode OSPF (IP protocol 89) packets. Sends nothing."""
    from scapy.contrib.ospf import OSPF_Hdr
    from scapy.sendrecv import sniff

    stop = stop_event or threading.Event()
    try:
        packets = sniff(
            iface=config.interface,
            filter="ip proto 89",
            timeout=config.seconds,
            store=True,
            stop_filter=lambda _pkt: stop.is_set(),
        )
    except Exception as exc:
        return ProtocolProbeResult(
            protocol="OSPF",
            target=config.interface or "default",
            success=False,
            summary=f"passive capture unavailable: {exc}",
        )
    records: list[str] = []
    neighbors: set[str] = set()
    for pkt in packets:
        if pkt.haslayer(OSPF_Hdr):
            hdr = pkt[OSPF_Hdr]
            ptype = _OSPF_TYPES.get(int(hdr.type), str(hdr.type))
            neighbors.add(str(hdr.src))
            records.append(f"{ptype} from RID {hdr.src} area {hdr.area}")
    return ProtocolProbeResult(
        protocol="OSPF",
        target=config.interface or "default",
        success=bool(records),
        summary=f"observed {len(records)} OSPF packet(s) from {len(neighbors)} router(s)",
        detail={"routers": ", ".join(sorted(neighbors))},
        records=records,
    )


def send_hello(
    config: OspfActiveProbe,
) -> ProtocolProbeResult:  # pragma: no cover - requires raw sockets
    """Send a single OSPF Hello. Lab mode only; can form adjacencies."""
    if not config.lab_mode:
        return ProtocolProbeResult(
            protocol="OSPF",
            target=config.interface or "multicast",
            success=False,
            summary="OSPF Hello not sent (lab mode required)",
            warnings=[
                "Injecting OSPF Hellos can form adjacencies and influence routing. "
                "Enable Lab mode only on isolated lab routers you own.",
            ],
        )
    from scapy.contrib.ospf import OSPF_Hdr, OSPF_Hello
    from scapy.layers.inet import IP
    from scapy.sendrecv import send

    hello = (
        IP(dst="224.0.0.5", proto=89)
        / OSPF_Hdr(version=2, type=1, src=config.router_id, area=config.area)
        / OSPF_Hello()
    )
    warnings = ["Lab mode: sent an OSPF Hello to 224.0.0.5. Lab networks only."]
    try:
        send(hello, iface=config.interface, verbose=False)
    except Exception as exc:
        return ProtocolProbeResult(
            protocol="OSPF",
            target=config.interface or "multicast",
            success=False,
            summary=f"OSPF Hello send failed: {exc}",
            lab_mode=True,
            warnings=warnings,
        )
    return ProtocolProbeResult(
        protocol="OSPF",
        target=config.interface or "multicast",
        success=True,
        summary="sent one OSPF Hello (no adjacency state maintained)",
        lab_mode=True,
        warnings=warnings,
    )
