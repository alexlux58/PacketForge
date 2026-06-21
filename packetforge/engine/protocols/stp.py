from __future__ import annotations

import threading
from dataclasses import dataclass

from packetforge.models.discovery import ProtocolProbeResult


@dataclass
class StpPassiveProbe:
    interface: str | None = None
    seconds: int = 30


@dataclass
class StpActiveProbe:
    interface: str | None = None
    root_id: int = 32768
    bridge_id: int = 32768
    lab_mode: bool = False


def observe(
    config: StpPassiveProbe, stop_event: threading.Event | None = None
) -> ProtocolProbeResult:  # pragma: no cover - requires raw sockets
    """Passively decode STP BPDUs. Sends nothing."""
    from scapy.layers.l2 import STP
    from scapy.sendrecv import sniff

    stop = stop_event or threading.Event()
    try:
        packets = sniff(
            iface=config.interface,
            filter="stp",
            timeout=config.seconds,
            store=True,
            stop_filter=lambda _pkt: stop.is_set(),
        )
    except Exception as exc:
        return ProtocolProbeResult(
            protocol="STP",
            target=config.interface or "default",
            success=False,
            summary=f"passive capture unavailable: {exc}",
        )
    records: list[str] = []
    roots: set[str] = set()
    for pkt in packets:
        if pkt.haslayer(STP):
            bpdu = pkt[STP]
            root = f"{bpdu.rootid}/{bpdu.rootmac}"
            roots.add(root)
            records.append(
                f"root {root} cost {bpdu.pathcost} bridge {bpdu.bridgeid}/{bpdu.bridgemac}"
            )
    return ProtocolProbeResult(
        protocol="STP",
        target=config.interface or "default",
        success=bool(records),
        summary=f"observed {len(records)} BPDU(s); {len(roots)} root bridge(s)",
        detail={"roots": ", ".join(sorted(roots))},
        records=records,
    )


def send_bpdu(
    config: StpActiveProbe,
) -> ProtocolProbeResult:  # pragma: no cover - requires raw sockets
    """Send a single STP configuration BPDU. Lab mode only; can affect spanning tree."""
    if not config.lab_mode:
        return ProtocolProbeResult(
            protocol="STP",
            target=config.interface or "l2",
            success=False,
            summary="BPDU not sent (lab mode required)",
            warnings=[
                "Injecting BPDUs can trigger topology changes or root takeover and "
                "disrupt switching. Enable Lab mode only on isolated lab switches.",
            ],
        )
    from scapy.layers.l2 import LLC, STP, Dot3
    from scapy.sendrecv import sendp

    bpdu = (
        Dot3(dst="01:80:c2:00:00:00")
        / LLC(dsap=0x42, ssap=0x42, ctrl=3)
        / STP(rootid=config.root_id, bridgeid=config.bridge_id)
    )
    warnings = ["Lab mode: sent an STP BPDU. Lab switches only."]
    try:
        sendp(bpdu, iface=config.interface, verbose=False)
    except Exception as exc:
        return ProtocolProbeResult(
            protocol="STP",
            target=config.interface or "l2",
            success=False,
            summary=f"BPDU send failed: {exc}",
            lab_mode=True,
            warnings=warnings,
        )
    return ProtocolProbeResult(
        protocol="STP",
        target=config.interface or "l2",
        success=True,
        summary="sent one configuration BPDU",
        lab_mode=True,
        warnings=warnings,
    )
