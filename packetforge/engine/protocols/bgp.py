from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from packetforge.models.discovery import ProtocolProbeResult


@dataclass
class BgpProbe:
    host: str
    port: int = 179
    timeout_s: float = 4.0
    lab_mode: bool = False
    local_as: int = 65000
    bgp_id: str = "10.255.255.1"
    hold_time: int = 90


def probe(config: BgpProbe) -> ProtocolProbeResult:
    """Check TCP/179 reachability. Sends a BGP OPEN only in explicit lab mode."""
    start = time.perf_counter()
    try:
        sock = socket.create_connection((config.host, config.port), timeout=config.timeout_s)
    except ConnectionRefusedError:
        return ProtocolProbeResult(
            protocol="BGP",
            target=f"{config.host}:{config.port}",
            success=False,
            summary="TCP/179 refused (no BGP listener or filtered)",
        )
    except OSError as exc:
        return ProtocolProbeResult(
            protocol="BGP",
            target=f"{config.host}:{config.port}",
            success=False,
            summary=f"TCP/179 unreachable: {exc}",
        )
    latency = (time.perf_counter() - start) * 1000
    if not config.lab_mode:
        sock.close()
        return ProtocolProbeResult(
            protocol="BGP",
            target=f"{config.host}:{config.port}",
            success=True,
            summary=f"TCP/179 reachable in {latency:.1f} ms (reachability only)",
            detail={"tcp_179": "open"},
            latency_ms=latency,
            warnings=["Enable Lab mode to send a BGP OPEN capability probe (lab networks only)."],
        )
    return _open_probe(sock, config, latency)


def _open_probe(
    sock: socket.socket, config: BgpProbe, latency: float
) -> ProtocolProbeResult:
    from scapy.contrib.bgp import BGP, BGPHeader, BGPOpen

    open_msg = BGPHeader(type=1) / BGPOpen(
        my_as=config.local_as,
        hold_time=config.hold_time,
        bgp_id=config.bgp_id,
    )
    warnings = ["Lab mode: sent a BGP OPEN. Only do this on routers you control."]
    try:
        sock.sendall(bytes(open_msg))
        sock.settimeout(config.timeout_s)
        data = sock.recv(4096)
    except OSError as exc:
        sock.close()
        return ProtocolProbeResult(
            protocol="BGP",
            target=f"{config.host}:{config.port}",
            success=True,
            summary=f"TCP/179 reachable; OPEN exchange error: {exc}",
            latency_ms=latency,
            lab_mode=True,
            warnings=warnings,
        )
    sock.close()
    detail = {"tcp_179": "open", "open_sent": "yes"}
    if data:
        parsed = BGP(data)
        detail["peer_reply"] = parsed.summary()
    return ProtocolProbeResult(
        protocol="BGP",
        target=f"{config.host}:{config.port}",
        success=True,
        summary=f"BGP OPEN exchanged; {len(data)} bytes returned",
        detail=detail,
        latency_ms=latency,
        lab_mode=True,
        warnings=warnings,
    )
