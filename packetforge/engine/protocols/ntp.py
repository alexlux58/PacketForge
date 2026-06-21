from __future__ import annotations

import time
from dataclasses import dataclass

from packetforge.engine.protocols import udp_query
from packetforge.models.discovery import ProtocolProbeResult

# Seconds between the NTP epoch (1900) and the Unix epoch (1970).
NTP_UNIX_DELTA = 2_208_988_800


@dataclass
class NtpProbe:
    host: str
    port: int = 123
    timeout_s: float = 3.0


def probe(config: NtpProbe) -> ProtocolProbeResult:
    """Standard NTP client (mode 3) time query. No monlist/legacy mode 7 commands."""
    from scapy.layers.ntp import NTP

    request = NTP(version=4, mode=3)
    t1 = time.time()
    try:
        raw = udp_query(bytes(request), config.host, config.port, config.timeout_s)
    except TimeoutError:
        return ProtocolProbeResult(
            protocol="NTP",
            target=config.host,
            success=False,
            summary=f"no NTP response within {config.timeout_s:.1f}s",
        )
    except OSError as exc:
        return ProtocolProbeResult(
            protocol="NTP", target=config.host, success=False, summary=f"socket error: {exc}"
        )
    t4 = time.time()
    response = NTP(raw)
    t2 = _to_unix(getattr(response, "recv", 0))
    t3 = _to_unix(getattr(response, "sent", 0))
    offset = ((t2 - t1) + (t3 - t4)) / 2 if t2 and t3 else None
    delay = (t4 - t1) - (t3 - t2) if t2 and t3 else (t4 - t1)
    stratum = int(getattr(response, "stratum", 0))
    detail = {
        "stratum": str(stratum),
        "offset_ms": "n/a" if offset is None else f"{offset * 1000:.2f}",
        "delay_ms": f"{delay * 1000:.2f}",
        "ref_id": str(getattr(response, "ref_id", getattr(response, "id", ""))),
        "poll": str(getattr(response, "poll", "")),
        "precision": str(getattr(response, "precision", "")),
    }
    return ProtocolProbeResult(
        protocol="NTP",
        target=config.host,
        success=stratum > 0,
        summary=(
            f"stratum {stratum}, offset {detail['offset_ms']} ms, delay {detail['delay_ms']} ms"
        ),
        detail=detail,
        latency_ms=(t4 - t1) * 1000,
    )


def _to_unix(ntp_timestamp: float) -> float:
    if not ntp_timestamp:
        return 0.0
    return float(ntp_timestamp) - NTP_UNIX_DELTA
