"""Safe, read-only-by-default protocol troubleshooting helpers.

Every probe in this package defaults to passive or normal-client behaviour.
Anything that emits non-standard traffic (zone transfers, DHCP discover,
BGP OPEN, active OSPF/STP) is gated behind an explicit lab-mode / confirmation
flag and surfaced to the user through ``ProtocolProbeResult.warnings``.
"""

from __future__ import annotations

import socket


def udp_query(payload: bytes, host: str, port: int, timeout: float) -> bytes:
    """Send a single UDP datagram and return the first response (unprivileged)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        sock.sendto(payload, (host, port))
        data, _addr = sock.recvfrom(65535)
        return data
    finally:
        sock.close()
