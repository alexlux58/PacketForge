from __future__ import annotations

import socket
import time
from dataclasses import dataclass

from packetforge.models.discovery import ProtocolProbeResult


@dataclass
class SmtpProbe:
    host: str
    port: int = 25
    ehlo_name: str = "packetforge.local"
    timeout_s: float = 5.0


def probe(config: SmtpProbe) -> ProtocolProbeResult:
    """Connect, read the banner, send EHLO, and list capabilities. No mail is sent."""
    start = time.perf_counter()
    try:
        with socket.create_connection((config.host, config.port), timeout=config.timeout_s) as sock:
            sock.settimeout(config.timeout_s)
            banner = _read_line(sock)
            sock.sendall(f"EHLO {config.ehlo_name}\r\n".encode("ascii"))
            ehlo = _read_block(sock)
    except OSError as exc:
        return ProtocolProbeResult(
            protocol="SMTP",
            target=f"{config.host}:{config.port}",
            success=False,
            summary=f"connection failed: {exc}",
        )
    latency = (time.perf_counter() - start) * 1000
    capabilities = _parse_capabilities(ehlo)
    starttls = any(cap.upper().startswith("STARTTLS") for cap in capabilities)
    return ProtocolProbeResult(
        protocol="SMTP",
        target=f"{config.host}:{config.port}",
        success=bool(banner),
        summary=f"banner received; {len(capabilities)} EHLO capabilities; "
        f"STARTTLS {'available' if starttls else 'not advertised'}",
        detail={
            "banner": banner,
            "starttls": "yes" if starttls else "no",
        },
        records=capabilities,
        latency_ms=latency,
        warnings=[] if starttls else ["No STARTTLS advertised; this server may accept cleartext."],
    )


def _read_line(sock: socket.socket) -> str:
    return sock.recv(1024).decode("latin-1", errors="replace").strip()


def _read_block(sock: socket.socket) -> str:
    buffer = b""
    try:
        for _ in range(8):
            data = sock.recv(2048)
            if not data:
                break
            buffer += data
            last = buffer.splitlines()[-1] if buffer.splitlines() else b""
            # A multiline SMTP reply ends when the code is followed by a space.
            if len(last) >= 4 and last[:3].isdigit() and last[3:4] == b" ":
                break
    except OSError:
        pass
    return buffer.decode("latin-1", errors="replace")


def _parse_capabilities(ehlo: str) -> list[str]:
    capabilities: list[str] = []
    for line in ehlo.splitlines():
        line = line.strip()
        if len(line) >= 4 and line[:3].isdigit():
            capability = line[4:].strip()
            if capability:
                capabilities.append(capability)
    return capabilities
