from __future__ import annotations

import socket

from packetforge.engine.fingerprint import (
    FingerprintObservations,
    score_fingerprint,
)
from packetforge.models.discovery import FingerprintEvidence

# Ports likely to emit a useful banner without authentication.
_BANNER_PORTS: tuple[int, ...] = (22, 21, 25, 80, 110, 143, 443, 587)


def gather_observations(
    host: str,
    *,
    ports: tuple[int, ...] = _BANNER_PORTS,
    timeout: float = 2.0,
    interface: str | None = None,
    raw_ok: bool = False,
) -> FingerprintObservations:
    """Collect fingerprint signals using whatever privileges are available.

    Unprivileged path: banner grabbing over TCP connect.
    Privileged path (raw sockets): adds ICMP TTL and TCP SYN option signals.
    """
    observations = FingerprintObservations(host=host, raw_signals_available=raw_ok)
    observations.banners, observations.connect_results = _grab_banners(host, ports, timeout)
    if raw_ok:
        _add_raw_signals(observations, host, timeout, interface, ports)
    return observations


def fingerprint_host(
    host: str,
    *,
    ports: tuple[int, ...] = _BANNER_PORTS,
    timeout: float = 2.0,
    interface: str | None = None,
    raw_ok: bool = False,
) -> FingerprintEvidence:
    observations = gather_observations(
        host, ports=ports, timeout=timeout, interface=interface, raw_ok=raw_ok
    )
    return score_fingerprint(observations)


def _grab_banners(
    host: str, ports: tuple[int, ...], timeout: float
) -> tuple[dict[str, str], dict[int, str]]:
    """Connect to each port, capturing banners and the outcome of every attempt."""
    banners: dict[str, str] = {}
    results: dict[int, str] = {}
    for port in ports:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(min(timeout, 1.5))
                if port in {80, 443, 8080}:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                data = sock.recv(256)
        except ConnectionRefusedError:
            results[port] = "connection refused"
            continue
        except TimeoutError:
            results[port] = "timeout / filtered"
            continue
        except OSError as exc:
            results[port] = f"error: {type(exc).__name__}"
            continue
        text = data.decode("latin-1", errors="replace").strip()
        if text:
            banners[_port_label(port)] = text
            results[port] = "open (banner)"
        else:
            results[port] = "open (no banner)"
    return banners, results


def _port_label(port: int) -> str:
    return {
        22: "SSH", 21: "FTP", 25: "SMTP", 80: "HTTP", 110: "POP3",
        143: "IMAP", 443: "HTTPS", 587: "SMTP", 8080: "HTTP",
    }.get(port, f"port-{port}")


def _add_raw_signals(  # pragma: no cover - requires raw sockets
    observations: FingerprintObservations,
    host: str,
    timeout: float,
    interface: str | None,
    ports: tuple[int, ...],
) -> None:
    from scapy.layers.inet import ICMP, IP, TCP
    from scapy.sendrecv import sr1

    try:
        echo = sr1(IP(dst=host) / ICMP(), timeout=timeout, iface=interface, verbose=False)
    except (OSError, PermissionError):
        echo = None
    if echo is not None:
        observations.icmp_echo_reply = True
        observations.ttl = int(getattr(echo[IP], "ttl", 0)) or None
    else:
        observations.icmp_echo_reply = False

    for port in ports:
        try:
            synack = sr1(
                IP(dst=host) / TCP(dport=port, flags="S", options=[("MSS", 1460)]),
                timeout=timeout,
                iface=interface,
                verbose=False,
            )
        except (OSError, PermissionError):
            break
        if synack is None or not synack.haslayer(TCP):
            continue
        tcp = synack[TCP]
        if observations.ttl is None:
            observations.ttl = int(getattr(synack[IP], "ttl", 0)) or None
        observations.tcp_window = int(tcp.window)
        _parse_tcp_options(observations, tcp.options)
        # Be polite: tear the half-open connection down.
        try:
            from scapy.layers.inet import TCP as _TCP
            from scapy.sendrecv import send

            send(
                IP(dst=host) / _TCP(dport=port, sport=tcp.dport, flags="R", seq=tcp.ack),
                iface=interface,
                verbose=False,
            )
        except (OSError, PermissionError):
            pass
        break


def _parse_tcp_options(  # pragma: no cover - requires raw sockets
    observations: FingerprintObservations, options: list[tuple[str, object]]
) -> None:
    for name, value in options:
        if name == "MSS" and isinstance(value, int):
            observations.mss = value
        elif name == "WScale" and isinstance(value, int):
            observations.window_scale = value
        elif name == "SAckOK":
            observations.sack_permitted = True
        elif name == "Timestamp":
            observations.tcp_timestamps = True
    if observations.sack_permitted is None:
        observations.sack_permitted = False
    if observations.tcp_timestamps is None:
        observations.tcp_timestamps = False
