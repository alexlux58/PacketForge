from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from packetforge.engine.merge import upsert_host
from packetforge.engine.targets import is_local_subnet, parse_targets
from packetforge.models.discovery import (
    DiscoveryConfig,
    DiscoveryMethod,
    DiscoveryRun,
    HostRecord,
    PortState,
    ServiceRecord,
)
from packetforge.models.profiles import ScanProfile, profile_by_name
from packetforge.security.privileges import detect_privileges
from packetforge.security.rate_limit import RateLimiter

HostCallback = Callable[[HostRecord], None]
ProgressCallback = Callable[[int, int], None]
LogCallback = Callable[[str], None]

# Minimal, well-known service names so the UI shows something useful without nmap.
_SERVICE_NAMES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 123: "ntp", 135: "msrpc", 139: "netbios", 143: "imap",
    161: "snmp", 179: "bgp", 443: "https", 445: "smb", 500: "isakmp",
    587: "submission", 993: "imaps", 995: "pop3s", 3389: "rdp", 8080: "http-alt",
}


def service_name(port: int) -> str | None:
    return _SERVICE_NAMES.get(port)


class DiscoveryEngine:
    """Coordinates rate-limited, safe active and passive host discovery."""

    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.captured_packets: list[object] = []
        self._index: dict[str, HostRecord] = {}
        self._lock = threading.Lock()
        self._done = 0
        self._total = 0

    def stop(self) -> None:
        self.stop_event.set()

    def pause(self) -> None:
        self.pause_event.set()

    def resume(self) -> None:
        self.pause_event.clear()

    def _wait_if_paused(self) -> None:
        while self.pause_event.is_set() and not self.stop_event.is_set():
            time.sleep(0.05)

    def run(
        self,
        config: DiscoveryConfig,
        *,
        on_host: HostCallback | None = None,
        on_progress: ProgressCallback | None = None,
        on_log: LogCallback | None = None,
    ) -> DiscoveryRun:
        self.stop_event.clear()
        self.pause_event.clear()
        self.captured_packets.clear()
        self._index.clear()
        self._done = 0

        log = on_log or (lambda _message: None)
        profile = profile_by_name(config.profile_name)
        limiter = RateLimiter(profile.max_packets_per_second)
        parsed = parse_targets(config.targets, max_targets=config.max_targets)
        for warning in parsed.warnings:
            log(warning)
        targets = parsed.targets
        self._total = max(1, len(targets))
        privileges = detect_privileges()

        run = DiscoveryRun(
            profile=profile.name,
            targets=config.targets,
            methods=config.methods,
            interface=config.interface,
        )

        if "arp" in config.methods:
            self._run_arp(config, profile, limiter, privileges.raw_sockets, on_host, log)

        active_methods: list[DiscoveryMethod] = [
            m for m in config.methods if m in {"icmp", "tcp", "udp"}
        ]
        if active_methods and targets:
            self._run_active(
                targets, active_methods, config, profile, limiter,
                privileges.raw_sockets, on_host, on_progress, log,
            )

        if "dns_reverse" in config.methods and not self.stop_event.is_set():
            self._run_reverse_dns(targets, on_host, log)

        if "passive" in config.methods and not self.stop_event.is_set():
            self._run_passive(config, on_host, log)

        if config.resolve_hostnames:
            self._resolve_known_hostnames(on_host)

        run.hosts = sorted(self._index.values(), key=lambda h: h.ip)
        run.finished_at = _utcnow()
        log(f"Discovery finished: {len(run.hosts)} host(s).")
        return run

    def _emit(self, host: HostRecord, on_host: HostCallback | None) -> None:
        if on_host is not None:
            on_host(host)

    def _record(
        self, partial: HostRecord, on_host: HostCallback | None
    ) -> HostRecord:
        with self._lock:
            merged = upsert_host(self._index, partial)
        self._emit(merged, on_host)
        return merged

    def _run_active(
        self,
        targets: list[str],
        methods: list[DiscoveryMethod],
        config: DiscoveryConfig,
        profile: ScanProfile,
        limiter: RateLimiter,
        raw_ok: bool,
        on_host: HostCallback | None,
        on_progress: ProgressCallback | None,
        log: LogCallback,
    ) -> None:
        if "icmp" in methods and not raw_ok:
            log("ICMP echo needs raw sockets; skipping (run elevated to enable).")

        def worker(target: str) -> None:
            if self.stop_event.is_set():
                return
            self._wait_if_paused()
            self._probe_target(target, methods, config, profile, limiter, raw_ok, on_host, log)
            with self._lock:
                self._done += 1
                done = self._done
            if on_progress is not None:
                on_progress(done, self._total)
            if profile.inter_target_delay_ms:
                time.sleep(profile.inter_target_delay_ms / 1000)

        with ThreadPoolExecutor(max_workers=profile.concurrency) as pool:
            list(pool.map(worker, targets))

    def _probe_target(
        self,
        target: str,
        methods: list[DiscoveryMethod],
        config: DiscoveryConfig,
        profile: ScanProfile,
        limiter: RateLimiter,
        raw_ok: bool,
        on_host: HostCallback | None,
        log: LogCallback,
    ) -> None:
        timeout = profile.probe_timeout_ms / 1000
        found_methods: list[DiscoveryMethod] = []
        latency: float | None = None
        services: list[ServiceRecord] = []

        if "icmp" in methods and raw_ok:
            limiter.acquire()
            alive, rtt = _icmp_echo(target, timeout, config.interface)
            if alive:
                found_methods.append("icmp")
                latency = rtt

        if "tcp" in methods:
            for port in config.tcp_ports[: profile.max_ports_per_host]:
                if self.stop_event.is_set():
                    break
                self._wait_if_paused()
                limiter.acquire()
                state, banner, rtt = _tcp_connect(
                    target, port, timeout, grab_banner=config.grab_banners
                )
                if state == "open":
                    if "tcp" not in found_methods:
                        found_methods.append("tcp")
                    if latency is None:
                        latency = rtt
                    services.append(
                        ServiceRecord(
                            port=port, protocol="tcp", state=state,
                            name=service_name(port), banner=banner,
                        )
                    )

        if "udp" in methods:
            for port in config.udp_ports[: profile.max_ports_per_host]:
                if self.stop_event.is_set():
                    break
                self._wait_if_paused()
                limiter.acquire()
                state = _udp_probe(target, port, timeout)
                if state in {"open", "open|filtered"}:
                    if "udp" not in found_methods:
                        found_methods.append("udp")
                    services.append(
                        ServiceRecord(
                            port=port, protocol="udp", state=state, name=service_name(port)
                        )
                    )

        if not found_methods and not services:
            return
        host = HostRecord(
            ip=target,
            latency_ms=latency,
            services=services,
            methods=found_methods,
            subnet=_subnet_for(target),
        )
        self._record(host, on_host)

    def _run_arp(
        self,
        config: DiscoveryConfig,
        profile: ScanProfile,
        limiter: RateLimiter,
        raw_ok: bool,
        on_host: HostCallback | None,
        log: LogCallback,
    ) -> None:
        if not raw_ok:
            log("ARP scan needs raw sockets; skipping (run elevated to enable).")
            return
        if not is_local_subnet(config.targets.split()[0] if config.targets.strip() else ""):
            log("ARP scan only runs against local/private subnets; skipping.")
            return
        log("Running ARP scan on local segment...")
        try:
            entries = _arp_scan(config.targets, config.interface, profile.probe_timeout_ms / 1000)
        except Exception as exc:  # pragma: no cover - depends on host privileges
            log(f"ARP scan unavailable: {exc}")
            return
        for ip, mac in entries.items():
            host = HostRecord(ip=ip, mac=mac, methods=["arp"], subnet=_subnet_for(ip))
            self._record(host, on_host)

    def _run_reverse_dns(
        self, targets: list[str], on_host: HostCallback | None, log: LogCallback
    ) -> None:
        log("Running reverse DNS lookups...")
        for target in targets:
            if self.stop_event.is_set():
                break
            self._wait_if_paused()
            hostname = _reverse_dns(target)
            if hostname:
                host = HostRecord(
                    ip=target, hostname=hostname, methods=["dns_reverse"],
                    subnet=_subnet_for(target),
                )
                self._record(host, on_host)

    def _resolve_known_hostnames(self, on_host: HostCallback | None) -> None:
        for ip in list(self._index):
            host = self._index[ip]
            if host.hostname is None:
                hostname = _reverse_dns(ip)
                if hostname:
                    updated = host.model_copy(update={"hostname": hostname})
                    self._record(updated, on_host)

    def _run_passive(
        self, config: DiscoveryConfig, on_host: HostCallback | None, log: LogCallback
    ) -> None:
        log(f"Passive capture for {config.passive_seconds}s...")
        try:
            hosts, packets = _passive_capture(
                config.interface, config.passive_seconds, self.stop_event
            )
        except Exception as exc:  # pragma: no cover - depends on host privileges
            log(f"Passive capture unavailable: {exc}")
            return
        if config.record_pcap:
            self.captured_packets.extend(packets)
        for host in hosts:
            self._record(host, on_host)


def _subnet_for(ip: str) -> str | None:
    import ipaddress

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return str(ipaddress.ip_network(f"{ip}/64", strict=False))


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _tcp_connect(
    ip: str, port: int, timeout: float, *, grab_banner: bool
) -> tuple[PortState, str | None, float | None]:
    start = time.perf_counter()
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            rtt = (time.perf_counter() - start) * 1000
            banner: str | None = None
            if grab_banner:
                banner = _read_banner(sock, timeout)
            return "open", banner, rtt
    except (ConnectionRefusedError, OSError) as exc:
        if isinstance(exc, ConnectionRefusedError):
            return "closed", None, None
        if isinstance(exc, TimeoutError) or "timed out" in str(exc):
            return "filtered", None, None
        return "filtered", None, None


def _read_banner(sock: socket.socket, timeout: float) -> str | None:
    try:
        sock.settimeout(min(timeout, 1.5))
        data = sock.recv(256)
    except OSError:
        return None
    if not data:
        return None
    return data.decode("latin-1", errors="replace").strip() or None


def _udp_probe(ip: str, port: int, timeout: float) -> PortState:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        return "unknown"
    try:
        sock.settimeout(timeout)
        sock.sendto(b"", (ip, port))
        try:
            sock.recvfrom(512)
            return "open"
        except TimeoutError:
            return "open|filtered"
        except ConnectionRefusedError:
            return "closed"
        except OSError:
            return "closed"
    finally:
        sock.close()


def _reverse_dns(ip: str) -> str | None:
    try:
        host, _aliases, _addrs = socket.gethostbyaddr(ip)
    except (OSError, UnicodeError):
        return None
    return host or None


def _icmp_echo(
    ip: str, timeout: float, iface: str | None
) -> tuple[bool, float | None]:  # pragma: no cover - requires raw sockets
    from scapy.layers.inet import ICMP, IP
    from scapy.sendrecv import sr1

    start = time.perf_counter()
    try:
        reply = sr1(IP(dst=ip) / ICMP(), timeout=timeout, iface=iface, verbose=False)
    except (OSError, PermissionError):
        return False, None
    if reply is None:
        return False, None
    return True, (time.perf_counter() - start) * 1000


def _arp_scan(
    targets: str, iface: str | None, timeout: float
) -> dict[str, str]:  # pragma: no cover - requires raw sockets
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp

    answered, _unanswered = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets),
        timeout=timeout,
        iface=iface,
        verbose=False,
    )
    entries: dict[str, str] = {}
    for _sent, received in answered:
        entries[str(received.psrc)] = str(received.hwsrc)
    return entries


def _passive_capture(
    iface: str | None, seconds: int, stop_event: threading.Event
) -> tuple[list[HostRecord], list[object]]:  # pragma: no cover - requires raw sockets
    from scapy.layers.inet import IP
    from scapy.layers.l2 import ARP
    from scapy.sendrecv import sniff

    packets = sniff(
        iface=iface,
        timeout=seconds,
        store=True,
        stop_filter=lambda _pkt: stop_event.is_set(),
    )
    seen: dict[str, HostRecord] = {}
    for pkt in packets:
        ip = None
        mac = None
        if pkt.haslayer(ARP):
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
        elif pkt.haslayer(IP):
            ip = pkt[IP].src
        if ip:
            current = seen.get(ip)
            if current is None:
                seen[ip] = HostRecord(
                    ip=ip, mac=mac, methods=["passive"], subnet=_subnet_for(ip)
                )
            elif mac and not current.mac:
                seen[ip] = current.model_copy(update={"mac": mac})
    return list(seen.values()), list(packets)
