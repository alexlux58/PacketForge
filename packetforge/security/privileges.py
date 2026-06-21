from __future__ import annotations

import os
import platform
import socket
from dataclasses import dataclass, field


def privilege_status() -> str:
    if platform.system() == "Windows":
        return "Privilege status: Windows support is planned"
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return "Privilege status: raw sockets available"
    return "Privilege status: unprivileged; sending may require sudo/capabilities"


@dataclass(frozen=True)
class PrivilegeReport:
    """Snapshot of which capabilities are available in the current process.

    The discovery and protocol tools use this to choose unprivileged fallbacks
    where possible and to clearly warn the user when a probe needs elevation.
    """

    is_root: bool
    raw_sockets: bool
    platform_name: str
    notes: list[str] = field(default_factory=list)

    @property
    def headline(self) -> str:
        if self.raw_sockets:
            return "Raw sockets available (full discovery enabled)"
        return "Unprivileged mode (using socket-based fallbacks where possible)"


def detect_privileges() -> PrivilegeReport:
    system = platform.system()
    is_root = bool(hasattr(os, "geteuid") and os.geteuid() == 0)
    raw_sockets = _can_open_raw_socket()
    notes: list[str] = []
    if not raw_sockets:
        notes.append(
            "ARP scan, ICMP echo, and OS fingerprinting need raw sockets; "
            "run with elevated privileges (sudo / setcap) to enable them."
        )
        notes.append(
            "TCP connect, UDP, DNS, SMTP, NTP, SNMP, and passive capture parsing "
            "still work without elevation."
        )
    if system == "Windows":
        notes.append("Raw send on Windows additionally requires Npcap.")
    return PrivilegeReport(
        is_root=is_root,
        raw_sockets=raw_sockets,
        platform_name=system,
        notes=notes,
    )


def _can_open_raw_socket() -> bool:
    if not hasattr(socket, "SOCK_RAW"):
        return False
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except (PermissionError, OSError):
        return False
    raw.close()
    return True


# Which discovery methods need raw socket privileges to run reliably.
PRIVILEGED_METHODS = frozenset({"arp", "icmp"})
UNPRIVILEGED_METHODS = frozenset({"tcp", "udp", "dns_reverse", "passive"})
