"""First-run environment checks.

GUI-free so it can be unit tested without Qt or a live network. Each check
returns a :class:`CheckResult`; :func:`run_environment_checks` aggregates them
into an :class:`EnvironmentReport` that the GUI renders on first launch and on
demand.

None of these checks send packets or require elevation - the PCAP test writes a
single crafted packet to a temporary file and reads it back.
"""

from __future__ import annotations

import sys
import tempfile
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

CheckStatus = Literal["ok", "warning", "fail"]

MIN_PYTHON: tuple[int, int] = (3, 12)


@dataclass(frozen=True)
class CheckResult:
    name: str
    status: CheckStatus
    detail: str
    hint: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "ok"


@dataclass(frozen=True)
class EnvironmentReport:
    results: list[CheckResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """True when nothing failed (warnings are acceptable)."""
        return all(result.status != "fail" for result in self.results)

    @property
    def has_warnings(self) -> bool:
        return any(result.status == "warning" for result in self.results)

    @property
    def has_failures(self) -> bool:
        return any(result.status == "fail" for result in self.results)

    def get(self, name: str) -> CheckResult | None:
        return next((result for result in self.results if result.name == name), None)

    def summary(self) -> str:
        if self.has_failures:
            return "Environment has blocking problems - see the failed checks below."
        if self.has_warnings:
            return "Environment is usable; some optional capabilities are limited."
        return "Environment looks good. All checks passed."


def check_python_version() -> CheckResult:
    current = sys.version_info[:3]
    text = ".".join(str(part) for part in current)
    if current[:2] >= MIN_PYTHON:
        return CheckResult("Python version", "ok", f"Python {text}")
    return CheckResult(
        "Python version",
        "fail",
        f"Python {text} is too old",
        f"PacketForge requires Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]} or newer.",
    )


def check_scapy() -> CheckResult:
    try:
        import scapy

        version = getattr(scapy, "VERSION", None) or getattr(scapy, "__version__", "unknown")
        return CheckResult("Scapy", "ok", f"scapy {version} available")
    except Exception as exc:  # pragma: no cover - exercised via monkeypatch in tests
        return CheckResult(
            "Scapy",
            "fail",
            f"scapy could not be imported: {exc}",
            "Install with 'pip install scapy'. On macOS/Linux ensure libpcap is present.",
        )


def check_pyside6() -> CheckResult:
    try:
        from PySide6 import __version__ as pyside_version

        return CheckResult("PySide6", "ok", f"PySide6 {pyside_version} available")
    except Exception as exc:  # pragma: no cover - exercised via monkeypatch in tests
        return CheckResult(
            "PySide6",
            "fail",
            f"PySide6 could not be imported: {exc}",
            "Install with 'pip install PySide6'. On Linux also install libGL and xcb libraries.",
        )


def check_interfaces(interfaces: Sequence[str] | None = None) -> CheckResult:
    if interfaces is None:
        from packetforge.engine.interfaces import list_interfaces

        interfaces = list_interfaces()
    names = list(interfaces)
    if names:
        preview = ", ".join(names[:6])
        if len(names) > 6:
            preview += ", ..."
        return CheckResult("Interfaces", "ok", f"{len(names)} detected: {preview}")
    return CheckResult(
        "Interfaces",
        "warning",
        "no network interfaces detected",
        "Scapy could not enumerate interfaces; capture and raw send may be unavailable.",
    )


def check_raw_socket_privilege(*, raw_sockets: bool | None = None) -> CheckResult:
    notes: list[str] = []
    if raw_sockets is None:
        from packetforge.security.privileges import detect_privileges

        report = detect_privileges()
        raw_sockets = report.raw_sockets
        notes = list(report.notes)
    if raw_sockets:
        return CheckResult("Raw socket privilege", "ok", "raw sockets available")
    return CheckResult(
        "Raw socket privilege",
        "warning",
        "unprivileged - socket-based fallbacks active",
        notes[0]
        if notes
        else "ICMP, ARP, and fingerprint probes need elevation (sudo / setcap).",
    )


def check_pcap_write(directory: str | Path | None = None) -> CheckResult:
    """Write a single crafted packet to a PCAP file and read it back."""
    try:
        from scapy.layers.inet import ICMP, IP

        from packetforge.utils.export import export_packets_to_pcap, load_packets_from_pcap

        packet = IP(dst="127.0.0.1") / ICMP()
        if directory is not None:
            target = Path(directory) / "packetforge-selftest.pcap"
            target.parent.mkdir(parents=True, exist_ok=True)
            export_packets_to_pcap([packet], target)
            count = len(load_packets_from_pcap(target))
            target.unlink(missing_ok=True)
        else:
            with tempfile.TemporaryDirectory(prefix="packetforge-") as tmp:
                target = Path(tmp) / "packetforge-selftest.pcap"
                export_packets_to_pcap([packet], target)
                count = len(load_packets_from_pcap(target))
        return CheckResult("PCAP write test", "ok", f"wrote and re-read {count} packet")
    except Exception as exc:
        return CheckResult(
            "PCAP write test",
            "fail",
            f"PCAP read/write failed: {exc}",
            "Check the scapy/libpcap install and that the temp directory is writable.",
        )


def run_environment_checks(
    *,
    interfaces: Iterable[str] | None = None,
    raw_sockets: bool | None = None,
    pcap_directory: str | Path | None = None,
) -> EnvironmentReport:
    """Run all environment checks. External lookups are injectable for tests."""
    return EnvironmentReport(
        results=[
            check_python_version(),
            check_scapy(),
            check_pyside6(),
            check_interfaces(None if interfaces is None else list(interfaces)),
            check_raw_socket_privilege(raw_sockets=raw_sockets),
            check_pcap_write(pcap_directory),
        ]
    )
