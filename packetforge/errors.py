"""Central error model, exception classification, and safe reporting.

This module is GUI-free so it can be unit tested without Qt. It turns raw
exceptions (Scapy errors, permission failures, bad CIDRs, timeouts, ...) into a
:class:`ErrorEvent` that carries a *safe* user-facing summary plus a suggested
fix, while preserving the full traceback for logging only.
"""

from __future__ import annotations

import errno
import ipaddress
import logging
import socket
import struct
import traceback as traceback_mod
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from packetforge.diagnostics import get_logger

ErrorSeverity = Literal["info", "warning", "error", "critical"]
ErrorCategory = Literal[
    "permission_denied",
    "interface_unavailable",
    "invalid_cidr",
    "dns_failure",
    "timeout",
    "malformed_packet",
    "unsupported_platform",
    "scapy_error",
    "unknown",
]

_SEVERITY_TO_LEVEL: dict[ErrorSeverity, int] = {
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}


# --------------------------------------------------------------------------- #
# Domain exceptions the engine can raise to force a precise classification.
# --------------------------------------------------------------------------- #
class PacketForgeError(Exception):
    """Base class for PacketForge domain errors."""


class InterfaceUnavailableError(PacketForgeError):
    """The requested network interface is missing or cannot be opened."""


class InvalidTargetError(PacketForgeError, ValueError):
    """A target / CIDR / range specification could not be parsed."""


class UnsupportedPlatformError(PacketForgeError):
    """The operation is not supported on the current OS/platform."""


@dataclass(frozen=True)
class _Template:
    severity: ErrorSeverity
    message: str
    fix: str


_TEMPLATES: dict[ErrorCategory, _Template] = {
    "permission_denied": _Template(
        "error",
        "Permission denied for this operation.",
        "Run PacketForge with elevated privileges (sudo, or 'setcap cap_net_raw+ep' on the "
        "Python binary), or use an unprivileged method such as TCP connect, UDP, or DNS.",
    ),
    "interface_unavailable": _Template(
        "error",
        "The selected network interface is unavailable.",
        "Pick a different interface or leave it blank to use the default. Ensure the interface "
        "is up; on Windows, install Npcap for raw capture/send.",
    ),
    "invalid_cidr": _Template(
        "warning",
        "The target specification is invalid.",
        "Use a valid IP, CIDR (e.g. 192.168.1.0/24), or range (e.g. 192.168.1.10-20).",
    ),
    "dns_failure": _Template(
        "warning",
        "DNS resolution failed.",
        "Check the hostname spelling and your resolver, or target the IP address directly.",
    ),
    "timeout": _Template(
        "warning",
        "The operation timed out with no response.",
        "Increase the timeout, confirm the host is reachable, or check for firewall/ACL "
        "filtering between you and the target.",
    ),
    "malformed_packet": _Template(
        "warning",
        "The packet definition is invalid or malformed.",
        "Review the layer fields, order, and payload; correct any out-of-range or invalid values.",
    ),
    "unsupported_platform": _Template(
        "warning",
        "This operation is not supported on the current platform.",
        "Use a supported platform or feature. Some probes are POSIX-only; on Windows, raw "
        "send/capture requires Npcap.",
    ),
    "scapy_error": _Template(
        "error",
        "Scapy could not complete the operation.",
        "Check the packet definition, interface, and privileges. See the Diagnostics tab for "
        "the full technical trace.",
    ),
    "unknown": _Template(
        "error",
        "An unexpected error occurred.",
        "See the Diagnostics tab for details. Retry the operation, and report the issue if it "
        "keeps happening.",
    ),
}


class ErrorEvent(BaseModel):
    """A classified, GUI-safe representation of a failure."""

    model_config = ConfigDict(validate_assignment=True)

    severity: ErrorSeverity = "error"
    category: ErrorCategory = "unknown"
    source: str = "app"
    operation: str = ""
    message: str = ""
    suggested_fix: str = ""
    detail: str = ""
    traceback: str = ""
    timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))

    @property
    def log_level(self) -> int:
        return _SEVERITY_TO_LEVEL.get(self.severity, logging.ERROR)

    @property
    def gui_summary(self) -> str:
        """Safe one/two-line summary for banners - never includes the traceback."""
        if self.suggested_fix:
            return f"{self.message}\nSuggested fix: {self.suggested_fix}"
        return self.message

    @property
    def log_text(self) -> str:
        parts = [
            f"[{self.category}] {self.source} / {self.operation}: {self.message}",
        ]
        if self.detail:
            parts.append(f"detail: {self.detail}")
        if self.traceback:
            parts.append(self.traceback.rstrip())
        return "\n".join(parts)


def _scapy_exception_types() -> tuple[type[BaseException], ...]:
    try:
        from scapy.error import Scapy_Exception

        return (Scapy_Exception,)
    except Exception:  # pragma: no cover - scapy always present in practice
        return ()


def _categorize(exc: BaseException) -> ErrorCategory:
    from packetforge.engine.builder import PacketBuildError
    from packetforge.security.safe_scapy import SafeScapyError

    message = str(exc).lower()

    # Most specific, type-based checks first.
    if isinstance(exc, (PacketBuildError, SafeScapyError, struct.error)):
        return "malformed_packet"
    if isinstance(exc, InvalidTargetError):
        return "invalid_cidr"
    if isinstance(exc, (ipaddress.AddressValueError, ipaddress.NetmaskValueError)):
        return "invalid_cidr"
    if isinstance(exc, InterfaceUnavailableError):
        return "interface_unavailable"
    if isinstance(exc, (UnsupportedPlatformError, NotImplementedError)):
        return "unsupported_platform"
    if isinstance(exc, PermissionError):
        return "permission_denied"
    if isinstance(exc, socket.gaierror):
        return "dns_failure"
    if isinstance(exc, TimeoutError):  # socket.timeout is an alias of TimeoutError
        return "timeout"

    if isinstance(exc, OSError):
        if exc.errno in {errno.EACCES, errno.EPERM}:
            return "permission_denied"
        if exc.errno in {errno.ENODEV, errno.ENXIO, errno.EADDRNOTAVAIL}:
            return "interface_unavailable"
        if exc.errno == errno.ETIMEDOUT or "timed out" in message:
            return "timeout"
        if "no such device" in message or "interface" in message:
            return "interface_unavailable"

    # Message heuristics for libraries that raise plain exceptions.
    if "timed out" in message or "timeout" in message:
        return "timeout"
    if any(k in message for k in ("npcap", "winpcap", "not supported on", "unsupported platform")):
        return "unsupported_platform"
    if any(
        k in message
        for k in ("no such device", "libpcap", "l2socket", "l2listen", "winpcap", "no interface")
    ):
        return "interface_unavailable"
    if any(
        k in message
        for k in ("name or service not known", "nodename nor servname", "getaddrinfo", "dns")
    ):
        return "dns_failure"
    if any(
        k in message
        for k in (
            "does not appear to be",
            "cidr",
            "netmask",
            "not an ip",
            "malformed ipv4",
            "range end",
            "address family",
        )
    ):
        return "invalid_cidr"

    if isinstance(exc, _scapy_exception_types()):
        return "scapy_error"
    if isinstance(exc, ValueError):
        return "malformed_packet"
    return "unknown"


def classify_exception(exc: BaseException, *, source: str, operation: str) -> ErrorEvent:
    """Turn a raw exception into a classified, GUI-safe :class:`ErrorEvent`."""
    category = _categorize(exc)
    template = _TEMPLATES[category]
    tb = "".join(traceback_mod.format_exception(type(exc), exc, exc.__traceback__))
    return ErrorEvent(
        severity=template.severity,
        category=category,
        source=source,
        operation=operation,
        message=template.message,
        suggested_fix=template.fix,
        detail=f"{type(exc).__name__}: {exc}".strip(),
        traceback=tb,
        timestamp=datetime.now(tz=UTC),
    )


def report_exception(
    exc: BaseException,
    *,
    source: str,
    operation: str,
    logger: logging.Logger | None = None,
) -> ErrorEvent:
    """Classify *and log* an exception (full detail + traceback), returning the event.

    The GUI should display only :attr:`ErrorEvent.gui_summary`; the full trace is
    written to the logs (and surfaced in the Diagnostics panel) but never shown
    inline.
    """
    event = classify_exception(exc, source=source, operation=operation)
    log = logger or get_logger("errors")
    log.log(event.log_level, "%s", event.log_text)
    return event
