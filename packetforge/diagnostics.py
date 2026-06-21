"""Structured logging, an in-memory log ring buffer, and debug-bundle export.

This module is intentionally GUI-free so it can be unit tested without Qt. The
GUI Diagnostics panel reads from the same :class:`Diagnostics` singleton that
the engine and workers log into.
"""

from __future__ import annotations

import json
import logging
import platform
import sys
import threading
import time
from collections import deque
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from packetforge import __version__

LOGGER_NAME = "packetforge"
_LOG_FORMAT = "%(asctime)s %(levelname)-7s %(name)s: %(message)s"

# Substrings that mark a config key as sensitive; values are redacted in bundles.
_SECRET_HINTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "community",
    "credential",
    "apikey",
    "api_key",
    "private",
    "auth",
)


@dataclass(frozen=True)
class LogEntry:
    timestamp: float
    levelno: int
    level: str
    logger: str
    message: str

    @property
    def time_text(self) -> str:
        return datetime.fromtimestamp(self.timestamp, tz=UTC).strftime("%H:%M:%S.%f")[:-3]

    def format(self) -> str:
        return f"{self.time_text} {self.level:<7} {self.logger}: {self.message}"


class RingBufferHandler(logging.Handler):
    """Thread-safe, fixed-capacity buffer of recent log records for the UI."""

    def __init__(self, capacity: int = 1000) -> None:
        super().__init__()
        self._entries: deque[LogEntry] = deque(maxlen=capacity)
        self._lock = threading.Lock()

    def emit(self, record: logging.LogRecord) -> None:
        try:
            message = record.getMessage()
            if record.exc_info:
                message = f"{message}\n{self._format_exc(record)}"
            entry = LogEntry(
                timestamp=record.created,
                levelno=record.levelno,
                level=record.levelname,
                logger=record.name,
                message=message,
            )
            with self._lock:
                self._entries.append(entry)
        except Exception:  # logging handlers must never raise
            self.handleError(record)

    @staticmethod
    def _format_exc(record: logging.LogRecord) -> str:
        formatter = logging.Formatter()
        return formatter.formatException(record.exc_info) if record.exc_info else ""

    def entries(self, *, limit: int | None = None, min_level: int = 0) -> list[LogEntry]:
        with self._lock:
            snapshot = [entry for entry in self._entries if entry.levelno >= min_level]
        if limit is not None:
            snapshot = snapshot[-limit:]
        return snapshot

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


class Diagnostics:
    """Central diagnostics state: the log ring buffer plus last-packet context."""

    def __init__(self, *, capacity: int = 1000) -> None:
        self.ring = RingBufferHandler(capacity=capacity)
        self.logger = logging.getLogger(LOGGER_NAME)
        self._lock = threading.Lock()
        self._last_packet_summary: str | None = None

    @property
    def last_packet_summary(self) -> str | None:
        with self._lock:
            return self._last_packet_summary

    def set_last_packet_summary(self, summary: str | None) -> None:
        with self._lock:
            self._last_packet_summary = summary

    def recent(self, *, limit: int | None = None, min_level: int = 0) -> list[LogEntry]:
        return self.ring.entries(limit=limit, min_level=min_level)

    def clear(self) -> None:
        self.ring.clear()

    @contextmanager
    def operation(self, name: str, *, logger: str | None = None) -> Iterator[None]:
        """Log start/finish of an operation with timing; re-raises on error."""
        log = get_logger(logger) if logger else self.logger
        start = time.perf_counter()
        log.info("operation started: %s", name)
        try:
            yield
        except Exception:
            elapsed = (time.perf_counter() - start) * 1000.0
            log.exception("operation failed: %s (%.1f ms)", name, elapsed)
            raise
        else:
            elapsed = (time.perf_counter() - start) * 1000.0
            log.info("operation succeeded: %s (%.1f ms)", name, elapsed)


_DIAGNOSTICS: Diagnostics | None = None
_CONFIGURED = False


def get_diagnostics() -> Diagnostics:
    global _DIAGNOSTICS
    if _DIAGNOSTICS is None:
        _DIAGNOSTICS = Diagnostics()
    return _DIAGNOSTICS


def get_logger(name: str | None = None) -> logging.Logger:
    if not name or name == LOGGER_NAME:
        return logging.getLogger(LOGGER_NAME)
    return logging.getLogger(f"{LOGGER_NAME}.{name}")


def default_log_dir() -> Path:
    return Path.home() / ".packetforge" / "logs"


def configure_logging(
    *,
    log_dir: Path | str | None = None,
    level: int = logging.INFO,
    diagnostics: Diagnostics | None = None,
    enable_file: bool = True,
    enable_console: bool = True,
) -> Diagnostics:
    """Attach rotating-file, console, and ring-buffer handlers to the package logger.

    Safe to call more than once; handlers are only attached on the first call.
    """
    global _CONFIGURED
    diagnostics = diagnostics or get_diagnostics()
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(logging.DEBUG)
    if _CONFIGURED:
        return diagnostics

    formatter = logging.Formatter(_LOG_FORMAT)
    if enable_file:
        try:
            directory = Path(log_dir) if log_dir is not None else default_log_dir()
            directory.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(
                directory / "packetforge.log",
                maxBytes=1_000_000,
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            logger.addHandler(file_handler)
        except OSError:
            # A read-only home should never stop the app from running.
            logger.warning("could not open rotating log file; file logging disabled")

    if enable_console:
        console = logging.StreamHandler(stream=sys.stderr)
        console.setLevel(level)
        console.setFormatter(formatter)
        logger.addHandler(console)

    diagnostics.ring.setLevel(logging.DEBUG)
    logger.addHandler(diagnostics.ring)
    logger.propagate = False
    _CONFIGURED = True
    return diagnostics


def reset_logging_for_tests() -> None:
    """Detach handlers and reset module state (used by the test-suite only)."""
    global _CONFIGURED, _DIAGNOSTICS
    logger = logging.getLogger(LOGGER_NAME)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
    _CONFIGURED = False
    _DIAGNOSTICS = None


def redact_config(config: Mapping[str, Any]) -> dict[str, Any]:
    """Return a copy of ``config`` with secret-looking values masked."""
    redacted: dict[str, Any] = {}
    for key, value in config.items():
        if isinstance(key, str) and any(hint in key.lower() for hint in _SECRET_HINTS):
            redacted[key] = "***redacted***"
        elif isinstance(value, Mapping):
            redacted[key] = redact_config(value)
        elif isinstance(value, (list, tuple)):
            redacted[key] = [
                redact_config(item) if isinstance(item, Mapping) else item for item in value
            ]
        else:
            redacted[key] = value
    return redacted


@dataclass
class DebugBundle:
    app_version: str
    python_version: str
    platform: str
    platform_detail: str
    interfaces: list[str]
    privileges: dict[str, Any]
    config: dict[str, Any] = field(default_factory=dict)
    recent_logs: list[str] = field(default_factory=list)
    generated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_text(self) -> str:
        lines = [
            "PacketForge debug bundle",
            f"generated_at : {self.generated_at}",
            f"app_version  : {self.app_version}",
            f"python       : {self.python_version}",
            f"platform     : {self.platform}",
            f"detail       : {self.platform_detail}",
            "",
            "Privileges:",
        ]
        lines += [f"  {key}: {value}" for key, value in self.privileges.items()]
        lines += ["", "Interfaces:"]
        lines += [f"  {iface}" for iface in self.interfaces] if self.interfaces else ["  (none)"]
        lines += ["", "Config (secrets redacted):"]
        lines += (
            [f"  {key}: {value}" for key, value in self.config.items()]
            if self.config
            else ["  (none)"]
        )
        lines += ["", f"Recent logs ({len(self.recent_logs)}):"]
        lines += [f"  {line}" for line in self.recent_logs] if self.recent_logs else ["  (none)"]
        return "\n".join(lines)


def build_debug_bundle(
    config: Mapping[str, Any] | None = None,
    *,
    diagnostics: Diagnostics | None = None,
    interfaces: Iterable[str] | None = None,
    privileges: Mapping[str, Any] | None = None,
    log_limit: int = 200,
) -> DebugBundle:
    """Collect a support bundle. All external lookups are injectable for tests."""
    diagnostics = diagnostics or get_diagnostics()

    if interfaces is None:
        from packetforge.engine.interfaces import list_interfaces

        interface_list = list(list_interfaces())
    else:
        interface_list = list(interfaces)

    if privileges is None:
        from packetforge.security.privileges import detect_privileges

        report = detect_privileges()
        privilege_info: dict[str, Any] = {
            "is_root": report.is_root,
            "raw_sockets": report.raw_sockets,
            "platform": report.platform_name,
            "headline": report.headline,
            "notes": list(report.notes),
        }
    else:
        privilege_info = dict(privileges)

    return DebugBundle(
        app_version=__version__,
        python_version=sys.version.split()[0],
        platform=platform.system(),
        platform_detail=platform.platform(),
        interfaces=interface_list,
        privileges=privilege_info,
        config=redact_config(config or {}),
        recent_logs=[entry.format() for entry in diagnostics.recent(limit=log_limit)],
        generated_at=datetime.now(tz=UTC).isoformat(timespec="seconds"),
    )
