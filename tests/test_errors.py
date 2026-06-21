from __future__ import annotations

import errno
import ipaddress
import logging
import socket
import struct
from collections.abc import Callable

import pytest

pytest.importorskip("pydantic")

from packetforge.engine.builder import PacketBuildError
from packetforge.errors import (
    InterfaceUnavailableError,
    InvalidTargetError,
    UnsupportedPlatformError,
    classify_exception,
    report_exception,
)
from packetforge.security.safe_scapy import SafeScapyError


def _scapy_error() -> BaseException:
    from scapy.error import Scapy_Exception

    return Scapy_Exception("could not build packet structure")


def _gaierror() -> BaseException:
    return socket.gaierror(socket.EAI_NONAME, "Name or service not known")


def _bad_cidr() -> BaseException:
    try:
        ipaddress.ip_network("not-a-network")
    except ValueError as exc:
        return exc
    raise AssertionError("expected ValueError")


# Every major error class -> expected category.
_CASES: dict[str, tuple[Callable[[], BaseException], str]] = {
    "permission_error": (lambda: PermissionError("need root for raw sockets"), "permission_denied"),
    "permission_oserrno": (
        lambda: OSError(errno.EACCES, "Permission denied"),
        "permission_denied",
    ),
    "interface_custom": (
        lambda: InterfaceUnavailableError("eth9 missing"),
        "interface_unavailable",
    ),
    "interface_oserrno": (
        lambda: OSError(errno.ENODEV, "No such device"),
        "interface_unavailable",
    ),
    "invalid_cidr_value": (_bad_cidr, "invalid_cidr"),
    "invalid_cidr_custom": (lambda: InvalidTargetError("bad range 1-"), "invalid_cidr"),
    "invalid_cidr_addr": (
        lambda: ipaddress.AddressValueError("malformed IPv4 address"),
        "invalid_cidr",
    ),
    "dns_failure": (_gaierror, "dns_failure"),
    "timeout_builtin": (lambda: TimeoutError("operation timed out"), "timeout"),
    "timeout_message": (lambda: OSError("connection timed out"), "timeout"),
    "malformed_build": (lambda: PacketBuildError("no layers"), "malformed_packet"),
    "malformed_safe_scapy": (lambda: SafeScapyError("call not allowed"), "malformed_packet"),
    "malformed_struct": (lambda: struct.error("unpack requires a buffer"), "malformed_packet"),
    "unsupported_notimpl": (lambda: NotImplementedError("ipv6 raw"), "unsupported_platform"),
    "unsupported_custom": (
        lambda: UnsupportedPlatformError("windows raw send"),
        "unsupported_platform",
    ),
    "unsupported_npcap": (lambda: OSError("Npcap is required"), "unsupported_platform"),
    "scapy_error": (_scapy_error, "scapy_error"),
    "unknown": (lambda: RuntimeError("something weird happened"), "unknown"),
}


@pytest.mark.parametrize("name", list(_CASES))
def test_classify_each_error_class(name: str) -> None:
    factory, expected = _CASES[name]
    event = classify_exception(factory(), source="Tests", operation="unit")
    assert event.category == expected
    assert event.source == "Tests"
    assert event.operation == "unit"
    assert event.message  # always a human-friendly summary
    assert event.suggested_fix  # always actionable
    assert event.traceback  # full trace captured for logging


def test_gui_summary_is_safe_and_excludes_traceback() -> None:
    event = classify_exception(RuntimeError("secret stack detail"), source="X", operation="op")
    summary = event.gui_summary
    assert "Traceback" not in summary
    assert "secret stack detail" not in summary
    assert event.suggested_fix in summary


def test_log_text_includes_detail_and_traceback() -> None:
    try:
        raise PermissionError("need root")
    except PermissionError as exc:
        event = classify_exception(exc, source="X", operation="op")
    text = event.log_text
    assert "PermissionError" in text
    assert "Traceback" in text


def test_report_exception_logs_full_detail_and_returns_event() -> None:
    logger = logging.getLogger("packetforge.tests.errors")
    logger.setLevel(logging.DEBUG)
    records: list[logging.LogRecord] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Capture()
    logger.addHandler(handler)
    try:
        try:
            raise TimeoutError("no reply")
        except TimeoutError as exc:
            event = report_exception(exc, source="Ping Lab", operation="ping", logger=logger)
    finally:
        logger.removeHandler(handler)

    assert event.category == "timeout"
    assert records
    assert records[0].levelno == logging.WARNING  # timeouts are warnings
    assert "Traceback" in records[0].getMessage()


def test_severity_maps_to_log_level() -> None:
    event = classify_exception(PermissionError("x"), source="X", operation="op")
    assert event.severity == "error"
    assert event.log_level == logging.ERROR
