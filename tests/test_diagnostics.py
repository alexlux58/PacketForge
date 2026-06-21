from __future__ import annotations

import logging

import pytest

pytest.importorskip("pydantic")

from packetforge.diagnostics import (
    Diagnostics,
    RingBufferHandler,
    build_debug_bundle,
    configure_logging,
    redact_config,
    reset_logging_for_tests,
)


def test_ring_buffer_keeps_recent_records_in_order() -> None:
    handler = RingBufferHandler(capacity=3)
    logger = logging.getLogger("packetforge.test.ring")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    try:
        for index in range(5):
            logger.info("message %d", index)
    finally:
        logger.removeHandler(handler)

    entries = handler.entries()
    assert len(entries) == 3  # capacity bound
    assert [entry.message for entry in entries] == ["message 2", "message 3", "message 4"]


def test_ring_buffer_filters_by_level_and_limit() -> None:
    handler = RingBufferHandler(capacity=10)
    logger = logging.getLogger("packetforge.test.levels")
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    try:
        logger.debug("d")
        logger.info("i")
        logger.warning("w")
        logger.error("e")
    finally:
        logger.removeHandler(handler)

    warnings_plus = handler.entries(min_level=logging.WARNING)
    assert [entry.message for entry in warnings_plus] == ["w", "e"]
    assert [entry.message for entry in handler.entries(limit=1)] == ["e"]


def test_ring_buffer_captures_exception_text() -> None:
    handler = RingBufferHandler()
    logger = logging.getLogger("packetforge.test.exc")
    logger.addHandler(handler)
    try:
        try:
            raise ValueError("boom")
        except ValueError:
            logger.exception("operation failed")
    finally:
        logger.removeHandler(handler)

    entry = handler.entries()[-1]
    assert "operation failed" in entry.message
    assert "ValueError: boom" in entry.message
    assert "Traceback" in entry.message


def test_operation_context_logs_success_with_timing(diagnostics: Diagnostics) -> None:
    with diagnostics.operation("unit-test op"):
        pass
    messages = [entry.message for entry in diagnostics.recent()]
    assert any("operation started: unit-test op" in m for m in messages)
    assert any("operation succeeded: unit-test op" in m for m in messages)


def test_operation_context_logs_and_reraises_on_failure(diagnostics: Diagnostics) -> None:
    with pytest.raises(RuntimeError), diagnostics.operation("doomed op"):
        raise RuntimeError("nope")
    failed = [e for e in diagnostics.recent() if "operation failed: doomed op" in e.message]
    assert failed
    assert "RuntimeError: nope" in failed[-1].message


def test_redact_config_masks_secret_keys() -> None:
    config = {
        "community": "private-string",
        "password": "hunter2",
        "snmp": {"v3_secret": "x", "host": "10.0.0.1"},
        "ports": [22, 80],
        "theme": "dark",
    }
    redacted = redact_config(config)
    assert redacted["community"] == "***redacted***"
    assert redacted["password"] == "***redacted***"
    assert redacted["snmp"]["v3_secret"] == "***redacted***"
    assert redacted["snmp"]["host"] == "10.0.0.1"  # non-secret preserved
    assert redacted["ports"] == [22, 80]
    assert redacted["theme"] == "dark"


def test_build_debug_bundle_includes_environment_and_redacted_config(
    diagnostics: Diagnostics,
) -> None:
    diagnostics.logger.info("seed log line")
    bundle = build_debug_bundle(
        {"token": "abc", "interface": "eth0"},
        diagnostics=diagnostics,
        interfaces=["lo0", "en0"],
        privileges={"raw_sockets": False, "is_root": False},
    )
    assert bundle.app_version
    assert bundle.python_version
    assert bundle.platform
    assert bundle.interfaces == ["lo0", "en0"]
    assert bundle.privileges == {"raw_sockets": False, "is_root": False}
    assert bundle.config["token"] == "***redacted***"
    assert bundle.config["interface"] == "eth0"
    assert any("seed log line" in line for line in bundle.recent_logs)

    text = bundle.to_text()
    assert "PacketForge debug bundle" in text
    assert "***redacted***" not in bundle.config["interface"]
    assert "lo0" in text

    payload = bundle.to_json()
    assert '"app_version"' in payload


def test_build_debug_bundle_handles_empty_state(diagnostics: Diagnostics) -> None:
    bundle = build_debug_bundle(diagnostics=diagnostics, interfaces=[], privileges={})
    text = bundle.to_text()
    assert "(none)" in text  # empty interfaces / config / logs render cleanly


def test_configure_logging_is_idempotent_and_writes_file(tmp_path) -> None:  # type: ignore[no-untyped-def]
    reset_logging_for_tests()
    try:
        diag = configure_logging(log_dir=tmp_path, enable_console=False)
        logger = logging.getLogger("packetforge")
        first_handler_count = len(logger.handlers)
        configure_logging(log_dir=tmp_path, enable_console=False)
        assert len(logger.handlers) == first_handler_count  # no duplicate handlers

        logger.info("hello file")
        for handler in logger.handlers:
            handler.flush()
        log_file = tmp_path / "packetforge.log"
        assert log_file.exists()
        assert "hello file" in log_file.read_text(encoding="utf-8")
        assert any("hello file" in e.message for e in diag.recent())
    finally:
        reset_logging_for_tests()
