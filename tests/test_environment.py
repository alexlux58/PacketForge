from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("scapy")

from packetforge.engine import environment
from packetforge.engine.environment import (
    check_interfaces,
    check_pcap_write,
    check_python_version,
    check_raw_socket_privilege,
    run_environment_checks,
)


def test_python_version_check_passes_on_supported_runtime() -> None:
    result = check_python_version()
    assert result.name == "Python version"
    assert result.status == "ok"  # the test suite runs on a supported interpreter


def test_python_version_check_fails_when_too_old(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(environment, "MIN_PYTHON", (99, 0))
    result = check_python_version()
    assert result.status == "fail"
    assert result.hint


def test_interfaces_check_ok_when_present() -> None:
    result = check_interfaces(["en0", "lo0"])
    assert result.status == "ok"
    assert "2 detected" in result.detail


def test_interfaces_check_warns_when_empty() -> None:
    result = check_interfaces([])
    assert result.status == "warning"
    assert result.hint


def test_interfaces_check_truncates_long_lists() -> None:
    result = check_interfaces([f"if{i}" for i in range(10)])
    assert result.status == "ok"
    assert result.detail.endswith("...")


def test_raw_socket_check_ok_when_privileged() -> None:
    result = check_raw_socket_privilege(raw_sockets=True)
    assert result.status == "ok"


def test_raw_socket_check_warns_when_unprivileged() -> None:
    result = check_raw_socket_privilege(raw_sockets=False)
    assert result.status == "warning"
    assert result.hint


def test_pcap_write_roundtrip_ok(tmp_path: Path) -> None:
    result = check_pcap_write(tmp_path)
    assert result.status == "ok"
    assert "1 packet" in result.detail
    # The self-test cleans up after itself.
    assert not (tmp_path / "packetforge-selftest.pcap").exists()


def test_pcap_write_uses_tempdir_when_unspecified() -> None:
    result = check_pcap_write()
    assert result.status == "ok"


def test_pcap_write_reports_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    from packetforge.utils import export

    def boom(*_a: object, **_k: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(export, "export_packets_to_pcap", boom)
    result = check_pcap_write()
    assert result.status == "fail"
    assert result.hint


def test_run_environment_checks_aggregates_all() -> None:
    report = run_environment_checks(
        interfaces=["en0"], raw_sockets=True, pcap_directory=None
    )
    names = [result.name for result in report.results]
    assert names == [
        "Python version",
        "Scapy",
        "PySide6",
        "Interfaces",
        "Raw socket privilege",
        "PCAP write test",
    ]
    # Injected supported environment -> no blocking failures, no warnings.
    assert report.ok
    assert not report.has_warnings
    assert "good" in report.summary().lower()


def test_report_summary_flags_failures() -> None:
    report = run_environment_checks(interfaces=[], raw_sockets=False)
    assert report.has_warnings
    assert report.ok  # warnings are not blocking
