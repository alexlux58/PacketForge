from __future__ import annotations

from collections.abc import Callable

import pytest

pytest.importorskip("pydantic")

from packetforge.engine.statistics import calculate_ping_summary
from packetforge.models.results import PingResult


def test_empty_results_produce_zeroed_summary() -> None:
    summary = calculate_ping_summary([])
    assert summary.transmitted == 0
    assert summary.received == 0
    assert summary.loss_percent == 0.0
    assert summary.min_rtt_ms is None
    assert summary.avg_rtt_ms is None
    assert summary.jitter_ms is None
    assert summary.p95_rtt_ms is None
    assert summary.duration_s == 0.0
    assert summary.effective_pps == 0.0
    assert summary.loss_timeline == []


def test_all_timeouts_report_full_loss(
    make_ping_results: Callable[..., list[PingResult]],
) -> None:
    results = make_ping_results([None, None, None])
    summary = calculate_ping_summary(results)
    assert summary.transmitted == 3
    assert summary.received == 0
    assert summary.loss_percent == 100.0
    assert summary.min_rtt_ms is None
    assert summary.jitter_ms is None
    assert summary.loss_timeline == [True, True, True]


def test_single_reply_has_zero_jitter_and_stddev(
    make_ping_result: Callable[..., PingResult],
) -> None:
    summary = calculate_ping_summary([make_ping_result(1, rtt_ms=12.5)])
    assert summary.received == 1
    assert summary.jitter_ms == 0.0
    assert summary.stddev_rtt_ms == 0.0
    assert summary.p95_rtt_ms == 12.5
    assert summary.min_rtt_ms == summary.max_rtt_ms == 12.5


def test_duplicate_replies_are_counted(
    make_ping_result: Callable[..., PingResult],
) -> None:
    results = [
        make_ping_result(1, rtt_ms=5.0),
        make_ping_result(1, rtt_ms=6.0, duplicate=True),
    ]
    summary = calculate_ping_summary(results)
    assert summary.duplicate_replies == 1


def test_icmp_errors_counted_for_non_echo_replies(
    make_ping_result: Callable[..., PingResult],
) -> None:
    results = [
        make_ping_result(1, rtt_ms=5.0, icmp_type=0),  # echo reply -> not an error
        make_ping_result(2, rtt_ms=None, icmp_type=3),  # dest unreachable -> error
        make_ping_result(3, rtt_ms=None, icmp_type=11),  # time exceeded -> error
    ]
    summary = calculate_ping_summary(results)
    assert summary.icmp_errors == 2


def test_percentile_interpolates_between_samples(
    make_ping_results: Callable[..., list[PingResult]],
) -> None:
    summary = calculate_ping_summary(make_ping_results([10.0, 20.0, 30.0, 40.0]))
    # p95 of [10,20,30,40] = rank 2.85 -> 30 + 0.85*(40-30) = 38.5
    assert summary.p95_rtt_ms == pytest.approx(38.5)


def test_effective_pps_uses_observed_duration(
    make_ping_result: Callable[..., PingResult],
) -> None:
    results = [
        make_ping_result(1, rtt_ms=5.0, send_timestamp=0.0, receive_timestamp=0.005),
        make_ping_result(2, rtt_ms=5.0, send_timestamp=2.0, receive_timestamp=2.005),
    ]
    summary = calculate_ping_summary(results)
    assert summary.duration_s == pytest.approx(2.005)
    assert summary.effective_pps == pytest.approx(2 / 2.005)
