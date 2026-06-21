from __future__ import annotations

from collections.abc import Sequence
from itertools import pairwise
from statistics import mean, median, pstdev

from packetforge.models.results import PingResult, PingSummary


def calculate_ping_summary(results: Sequence[PingResult]) -> PingSummary:
    transmitted = len(results)
    received_results = [
        result for result in results if result.rtt_ms is not None and not result.timeout
    ]
    rtts = [result.rtt_ms for result in received_results if result.rtt_ms is not None]
    received = len(received_results)
    loss_percent = 0.0 if transmitted == 0 else ((transmitted - received) / transmitted) * 100.0
    duplicates = sum(1 for result in results if result.duplicate)
    icmp_errors = sum(
        1 for result in results if result.icmp_type is not None and result.icmp_type not in {0, 129}
    )
    duration_s = _duration(results)
    return PingSummary(
        transmitted=transmitted,
        received=received,
        loss_percent=loss_percent,
        duplicate_replies=duplicates,
        min_rtt_ms=min(rtts) if rtts else None,
        avg_rtt_ms=mean(rtts) if rtts else None,
        max_rtt_ms=max(rtts) if rtts else None,
        median_rtt_ms=median(rtts) if rtts else None,
        stddev_rtt_ms=pstdev(rtts) if len(rtts) > 1 else 0.0 if rtts else None,
        jitter_ms=_jitter(rtts),
        p95_rtt_ms=_percentile(rtts, 95),
        duration_s=duration_s,
        effective_pps=0.0 if duration_s <= 0 else transmitted / duration_s,
        icmp_errors=icmp_errors,
        loss_timeline=[result.timeout for result in results],
    )


def _duration(results: Sequence[PingResult]) -> float:
    if not results:
        return 0.0
    start = min(result.send_timestamp for result in results)
    end = max(result.receive_timestamp or result.send_timestamp for result in results)
    return max(0.0, end - start)


def _jitter(rtts: list[float]) -> float | None:
    if not rtts:
        return None
    if len(rtts) == 1:
        return 0.0
    differences = [abs(current - previous) for previous, current in pairwise(rtts)]
    return mean(differences)


def _percentile(values: list[float], percentile: int) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * (percentile / 100)
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    weight = rank - lower
    return ordered[lower] * (1 - weight) + ordered[upper] * weight
