import pytest

pytest.importorskip("pydantic")

from pydantic import ValidationError

from packetforge.models.profiles import (
    BALANCED,
    BUILTIN_PROFILES,
    GENTLE,
    LAB_FAST,
    profile_by_name,
)
from packetforge.security.rate_limit import RateLimiter


def test_profiles_are_ordered_by_aggressiveness() -> None:
    assert GENTLE.max_packets_per_second < BALANCED.max_packets_per_second
    assert BALANCED.max_packets_per_second < LAB_FAST.max_packets_per_second
    assert GENTLE.concurrency <= BALANCED.concurrency <= LAB_FAST.concurrency


def test_all_profiles_stay_within_safe_ceiling() -> None:
    for profile in BUILTIN_PROFILES:
        assert 0 < profile.max_packets_per_second <= 2000
        assert profile.probe_timeout_ms >= 50


def test_min_interval_matches_rate() -> None:
    assert GENTLE.min_interval_s == pytest.approx(1.0 / GENTLE.max_packets_per_second)


def test_profile_lookup_and_unknown() -> None:
    assert profile_by_name("Balanced") is BALANCED
    with pytest.raises(KeyError):
        profile_by_name("Aggressive")


def test_profiles_are_immutable() -> None:
    with pytest.raises(ValidationError):
        GENTLE.max_packets_per_second = 9999  # type: ignore[misc]


def _fake_clock() -> tuple[list[float], RateLimiter, list[float]]:
    now = [0.0]
    sleeps: list[float] = []

    def monotonic() -> float:
        return now[0]

    def sleep(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    limiter = RateLimiter(10.0, monotonic=monotonic, sleep=sleep)
    return now, limiter, sleeps


def test_rate_limiter_allows_burst_up_to_capacity_without_sleeping() -> None:
    _now, limiter, sleeps = _fake_clock()
    for _ in range(10):
        limiter.acquire()
    assert sleeps == []


def test_rate_limiter_blocks_after_capacity_exhausted() -> None:
    _now, limiter, sleeps = _fake_clock()
    for _ in range(10):
        limiter.acquire()
    limiter.acquire()
    assert sleeps
    assert sum(sleeps) == pytest.approx(0.1, rel=0.2)


def test_time_until_available_reports_wait() -> None:
    _now, limiter, _sleeps = _fake_clock()
    for _ in range(10):
        limiter.acquire()
    assert limiter.time_until_available() > 0


def test_rate_limiter_rejects_non_positive_rate() -> None:
    with pytest.raises(ValueError):
        RateLimiter(0)
