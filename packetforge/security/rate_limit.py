from __future__ import annotations

import threading
import time
from collections.abc import Callable


class RateLimiter:
    """A simple thread-safe token-bucket rate limiter.

    Used to keep every active discovery method below the packets-per-second
    ceiling defined by the selected :class:`~packetforge.models.profiles.ScanProfile`.
    The bucket never bursts above one second worth of capacity, so a paused and
    resumed scan cannot dump a backlog of probes onto the network.
    """

    def __init__(
        self,
        rate_per_second: float,
        *,
        capacity: float | None = None,
        monotonic: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate_per_second <= 0:
            raise ValueError("rate_per_second must be positive")
        self.rate = rate_per_second
        self.capacity = capacity if capacity is not None else max(1.0, rate_per_second)
        self._monotonic = monotonic
        self._sleep = sleep
        self._tokens = self.capacity
        self._updated = monotonic()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self._monotonic()
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._updated = now

    def time_until_available(self, tokens: float = 1.0) -> float:
        """Return seconds to wait before ``tokens`` are available (no blocking)."""
        with self._lock:
            self._refill()
            if self._tokens >= tokens:
                return 0.0
            return (tokens - self._tokens) / self.rate

    def acquire(self, tokens: float = 1.0) -> None:
        """Block until ``tokens`` are available, then consume them."""
        while True:
            with self._lock:
                self._refill()
                if self._tokens >= tokens:
                    self._tokens -= tokens
                    return
                wait = (tokens - self._tokens) / self.rate
            self._sleep(min(wait, 0.25))
