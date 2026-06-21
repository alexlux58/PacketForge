from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PingResult(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    sequence: int
    send_timestamp: float
    receive_timestamp: float | None = None
    rtt_ms: float | None = None
    reply_source: str | None = None
    reply_ttl: int | None = None
    reply_size: int | None = None
    icmp_type: int | None = None
    icmp_code: int | None = None
    timeout: bool = False
    duplicate: bool = False
    error: str | None = None
    interface: str | None = None


class PingSummary(BaseModel):
    transmitted: int = 0
    received: int = 0
    loss_percent: float = 0.0
    duplicate_replies: int = 0
    min_rtt_ms: float | None = None
    avg_rtt_ms: float | None = None
    max_rtt_ms: float | None = None
    median_rtt_ms: float | None = None
    stddev_rtt_ms: float | None = None
    jitter_ms: float | None = None
    p95_rtt_ms: float | None = None
    duration_s: float = 0.0
    effective_pps: float = 0.0
    icmp_errors: int = 0
    loss_timeline: list[bool] = Field(default_factory=list)
