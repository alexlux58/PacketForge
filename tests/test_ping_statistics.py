import pytest

pytest.importorskip("pydantic")

from packetforge.engine.statistics import calculate_ping_summary
from packetforge.models.results import PingResult


def test_ping_summary_calculates_loss_and_rtt_metrics() -> None:
    results = [
        PingResult(sequence=1, send_timestamp=0.0, receive_timestamp=0.01, rtt_ms=10.0),
        PingResult(sequence=2, send_timestamp=1.0, timeout=True),
        PingResult(sequence=3, send_timestamp=2.0, receive_timestamp=2.03, rtt_ms=30.0),
    ]

    summary = calculate_ping_summary(results)

    assert summary.transmitted == 3
    assert summary.received == 2
    assert summary.loss_percent == pytest.approx(33.333, rel=0.01)
    assert summary.min_rtt_ms == 10.0
    assert summary.avg_rtt_ms == 20.0
    assert summary.max_rtt_ms == 30.0
    assert summary.jitter_ms == 20.0
