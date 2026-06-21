import pytest

pytest.importorskip("pydantic")

from packetforge.engine.fingerprint import (
    LINUX,
    WINDOWS,
    FingerprintObservations,
    infer_initial_ttl,
    score_fingerprint,
)


def test_infer_initial_ttl() -> None:
    assert infer_initial_ttl(64) == 64
    assert infer_initial_ttl(60) == 64
    assert infer_initial_ttl(120) == 128
    assert infer_initial_ttl(250) == 255
    assert infer_initial_ttl(0) is None
    assert infer_initial_ttl(300) is None


def test_no_observations_yields_no_confidence() -> None:
    evidence = score_fingerprint(FingerprintObservations(host="10.0.0.1"))
    assert evidence.os_guesses == []
    assert evidence.confidence == 0.0
    assert evidence.summary == "insufficient evidence"


def test_windows_signals_rank_windows_first() -> None:
    obs = FingerprintObservations(
        host="10.0.0.5",
        ttl=128,
        tcp_window=8192,
        tcp_timestamps=False,
        banners={"SMTP": "220 mail Microsoft ESMTP"},
    )
    evidence = score_fingerprint(obs)
    assert evidence.best_guess is not None
    assert evidence.best_guess.family == WINDOWS
    assert evidence.confidence > 0.5


def test_linux_signals_rank_linux_first() -> None:
    obs = FingerprintObservations(
        host="10.0.0.6",
        ttl=64,
        tcp_window=64240,
        tcp_timestamps=True,
        banners={"SSH": "SSH-2.0-OpenSSH_8.9 Ubuntu"},
    )
    evidence = score_fingerprint(obs)
    assert evidence.best_guess is not None
    assert evidence.best_guess.family == LINUX
    assert evidence.confidence > 0.5
    assert any(signal.name == "TTL/hop limit" for signal in evidence.signals)


def test_more_evidence_increases_confidence() -> None:
    weak = score_fingerprint(FingerprintObservations(host="h", ttl=128))
    strong = score_fingerprint(
        FingerprintObservations(
            host="h",
            ttl=128,
            tcp_window=8192,
            tcp_timestamps=False,
            banners={"SMTP": "220 Windows"},
        )
    )
    assert strong.confidence > weak.confidence


def test_confidence_is_bounded() -> None:
    obs = FingerprintObservations(
        host="h",
        ttl=128,
        tcp_window=8192,
        tcp_timestamps=False,
        banners={"SMTP": "Microsoft", "HTTP": "IIS Windows", "SSH": "windows"},
    )
    evidence = score_fingerprint(obs)
    assert 0.0 <= evidence.confidence <= 1.0


def test_unusual_ttl_contributes_no_vote() -> None:
    evidence = score_fingerprint(FingerprintObservations(host="h", ttl=300))
    # 300 is out of range -> no confident initial TTL
    assert evidence.confidence == 0.0
