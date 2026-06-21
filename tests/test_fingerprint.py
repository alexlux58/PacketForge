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


def test_insufficient_evidence_still_reports_attempts() -> None:
    # Unprivileged, no banners, but ports were probed: the evidence table must not
    # be blank — it should list every attempt plus a privilege note.
    obs = FingerprintObservations(
        host="192.168.4.1",
        raw_signals_available=False,
        connect_results={22: "connection refused", 80: "open (no banner)"},
    )
    evidence = score_fingerprint(obs)
    assert evidence.summary == "insufficient evidence"
    names = {s.name for s in evidence.signals}
    assert {"TCP 22", "TCP 80", "Privilege"} <= names
    refused = next(s for s in evidence.signals if s.name == "TCP 22")
    assert "refused" in refused.value
    assert "closed" in refused.interpretation.lower()
    privilege = next(s for s in evidence.signals if s.name == "Privilege")
    assert "elevation" in privilege.interpretation.lower()
    # Context rows must never sway the OS vote.
    assert all(s.weight == 0.0 for s in evidence.signals)


def test_privilege_note_absent_when_raw_available() -> None:
    obs = FingerprintObservations(
        host="h", raw_signals_available=True, connect_results={22: "open (banner)"}
    )
    evidence = score_fingerprint(obs)
    assert not any(s.name == "Privilege" for s in evidence.signals)
