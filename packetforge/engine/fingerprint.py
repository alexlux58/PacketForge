from __future__ import annotations

from dataclasses import dataclass, field

from packetforge.models.discovery import FingerprintEvidence, FingerprintSignal, OsGuess

# OS families PacketForge will reason about. Deliberately coarse: we report a
# "likely" family with evidence rather than pretending to know an exact OS build.
LINUX = "Linux"
WINDOWS = "Windows"
MAC_BSD = "macOS/BSD"
NETWORK = "Network device"

FAMILIES = (LINUX, WINDOWS, MAC_BSD, NETWORK)

# Common initial TTL / hop-limit values by stack.
_INITIAL_TTLS = (64, 128, 255)
_MAX_HOPS = 32

# How much accumulated signal weight is needed before we trust the leading guess.
_SATURATION = 6.0


@dataclass
class FingerprintObservations:
    host: str
    ttl: int | None = None
    tcp_window: int | None = None
    mss: int | None = None
    window_scale: int | None = None
    sack_permitted: bool | None = None
    tcp_timestamps: bool | None = None
    icmp_echo_reply: bool | None = None
    banners: dict[str, str] = field(default_factory=dict)
    # Per-port TCP connect outcome (e.g. {22: "open (banner)", 80: "connection refused"}).
    # Recorded even on failure so the UI can show what was attempted, never a blank table.
    connect_results: dict[int, str] = field(default_factory=dict)
    # False when running unprivileged: only TCP connect / banner grabbing were possible.
    raw_signals_available: bool = False


def infer_initial_ttl(observed: int) -> int | None:
    """Best-guess original TTL/hop-limit for an observed value."""
    if observed <= 0 or observed > 255:
        return None
    for initial in _INITIAL_TTLS:
        if observed <= initial and (initial - observed) <= _MAX_HOPS:
            return initial
    return None


def score_fingerprint(observations: FingerprintObservations) -> FingerprintEvidence:
    signals: list[FingerprintSignal] = []
    votes: dict[str, float] = dict.fromkeys(FAMILIES, 0.0)
    total_weight = 0.0

    total_weight += _score_ttl(observations, signals, votes)
    total_weight += _score_window(observations, signals, votes)
    total_weight += _score_tcp_options(observations, signals, votes)
    total_weight += _score_icmp(observations, signals, votes)
    total_weight += _score_banners(observations, signals, votes)
    _record_connectivity(observations, signals)
    _record_privilege_note(observations, signals)

    guesses = _rank(votes)
    confidence = _confidence(guesses, total_weight)
    return FingerprintEvidence(
        host=observations.host,
        signals=signals,
        os_guesses=guesses,
        confidence=confidence,
    )


def _score_ttl(
    obs: FingerprintObservations,
    signals: list[FingerprintSignal],
    votes: dict[str, float],
) -> float:
    if obs.ttl is None:
        return 0.0
    initial = infer_initial_ttl(obs.ttl)
    if initial is None:
        signals.append(
            FingerprintSignal(
                name="TTL/hop limit",
                value=str(obs.ttl),
                interpretation="unusual TTL; no confident initial-value match",
                weight=0.0,
            )
        )
        return 0.0
    hops = initial - obs.ttl
    weight = 2.0
    if initial == 64:
        votes[LINUX] += weight
        votes[MAC_BSD] += weight * 0.8
        interp = f"initial TTL 64 (~{hops} hops): Linux/Unix/macOS family"
    elif initial == 128:
        votes[WINDOWS] += weight * 1.2
        interp = f"initial TTL 128 (~{hops} hops): Windows family"
    else:
        votes[NETWORK] += weight
        votes[MAC_BSD] += weight * 0.3
        interp = f"initial TTL 255 (~{hops} hops): router/switch or BSD-style stack"
    signals.append(
        FingerprintSignal(
            name="TTL/hop limit", value=str(obs.ttl), interpretation=interp, weight=weight
        )
    )
    return weight


def _score_window(
    obs: FingerprintObservations,
    signals: list[FingerprintSignal],
    votes: dict[str, float],
) -> float:
    if obs.tcp_window is None:
        return 0.0
    window = obs.tcp_window
    weight = 1.5
    if window in {64240, 64800, 29200, 14600, 5840}:
        votes[LINUX] += weight
        interp = "window size typical of Linux TCP stacks"
    elif window in {8192, 16384, 64512, 65535} and window != 65535:
        votes[WINDOWS] += weight
        interp = "window size typical of Windows TCP stacks"
    elif window == 65535:
        votes[MAC_BSD] += weight * 0.8
        votes[WINDOWS] += weight * 0.4
        interp = "window 65535 seen on macOS/BSD and some Windows builds"
    elif window in {4128, 4096, 16616}:
        votes[NETWORK] += weight
        interp = "small window common on embedded/network gear"
    else:
        weight = 0.5
        interp = "window size not strongly associated with a family"
    signals.append(
        FingerprintSignal(
            name="TCP window size", value=str(window), interpretation=interp, weight=weight
        )
    )
    return weight


def _score_tcp_options(
    obs: FingerprintObservations,
    signals: list[FingerprintSignal],
    votes: dict[str, float],
) -> float:
    accumulated = 0.0
    if obs.mss is not None:
        signals.append(
            FingerprintSignal(
                name="TCP MSS",
                value=str(obs.mss),
                interpretation="1460 indicates standard 1500-byte Ethernet MTU"
                if obs.mss == 1460
                else "non-default MSS; possible tunnel/PPPoE/jumbo path",
                weight=0.5,
            )
        )
        accumulated += 0.5
    if obs.tcp_timestamps is not None:
        weight = 1.0
        if obs.tcp_timestamps:
            votes[LINUX] += weight
            votes[MAC_BSD] += weight * 0.6
            interp = "TCP timestamps enabled (default on Linux/macOS/BSD)"
        else:
            votes[WINDOWS] += weight * 0.8
            interp = "TCP timestamps absent (common on Windows defaults)"
        signals.append(
            FingerprintSignal(
                name="TCP timestamps",
                value="on" if obs.tcp_timestamps else "off",
                interpretation=interp,
                weight=weight,
            )
        )
        accumulated += weight
    if obs.sack_permitted is not None:
        signals.append(
            FingerprintSignal(
                name="TCP SACK",
                value="permitted" if obs.sack_permitted else "absent",
                interpretation="SACK permitted (near-universal on modern stacks)"
                if obs.sack_permitted
                else "SACK absent (older or minimal stack)",
                weight=0.3,
            )
        )
        accumulated += 0.3
    if obs.window_scale is not None:
        signals.append(
            FingerprintSignal(
                name="TCP window scale",
                value=str(obs.window_scale),
                interpretation=f"window scale factor {obs.window_scale}",
                weight=0.3,
            )
        )
        accumulated += 0.3
    return accumulated


def _score_icmp(
    obs: FingerprintObservations,
    signals: list[FingerprintSignal],
    votes: dict[str, float],
) -> float:
    if obs.icmp_echo_reply is None:
        return 0.0
    signals.append(
        FingerprintSignal(
            name="ICMP echo",
            value="reply" if obs.icmp_echo_reply else "no reply",
            interpretation="host answers ICMP echo"
            if obs.icmp_echo_reply
            else "no ICMP echo reply (filtered or disabled)",
            weight=0.5,
            source="fingerprint",
        )
    )
    return 0.5


def _score_banners(
    obs: FingerprintObservations,
    signals: list[FingerprintSignal],
    votes: dict[str, float],
) -> float:
    accumulated = 0.0
    for service, banner in obs.banners.items():
        lowered = banner.lower()
        weight = 3.0
        family: str | None = None
        if any(tok in lowered for tok in ("ubuntu", "debian", "linux", "raspbian", "centos")):
            family = LINUX
        elif "windows" in lowered or "microsoft" in lowered:
            family = WINDOWS
        elif any(tok in lowered for tok in ("darwin", "mac os", "macos", "freebsd", "openbsd")):
            family = MAC_BSD
        elif any(tok in lowered for tok in ("cisco", "mikrotik", "juniper", "routeros", "edgeos")):
            family = NETWORK
        if family is None:
            weight = 0.5
            interp = f"{service} banner present but not OS-distinctive"
        else:
            votes[family] += weight
            interp = f"{service} banner indicates {family}"
        signals.append(
            FingerprintSignal(
                name=f"{service} banner",
                value=banner[:120],
                interpretation=interp,
                weight=weight,
                source="service",
            )
        )
        accumulated += weight
    return accumulated


def _record_connectivity(
    obs: FingerprintObservations, signals: list[FingerprintSignal]
) -> None:
    """Add zero-weight evidence rows for every port probed, including failures.

    These do not move the OS vote, but they ensure the evidence table shows what
    was attempted (e.g. "port 22: connection refused") rather than nothing at all
    when banners and raw signals are unavailable.
    """
    for port in sorted(obs.connect_results):
        outcome = obs.connect_results[port]
        signals.append(
            FingerprintSignal(
                name=f"TCP {port}",
                value=outcome,
                interpretation=_connectivity_interpretation(outcome),
                weight=0.0,
                source="service",
            )
        )


def _connectivity_interpretation(outcome: str) -> str:
    lowered = outcome.lower()
    if "banner" in lowered and "no banner" not in lowered:
        return "open; banner captured for analysis"
    if "no banner" in lowered:
        return "open but returned no banner to fingerprint"
    if "refused" in lowered:
        return "port closed (connection refused) — host is up but not serving here"
    if "timeout" in lowered or "filtered" in lowered:
        return "no response (filtered or host down)"
    return "probe outcome recorded"


def _record_privilege_note(
    obs: FingerprintObservations, signals: list[FingerprintSignal]
) -> None:
    if obs.raw_signals_available:
        return
    signals.append(
        FingerprintSignal(
            name="Privilege",
            value="unprivileged",
            interpretation="Raw TTL/TCP SYN/ICMP signals require elevation; only TCP "
            "connect and banner grabbing were used. Run elevated for stronger evidence.",
            weight=0.0,
            source="fingerprint",
        )
    )


def _rank(votes: dict[str, float]) -> list[OsGuess]:
    total = sum(votes.values())
    if total <= 0:
        return []
    ranked = sorted(votes.items(), key=lambda item: item[1], reverse=True)
    guesses: list[OsGuess] = []
    for family, score in ranked:
        if score <= 0:
            continue
        guesses.append(
            OsGuess(
                family=family,
                confidence=round(score / total, 3),
                rationale=f"weighted score {score:.1f} of {total:.1f}",
            )
        )
    return guesses


def _confidence(guesses: list[OsGuess], total_weight: float) -> float:
    if not guesses:
        return 0.0
    share = guesses[0].confidence
    saturation = min(1.0, total_weight / _SATURATION)
    return round(share * saturation, 3)
