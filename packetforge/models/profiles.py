from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ProfileName = Literal["Gentle", "Balanced", "Lab Fast"]


class ScanProfile(BaseModel):
    """Safe, rate-limited discovery profile.

    Every active discovery method in PacketForge runs through a profile so that
    packet rates stay bounded and predictable. Defaults are conservative; the
    fastest profile is still far below anything resembling a stress test.
    """

    model_config = ConfigDict(validate_assignment=True, frozen=True)

    name: ProfileName
    description: str
    max_packets_per_second: float = Field(gt=0, le=2000)
    concurrency: int = Field(ge=1, le=256)
    probe_timeout_ms: int = Field(ge=50, le=60_000)
    retries: int = Field(ge=0, le=5)
    inter_target_delay_ms: int = Field(ge=0, le=60_000)
    max_ports_per_host: int = Field(ge=1, le=1024)

    @property
    def min_interval_s(self) -> float:
        """Minimum spacing between probes implied by the packet-rate limit."""
        return 1.0 / self.max_packets_per_second


GENTLE = ScanProfile(
    name="Gentle",
    description=(
        "Lowest impact. Sequential probes with generous timeouts. Best for "
        "production-adjacent or sensitive networks where caution matters most."
    ),
    max_packets_per_second=20,
    concurrency=1,
    probe_timeout_ms=2000,
    retries=1,
    inter_target_delay_ms=50,
    max_ports_per_host=64,
)

BALANCED = ScanProfile(
    name="Balanced",
    description=(
        "Reasonable default. Modest concurrency and rate limit suitable for "
        "most authorized lab and troubleshooting work."
    ),
    max_packets_per_second=100,
    concurrency=16,
    probe_timeout_ms=1000,
    retries=1,
    inter_target_delay_ms=0,
    max_ports_per_host=128,
)

LAB_FAST = ScanProfile(
    name="Lab Fast",
    description=(
        "Fastest profile, still rate limited. Intended only for isolated lab "
        "networks you own. Not for shared or production environments."
    ),
    max_packets_per_second=500,
    concurrency=64,
    probe_timeout_ms=600,
    retries=0,
    inter_target_delay_ms=0,
    max_ports_per_host=256,
)

BUILTIN_PROFILES: tuple[ScanProfile, ...] = (GENTLE, BALANCED, LAB_FAST)


def profile_by_name(name: str) -> ScanProfile:
    for profile in BUILTIN_PROFILES:
        if profile.name == name:
            return profile
    raise KeyError(f"unknown scan profile: {name!r}")


def default_profile() -> ScanProfile:
    return BALANCED
