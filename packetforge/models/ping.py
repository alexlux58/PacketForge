from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PingConfig(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    destination: str = "192.168.1.1"
    address_family: Literal["IPv4", "IPv6"] = "IPv4"
    interface: str | None = None
    source_ip: str | None = None
    count: int = Field(default=4, ge=1, le=100000)
    interval_ms: int = Field(default=1000, ge=10, le=3_600_000)
    timeout_ms: int = Field(default=1000, ge=50, le=3_600_000)
    ttl: int = Field(default=64, ge=0, le=255)
    payload_size: int = Field(default=32, ge=0, le=65507)
    dscp: int = Field(default=0, ge=0, le=63)
    ecn: int = Field(default=0, ge=0, le=3)
    icmp_id: int = Field(default=0xF00D, ge=0, le=65535)
    start_sequence: int = Field(default=1, ge=0, le=65535)
    payload_pattern: str = "PacketForge"
    random_payload: bool = False
    do_not_fragment: bool = False
    resolve_dns: bool = True
    record_pcap: bool = False

    @property
    def tos(self) -> int:
        return (self.dscp << 2) | self.ecn

    @field_validator("payload_pattern")
    @classmethod
    def non_empty_pattern(cls, value: str) -> str:
        return value or "PacketForge"
