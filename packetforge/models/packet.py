from __future__ import annotations

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class IPv4Layer(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    kind: Literal["IPv4"] = "IPv4"
    src: str | None = None
    dst: str = "192.168.1.1"
    ttl: int = Field(default=64, ge=0, le=255)
    dscp: int = Field(default=0, ge=0, le=63)
    ecn: int = Field(default=0, ge=0, le=3)
    identification: int | None = Field(default=None, ge=0, le=65535)
    flags: list[Literal["DF", "MF"]] = Field(default_factory=list)
    fragment_offset: int = Field(default=0, ge=0, le=8191)
    options: str = ""

    @property
    def tos(self) -> int:
        return (self.dscp << 2) | self.ecn


class ICMPLayer(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    kind: Literal["ICMP"] = "ICMP"
    icmp_type: int = Field(default=8, ge=0, le=255)
    code: int = Field(default=0, ge=0, le=255)
    identifier: int | None = Field(default=None, ge=0, le=65535)
    sequence: int = Field(default=1, ge=0, le=65535)


TcpFlag = Literal["F", "S", "R", "P", "A", "U", "E", "C"]


def default_tcp_flags() -> list[TcpFlag]:
    return ["S"]


class TCPLayer(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    kind: Literal["TCP"] = "TCP"
    sport: int = Field(default=40000, ge=0, le=65535)
    dport: int = Field(default=80, ge=0, le=65535)
    seq: int = Field(default=0, ge=0)
    ack: int = Field(default=0, ge=0)
    flags: list[TcpFlag] = Field(default_factory=default_tcp_flags)
    window: int = Field(default=8192, ge=0, le=65535)

    @field_validator("flags")
    @classmethod
    def unique_flags(cls, flags: list[TcpFlag]) -> list[TcpFlag]:
        seen: set[TcpFlag] = set()
        unique: list[TcpFlag] = []
        for flag in flags:
            if flag not in seen:
                seen.add(flag)
                unique.append(flag)
        return unique

    @property
    def scapy_flags(self) -> str:
        return "".join(self.flags)


class UDPLayer(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    kind: Literal["UDP"] = "UDP"
    sport: int = Field(default=40000, ge=0, le=65535)
    dport: int = Field(default=53, ge=0, le=65535)


class RawLayer(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    kind: Literal["Raw"] = "Raw"
    mode: Literal["text", "hex", "repeated", "random"] = "text"
    text: str = "PacketForge"
    hex_data: str = ""
    byte_value: int = Field(default=65, ge=0, le=255)
    length: int = Field(default=11, ge=0, le=65535)

    @field_validator("hex_data")
    @classmethod
    def normalize_hex(cls, value: str) -> str:
        return "".join(value.split()).lower()

    @model_validator(mode="after")
    def validate_hex_mode(self) -> RawLayer:
        if self.mode == "hex" and self.hex_data:
            try:
                bytes.fromhex(self.hex_data)
            except ValueError as exc:
                raise ValueError("hex payload must contain valid hexadecimal bytes") from exc
        return self


LayerConfig = Annotated[
    IPv4Layer | ICMPLayer | TCPLayer | UDPLayer | RawLayer, Field(discriminator="kind")
]


class PacketConfig(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    name: str = "Untitled packet"
    description: str = ""
    layers: list[LayerConfig] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_layer_order(self) -> PacketConfig:
        layer_names = [layer.kind for layer in self.layers]
        if layer_names.count("IPv4") > 1:
            raise ValueError("only one IPv4 layer is supported in the first release")
        if layer_names.count("ICMP") > 1:
            raise ValueError("only one ICMP layer is supported in the first release")
        transport_layers = {"ICMP", "TCP", "UDP"}
        if sum(1 for name in layer_names if name in transport_layers) > 1:
            raise ValueError("choose one transport layer: ICMP, TCP, or UDP")
        if "IPv4" in layer_names:
            ip_index = layer_names.index("IPv4")
            for transport in transport_layers:
                if transport in layer_names and layer_names.index(transport) < ip_index:
                    raise ValueError(f"{transport} must appear after IPv4")
        if "Raw" in layer_names and layer_names.index("Raw") != len(layer_names) - 1:
            raise ValueError("Raw payload must be the final layer")
        return self


def default_ping_packet() -> PacketConfig:
    return PacketConfig(
        name="Standard IPv4 ping",
        description="IPv4 ICMP echo request with a text payload.",
        layers=[
            IPv4Layer(dst="192.168.1.1", ttl=64),
            ICMPLayer(icmp_type=8, code=0, sequence=1),
            RawLayer(text="PacketForge"),
        ],
    )
