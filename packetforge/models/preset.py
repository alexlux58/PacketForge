from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from packetforge.models.packet import PacketConfig

PresetCategory = Literal["ICMP", "TCP", "UDP", "Raw", "Diagnostic"]


class Preset(BaseModel):
    model_config = ConfigDict(validate_assignment=True)

    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    category: PresetCategory
    description: str
    use_case: str
    packet: PacketConfig
    builtin: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(tz=UTC))

    def mark_updated(self) -> None:
        self.updated_at = datetime.now(tz=UTC)

    def duplicate(self, *, name: str | None = None) -> Preset:
        clone = self.model_copy(deep=True)
        clone.id = str(uuid4())
        clone.name = name or f"{self.name} copy"
        clone.builtin = False
        clone.created_at = datetime.now(tz=UTC)
        clone.updated_at = clone.created_at
        return clone
