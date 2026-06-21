from __future__ import annotations

import json
from pathlib import Path

from pydantic import TypeAdapter

from packetforge.models.preset import Preset
from packetforge.presets.builtins import builtin_presets

PRESET_LIST = TypeAdapter(list[Preset])


class PresetStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_preset_path()

    def all_presets(self) -> list[Preset]:
        return [*builtin_presets(), *self.load_custom()]

    def load_custom(self) -> list[Preset]:
        if not self.path.exists():
            return []
        data = self.path.read_text(encoding="utf-8")
        if not data.strip():
            return []
        return PRESET_LIST.validate_json(data)

    def save_custom(self, presets: list[Preset]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        custom = [preset for preset in presets if not preset.builtin]
        payload = json.dumps([preset.model_dump(mode="json") for preset in custom], indent=2)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(payload, encoding="utf-8")
        temporary.replace(self.path)

    def upsert(self, preset: Preset) -> None:
        if preset.builtin:
            preset = preset.duplicate(name=preset.name)
        custom = self.load_custom()
        for index, existing in enumerate(custom):
            if existing.id == preset.id:
                preset.mark_updated()
                custom[index] = preset
                self.save_custom(custom)
                return
        preset.builtin = False
        preset.mark_updated()
        custom.append(preset)
        self.save_custom(custom)

    def delete(self, preset_id: str) -> bool:
        custom = self.load_custom()
        remaining = [preset for preset in custom if preset.id != preset_id]
        if len(remaining) == len(custom):
            return False
        self.save_custom(remaining)
        return True

    def export_json(self, presets: list[Preset], path: Path) -> None:
        path.write_text(
            json.dumps([preset.model_dump(mode="json") for preset in presets], indent=2),
            encoding="utf-8",
        )

    def import_json(self, path: Path) -> list[Preset]:
        imported = PRESET_LIST.validate_json(path.read_text(encoding="utf-8"))
        custom = self.load_custom()
        by_id = {preset.id: preset for preset in custom}
        for preset in imported:
            preset.builtin = False
            by_id[preset.id] = preset
        merged = list(by_id.values())
        self.save_custom(merged)
        return imported


def default_preset_path() -> Path:
    return Path.home() / ".packetforge" / "presets.json"
