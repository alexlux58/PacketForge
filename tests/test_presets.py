import pytest

pytest.importorskip("pydantic")

from packetforge.presets.builtins import builtin_presets
from packetforge.presets.storage import PresetStore


def test_builtin_presets_include_first_release_protocols() -> None:
    categories = {preset.category for preset in builtin_presets()}

    assert {"ICMP", "TCP", "UDP", "Raw"}.issubset(categories)


def test_custom_preset_storage_round_trips(tmp_path) -> None:
    store = PresetStore(tmp_path / "presets.json")
    preset = builtin_presets()[0].duplicate(name="custom ping")

    store.upsert(preset)

    loaded = store.load_custom()
    assert len(loaded) == 1
    assert loaded[0].name == "custom ping"
