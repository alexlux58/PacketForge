from __future__ import annotations

from unittest.mock import MagicMock, patch

from packetforge.ui.widgets.interface_combo import populate_interface_combo


def test_populate_interface_combo_sets_items_and_selection() -> None:
    combo = MagicMock()
    combo.blockSignals = MagicMock()
    combo.unblockSignals = MagicMock()
    with patch(
        "packetforge.ui.widgets.interface_combo.list_interfaces",
        return_value=["en0", "lo0"],
    ):
        populate_interface_combo(combo, selected="en0")
    combo.clear.assert_called_once()
    combo.addItem.assert_any_call("")
    combo.addItems.assert_called_once_with(["en0", "lo0"])
    combo.setCurrentText.assert_called_once_with("en0")
