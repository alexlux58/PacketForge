from __future__ import annotations

from PySide6.QtWidgets import QFormLayout, QLabel, QWidget


def add_form_row(
    form: QFormLayout,
    label: str,
    widget: QWidget,
    *,
    tooltip: str = "",
) -> None:
    """Add a form row with an optional engineering tooltip on the label."""
    if tooltip:
        widget.setToolTip(tooltip)
        label_widget = QLabel(label)
        label_widget.setToolTip(tooltip)
        form.addRow(label_widget, widget)
    else:
        form.addRow(label, widget)
