from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFormLayout,
    QGroupBox,
    QSpinBox,
)

from packetforge.ui.widgets.form_helpers import add_form_row
from packetforge.ui.widgets.interface_combo import defer_populate_interface_combo, tune_combo_box

_FIELD_TOOLTIPS: dict[str, str] = {
    "Interface": "Outbound interface for L2 send or capture binding.",
    "Send mode": "Layer 3 (IP) send vs Layer 2 (Ethernet) sendp.",
    "Count": "Number of times to transmit the packet.",
    "Interval (ms)": "Delay between repeated transmissions.",
    "Timeout (ms)": "Wait time when using send-and-wait (sr/sr1).",
    "Retry": "Retransmit count for send-and-wait operations.",
    "Verbose": "Ask Scapy to print send/receive details to the log.",
}


@dataclass
class TransmissionControls:
    interface: QComboBox
    send_mode: QComboBox
    count: QSpinBox
    interval_ms: QSpinBox
    timeout_ms: QSpinBox
    retry_count: QSpinBox
    verbose: QCheckBox


def _combo_box(*items: str) -> QComboBox:
    combo = tune_combo_box(QComboBox())
    combo.addItems(list(items))
    return combo


def _spin_box(minimum: int, maximum: int, value: int) -> QSpinBox:
    spin = QSpinBox()
    spin.setRange(minimum, maximum)
    spin.setValue(value)
    spin.setMinimumWidth(120)
    return spin


def build_transmission_group(
    *,
    tooltips: dict[str, str] | None = None,
) -> tuple[QGroupBox, TransmissionControls]:
    """Build a consistently laid-out transmission settings group."""
    tips = {**_FIELD_TOOLTIPS, **(tooltips or {})}
    box = QGroupBox("Transmission")
    form = QFormLayout(box)
    form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
    form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
    form.setVerticalSpacing(8)
    form.setHorizontalSpacing(12)
    form.setContentsMargins(8, 12, 8, 8)

    interface = _combo_box("")
    defer_populate_interface_combo(interface)
    send_mode = _combo_box("Layer 3", "Layer 2")
    count = _spin_box(1, 100_000, 1)
    interval_ms = _spin_box(0, 3_600_000, 100)
    timeout_ms = _spin_box(50, 3_600_000, 1000)
    retry_count = _spin_box(0, 100, 0)
    verbose = QCheckBox()

    add_form_row(form, "Interface", interface, tooltip=tips["Interface"])
    add_form_row(form, "Send mode", send_mode, tooltip=tips["Send mode"])
    add_form_row(form, "Count", count, tooltip=tips["Count"])
    add_form_row(form, "Interval (ms)", interval_ms, tooltip=tips["Interval (ms)"])
    add_form_row(form, "Timeout (ms)", timeout_ms, tooltip=tips["Timeout (ms)"])
    add_form_row(form, "Retry", retry_count, tooltip=tips["Retry"])
    add_form_row(form, "Verbose", verbose, tooltip=tips["Verbose"])

    controls = TransmissionControls(
        interface=interface,
        send_mode=send_mode,
        count=count,
        interval_ms=interval_ms,
        timeout_ms=timeout_ms,
        retry_count=retry_count,
        verbose=verbose,
    )
    return box, controls


def configure_form_layout(form: QFormLayout) -> None:
    """Apply standard spacing and growth rules to an existing form."""
    form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.ExpandingFieldsGrow)
    form.setLabelAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
    form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
    form.setVerticalSpacing(8)
    form.setHorizontalSpacing(12)
    form.setContentsMargins(8, 12, 8, 8)


def tune_spin_box(spin: QSpinBox, *, minimum_width: int = 120) -> QSpinBox:
    spin.setMinimumWidth(minimum_width)
    return spin
