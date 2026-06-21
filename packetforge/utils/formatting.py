from __future__ import annotations


def format_ms(value: float | None) -> str:
    return "--" if value is None else f"{value:.2f} ms"


def format_percent(value: float) -> str:
    return f"{value:.1f}%"


def format_pps(value: float) -> str:
    return f"{value:.2f} pps"
