from __future__ import annotations

import pytest

from packetforge.engine.ports import parse_port_list


def test_parse_port_list_accepts_commas_spaces_ranges_and_dedupes() -> None:
    assert parse_port_list("22, 80 443\n8000-8002,80") == [22, 80, 443, 8000, 8001, 8002]


@pytest.mark.parametrize("text", ["abc", "80-", "-90", "90-80", "70000"])
def test_parse_port_list_rejects_invalid_values(text: str) -> None:
    with pytest.raises(ValueError):
        parse_port_list(text)


def test_parse_port_list_enforces_limit() -> None:
    with pytest.raises(ValueError, match="too many"):
        parse_port_list("1-5", max_ports=3)
