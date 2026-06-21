from __future__ import annotations


def list_interfaces() -> list[str]:
    try:
        from scapy.all import get_if_list

        return list(get_if_list())
    except Exception:
        return []
