"""Subnet grouping helpers shared by discovery, observability, and the map.

The grouping rule is: when a discovered host falls inside one of the CIDR
networks the user actually scanned, label it with that network (so a ``/22``
scan groups under ``/22``). Only when no scanned network contains the host do
we fall back to a synthetic ``/24`` (IPv4) or ``/64`` (IPv6) bucket.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Sequence

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_scan_networks(spec: str) -> list[IPNetwork]:
    """Extract the explicit CIDR networks from a discovery target spec.

    Only ``a.b.c.d/n`` tokens describe a subnet, so single IPs, ranges, and
    hostnames are ignored. Ordering is preserved so callers can prefer the most
    specific match deterministically.
    """
    networks: list[IPNetwork] = []
    for token in re.split(r"[\s,]+", spec.strip()):
        if "/" not in token:
            continue
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            continue
    return networks


def containing_network(ip: str, scan_networks: Sequence[IPNetwork]) -> IPNetwork | None:
    """Return the most specific scanned network that contains ``ip``, if any."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    best: IPNetwork | None = None
    for network in scan_networks:
        if addr.version != network.version or addr not in network:
            continue
        if best is None or network.prefixlen > best.prefixlen:
            best = network
    return best


def subnet_for_ip(ip: str, scan_networks: Sequence[IPNetwork] = ()) -> str | None:
    """Best subnet label for ``ip``: the scanned prefix if known, else /24 or /64.

    Returns ``None`` for values that are not valid IP addresses.
    """
    network = containing_network(ip, scan_networks)
    if network is not None:
        return str(network)
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv4Address):
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    return str(ipaddress.ip_network(f"{ip}/64", strict=False))
