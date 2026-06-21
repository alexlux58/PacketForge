from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

# Hard ceiling so an accidental "0.0.0.0/0" cannot expand into millions of probes.
DEFAULT_MAX_TARGETS = 4096

_HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?:\.[A-Za-z0-9-]{1,63})*$")


@dataclass(frozen=True)
class TargetParseResult:
    targets: list[str]
    skipped: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def count(self) -> int:
        return len(self.targets)


def parse_targets(spec: str, *, max_targets: int = DEFAULT_MAX_TARGETS) -> TargetParseResult:
    """Parse a discovery target specification into a de-duplicated host list.

    Supported tokens (comma, space, or newline separated):

    * single IPv4/IPv6 address - ``192.168.1.10`` / ``2001:db8::1``
    * CIDR network - ``192.168.1.0/24`` (usable hosts only)
    * last-octet range - ``192.168.1.10-20``
    * full dashed range - ``192.168.1.10-192.168.1.40``
    * hostname - ``router.lab.example`` (resolved later, at scan time)
    """
    seen: set[str] = set()
    targets: list[str] = []
    skipped: list[str] = []
    warnings: list[str] = []
    truncated = False

    for token in _tokenize(spec):
        try:
            expanded = expand_token(token)
        except ValueError:
            skipped.append(token)
            continue
        for host in expanded:
            if host in seen:
                continue
            if len(targets) >= max_targets:
                truncated = True
                break
            seen.add(host)
            targets.append(host)
        if truncated:
            break

    if truncated:
        warnings.append(
            f"Target list truncated to {max_targets} hosts. Narrow the range for a full scan."
        )
    if skipped:
        warnings.append(f"Ignored {len(skipped)} invalid token(s): {', '.join(skipped[:5])}")
    return TargetParseResult(
        targets=targets, skipped=skipped, warnings=warnings, truncated=truncated
    )


def _tokenize(spec: str) -> list[str]:
    raw = re.split(r"[\s,]+", spec.strip())
    return [token for token in raw if token]


def expand_token(token: str) -> list[str]:
    token = token.strip()
    if not token:
        raise ValueError("empty token")
    if "/" in token:
        return _expand_cidr(token)
    if "-" in token:
        return _expand_range(token)
    return [_normalize_host(token)]


def _expand_cidr(token: str) -> list[str]:
    network = ipaddress.ip_network(token, strict=False)
    if network.num_addresses <= 2 or network.prefixlen >= network.max_prefixlen - 1:
        return [str(addr) for addr in network]
    return [str(addr) for addr in network.hosts()]


def _expand_range(token: str) -> list[str]:
    start_str, _, end_str = token.partition("-")
    start_str = start_str.strip()
    end_str = end_str.strip()
    start = ipaddress.ip_address(start_str)
    if end_str.isdigit() and isinstance(start, ipaddress.IPv4Address):
        octets = start_str.split(".")
        end = ipaddress.ip_address(".".join([*octets[:3], end_str]))
    else:
        end = ipaddress.ip_address(end_str)
    if type(start) is not type(end):
        raise ValueError("range endpoints must be the same address family")
    if int(end) < int(start):
        raise ValueError("range end is before range start")
    return [str(ipaddress.ip_address(value)) for value in range(int(start), int(end) + 1)]


def _normalize_host(token: str) -> str:
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        pass
    # A token made only of digits and dots is a malformed IP, not a hostname.
    if all(char.isdigit() or char == "." for char in token):
        raise ValueError(f"malformed IPv4 address: {token!r}")
    if _HOSTNAME_RE.match(token):
        return token
    raise ValueError(f"not an IP, CIDR, range, or hostname: {token!r}")


def estimate_count(spec: str, *, max_targets: int = DEFAULT_MAX_TARGETS) -> int:
    return parse_targets(spec, max_targets=max_targets).count


def is_local_subnet(token: str) -> bool:
    """True when a token is private/link-local (a reasonable ARP-scan candidate)."""
    try:
        if "/" in token:
            net = ipaddress.ip_network(token, strict=False)
            return net.is_private or net.is_link_local
        addr = ipaddress.ip_address(token.split("-")[0])
        return addr.is_private or addr.is_link_local
    except ValueError:
        return False
