from __future__ import annotations


def parse_port_list(text: str, *, max_ports: int = 1024) -> list[int]:
    """Parse comma/space separated ports and inclusive ranges.

    Examples:
    - ``"22,80,443"``
    - ``"20-25 53"``
    """
    ports: list[int] = []
    seen: set[int] = set()
    tokens = [
        token.strip()
        for chunk in text.replace("\n", ",").replace(" ", ",").split(",")
        if (token := chunk.strip())
    ]
    for token in tokens:
        parsed = _parse_port_token(token)
        for port in parsed:
            if port not in seen:
                ports.append(port)
                seen.add(port)
            if len(ports) > max_ports:
                raise ValueError(f"too many ports; limit is {max_ports}")
    return ports


def _parse_port_token(token: str) -> range:
    if "-" in token:
        start_text, end_text, *extra = token.split("-")
        if extra or not start_text or not end_text:
            raise ValueError(f"invalid port range: {token}")
        start = _parse_single_port(start_text)
        end = _parse_single_port(end_text)
        if end < start:
            raise ValueError(f"port range ends before it starts: {token}")
        return range(start, end + 1)
    port = _parse_single_port(token)
    return range(port, port + 1)


def _parse_single_port(token: str) -> int:
    if not token.isdigit():
        raise ValueError(f"invalid port: {token}")
    port = int(token)
    if not 0 <= port <= 65535:
        raise ValueError(f"port out of range: {token}")
    return port
