from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Literal

from scapy.packet import Packet
from scapy.sendrecv import send, sendp, sr, sr1, srp, srp1

SendFunction = Literal["send", "sendp", "sr", "sr1", "srp", "srp1"]


@dataclass(frozen=True)
class SendOptions:
    function: SendFunction = "send"
    iface: str | None = None
    count: int = 1
    interval_s: float = 0.0
    timeout_s: float = 1.0
    retry: int = 0
    verbose: bool = False


def send_packet(packet: Packet, options: SendOptions) -> object:
    kwargs: dict[str, Any] = {"iface": options.iface, "verbose": options.verbose}
    if options.function == "send":
        return send(packet, count=options.count, inter=options.interval_s, **kwargs)
    if options.function == "sendp":
        return sendp(packet, count=options.count, inter=options.interval_s, **kwargs)
    if options.function == "sr":
        return sr(
            packet,
            timeout=options.timeout_s,
            retry=options.retry,
            inter=options.interval_s,
            **kwargs,
        )
    if options.function == "srp":
        return srp(
            packet,
            timeout=options.timeout_s,
            retry=options.retry,
            inter=options.interval_s,
            **kwargs,
        )
    if options.function == "sr1":
        return sr1(packet, timeout=options.timeout_s, retry=options.retry, **kwargs)
    return srp1(packet, timeout=options.timeout_s, retry=options.retry, **kwargs)


def send_multiple(packet: Packet, *, count: int, interval_s: float, options: SendOptions) -> None:
    for index in range(count):
        send_packet(packet, options)
        if index < count - 1 and interval_s > 0:
            time.sleep(interval_s)
