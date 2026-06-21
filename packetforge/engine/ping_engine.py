from __future__ import annotations

import secrets
import threading
import time
from collections.abc import Callable
from typing import cast

from scapy.layers.inet import ICMP, IP
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6
from scapy.packet import Packet, Raw
from scapy.sendrecv import sr1

from packetforge.models.ping import PingConfig
from packetforge.models.results import PingResult

PingResultCallback = Callable[[PingResult], None]


class PingEngine:
    def __init__(self) -> None:
        self.stop_event = threading.Event()
        self.pause_event = threading.Event()
        self.captured_packets: list[Packet] = []

    def stop(self) -> None:
        self.stop_event.set()

    def pause(self) -> None:
        self.pause_event.set()

    def resume(self) -> None:
        self.pause_event.clear()

    def run(
        self, config: PingConfig, on_result: PingResultCallback | None = None
    ) -> list[PingResult]:
        self.stop_event.clear()
        self.pause_event.clear()
        self.captured_packets.clear()
        results: list[PingResult] = []
        for offset in range(config.count):
            if self.stop_event.is_set():
                break
            while self.pause_event.is_set() and not self.stop_event.is_set():
                time.sleep(0.05)
            sequence = (config.start_sequence + offset) & 0xFFFF
            packet = self._packet_for_sequence(config, sequence)
            send_wall_time = time.time()
            start = time.perf_counter()
            try:
                reply = sr1(
                    packet,
                    timeout=config.timeout_ms / 1000,
                    iface=config.interface,
                    verbose=False,
                )
                elapsed_ms = (time.perf_counter() - start) * 1000.0
                result = self._result_from_reply(
                    sequence=sequence,
                    send_timestamp=send_wall_time,
                    elapsed_ms=elapsed_ms,
                    reply=reply,
                    interface=config.interface,
                )
                if config.record_pcap:
                    self.captured_packets.append(packet)
                    if reply is not None:
                        self.captured_packets.append(reply)
            except Exception as exc:
                result = PingResult(
                    sequence=sequence,
                    send_timestamp=send_wall_time,
                    timeout=True,
                    error=str(exc),
                    interface=config.interface,
                )
            results.append(result)
            if on_result is not None:
                on_result(result)
            if offset < config.count - 1:
                self._sleep_interval(config.interval_ms / 1000)
        return results

    def _sleep_interval(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and not self.stop_event.is_set():
            time.sleep(min(0.05, deadline - time.monotonic()))

    def _packet_for_sequence(self, config: PingConfig, sequence: int) -> Packet:
        payload = _payload(config)
        if config.address_family == "IPv6":
            ipv6_base = IPv6(dst=config.destination, hlim=config.ttl, tc=config.tos)
            if config.source_ip:
                ipv6_base.src = config.source_ip
            return cast(
                Packet,
                ipv6_base
                / ICMPv6EchoRequest(id=config.icmp_id, seq=sequence)
                / Raw(load=payload),
            )
        flags = "DF" if config.do_not_fragment else 0
        ipv4_base = IP(dst=config.destination, ttl=config.ttl, flags=flags, tos=config.tos)
        if config.source_ip:
            ipv4_base.src = config.source_ip
        return cast(
            Packet,
            ipv4_base / ICMP(id=config.icmp_id, seq=sequence) / Raw(load=payload),
        )

    def _result_from_reply(
        self,
        *,
        sequence: int,
        send_timestamp: float,
        elapsed_ms: float,
        reply: Packet | None,
        interface: str | None,
    ) -> PingResult:
        if reply is None:
            return PingResult(
                sequence=sequence,
                send_timestamp=send_timestamp,
                timeout=True,
                interface=interface,
            )
        icmp_layer = reply.getlayer(ICMP) or reply.getlayer(ICMPv6EchoRequest)
        ip_layer = reply.getlayer(IP) or reply.getlayer(IPv6)
        return PingResult(
            sequence=sequence,
            send_timestamp=send_timestamp,
            receive_timestamp=time.time(),
            rtt_ms=elapsed_ms,
            reply_source=getattr(ip_layer, "src", None),
            reply_ttl=getattr(ip_layer, "ttl", getattr(ip_layer, "hlim", None)),
            reply_size=len(bytes(reply)),
            icmp_type=getattr(icmp_layer, "type", None),
            icmp_code=getattr(icmp_layer, "code", None),
            timeout=False,
            interface=interface,
        )


def _payload(config: PingConfig) -> bytes:
    if config.random_payload:
        return secrets.token_bytes(config.payload_size)
    pattern = config.payload_pattern.encode()
    if not pattern:
        pattern = b"PacketForge"
    repeats = (config.payload_size // len(pattern)) + 1
    return (pattern * repeats)[: config.payload_size]
