# PacketForge Research Notes

Research date: 2026-06-20.

PacketForge is intentionally a defensive, authorized-use desktop workbench. These notes summarize current official or primary references used to guide the audit and implementation work. They are design inputs, not copied implementation recipes.

## Scapy Packet I/O

- Scapy's usage guide distinguishes layer-3 `send()` from layer-2 `sendp()` and emphasizes that packet sending generally requires elevated privileges. PacketForge should keep Scapy calls in engine modules and expose privilege-aware fallbacks in the GUI. Source: <https://scapy.readthedocs.io/en/latest/usage.html>
- `sr()` / `sr1()` are the right Scapy primitives for request/response probes such as ICMP echo and TCP SYN evidence collection. They should always be wrapped with timeouts and exception handling so GUI workers can cancel safely. Source: <https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html>
- Scapy supports PCAP read/write with `rdpcap()` and `wrpcap()`, which fits PacketForge's export/import tests and Wireshark handoff workflow. Source: <https://scapy.readthedocs.io/en/latest/usage.html>
- Scapy documents `sniff()` plus `AsyncSniffer` for programmatic stop/join. Passive capture workflows should prefer bounded sniffing with explicit stop paths and avoid blocking the GUI thread. Under heavy load Scapy may drop packets — use strict BPF filters and consider `store=False` with on-the-fly processing. Source: <https://scapy.readthedocs.io/en/latest/usage.html#asynchronous-sniffing>, <https://github.com/secdev/scapy/issues/2608>
- For large PCAP files prefer `PcapReader` iteration over loading entire files with `rdpcap()`. Source: Scapy usage docs and community guidance on memory-efficient PCAP reads.

## PySide6 / Qt Desktop Patterns

- `QThread` manages a separate thread of control, and Qt recommends worker objects moved to threads for long-running work. PacketForge's network probes stay behind worker classes and communicate through signals. Use `requestInterruption()` / `isInterruptionRequested()` for cooperative cancellation in long loops. Source: <https://doc.qt.io/qtforpython-6/PySide6/QtCore/QThread.html>
- Qt's model/view architecture and `QSortFilterProxyModel` support sortable/filterable tables without mutating the source model. PacketForge already has a reusable `DataTable`; longer term, high-volume discovery tables should graduate from `QTableWidget` to a `QAbstractTableModel` plus proxy. Source: <https://doc.qt.io/qt-6/model-view-programming.html>

## PyQtGraph Observability

- `PlotWidget` wraps a `PlotItem` and directly exposes common plotting/range controls, making it appropriate for latency timelines, RTT series, and compact operational charts. Source: <https://pyqtgraph.readthedocs.io/en/latest/api_reference/widgets/plotwidget.html>
- `ImageItem` accepts NumPy arrays and supports levels/colormaps, which maps well to port/service heatmaps. Source: <https://pyqtgraph.readthedocs.io/en/latest/api_reference/graphicsItems/imageitem.html>

## Nmap-Style Concepts Without Nmap

- Host discovery should be a set of techniques, not one probe. Nmap documents ARP, ICMP, TCP, and UDP-style discovery concepts; PacketForge should implement comparable concepts directly in Python/Scapy without shelling out. Source: <https://nmap.org/book/man-host-discovery.html>
- TCP SYN scans require raw packet privileges; TCP connect is the unprivileged fallback. PacketForge should surface both paths clearly and explain which is active. Source: <https://nmap.org/book/man-port-scanning-techniques.html>
- UDP results are often ambiguous because lack of response can mean open or filtered, and ICMP unreachable responses can be rate-limited. PacketForge should report `open|filtered` cautiously and avoid overclaiming. Source: <https://nmap.org/book/man-port-scanning-techniques.html>
- Version and OS detection are evidence-driven and imperfect. PacketForge should show supporting evidence and confidence rather than exact OS claims. Sources: <https://nmap.org/book/man-version-detection.html>, <https://nmap.org/book/man-os-detection.html>

## Wireshark / PCAP Workflow

- Wireshark's user guide covers live capture, capture-file modes, file input/output, export, packet filtering, statistics, endpoints, conversations, I/O graphs, and protocol hierarchy. PacketForge should export PCAP plus human-readable summaries that help engineers move between PacketForge and Wireshark. Source: <https://www.wireshark.org/docs/wsug_html_chunked/>

## Protocol References

- DNS: RFC 1035 defines DNS message format and core RR types such as A, MX, NS, PTR, SOA, and TXT. PacketForge DNS probes should remain normal recursive/read-only queries unless AXFR is explicitly confirmed. Source: <https://www.rfc-editor.org/rfc/rfc1035>
- DHCP: RFC 2131 defines DHCP operation. Active DHCP Discover is broadcast traffic and belongs behind explicit lab-mode confirmation; passive observation should be the default. Source: <https://www.rfc-editor.org/rfc/rfc2131>
- SNMP: RFC 3416 defines protocol operations for SNMPv2; RFC 3414 covers SNMPv3 USM. PacketForge should only use user-supplied read-only credentials and must never guess communities or credentials. Sources: <https://www.rfc-editor.org/rfc/rfc3416>, <https://www.rfc-editor.org/rfc/rfc3414>
- SMTP: RFC 5321 defines SMTP; RFC 3207 defines STARTTLS. PacketForge should inspect banners, EHLO capabilities, and STARTTLS availability without sending mail by default. Sources: <https://www.rfc-editor.org/rfc/rfc5321>, <https://www.rfc-editor.org/rfc/rfc3207>
- NTP: RFC 5905 defines NTPv4 fields and calculations. PacketForge should report offset/delay/stratum and make drift trends visible over repeated probes. Source: <https://www.rfc-editor.org/rfc/rfc5905>
- BGP: RFC 4271 defines BGP-4. PacketForge should default to TCP/179 reachability and only send BGP OPEN in an explicit lab mode. Source: <https://www.rfc-editor.org/rfc/rfc4271>
- OSPF: RFC 2328 defines OSPFv2. PacketForge should prefer passive decode and require warnings for active OSPF lab probes. Source: <https://www.rfc-editor.org/rfc/rfc2328>
- STP/RSTP/MSTP: IEEE 802.1Q-2022 is the active Bridges and Bridged Networks standard. PacketForge should treat STP/BPDU handling as passive-first and label any active behavior as lab-only. Source: <https://standards.ieee.org/ieee/802.1Q/10323/>

## Implementation Takeaways

- Keep all live network activity bounded by profiles, timeouts, cancellation, and visible privilege warnings.
- Prefer passive observation for routing/switching/control protocols.
- Keep evidence and confidence visible for fingerprinting and anomalies.
- Use Scapy directly for packet work, never `nmap` or arbitrary shell commands.
- Preserve offline/simulation paths so UI and reports are testable without root or a live network.
