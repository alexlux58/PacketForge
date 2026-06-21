# PacketForge Improvement Plan

Updated: 2026-06-20 (full audit pass).

## Architecture Map

| Layer | Path | Role |
|-------|------|------|
| Entry | `packetforge/main.py`, `app.py` | Python version gate, Qt bootstrap |
| Models | `packetforge/models/` | Pydantic contracts for discovery, observability, ping, packets |
| Engine | `packetforge/engine/` | Scapy/network logic, no GUI imports |
| Protocols | `packetforge/engine/protocols/` | DNS, DHCP, SNMP, SMTP, NTP, BGP, OSPF, STP probes |
| Security | `packetforge/security/` | Privileges, rate limits, safe Scapy, command policy |
| UI | `packetforge/ui/` | Main window, tabs, workers, charts, shared state |
| Utils | `packetforge/utils/` | Export, formatting |
| Tests | `tests/` | Mocked engine/worker tests; optional GUI smoke |

## Baseline (this pass)

- `pytest`, `ruff check .`, and `mypy packetforge` pass in `.venv`.
- GUI smoke: `tests/test_gui_smoke.py` instantiates `MainWindow` with `QT_QPA_PLATFORM=offscreen`.
- Safety posture: no nmap shell-out, rate-limited profiles, lab-mode gates, AST-only Safe Console.

## Gaps Found (audit)

### Incomplete / placeholder

| Area | Status | Notes |
|------|--------|-------|
| **History** | Was placeholder | Now browse/load/delete/compare saved runs |
| **Packet Capture** | Placeholder | PCAP via Discovery passive, Ping Lab, Packet Builder |
| **Model/view tables** | Partial | `DataTable` widget; large runs still use `QTableWidget` rows |

### Duplicated logic

- Topology: `network_map.py` and `observability.py` both embed `TopologyView` + `build_topology()`.
- Run comparison: `engine/history.py` (simple) vs `engine/observability.py` (rich).
- Legacy `engine/topology.py` (`build_map`) unused by production UI.

### GUI / threading risks

- Passive capture uses blocking `sniff()` in worker (safe for GUI, but stop semantics could improve with `AsyncSniffer`).
- Observability debounce can queue workers while one is running.
- Fingerprint/protocol workers lack mid-probe cancellation.

### Validation gaps (addressed in this pass)

- Fingerprinting and Protocol Troubleshooter now validate host inputs before probes.
- Protocol tab blocks concurrent probes with a clear banner.
- Simulation clear/toggle confirms before wiping real scan data.
- Settings → Discovery Center defaults apply live via `preferences_changed`.

## Priority Work

### P0 — Safety and correctness ✅ (ongoing)

- [x] Raw probes gated by privilege detection
- [x] Lab-mode confirmations for DHCP/BGP/OSPF/STP
- [x] Strict port parsing in Discovery Center
- [x] Simulation clear confirmation
- [x] Shared `DiscoveryHistory` instance wired through main window

### P1 — Core discovery completeness ✅ (mostly done)

- [x] TCP SYN when raw sockets available; TCP connect fallback
- [x] UDP with conservative `open|filtered` labeling
- [x] CSV / JSON / Markdown / PCAP export
- [x] History tab for saved runs
- [ ] PCAP export after worker GC (store passive packets on `DiscoveryState`)

### P2 — Observability polish

- [ ] Consolidate topology tabs or share one widget instance
- [ ] Expose anomaly thresholds in Settings
- [ ] Theme-aware anomaly cards and chart defaults
- [ ] Model/proxy table backend for 1000+ host runs
- [ ] Protocol probe export from Troubleshooter tab

### P3 — Capture and replay

- [ ] Dedicated Packet Capture tab with ring buffer
- [ ] `AsyncSniffer` passive path
- [ ] PCAP import/replay analysis UI

## Implemented In This Pass

- Researched Scapy, PySide6, PyQtGraph, nmap concepts, Wireshark, and protocol RFCs → `docs/RESEARCH_NOTES.md`.
- This plan and `docs/TESTING.md`.
- TCP SYN discovery, strict port parsing, Markdown export (engine + tests).
- **History tab**: browse, load, compare, delete saved runs.
- **Settings live defaults** for Discovery Center profile/interface.
- **Simulation** destructive clear/toggle confirmation.
- **Fingerprinting / Protocol Troubleshooter** input validation; deferred interface combo population.
- **Protocol probe concurrency guard** (one probe at a time).
- **`validate_host_token()`** helper + tests.
- **GUI smoke tests** for `MainWindow` and `HistoryTab`.

## Remaining Work

See P2/P3 above. Highest-value next items:

1. Persist passive PCAP packets on completed runs (not only on live worker).
2. Model/view tables for Discovery Center at scale.
3. Packet Capture tab + `AsyncSniffer`.
4. Unify topology rendering between Network Map and Observability.
5. Worker cancellation for fingerprint and protocol probes.
