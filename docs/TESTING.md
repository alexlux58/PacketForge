# PacketForge Testing

PacketForge's automated tests are designed to run without root and without live network access. Scapy send/receive/sniff behavior is mocked or exercised with crafted packets.

Use the local Python 3.12 venv:

```bash
.venv/bin/python -m pytest
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy packetforge
```

The same commands also passed in `.venv312` during the audit, but GUI startup did not work there because Qt reported an empty platform-plugin search path even though the plugins existed on disk.

## GUI Smoke

The app can be smoke-started headlessly in `.venv`:

```bash
env QT_QPA_PLATFORM=offscreen .venv/bin/python -c "from PySide6.QtWidgets import QApplication; from packetforge.ui.main_window import MainWindow; app = QApplication([]); window = MainWindow(); print(window.windowTitle()); window.close(); app.quit()"
```

Expected output includes `PacketForge`.

If Qt reports `Could not find the Qt platform plugin "cocoa"` or `offscreen`, recreate the venv with Python 3.12/3.13 and reinstall:

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -U pip
.venv/bin/python -m pip install -e ".[dev]"
```

## What Is Covered

- Target parsing for single hosts, CIDR, ranges, invalid values, truncation, previews, and `validate_host_token()`.
- Discovery engine TCP/UDP helpers, raw-privilege gating, TCP SYN orchestration, reverse DNS, stop/cancel behavior, and result merging.
- Fingerprint scoring and evidence confidence.
- Protocol parsers/probes for DNS, DHCP, SNMP, SMTP, NTP, BGP, OSPF, and STP using fake packets or mocked sockets.
- Observability aggregation, charts, topology, anomalies, run comparisons, and simulation scenarios.
- Safe Scapy expression parsing and rejection of imports, eval/exec-style constructs, filesystem/subprocess access, attributes, and unsupported syntax.
- PCAP export/import round trips plus CSV, JSON, and Markdown report exports.
- Worker-thread completion and cancellation behavior where practical without a GUI event loop.
- GUI smoke: `tests/test_gui_smoke.py` instantiates `MainWindow` and `HistoryTab` when Qt platform plugins are available (skipped automatically in broken/headless environments).
