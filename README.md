# PacketForge

PacketForge is a local desktop network discovery, fingerprinting, mapping, and protocol
troubleshooting workbench for **authorized** networks, labs, and engineering validation,
for cases where nmap is unavailable. It uses PySide6 for the GUI and Scapy plus
Python-native libraries for packet construction, transmission, inspection, and PCAP export.

> Authorized use only. PacketForge has no stealth scanning, evasion, exploit payloads,
> brute forcing, or credential attacks, and it never shells out to external scanners.
> See [SECURITY.md](SECURITY.md) for the threat model and safe-use boundaries.

## Workbench

- **Discovery Center** - CIDR/range/single-host/hostname targets, interface selector, and
  ICMP, TCP connect, TCP SYN (when raw sockets are available), UDP, ARP (local L2), reverse
  DNS, and passive-capture discovery. Live
  host table (IP, MAC, vendor, hostname, latency, ports, protocols, confidence, last seen),
  Gentle / Balanced / Lab Fast rate-limited profiles, start/stop/pause/resume/clear, and
  CSV / JSON / Markdown / PCAP export.
- **Fingerprinting** - TTL/hop-limit, TCP window size, MSS/window-scale/SACK/timestamps,
  ICMP behaviour, and service banners. Reports a *likely* OS family with a confidence score
  and the evidence behind it; never claims an exact OS. Evidence is stored per host.
- **Network Map** - subnet-grouped topology with host/gateway nodes, protocol badges, and
  ARP/passive/subnet edges. Export as JSON or PNG.
- **Protocol Troubleshooter** - read-only by default for DNS, DHCP, SNMP (v2c read-only,
  user-supplied community only), SMTP, NTP, BGP, OSPF, and STP. Anything that emits
  non-standard traffic (zone transfer, DHCP discover, BGP OPEN, active OSPF/STP) is gated
  behind an explicit Lab-mode toggle with confirmation.
- **Observability** - turns the collected data into troubleshooting visuals. Every chart
  answers a specific question and aggregation runs off the GUI thread:
  - *Discovery overview*: host-discovery timeline, service/protocol distribution,
    reachability breakdown, most-responsive hosts, subnet coverage, fingerprint-confidence
    distribution, and an open-port heatmap.
  - *Latency & health*: per-host RTT with rolling average, jitter, packet-loss timeline,
    RTT histogram, outlier detection, and a side-by-side host compare table.
  - *Protocol health*: per-protocol panels (DNS/DHCP/SNMP/SMTP/NTP/BGP/OSPF/STP) with
    latency/response charts and decoded tables.
  - *Interactive topology*: zoom/pan graph, group by subnet or protocol, gateway
    highlighting, node service badges, and click-to-inspect nodes (host detail) and edges
    (ARP/passive/latency/reverse-DNS evidence).
  - *Host detail*: identity, services, fingerprint evidence, latency sparkline, findings,
    and JSON/Markdown export.
  - *Run comparison*: added/removed hosts, opened/closed ports, capability changes, latency
    deltas, and fingerprint-confidence changes, with a Markdown/JSON report export.
  - *Anomaly cards*: cautious, evidence-backed hints (high DNS latency, ARP-without-ICMP,
    missing SMTP STARTTLS, SNMP interface errors, NTP offset, possible gateway, RTT spikes,
    packet loss). A **Load sample data** button populates realistic state for exploring the
    tab before any live scan.
  Mini-visuals are also embedded in Discovery Center (reachability) and Fingerprinting
  (confidence distribution).
- **Simulation Mode** - a toggle plus nine deterministic fake-network scenarios (small home
  LAN, enterprise subnet, DNS issue, DHCP issue, high latency/jitter, SMTP STARTTLS missing,
  SNMP interface errors, NTP clock drift, and router/gateway discovery). Loading a scenario
  populates the exact same `HostRecord`, `ServiceRecord`, `FingerprintEvidence`,
  `ProtocolProbeResult`, `PingResult`, and `DiscoveryRun` models a real scan produces, so
  discovery, fingerprinting, the network map, protocol panels, observability charts, and
  reports all behave identically - without sending a single packet. A prominent status-bar
  banner and window-title suffix make it obvious whenever data is simulated. Intended for
  demos, screenshots, development, and validating troubleshooting workflows.
- **Diagnostics** - a live debug-log panel showing recent operations, exceptions, Scapy and
  permission errors, timing, and the last packet summary. All activity is also written to a
  rotating log file under `~/.packetforge/logs/`. A **Copy Debug Bundle** action (and a
  *Save* variant) exports app/Python/OS versions, the interface list, privilege status, recent
  logs, and the current config with secrets (communities, passwords, tokens) redacted.
- **Resilient error handling** - every long-running operation is classified into a central
  `ErrorEvent` (severity, source tab, operation, safe message, suggested fix, timestamp, and a
  full traceback kept only for logging). Network failures surface in a non-modal, per-tab error
  banner with **Retry** and **Dismiss** actions instead of crashing the GUI thread or popping a
  modal. Friendly summaries cover permission-denied, interface-unavailable, invalid CIDR/target,
  DNS failure, timeout, malformed packet, unsupported platform, and generic Scapy exceptions;
  the full technical detail is always written to the logs and the Diagnostics panel, never shown
  inline.
- **Environment Check** - a first-run screen (and Help -> Environment Check) that verifies the
  Python version, that Scapy and PySide6 import, which interfaces are detected, raw-socket
  privilege status, and a PCAP write self-test (writes and re-reads one crafted packet to a temp
  file - no network traffic). Each check shows OK/WARN/FAIL with a suggested fix.
- **Run history** - discovery runs persist under `~/.packetforge/history`. The **History** tab
  lets you browse, load, compare with the current session, and delete saved runs.

## Original tools (still available)

- Ping Lab with payload size, TTL, DF, DSCP, interval, count, live statistics, and RTT charting.
- Visual Packet Builder for IPv4, ICMP, TCP, UDP, and Raw layers.
- Built-in and custom presets that populate the builder and regenerate editable Scapy code.
- Safe Scapy expression console backed by AST interpretation rather than unrestricted eval.
- PCAP export for builder and console packets so they can be opened in Wireshark.

## Install and run

PacketForge targets local desktop use on **macOS** and **Linux** with **Python 3.12 or 3.13**.
Python 3.14 is not supported yet — PySide6 cannot load the GUI platform plugins on 3.14+.

On macOS, Homebrew's default `python3` may be 3.14. Install 3.12 explicitly:

```bash
brew install python@3.12
./scripts/fix_venv.sh
source .venv/bin/activate
packetforge
```

`scripts/fix_venv.sh` creates/refreshes `.venv`, installs the package editable, clears macOS
**hidden** flags (common when the repo lives in iCloud-synced `~/Documents`), and installs a
robust `packetforge` launcher that does not depend on a fragile `.pth` file.

Manual equivalent:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e ".[dev]"
./scripts/fix_venv.sh
packetforge
```

If your system `python3` is already 3.12 or 3.13, you can use `python3 -m venv .venv` instead.
Run each line separately — do not paste inline comments into the shell.

The editable install above is the supported development workflow and is **not** affected by the
packaging steps below. You can also launch with `python -m packetforge.main`.

The first launch opens the **Environment Check** screen so you can confirm Python, Scapy,
PySide6, interfaces, raw-socket privilege, and PCAP write all work before scanning.

### macOS - raw sockets

Packet construction, validation, simulation, and PCAP export work fully unprivileged. Raw
sending/sniffing (ICMP echo, ARP, OS-fingerprint option probes, passive capture) needs elevated
privileges:

- Quick path: run from a terminal with `sudo packetforge` (or `sudo .venv/bin/packetforge`).
- Preferred path: install the **ChmodBPF** helper that ships with
  [Wireshark](https://www.wireshark.org/)/Npcap-equivalent tooling, which grants your user access
  to the `/dev/bpf*` devices so raw capture works without `sudo`.
- Apple Silicon: install a native (arm64) Python so PySide6 and Scapy wheels match your arch.

### Linux - raw socket capability

Prefer Linux capabilities over running the whole GUI as root. Grant `cap_net_raw` (and
`cap_net_admin` for some L2 operations) to the Python interpreter or the packaged binary:

```bash
# Grant the capability to your venv's interpreter (development):
sudo setcap cap_net_raw,cap_net_admin+eip "$(readlink -f .venv/bin/python)"

# ...or to the packaged binary (distribution):
sudo setcap cap_net_raw,cap_net_admin+eip dist/PacketForge/PacketForge
```

Remove it later with `sudo setcap -r <path>`. If you skip this, unprivileged fallbacks
(TCP connect, UDP, DNS, SMTP, NTP, SNMP, passive parsing) still work; TCP SYN, ARP, ICMP,
and raw fingerprint probes stay disabled. The status bar and the Environment Check screen show
whether raw sockets are available.

## Packaging a standalone bundle (optional)

Editable development mode does not require any of this. To build a self-contained local app:

### PyInstaller

```bash
pip install -e ".[package]"
./packaging/build_macos.sh     # -> dist/PacketForge.app
./packaging/build_linux.sh     # -> dist/PacketForge/PacketForge
```

Both scripts call `pyinstaller packaging/packetforge.spec`, which collects Scapy's submodules and
bundles the app icon. The placeholder icon lives at `packetforge/assets/icon.svg`; for a polished
build, export it to `.icns` (macOS) / `.ico` (Windows) and set the `icon=` arguments in the spec.

### Briefcase (experimental alternative)

```bash
pip install -e ".[briefcase]"
briefcase create && briefcase build && briefcase package
```

Briefcase metadata lives under `[tool.briefcase]` in `pyproject.toml`.

## Troubleshooting (Scapy / PySide6 install)

- **`ModuleNotFoundError: No module named 'packetforge'`.** The editable-install `.pth` file in
  `.venv` is missing or marked **hidden** (common under iCloud-synced `~/Documents`). Run
  `./scripts/fix_venv.sh` from the project root, then `packetforge` again.
- **`qt.qpa.plugin: Could not find the Qt platform plugin "cocoa"` (macOS).** Common causes:
  - **Python 3.14+** — PySide6 GUI plugins are not supported yet. Use Python 3.12 or 3.13.
  - **Hidden Qt plugins** — on macOS, pip/iCloud can mark `libqcocoa.dylib` with the `hidden`
    file flag so Qt never discovers it (`…plugin "cocoa" in ""`). PacketForge clears this at
    startup; if it still fails, run:
    `chflags -R nohidden .venv/lib/python*/site-packages/PySide6/Qt/plugins`
  - **iCloud-synced venv** — keep `.venv` outside iCloud Drive (e.g. move the project or venv
    to `~/Developer`).
  - Recreate the venv: `brew install python@3.12 && python3.12 -m venv .venv && pip install -e ".[dev]"`.
- **`qt.qpa.plugin: could not load the Qt platform plugin "xcb"` (Linux).** Install the platform
  libraries: `sudo apt-get install -y libxcb-cursor0 libgl1 libegl1` (Debian/Ubuntu). For headless
  servers/CI, set `QT_QPA_PLATFORM=offscreen`.
- **PySide6 fails to import / wheel not found.** Ensure 64-bit Python 3.12+ and an up-to-date pip
  (`pip install -U pip`). On Apple Silicon use a native arm64 Python so the arm64 wheel installs.
- **Scapy imports but interfaces are empty or sending fails with permission errors.** This is a
  privilege issue, not an install issue - see the macOS/Linux raw-socket notes above. Run the
  Environment Check to confirm.
- **`libpcap`/L2 errors from Scapy.** Install libpcap (`brew install libpcap` on macOS;
  `sudo apt-get install -y libpcap0.8` on Debian/Ubuntu). L3 features work without it.
- **Packaged app won't start.** Run the binary from a terminal to see the error. Missing Scapy
  submodules usually mean the build skipped a hidden import - the bundled spec collects them, so
  rebuild with `--clean`.

## Development

```bash
.venv/bin/python -m ruff check .
.venv/bin/python -m mypy packetforge
.venv/bin/python -m pytest
```

See [docs/TESTING.md](docs/TESTING.md) for GUI smoke-test notes and Qt platform-plugin
troubleshooting. See [docs/IMPROVEMENT_PLAN.md](docs/IMPROVEMENT_PLAN.md) for the audit
backlog and [docs/RESEARCH_NOTES.md](docs/RESEARCH_NOTES.md) for design references.
