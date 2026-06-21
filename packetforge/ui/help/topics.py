from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class HelpSection:
    heading: str
    body: str


@dataclass(frozen=True)
class HelpTopic:
    key: str
    title: str
    intro: str
    sections: tuple[HelpSection, ...]


def _topic(
    key: str,
    title: str,
    intro: str,
    *sections: tuple[str, str],
) -> HelpTopic:
    return HelpTopic(
        key=key,
        title=title,
        intro=intro,
        sections=tuple(HelpSection(heading=h, body=b) for h, b in sections),
    )


HELP_TOPICS: dict[str, HelpTopic] = {
    "dashboard": _topic(
        "dashboard",
        "Dashboard",
        "Quick launcher for built-in and custom packet presets.",
        (
            "What you see",
            "Each row is a preset with category, use case, layer stack, and generated Scapy code. "
            "Double-click a row or click Open Selected Preset to load it in Packet Builder.",
        ),
        (
            "Built-in vs custom",
            "Built-in presets ship with PacketForge. Custom presets are saved under "
            "~/.packetforge/presets.json and can be exported or imported from Packet Builder.",
        ),
    ),
    "discovery_center": _topic(
        "discovery_center",
        "Discovery Center",
        "Active and passive host discovery for authorized networks only. Results feed "
        "Fingerprinting, Network Map, and Observability.",
        (
            "Targets",
            "Enter an IP, CIDR (192.168.1.0/24), comma-separated list, range, or hostname. "
            "The estimate shows how many hosts will be probed. Clear stale results with Clear "
            "before scanning a new subnet.",
        ),
        (
            "Profiles",
            "Gentle, Balanced, and Lab Fast control probe rate, concurrency, and timeout. "
            "Start with Balanced on unfamiliar networks.",
        ),
        (
            "Methods",
            "ICMP and TCP connect work without root. ARP and passive capture need raw-socket "
            "privileges (sudo on macOS, capabilities on Linux). Disabled methods show "
            "'needs elevation'.",
        ),
        (
            "Reading the table",
            "Confidence (0-1) reflects how many independent methods agreed on the host. "
            "Low confidence with empty MAC/hostname often means a passive or partial sighting. "
            "Click a row for the full host detail panel.",
        ),
        (
            "Reachability chart",
            "Summarizes the latest run: reachable (replied), filtered (no reply but not timeout), "
            "unreachable, or unknown (partial evidence). All-unknown usually means passive-only "
            "sightings or incomplete probes.",
        ),
        (
            "Exports",
            "CSV/JSON export the host table. PCAP exports packets captured during passive "
            "monitoring when Record PCAP is enabled.",
        ),
    ),
    "fingerprinting": _topic(
        "fingerprinting",
        "Fingerprinting",
        "Collects TTL, TCP window, ICMP, and banner evidence to infer a likely OS family.",
        (
            "How to run",
            "Pick a host from Discovery or enter an IP manually, choose an interface, then "
            "Run fingerprint. Results appear in the evidence table.",
        ),
        (
            "Interpreting results",
            "PacketForge reports a likely OS family with a confidence score — never an exact OS "
            "version. Low confidence means sparse or conflicting evidence.",
        ),
    ),
    "network_map": _topic(
        "network_map",
        "Network Map",
        "Interactive topology built from discovered hosts.",
        (
            "Navigation",
            "Scroll to zoom, drag to pan. Reset view restores zoom only. Clear map removes all "
            "discovered hosts from shared state (Discovery Center and Fingerprinting too).",
        ),
        (
            "Grouping",
            "Subnet groups hosts by CIDR. Protocol groups by detected service/protocol badges.",
        ),
        (
            "Inspecting",
            "Click a node for host detail. Click an edge for evidence (ARP, passive capture, "
            "latency, reverse DNS).",
        ),
    ),
    "protocol_troubleshooter": _topic(
        "protocol_troubleshooter",
        "Protocol Troubleshooter",
        "Read-only protocol probes by default. Lab mode unlocks traffic that can disrupt networks.",
        (
            "Read-only vs Lab mode",
            "DNS lookups, SNMP GET, SMTP banner, and NTP queries are safe read-only checks. "
            "Enable Lab mode (with confirmation) for zone transfers, DHCP discover, BGP OPEN, "
            "OSPF hello, and STP BPDU — only on lab networks you control.",
        ),
        (
            "Results",
            "Decoded responses feed the Observability tab charts. SNMP never stores communities "
            "in exports.",
        ),
    ),
    "observability": _topic(
        "observability",
        "Observability",
        "Charts and comparisons built from discovery, ping, and protocol probe data.",
        (
            "Getting data",
            "Run Discovery Center, Ping Lab, or Protocol Troubleshooter first. Use Load sample "
            "data to explore charts without sending packets.",
        ),
        (
            "Tabs",
            "Overview summarizes reachability and coverage. Latency & health charts RTT trains "
            "from Ping Lab. Protocol health shows per-protocol panels. Topology is an interactive "
            "graph. Run comparison diffs two discovery runs.",
        ),
        (
            "Anomalies",
            "Cards highlight cautious, evidence-backed hints (high DNS latency, ARP without ICMP, "
            "missing STARTTLS, etc.). They are hints, not verdicts.",
        ),
    ),
    "ping_lab": _topic(
        "ping_lab",
        "Ping Lab",
        "ICMP echo probes with live RTT charting and export.",
        (
            "Defaults",
            "Payload size 56 bytes matches macOS ping. PacketForge uses Scapy in userspace, so "
            "RTT values are typically a few milliseconds higher than the system ping command.",
        ),
        (
            "Statistics",
            "Min/avg/max/median/stddev/jitter/P95 are computed from successful replies only. "
            "Timeouts count toward loss, not average RTT.",
        ),
        (
            "Privileges",
            "ICMP echo usually needs raw sockets. Without elevation, you may see permission "
            "errors — check Environment or run with sudo/capabilities.",
        ),
    ),
    "packet_builder": _topic(
        "packet_builder",
        "Packet Builder",
        "Visual layer editor with live Scapy code generation.",
        (
            "Workflow",
            "Pick a preset or add layers (IPv4, ICMP, TCP, UDP, Raw), edit fields, Build to "
            "preview, then Send or Save PCAP. Transmission settings choose Layer 3 (send) vs "
            "Layer 2 (sendp).",
        ),
        (
            "Scapy code",
            "The code panel stays in sync with the visual editor. You can copy it into Scapy "
            "Console for safe-expression sending.",
        ),
    ),
    "scapy_console": _topic(
        "scapy_console",
        "Safe Scapy Console",
        "Build packets from a restricted Scapy expression — no arbitrary Python.",
        (
            "Workflow",
            "Enter an expression like IP(dst=\"10.0.0.1\")/ICMP(), click Validate, then Build. "
            "Send transmits once; Send and Wait uses sr/sr1 for a reply.",
        ),
        (
            "Safety",
            "Only layer construction and division (/) are allowed. No imports, exec, or "
            "attribute assignment.",
        ),
    ),
    "simulation": _topic(
        "simulation",
        "Simulation Mode",
        "Load deterministic fake-network scenarios for demos and UI testing.",
        (
            "Scope",
            "Simulation populates the same models as real scans. Discovery Center, Network Map, "
            "Observability, and related tabs show fake data. A banner appears in the status bar.",
        ),
        (
            "Clearing",
            "Turn off the toggle or click Clear simulated data to return to an empty workspace.",
        ),
    ),
    "diagnostics": _topic(
        "diagnostics",
        "Diagnostics",
        "Live debug log and support bundle export.",
        (
            "Log panel",
            "Shows recent operations, timing, and errors. Full tracebacks stay in the log file "
            "under ~/.packetforge/logs/, not in the GUI.",
        ),
        (
            "Debug bundle",
            "Copy Debug Bundle exports versions, interfaces, privilege status, recent logs, and "
            "config with secrets redacted.",
        ),
    ),
    "environment": _topic(
        "environment",
        "Environment Check",
        "First-run verification before scanning or sending packets.",
        (
            "Checks",
            "Python version, Scapy/PySide6 imports, interface list, raw-socket privilege, and a "
            "PCAP write self-test (no network traffic).",
        ),
        (
            "Fixing failures",
            "Follow each row's suggested fix. On macOS use Python 3.12/3.13 and consider sudo "
            "or ChmodBPF for raw capture.",
        ),
    ),
    "settings": _topic(
        "settings",
        "Settings",
        "Application preferences persisted between launches.",
        (
            "Options",
            "Theme, default scan profile, default interface, remember last tab, and status "
            "message duration. Changes apply immediately except theme (View menu also works).",
        ),
    ),
    "global": _topic(
        "global",
        "PacketForge",
        "Local desktop network discovery and diagnostics for authorized networks.",
        (
            "Keyboard shortcuts",
            "Ctrl+F focuses table search in supported tabs. Ctrl+C copies selected table rows. "
            "Ctrl+, opens Settings.",
        ),
        (
            "Status bar",
            "Shows interface, raw-socket availability, privilege mode, and capture counters. "
            "Yellow simulation banner means data is fake.",
        ),
        (
            "Authorized use",
            "No stealth scanning, evasion, or credential attacks. See SECURITY.md for safe-use "
            "boundaries.",
        ),
    ),
}


def help_topic(key: str) -> HelpTopic:
    topic = HELP_TOPICS.get(key)
    if topic is None:
        return HELP_TOPICS["global"]
    return topic
