# PacketForge Security and Safety

PacketForge is a **local desktop workbench** for authorized network discovery,
fingerprinting, mapping, and protocol troubleshooting. It is designed for labs,
owned networks, and explicit engineering validation — not for scanning third
parties or evading controls.

This document describes the threat model, the safety boundaries built into the
application, and the responsibilities of the operator.

## Threat model

### Assets

| Asset | Why it matters |
| --- | --- |
| Operator credentials (SNMP communities, etc.) | Supplied at runtime; must not leak to disk or exports |
| Local PCAP / JSON / CSV exports | May contain traffic metadata from authorized scans |
| Raw-socket capability | Enables packet injection and passive capture |
| Operator workstation | GUI process runs with the user's OS privileges |

### Adversaries and abuse scenarios

| Scenario | Mitigation |
| --- | --- |
| Malicious Scapy console input executing arbitrary Python | AST interpreter with an allow-listed class set; no `eval`/`exec` |
| Shell injection via a future “run command” feature | `command_policy` module rejects operators and unapproved binaries (defense in depth; **the app does not shell out today**) |
| Credential guessing (SNMP communities, passwords) | Never implemented; empty community → no probe |
| Accidental production network disruption | Rate-limited scan profiles, conservative defaults, explicit Lab-mode gates |
| Unauthorized scanning of third-party networks | Operator responsibility; UI warnings and this document |
| Secret leakage via debug bundle or exports | Config redaction; probe results omit credential fields |
| Privilege escalation via PacketForge itself | No setuid; elevation is external (`sudo` / `setcap`) |

### Out of scope

PacketForge does **not** attempt to protect against:

- A malicious operator with root access to the machine
- Compromise of the Python/runtime environment outside the app
- Attacks against remote targets beyond what normal network tools can do when misused
- Windows support (planned; not a current target platform)

## Safe-use boundaries

### Authorized use only

Use PacketForge only on networks and systems you own or have **explicit written
authorization** to test. The README and several tabs display this requirement.
Simulation Mode exists for demos and workflow validation without sending packets.

### No external scanner shell-out

PacketForge **never** invokes `nmap`, `masscan`, or arbitrary shell commands.
Discovery, probing, and fingerprinting use Scapy and Python-native sockets only.

A small `command_policy` module exists as defense-in-depth (approved read-only
diagnostic commands, rejection of `;`, `|`, `` ` ``, `$()`, etc.) but is **not
wired to the GUI** in the current release because no shell execution path exists.

### Safe Scapy console

The Safe Scapy Console (`packetforge/security/safe_scapy.py`) parses user
expressions with `ast.parse(..., mode="eval")` and evaluates them with a custom
interpreter — **not** Python's built-in `eval()` or `exec()`.

**Allowed**

- Direct calls to an approved set of Scapy layer classes (`IP`, `TCP`, `UDP`,
  `ICMP`, `Ether`, `ARP`, `DNS`, `Raw`, …)
- Literal constants (strings, bytes, numbers, lists, tuples, dicts)
- Packet layering with `/` only

**Rejected**

- Any unapproved function or class name (`exec`, `open`, `__import__`, …)
- Attribute access, subscripts, lambdas, comprehensions, f-strings
- Binary operators other than `/`
- Bare names, `**kwargs` expansion, method calls on packets
- Expressions that do not produce a Scapy `Packet`

Regression tests in `tests/test_safe_scapy_rules.py` and `tests/test_security.py`
lock in these rules.

### Credential handling

| Area | Behaviour |
| --- | --- |
| SNMP v2c | Community string is **user-supplied only**; empty → probe refused with guidance. Never guessed or brute-forced. |
| SNMP v3 | Not implemented; returns an explanatory result without sending auth traffic. |
| SNMP in UI | Community field uses password echo mode; value is used only to build the wire request. |
| Probe results | `ProtocolProbeResult` has **no** `community` / `password` fields; credentials are not persisted in observability state. |
| Debug bundle | `redact_config()` masks keys matching `password`, `secret`, `community`, `token`, `credential`, etc. |
| Exports (JSON/CSV/PCAP) | Host, ping, discovery, and observability exports use structured models that omit credential fields. User-facing summary text may mention “community” in guidance strings but does not echo the supplied value. |

### Export files

Exports are explicit user actions (Save CSV/JSON/PCAP, Copy Debug Bundle). They
contain scan results and diagnostics metadata, **not** operator secrets, unless
the operator manually copies secrets elsewhere.

PCAP files may contain packet payloads from authorized captures; treat them like
any other capture file.

### Active probe rate limits

All Discovery Center methods share a **token-bucket rate limiter**
(`packetforge/security/rate_limit.py`) keyed to the selected scan profile:

| Profile | Max pps | Concurrency | Notes |
| --- | ---: | ---: | --- |
| Gentle | 20 | 1 | Default-safe for sensitive networks |
| Balanced | 100 | 16 | General lab/troubleshooting |
| Lab Fast | 500 | 64 | Isolated labs only; still capped at 2000 pps by schema |

Profiles are immutable Pydantic models with hard upper bounds (`max_packets_per_second ≤ 2000`,
`concurrency ≤ 256`, `max_ports_per_host ≤ 1024`). There is no “unlimited” profile.

### Dangerous protocol actions

Read-only probes (DNS lookups, SMTP banner/EHLO, NTP client query, SNMP GET with
user community, passive DHCP/OSPF/STP decode, BGP TCP/179 reachability) run
without Lab mode.

The following require **explicit opt-in** (Lab-mode checkbox and/or confirmation dialog):

| Action | Gate |
| --- | --- |
| DNS zone transfer (AXFR) | Confirmation dialog + `confirmed=True` in engine |
| DHCP Discover broadcast | Lab-mode checkbox + confirmation |
| BGP OPEN probe | Lab-mode checkbox + confirmation |
| OSPF Hello | Lab-mode checkbox + confirmation |
| STP BPDU | Lab-mode checkbox + confirmation |

Engine modules refuse these operations when `lab_mode=False` or `confirmed=False`,
even if the GUI is bypassed.

### Privileges and raw sockets

ICMP, ARP, OS fingerprint probes, and passive capture require raw sockets. The
status bar and Environment Check report availability. PacketForge does not
self-elevate; the operator uses `sudo` or Linux file capabilities externally.

Unprivileged fallbacks (TCP connect, UDP, DNS, etc.) remain available when raw
sockets are unavailable.

## Reporting vulnerabilities

If you believe you have found a security issue in PacketForge itself (not a
misconfiguration of your environment), please report it responsibly to the
project maintainers with:

1. Affected version
2. Steps to reproduce
3. Impact assessment
4. Suggested fix (if any)

Do not use the issue tracker for unauthorized scanning of third-party networks.

## Verification

Security regressions are covered by:

```bash
pytest tests/test_security.py tests/test_safe_scapy_rules.py tests/test_protocols.py
```

Key checks include rejected unsafe Scapy expressions, rejected unsafe command
inputs, absence of `subprocess` / `os.system` in application code, SNMP
credential non-storage, export/debug redaction, scan-profile rate ceilings, and
lab-mode gating for dangerous probes.
