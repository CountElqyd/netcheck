# simple-netcheck — Design Specification

- **Status:** Draft for review
- **Date:** 2026-09-29
- **Source requirements:** `idea.md` (repo root)
- **Hardware references:** `DGS-1210-28_REVC_MANUAL_4.00_EN.md`,
  `DGS-1210-28-CX-4-00-008.mib`

## 1. Overview

`simple-netcheck` is a single-file Python 3 CLI that diagnoses "no internet" problems
in the office network and tells the operator what to do. It walks the connectivity
layers, then audits the switch fabric for the conditions that most often cause
intermittent office outages: rogue DHCP servers, loops/broadcast storms, and
unhardened switch settings.

It runs on Windows, Linux, and macOS, prefers the Python standard library, requires
no installation (one file; plain Python 3.10+ or optionally `uv`), and never changes
configuration on the ISP router or the switches. Its output is one PASS/WARN/FAIL
line per check plus a likely cause and a suggested fix.

## 2. Goals

1. Locate the failing layer (local config → gateway → internet-by-IP → DNS) quickly
   and unambiguously.
2. When the basic layers pass but the network is still flaky, surface fabric causes:
   unreachable switches, rogue DHCP, loops/broadcast storms, and ports in loop state.
3. Trace a suspicious MAC to a physical switch and port so the operator can unplug it.
4. Report the switch hardening baseline and the exact values to change in the web UI.
5. Offer safe, local, reversible fixes with per-action confirmation.
6. Ship a usage guide (`USAGE.md`) covering the prerequisites for the management
   laptop and the switches, first run, and how to act on the results.
7. Distribute as one file via GitHub Releases: runs with plain Python 3.10+ (no
   install), optionally via `uv` with PEP 723 inline metadata.

## 3. Non-goals

- Configuring the ISP router (no access, and explicitly out of bounds).
- Writing switch configuration. All switch interaction is read-only (SNMP). The
  DGS-1210 Telnet CLI cannot configure LBD/STP/storm/DHCP-screening anyway.
- Continuous monitoring, alerting, or a GUI.
- Replacing SNMP managers, monitoring agents, or a full NMS.
- Supporting switch models other than DGS-1210-28 for the private-MIB features
  (standard-MIB features will work on any managed switch).

## 4. Network context (fixed assumptions)

- ISP router (Cisco 4321, ISP-owned): gateway/LAN IP `192.168.1.1`.
- ISP DNS: `58.71.2.8`, `45.63.30.117`.
- Topology: ISP router → `dlink1` port 23. `dlink2`–`dlink5` cascade off `dlink1`
  ports 24, 25, 26, 27 respectively. Strict tree; no redundant links.
- Switches: D-Link DGS-1210-28 (24 × GbE + 4 × SFP). Telnet CLI is a compact
  subset; SNMP v1/v2c/v3 supported. Web UI for advanced features.
- Management IPs: `dlink1` `10.90.90.90`, `dlink2` `.91`, `dlink3` `.92`,
  `dlink4` `.93`, `dlink5` `.94`. Default credential `admin`/`admin` (must be
  warned about if unchanged).
- These values are defaults; the config file may override them.

## 5. Architecture

One file, `netcheck.py`, logically organized into the units below. Each unit has one
purpose and a narrow interface, so it can be tested without the others.

| Unit | Purpose | Depends on |
|---|---|---|
| `Config` | Load and validate settings from env vars + optional INI file. | stdlib only |
| `Reporter` | Collect `CheckResult`s, print PASS/WARN/FAIL, write `--log` report. | stdlib only |
| `CheckResult` | Dataclass: `id`, `title`, `status`, `detail`, `likely_cause`, `suggested_fix`. | stdlib only |
| `checks_local` | Checks 1–4 (layered connectivity). | shell-out helpers |
| `checks_fabric` | Checks 5–9 (switches, DHCP, tracing, storm, hardening). | snmp, telnet, scapy |
| `snmp` | Minimal SNMP v2c client (GET, GETNEXT, GETBULK, WALK) in pure stdlib. | stdlib `socket`, BER codec |
| `ber` | Minimal BER/ASN.1 encode/decode for the SNMP subset. | stdlib only |
| `telnet` | Socket-based Telnet helper (no `telnetlib`; removed in 3.13). | stdlib `socket` |
| `oui` | MAC → vendor lookup from a small embedded OUI table (common vendors). | stdlib only |
| `fixes` | Optional local fix actions behind y/N prompts. | shell-out helpers |
| `cli` | argparse entry point, flag handling, exit codes. | everything above |

The `fixes` and `cli` units read prompts from `/dev/tty` (`CONIN$` on Windows) and
auto-skip fixes when stdin is not a TTY, so piped runs never hang.

### 5.1 Data flow

```
argv/env/file ──▶ Config ──▶ Phase A: checks 1–4  (short-circuit on first FAIL)
                                   │
                                   ▼
                          Phase B: checks 5–9  (run always unless --quick)
                                   │
                                   ▼
                    Reporter ──▶ stdout (+ timestamped file if --log)
                                   │
                                   ▼
                    fixes (interactive y/N, skipped with --no-fix)
```

### 5.2 Check-result semantics

- `PASS` — expected, healthy.
- `WARN` — degraded, unusual, or could not be determined (missing rights, no SNMP).
- `FAIL` — the condition is definitively broken.
- Exit code: `0` = no FAIL, `1` = WARN present, `2` = FAIL present. (Highest wins.)

### 5.3 Layered vs diagnostic checks (resolved interpretation)

The requirement "stop and report at the first failing layer" applies to the
connectivity layers, checks 1–4. If check 2 fails, checks 3–4 are skipped because
they cannot succeed. Checks 5–9 are fabric diagnostics and run after Phase A
regardless of its result, because a switch-side problem is often the *explanation*
of a Phase A failure. `--quick` runs Phase A only.

## 6. Check flow

### Phase A — connectivity layers (short-circuit)

**1. Local config** — `PASS/WARN/FAIL`
- Discover the active egress interface IP, netmask, default gateway, and DNS servers.
  Windows: `ipconfig /all` + `route print`; Linux: `ip route` + `/etc/resolv.conf`;
  macOS: `netstat -rn` + `scutil --dns`. Cross-check the primary IP with a UDP
  `connect()` trick to `1.1.1.1:53` and `socket.getsockname()`.
- FAIL if the IP is APIPA (`169.254.0.0/16`), if the gateway is not `192.168.1.1`,
  or if DNS servers are empty. WARN if the interface appears to be up but has no
  route.

**2. Gateway** — ping `192.168.1.1` (default 10 packets)
- Report loss %, min/avg/max RTT, and jitter (max − min or RFC 3550-style).
- PASS: 0% loss. WARN: 1–20% loss or jitter > 30 ms. FAIL: > 20% loss.
- FAIL here skips checks 3–4.

**3. Internet by IP** — ping `1.1.1.1` and `8.8.8.8`
- Distinguishes "gateway up but no upstream" from "gateway down".
- PASS: both reachable. WARN: one reachable. FAIL: neither.

**4. DNS** — resolve a fixed test domain against each of `58.71.2.8`,
  `45.63.30.117`, `1.1.1.1`, `8.8.8.8`
- Method: raw UDP DNS A-record query built with `struct`, measuring RTT. Fallback to
  `nslookup` if the raw query is blocked.
- ISP DNS failing while public DNS succeeds ⇒ "ISP DNS problem".
- PASS: all answer. WARN: some answer / slow (> 1 s). FAIL: none answer.

### Phase B — fabric diagnostics (independent)

**5. Switches** — ping all five management IPs
- PASS all reachable. For each unreachable switch, infer and state the implication:
  `dlink2`–`dlink5` unreachable ⇒ the corresponding cascade port (24–27) or that
  switch/uplink is suspect; `dlink1` unreachable ⇒ management path or switch 1 issue.
- WARN if any unreachable (management-plane only; does not by itself explain an
  internet outage).

**6. Rogue DHCP** — discover all DHCP responders
- Primary: `scapy` DHCP discover (broadcast, collect all OFFERs for ~5 s), listing
  server IP, Ethernet source MAC, and vendor (OUI). Flag any responder whose server
  IP is not `192.168.1.1`.
- Fallbacks in order: `nmap --script broadcast-dhcp-discover` (parse), then a
  passive/ARP approach (ARP the offered server IP for its MAC). If all fail, WARN
  "could not determine (needs root/scapy/nmap)".
- PASS: only the gateway answers. FAIL: a non-gateway responder appears.
- Any rogue responder MAC feeds check 7.

**7. Trace to port** — resolve a suspicious MAC to a switch and port
- Method A (preferred): SNMP walk the bridge FDB, starting at `dlink1`, then hop
  downstream. Q-BRIDGE `dot1qTpFdbPort`, fall back to BRIDGE `dot1dTpFdbPort`, map
  to ports via `dot1dBasePortIfIndex`. At startup, verify the walk returns data on
  this firmware; if not, use Method B.
- Method B (fallback): Telnet login, run `debug info` (dumps ARP table + MAC FDB on
  DGS-1210), parse for the MAC. The exact output format must be confirmed against a
  real switch before parsing is trusted.
- Hop logic: if the MAC is on `dlink1` port 24–27, query the matching downstream
  switch (`24→dlink2`, `25→dlink3`, `26→dlink4`, `27→dlink5`) and repeat until the
  MAC lands on an edge port. Found on `dlink1` port 23 ⇒ report as the ISP/upstream
  side. Report `Switch X, port Y`.
- Also run for any duplicate IP/MAC conflicts found in Phase A/B.

**8. Loop / broadcast-storm hints**
- Signals: gateway latency spikes or loss (from check 2), a MAC learned on multiple
  ports or flapping, rising error/broadcast counters on `dlink1` ports 23–27, and
  LBD live loop status (from check 9). Corroborate across signals before declaring
  a storm.

**9. Switch hardening audit** (SNMP read-only)
- For each switch, read the current state and report PASS/WARN/FAIL against the
  baseline in section 7. Include the *diff* (current vs recommended).
- A port whose `sysLBDPortLoopStatus` is `disabled(2)` is **directly in loop state**
  ⇒ FAIL with "loop detected on Switch X, port Y".
- Also runs a read-only storm-control **rate-sampling pass** (§7.1) to recommend a
  data-driven threshold; `--no-measure` uses the static baseline instead.

## 7. Switch hardening baseline

Recommended settings and why, given a strict-tree topology (router → dlink1 →
dlink2–5). Applied manually in the web UI; this script only reads and reports.

### Loopback Detection (L2 Functions)
- Global: **Enabled**. Mode: **Port-based**. Interval: **2 s**. Recover Time: **0**
  (port stays down until fixed; `60` would flap back into the loop every minute).
- Per port: **Enabled on access ports only** (`dlink1` 1–22 and the access ports of
  `dlink2`–`dlink5`). **Off** on the uplink (23) and inter-switch ports (24–27).
- Why: catches edge loops STP cannot see — both ends of a cable into two wall ports,
  or a looped unmanaged switch/hub — and shuts the offending port.

### Storm Control (Security)
- Global: **Enabled**. Type: **Multicast & Broadcast & Unknown Unicast**
  (fallback: Multicast & Broadcast). Threshold: **auto-measured** per port (§7.1);
  the static fallback when unmeasured is `20 000 Kbit/s` on access ports.
- Uplink/inter-switch ports: **disabled**, or a high backstop (~500 000 Kbit/s) so
  legitimate traffic is never dropped.
- Why: caps the blast radius of a storm so one bad port cannot saturate port 23 and
  take down the office. It is mitigation, not root-cause repair.

### 7.1 Storm-control threshold auto-measurement

The hardening audit recommends a data-driven threshold instead of a guessed one. The
pass is read-only (SNMP counters; no packets are sent):

- **Sample:** poll every switch's counters twice, `--sample` seconds apart (default
  30 s), in parallel across switches (`concurrent.futures.ThreadPoolExecutor`) so the
  wall-clock cost is one window, not five.
- **Counters:** `ifHCInBroadcastPkts` (`1.3.6.1.2.1.31.1.1.1.9`) and
  `ifHCInMulticastPkts` (`1.3.6.1.2.1.31.1.1.1.8`), per access port.
- **Compute:** `peak_kbps = max over the window of (Δpkts / Δt) × 512 / 1000`, using
  a conservative 64-byte minimum frame (512 bits) because broadcast/multicast are
  typically small frames.
- **Recommend** per access port:
  `threshold = clamp(ceil_to_64(peak_kbps × factor), floor, 0.8 × link_kbps)`, with
  defaults `factor = 4` and `floor = 10 000 Kbit/s`, both configurable.
- **Uplink / inter-switch ports:** recommend disabled, or a backstop of
  `max(measured, 500 000)` Kbit/s.
- **Unknown unicast (DLF):** not separately countable, so recommend the same measured
  value; this caveat is printed with the recommendation.
- **Fallback:** if SNMP is unavailable or `--no-measure` is set, report the static
  baseline (`20 000` access / off or `500 000` uplink) and state that it is unmeasured.

### RSTP (L2 Functions > Spanning Tree)
- Global: **Enabled**. Version: **RSTP**. Bridge Priority: `dlink1` = **4096**
  (force root; otherwise the lowest-MAC switch wins and a downstream switch can
  become root), `dlink2`–`dlink5` = 32768.
- Access ports: Edge = True, P2P = Auto, **Restricted Role = True**,
  **Restricted TCN = True** (root-guard-like hardening against user gear).
- Uplink/inter-switch ports: Edge = False, P2P = True, Migrate = Yes.
- Why: a safety net for loops between managed switches and fast link-failure
  recovery. In this tree it is mostly dormant; Loopback Detection and Storm Control
  are the features that matter.

### Other
- **Safeguard Engine:** Enabled (default). WARN if off.
- **DHCP Server Screening:** Enabled on access ports; trusted server `192.168.1.1`;
  do **not** screen port 23 or the inter-switch ports, or the ISP router's DHCP
  replies are dropped.
- **DoS Prevention:** Enabled (optional).
- **ARP Spoofing Prevention:** optional rule `192.168.1.1` → router MAC.
- **Port Security:** not recommended (breaks normal device moves in an office).

## 8. SNMP design

- Implement a minimal **SNMP v2c** client in pure stdlib: BER/ASN.1 encode/decode,
  `GetRequest`, `GetNextRequest` (walk), `GetBulkRequest` (v2c efficiency), community
  string auth, 1–3 s timeout, 2 retries.
- v1 fallback via the same codec (no GETBULK).
- **SNMP v3** (USM auth/privacy) is out of scope for the hand-rolled client; if
  `pysnmp` is importable, use it for v3, otherwise emit a clear WARN and continue in
  v2c or skip SNMP checks. This keeps the "standard library only" default intact.
- Community comes from `NETCHECK_SNMP_COMMUNITY` / config file; never hardcoded or
  logged.
- Startup self-check: verify the FDB walk returns rows; if empty, log the fact and
  switch check 7 to Method B.

### 8.1 OID reference (numeric, DGS-1210-28 firmware 4.00.008)

Enterprise base `dgs-1210-28cx` = `1.3.6.1.4.1.171.10.76.20.1`.

| Object | OID | Encoding |
|---|---|---|
| `sysSafeGuardEnable` | `1.3.6.1.4.1.171.10.76.20.1.1.8` | 1=enable, 2=disable |
| `rstpStatus` | `1.3.6.1.4.1.171.10.76.20.1.6.1.1` | 1=enabled, 2=disabled |
| `stpVersion` | `1.3.6.1.4.1.171.10.76.20.1.6.1.2` | 0=stp, 2=rstp |
| `stpPriority` | `1.3.6.1.4.1.171.10.76.20.1.6.1.3` | 0–61410 |
| `broadcastStormCtrlGlobalOnOff` | `1.3.6.1.4.1.171.10.76.20.1.13.3.1` | 1=enabled, 2=disabled |
| `broadcastStormCtrlLimitType` | `1.3.6.1.4.1.171.10.76.20.1.13.3.2` | 1=bcast, 2=mcast+bcast, 3=+unknown-ucast |
| `broadcastStormCtrlThreshold` | `1.3.6.1.4.1.171.10.76.20.1.13.3.3` | Kbit/s, 0 or 64–1024000, step 64 |
| `dhcpServerScreenEnablePortlist` | `1.3.6.1.4.1.171.10.76.20.1.14.7.1` | `PortList` bitmap |
| `dhcpServerScreenTrustedServerTable` | `1.3.6.1.4.1.171.10.76.20.1.14.7.3` | table, index 1–5 |
| `sysLBDStateEnable` | `1.3.6.1.4.1.171.10.76.20.1.17.1` | 1=enabled, 2=disabled |
| `sysLBDMode` | `1.3.6.1.4.1.171.10.76.20.1.17.2` | 1=port, 2=vlan |
| `sysLBDInterval` | `1.3.6.1.4.1.171.10.76.20.1.17.3` | 1–32767 s |
| `sysLBDRecoverTime` | `1.3.6.1.4.1.171.10.76.20.1.17.4` | 0 or 60–1000000 s |
| `sysLBDPortStatus` | `1.3.6.1.4.1.171.10.76.20.1.17.5.1.2` | per-port, 1=enabled, 2=disabled |
| `sysLBDPortLoopStatus` | `1.3.6.1.4.1.171.10.76.20.1.17.5.1.3` | 1=normal, 2=disabled ⇒ loop |
| `doSCtrlState` | `1.3.6.1.4.1.171.10.76.20.1.99.1` | 0=disabled, 1=enabled |

Standard MIBs (port/FDB/counters):

| Object | OID |
|---|---|
| `dot1dBasePortIfIndex` | `1.3.6.1.2.1.17.1.4.1.2` |
| `dot1dTpFdbPort` | `1.3.6.1.2.1.17.4.3.1.2` |
| `dot1qTpFdbPort` | `1.3.6.1.2.1.17.7.1.2.2.1.2` |
| `ifDescr` / `ifName` | `1.3.6.1.2.1.2.2.1.2` / `1.3.6.1.2.1.31.1.1.1.1` |
| `ifInErrors` / `ifOutErrors` | `1.3.6.1.2.1.2.2.1.14` / `1.3.6.1.2.1.2.2.1.20` |
| `ifHCInBroadcastPkts` | `1.3.6.1.2.1.31.1.1.1.9` |
| `ifHCInMulticastPkts` | `1.3.6.1.2.1.31.1.1.1.8` |

`PortList` decode: octet *i*, bit *j* (MSB = lowest port) ⇒ port number
`i*8 + j + 1`.

## 9. Config, flags, and output

### 9.1 Config sources (precedence: CLI/env > file > built-in defaults)

Environment variables:
`NETCHECK_SNMP_COMMUNITY`, `NETCHECK_SNMP_VERSION`, `NETCHECK_SWITCH_USER`,
`NETCHECK_SWITCH_PASS`, `NETCHECK_SWITCHES`, `NETCHECK_GATEWAY`, `NETCHECK_DNS`,
`NETCHECK_DOMAIN`, `NETCHECK_STORM_SAFETY_FACTOR`, `NETCHECK_STORM_FLOOR_KBPS`.

Config file (INI, `configparser`): default `./netcheck.ini`, override with
`--config`. An example is shipped as `netcheck.ini.example`. Secrets are never
printed or written to the log. The storm-control recommendation reads INI keys
`storm_safety_factor` (default `4`) and `storm_floor_kbps` (default `10000`).

### 9.2 Flags

| Flag | Effect |
|---|---|
| `--quick` | Phase A only (checks 1–4). |
| `--log` | Save a timestamped report (`netcheck-YYYYmmdd-HHMMSS.log`). |
| `--config PATH` | Use a specific INI file. |
| `--no-fix` | Never prompt for fixes. |
| `--sample SECONDS` | Counter-sampling window for the storm-threshold recommendation (default 30). |
| `--no-measure` | Skip rate sampling; use the static storm-control baseline. |
| `--timeout N` | Per-network-operation timeout (default 3 s). |
| `--verbose` | Show full tracebacks and raw errors on internal failures. |
| `--no-color` | Disable ANSI color (also auto-off when not a TTY). |
| `--version` | Print the tool version and exit. |

### 9.3 Output format

```
[PASS] 1. Local config  — 192.168.1.50/24 gw 192.168.1.1 dns 58.71.2.8,45.63.30.117
[FAIL] 6. Rogue DHCP    — responder 192.168.1.77 (aa:bb:cc:dd:ee:ff, TP-Link)
    Likely cause: A rogue DHCP server is handing out leases on the office LAN.
    Suggested fix: Trace aa:bb:cc:dd:ee:ff with check 7 and unplug it; enable DHCP
                   Server Screening (Security) with 192.168.1.1 trusted.
[WARN] 9. Hardening     — dlink1 LBD off; storm control off; RSTP off
    Suggested fix: Apply the baseline in USAGE.md.

Each result's likely cause and suggested fix print beneath its own line (a result with
a fix but no cause prints only the fix).

## 10. Error handling and degradation

- Every check is wrapped so a failure produces a `WARN`/`FAIL` result, never a crash.
- No admin/root: skip scapy/nmap paths, mark check 6 `WARN` with the reason.
- No `scapy`: fall back to `nmap`, then to ARP-only; if none, `WARN`.
- No SNMP response: retry; then fall back to Telnet `debug info` for check 7 and
  mark check 9 `WARN` "SNMP unavailable".
- Telnet format mismatch: do not guess — `WARN` "unverified format; run
  `--verbose` to capture a sample".
- Unchanged default `admin`/`admin`: `WARN` prominently.
- All external commands run with explicit timeouts; no shell interpolation of
  untrusted input.

## 11. Security

- Switch/router credentials and SNMP community only from env/file; never hardcoded,
  never echoed, never written to logs.
- Read-only against the switches; no SNMP SET, no CLI `config`/`save`.
- No changes to the ISP router under any code path.
- Capture files used for parser fixtures must be scrubbed of secrets before commit.

## 12. Testing strategy

- Unit tests (`unittest`, stdlib) for every parser and codec, using committed
  fixtures:
  - `ber` encode/decode round-trip; SNMP v2c GET/GETNEXT/GETBULK against captured
    byte streams.
  - `PortList` bitmap decode.
  - Ping output parsing: Windows, Linux, macOS variants (loss/avg/jitter).
  - `ipconfig /all`, `ip route`, `netstat -rn`, `scutil --dns` parsing.
  - DNS response parsing from crafted packets.
  - `debug info` output parsing (fixture captured from a real switch).
  - Hardening evaluator: state → PASS/WARN/FAIL and the produced diff.
  - Storm-threshold math: counter deltas → Kbit/s (64-byte frame), `ceil_to_64`, and
    clamp against floor/link cap, using a mocked two-poll fixture.
- Manual integration checklist (documented, run against the real fabric): FDB walk
  returns rows; `debug info` format matches; a deliberately looped access port is
  reported by `sysLBDPortLoopStatus`; a test rogue DHCP is detected.
- No test may mutate switch or router configuration.

## 13. File layout

```
simple-netcheck/
├── netcheck.py                        # the entire CLI (single file)
├── netcheck.ini.example               # config template
├── USAGE.md                           # operator usage guide (see §15)
├── .github/workflows/release.yml      # optional: tag -> assets + SHA256SUMS (§16)
├── tests/
│   ├── test_ber.py
│   ├── test_snmp.py
│   ├── test_parsers.py
│   ├── test_hardening.py
│   └── fixtures/                      # scrubbed capture samples
├── docs/superpowers/specs/
│   └── 2026-09-29-simple-netcheck-design.md
├── idea.md
├── DGS-1210-28_REVC_MANUAL_4.00_EN.md
└── DGS-1210-28-CX-4-00-008.mib
```

`SHA256SUMS` is generated at release time and is not stored in the repo.

## 14. Decisions

Resolved:
- Layered short-circuit (checks 1–4) vs. always-run fabric diagnostics (5–9). See
  §5.3.
- Switch interaction is read-only SNMP; remediation is manual in the web UI. Telnet
  is used only as a read fallback for `debug info`.
- LBD Recover Time defaults to `0` for persistent-loop safety.
- Storm-control threshold is **auto-measured from live rates** (§7.1), with the
  static `20 000 Kbit/s` value as the unmeasured fallback.
- MAC vendor (OUI) names come from a **small embedded table only** — offline,
  deterministic, no runtime dependency on system files.
- Check 6 (rogue DHCP) **runs by default** in the non-`--quick` run and degrades to
  `WARN` when scapy/nmap/admin rights are unavailable.
- The usage guide ships as **`USAGE.md`** at the repo root (§15).
- Distribution is **download-then-run** from GitHub Releases (pinned URL + SHA-256
  verification); **`uv` is optional, not required**. Piping remote code to the
  interpreter is supported but not recommended.
- Python floor is **3.10** (3.12+ recommended); declared in the PEP 723 header.

## 15. Usage guide deliverable (`USAGE.md`)

Implementation produces `USAGE.md` at the repo root. Required content:

- **What it does / does not** — read-only; never touches the ISP router or writes
  switch configuration; what each PASS/WARN/FAIL and exit code means.
- **Management-laptop prerequisites:**
  - Python 3.10+ (single file, standard library; 3.12+ recommended). `uv` is an
    optional alternative that needs no pre-installed Python.
  - Physical/logical position: plugged into the office LAN behind `dlink1`–`dlink5`,
    in the same L2 broadcast domain as the switches.
  - Reachability to the management subnet: add a secondary IPv4 address in
    `10.90.90.0/8` to the NIC (e.g. `10.90.90.100` / `255.0.0.0`) so
    `10.90.90.90`–`10.90.90.94` is reachable.
  - Elevated rights for check 6: Administrator on Windows, root/`sudo` or
    `setcap cap_net_raw+ep` on Linux/macOS; optional `pip install scapy` and/or
    `nmap` for the fallbacks.
  - Host firewall allows outbound UDP 161 (SNMP) and ICMP.
  - Copy `netcheck.ini.example` to `netcheck.ini` and set the SNMP community,
    switch list, and credentials; or export the `NETCHECK_*` variables. Secrets are
    never committed.
- **Switch prerequisites (one-time, via the web UI):**
  - Unique management IPs `dlink1` `.90` … `dlink5` `.94`, subnet mask `255.0.0.0`
    (factory default `10.90.90.90/8`); management reachable from the laptop's port
    (VLAN 1 by default).
  - Change the default `admin`/`admin` password.
  - **Enable SNMP** (disabled by default): SNMP Global enabled, a read-only v2c
    community and/or v3 user able to read the standard and private MIBs, permitted
    from the management subnet; confirm with the tool's self-check.
  - Keep Telnet enabled for the `debug info` fallback; confirm `debug info` prints
    the ARP table and MAC FDB.
  - Apply the switch hardening baseline (§7); the tool only audits and reports.
- **Getting the tool** — download-then-run from Releases with hash verification, or
  the optional `uv` one-liner (§16).
- **Install and first run**; **interpreting output**; **scenario walkthroughs** (no
  internet, flaky internet, rogue DHCP, loop/storm); **applying the hardening
  baseline** with exact web-UI paths and values; **optional fixes**; **troubleshooting
  the tool** (SNMP failures, scapy without rights, Telnet format drift); **security
  notes**.

## 16. Deployment and distribution

### 16.1 Supported platforms

| OS | Runs? | Notes |
|---|---|---|
| Windows 10/11 | Yes | Admin + Npcap for scapy; ANSI auto-off when not a TTY |
| Linux | Yes | raw sockets need root or `setcap cap_net_raw+ep` |
| macOS | Yes | same elevation need; `scutil --dns` / `netstat -rn` paths |
| Python < 3.10 | No | PEP 723 header declares the floor |

Requires **Python 3.10+** (3.12+ recommended). Checks degrade to `WARN` where a
platform path or privilege is unavailable; nothing hard-fails on OS grounds.

### 16.2 Primary: download-then-run (pinned, hash-verified)

Assets are attached to a GitHub Release, so the URL is stable and version-pinned:

```bash
# Linux / macOS
curl -sSLO https://github.com/<owner>/<repo>/releases/latest/download/netcheck.py
curl -sSLO https://github.com/<owner>/<repo>/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
python3 netcheck.py            # or: uv run netcheck.py
```

```powershell
# Windows PowerShell
iwr -useb https://github.com/<owner>/<repo>/releases/latest/download/netcheck.py -OutFile netcheck.py
Get-FileHash netcheck.py -Algorithm SHA256   # compare with the published hash
py netcheck.py                 # or: uv run netcheck.py
```

### 16.3 Optional: uv and PEP 723 inline metadata

The script carries a PEP 723 header at the top of `netcheck.py`. `uv` is **not
required** — plain CPython ignores the header (it is only comments); uv is what
reads it.

```python
#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
```

- `uv run netcheck.py` needs no pre-installed Python — uv fetches a suitable one.
- Optional extras, without making them hard dependencies:
  `uv run --with scapy netcheck.py` (rogue-DHCP probe) and
  `uv run --with pysnmp netcheck.py` (SNMP v3).
- Optional Unix self-executable form: shebang `#!/usr/bin/env -S uv run --script`
  plus `chmod +x netcheck.py`; not supported on Windows.
- Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh` (or `winget`/`scoop`).

### 16.4 Piping (supported, not recommended)

`curl -sSL <raw-url> | python3 -` works, but executes unpinned remote code that
cannot be hash-verified. It stays interactive only through the `/dev/tty` handling in
§5. Prefer the download-then-run path.

### 16.5 Release automation

Release assets: `netcheck.py`, `netcheck.ini.example`, `USAGE.md`, `SHA256SUMS`. An
optional `.github/workflows/release.yml` regenerates `SHA256SUMS` and uploads the
assets on tag push. Distribution assumes the project is published to a GitHub
repository (the working directory is not yet a git repo).
