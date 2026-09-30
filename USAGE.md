# netcheck — Operator Usage Guide

`netcheck` is a single-file, read-only diagnostic for the office network.
It finds *why the internet is broken*, and separately audits the D-Link switch
fabric for the things that cause intermittent outages: rogue DHCP servers,
loops/broadcast storms, and switch settings that drift below a hardening
baseline.

> **Read-only guarantee.** The tool never changes the ISP router, never writes
> switch configuration (no SNMP SET, no CLI `config`/`save`), and only reads
> switch state. Every change described in this guide is applied **by you, by
> hand, in the switch web UI**.

---

## 0. Quickstart

**One-time: install `uv`.** `uv` fetches a suitable Python itself — no `pip`, no
virtualenv, and no pre-installed Python.

```bash
# Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# macOS (alternative, via Homebrew)
brew install uv

# Windows PowerShell
winget install --id=astral-sh.uv
```

Confirm it is on your PATH:

```bash
uv --version
```

**Then the 3 commands:**

```bash
git clone https://github.com/CountElqyd/netcheck.git
cd netcheck
uv run netcheck.py --no-fix
```

That is install (once) → clone → enter → run. If you already have **Python
3.10+**, the last command can instead be `python3 netcheck.py --no-fix`.

**Enable the rogue-DHCP probe (check 6) and SNMP extras:**

```bash
uv run --with scapy netcheck.py --no-fix   # + rogue-DHCP broadcast probe (needs admin/root)
```

**Configure before a real run** (secrets stay out of git — the file is
gitignored):

```bash
cp netcheck.ini.example netcheck.ini       # then set snmp_community etc.
```

> **Before checks 1–4 pass** you must be on the office LAN, and **before checks
> 6–9 work** you need the one-time setup in [§3](#3-management-laptop-prerequisites)
> (the `10.90.90.0/8` management alias, admin rights for scapy) and
> [§4](#4-switch-prerequisites-one-time-web-ui) (read-only SNMP on each switch).
> See [§6](#6-get-the-tool-and-first-run) for the download-and-run alternative.

---

## Contents

0. [Quickstart](#0-quickstart)
1. [Network map and value checklist](#1-network-map-and-value-checklist)
2. [Baseline measurement first](#2-baseline-measurement-first)
3. [Management-laptop prerequisites](#3-management-laptop-prerequisites)
4. [Switch prerequisites (one-time, web UI)](#4-switch-prerequisites-one-time-web-ui)
5. [Switch hardening configuration (web UI)](#5-switch-hardening-configuration-web-ui)
6. [Get the tool and first run](#6-get-the-tool-and-first-run)
7. [Interpreting output](#7-interpreting-output)
8. [Scenario playbooks](#8-scenario-playbooks)
9. [Flags](#9-flags)
10. [Optional fixes](#10-optional-fixes)
11. [Troubleshooting the tool](#11-troubleshooting-the-tool)
12. [Security notes](#12-security-notes)
13. [Appendix A — Configuration worksheet](#appendix-a--configuration-worksheet)
14. [Appendix B — Web-UI menu quick reference](#appendix-b--web-ui-menu-quick-reference)

---

## 1. Network map and value checklist

```
                 ISP router (Cisco 4321, ISP-owned, out of scope)
                 LAN/gateway 192.168.1.1 · DNS 58.71.2.8 / 45.63.30.117
                                  │
                            dlink1 port 23
                                  │
              ┌───────────────────┼───────────────────┬───────────────┐
        port 24             port 25             port 26          port 27
              │                   │                   │               │
           dlink2              dlink3              dlink4          dlink5
      (access 1-22)       (access 1-22)       (access 1-22)   (access 1-22)
```

Strict tree — there are no redundant links. Management IPs are `10.90.90.90`
(`dlink1`) through `10.90.90.94` (`dlink5`), subnet mask `255.0.0.0`.

### Per-switch port roles (the convention this guide uses)

| Switch | Access ports | Uplink to upstream | Cascade ports |
|---|---|---|---|
| dlink1 | 1–22 | 23 (to router) | 24, 25, 26, 27 |
| dlink2 | 1–22 | port linking back to dlink1 port 24 | n/a (edge) |
| dlink3 | 1–22 | port linking back to dlink1 port 25 | n/a (edge) |
| dlink4 | 1–22 | port linking back to dlink1 port 26 | n/a (edge) |
| dlink5 | 1–22 | port linking back to dlink1 port 27 | n/a (edge) |

> **Confirm the real uplink port on dlink2–dlink5.** The hardening baseline
> assumes every non-access port is in the 23–27 range. If a downstream switch
> uses a different port for its link back to dlink1, treat *that* port as the
> uplink (Loopback Detection off, Storm Control off/high, STP edge off).

### Value checklist (fill this in before you start)

| Field | Expected value | Your value |
|---|---|---|
| Gateway | `192.168.1.1` | |
| ISP DNS | `58.71.2.8`, `45.63.30.117` | |
| Public DNS | `1.1.1.1`, `8.8.8.8` | |
| dlink1 mgmt IP | `10.90.90.90` | |
| dlink2 mgmt IP | `10.90.90.91` | |
| dlink3 mgmt IP | `10.90.90.92` | |
| dlink4 mgmt IP | `10.90.90.93` | |
| dlink5 mgmt IP | `10.90.90.94` | |
| SNMP community (read-only) | non-default, e.g. `netcheck-ro` | |
| Switch admin user / password | not `admin`/`admin` | |

---

## 2. Baseline measurement first

**Measure before you change anything.** Two reasons:

1. You need a record of what "healthy" looks like so you can prove that a change
   helped (or at least did not hurt).
2. Storm-control thresholds should be driven by **real traffic rates**, not a
   guessed number. The tool measures these for you.

> **One-time prerequisite:** complete [§4.3](#43-enable-snmp-read-only) (enable a
> read-only SNMP community on all five switches) before taking the baseline.
> Without it, check 9 reports `SNMP community not set` and check 7 cannot list
> devices. The storm measurement also requires SNMP.

### 2.1 Capture a connectivity baseline

On a normal working day (and again at a busy time if the office has one):

```bash
python3 netcheck.py --log          # full run, writes netcheck-<timestamp>.log
python3 netcheck.py --quick --log  # connectivity layers only (checks 1-4)
```

Keep the logs. A healthy baseline should show `[PASS]` on checks 1–5, `[PASS]`
on 6 (only the gateway answers DHCP), `[PASS]` on 8, and either `[PASS]` on 9
(already hardened) or `[WARN]` listing what is below baseline.

### 2.2 Measure the storm-control rates

Run the full tool and let it sample. The measurement is read-only: it polls each
switch's broadcast and multicast counters twice, `--sample` seconds apart, in
parallel across switches.

```bash
python3 netcheck.py --sample 30      # quick sample (default window)
python3 netcheck.py --sample 300     # 5-minute sample, use during peak hours
```

How the recommendation is computed (so you can sanity-check it):

- Counters read: `ifHCInBroadcastPkts` and `ifHCInMulticastPkts` per port.
- `peak_kbps = max rate × 512 / 1000` — 512 bits assumes a conservative 64-byte
  frame, which suits broadcast/multicast.
- Recommended threshold per port:
  `clamp( ceil_to_64(peak_kbps × factor), floor, 0.8 × 1,000,000 ) Kbit/s`
  - `factor` = `storm_safety_factor` (default `4`) — headroom over the peak.
  - `floor` = `storm_floor_kbps` (default `10000`) — never recommend below this.
  - The `0.8 × 1 GbE` cap keeps a recommendation from exceeding 80% of the link.

Tune the knobs if needed (INI keys `storm_safety_factor` / `storm_floor_kbps`, or
env `NETCHECK_STORM_SAFETY_FACTOR` / `NETCHECK_STORM_FLOOR_KBPS`).

Guidance:

- **30 s** is fine for a first look, but small.
- **300 s or more, during the busiest period**, gives a representative number.
- The tool samples once and applies the first switch's measured threshold as the
  recommendation shown for all switches (a known simplification). If you want a
  per-switch number, harden the switches one at a time and read each
  recommendation.
- `--no-measure` skips sampling and falls back to the static baseline
  (`20 000 Kbit/s` on access ports, see §5.3). Use it when SNMP is unavailable.

Record the recommended threshold per switch in the worksheet (Appendix A).

### 2.3 Pre/post-hardening comparison

1. Baseline: save a `--log` run from §2.1 **before** changing switch settings.
2. Apply the hardening configuration (§5), one switch at a time.
3. Re-run `python3 netcheck.py --log` after each switch and after the last one.
4. Diff the logs. Expected outcome: check 9 stops reporting findings for the
   switches you fixed, checks 1–8 stay `[PASS]`, and no new `[WARN]`/`[FAIL]`
   appears elsewhere. A transient extra `[WARN]` right after a change is usually
   a re-converging link; re-run to confirm.

---

## 3. Management-laptop prerequisites

### 3.1 Platform

| OS | Runs? | Notes |
|---|---|---|
| Windows 10/11 | Yes | Admin + Npcap for the scapy DHCP probe; ANSI auto-off when not a TTY |
| Linux | Yes | raw sockets need root or `setcap cap_net_raw+ep` |
| macOS | Yes | same elevation need; uses `scutil --dns` / `netstat -rn` |
| Python < 3.10 | No | the script's PEP 723 header declares the floor |

Requires **Python 3.10+ (3.12+ recommended)**. `uv` is optional and needs no
pre-installed Python.

### 3.2 Position on the network

- Plug the laptop into the office LAN behind `dlink1`–`dlink5`, in the same
  Layer-2 broadcast domain as the switches and the router.
- The laptop must get a normal DHCP lease on `192.168.1.0/24` (gateway
  `192.168.1.1`). This is what checks 1–4 test.

### 3.3 Reachability to the switch management subnet

The switches live on `10.90.90.0/8`. Add a **secondary IPv4 address** in that
range to the laptop NIC so `10.90.90.90`–`10.90.90.94` answer:

```bash
# Linux (replace eth0 with your interface)
sudo ip addr add 10.90.90.100/8 dev eth0

# macOS (replace en0)
sudo ifconfig en0 alias 10.90.90.100 255.0.0.0
```

```powershell
# Windows PowerShell (run as Administrator) — replace "Ethernet"
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 10.90.90.100 -PrefixLength 8
```

Verify with a ping to one switch management IP before running the tool.

### 3.4 Privileges and optional tools

| Capability | Needed for | How |
|---|---|---|
| Raw sockets / admin | Rogue-DHCP probe (check 6) | Administrator (Windows) or root / `sudo` (Linux/macOS) |
| `scapy` | Preferred rogue-DHCP probe | `pip install scapy`, or `uv run --with scapy netcheck.py` |
| `pysnmp` | SNMP v3 only | Optional; the built-in client speaks v1/v2c |

On Linux/macOS, if you cannot run as root, grant the interpreter raw-socket
capability: `sudo setcap cap_net_raw+ep $(command -v python3)`.

Without raw-socket rights (or without `scapy`), check 6 reports `WARN: not tested`
with the exact reason — the rest of the tool still works.

### 3.5 Firewall

Allow outbound **UDP 161** (SNMP) and **ICMP** (ping) from the laptop. On
Windows, the first `ping`/scapy run may prompt for a firewall exception.

### 3.6 Configuration file and environment variables

Copy the template and edit it (the real `netcheck.ini` is gitignored; never
commit secrets):

```bash
cp netcheck.ini.example netcheck.ini
```

The tool reads `./netcheck.ini` by default; `--config PATH` selects another file.
If no file exists, built-in defaults are used. Precedence is
**CLI/env > INI file > built-in defaults**.

`netcheck.ini` keys (section `[netcheck]`):

| Key | Default | Meaning |
|---|---|---|
| `gateway` | `192.168.1.1` | Default gateway (check 2), also the trusted DHCP server |
| `dns` | `58.71.2.8,45.63.30.117` | ISP DNS servers (check 4) |
| `domain` | `example.com` | Test domain for DNS resolution |
| `snmp_community` | *(empty)* | Read-only SNMP v2c community; empty disables the switch audit |
| `snmp_version` | `2c` | `1` or `2c` |
| `switch_user` | `admin` | Unused; retained for config compatibility |
| `switch_pass` | *(empty)* | Unused; retained for config compatibility |
| `storm_safety_factor` | `4` | Multiplier over measured peak |
| `storm_floor_kbps` | `10000` | Lower bound for the recommendation |
| `switches` | `dlink1=10.90.90.90,...` | `name=ip` list, comma-separated |

Equivalent environment variables (override the file):
`NETCHECK_GATEWAY`, `NETCHECK_DNS`, `NETCHECK_DOMAIN`,
`NETCHECK_SNMP_COMMUNITY`, `NETCHECK_SNMP_VERSION`, `NETCHECK_SWITCH_USER`,
`NETCHECK_SWITCH_PASS`, `NETCHECK_SWITCHES`, `NETCHECK_STORM_SAFETY_FACTOR`,
`NETCHECK_STORM_FLOOR_KBPS`.

Secrets are never printed and never written to the report.

---

## 4. Switch prerequisites (one-time, web UI)

Do this once per switch. Log in at `http://<mgmt-ip>/` (default `admin`/`admin`).

### 4.1 Set a unique management IP

`System > System Settings > IP Information`. Set **Static** mode:

| Switch | IP Address | NetMask |
|---|---|---|
| dlink1 | `10.90.90.90` | `255.0.0.0` |
| dlink2 | `10.90.90.91` | `255.0.0.0` |
| dlink3 | `10.90.90.92` | `255.0.0.0` |
| dlink4 | `10.90.90.93` | `255.0.0.0` |
| dlink5 | `10.90.90.94` | `255.0.0.0` |

Factory default is `10.90.90.90 / 255.0.0.0`. Give each switch a distinct IP
**before** cabling them together, or change them one at a time while directly
connected.

### 4.2 Change the default password

`System > Password`. Replace `admin`/`admin`. The tool prints a prominent `WARN`
if the default is still in use.

### 4.3 Enable SNMP (read-only)

SNMP is **disabled by default**, and the tool needs it to read switch state for
the hardening audit (check 9) and the device inventory (check 7). Configure each
switch as follows, then repeat steps 2–3 on all five using the **same** community
string.

1. **Enable SNMP globally.** `SNMP > SNMP > SNMP Global Settings` → select
   **Enable** → **Apply**. (The Smart Wizard's "SNMP" step toggles the same global
   state. Leave traps off — the tool does not receive traps.)
2. **Create a read-only community.** `SNMP > SNMP > SNMP Community` → **Add**:
   - **Community Name**: a non-default string, e.g. `netcheck-ro`. This must match
     `snmp_community`.
   - **Access / permission**: **Read Only** (the manual labels this column
     "User Name (View Policy)"). Never grant Read Write.
   - Click **Add** / **Apply**.
3. **Grant MIB access (only if your firmware restricts views).**
   `SNMP > SNMP > SNMP View` → add a view that **Includes** subtree `1.3.6.1`.
   That subtree covers both the standard MIBs the tool walks (`1.3.6.1.2.1…`)
   and the D-Link private MIBs (`1.3.6.1.4.1.171…`). Make sure the community's
   group can read it. Most default firmwares need no change here.
4. **Traps are not needed.** `SNMP > SNMP > SNMP Host` is for trap recipients;
   leave it empty — the tool polls, it does not listen for traps.
5. **Point the tool at it.** Set `snmp_community = netcheck-ro` in
   `netcheck.ini`, or export `NETCHECK_SNMP_COMMUNITY=netcheck-ro`.
6. **Verify.** Run `python3 netcheck.py --no-fix`; check 9 must stop saying
   `SNMP community not set` / `SNMP unavailable`. With net-snmp installed you can
   also probe directly:

   ```bash
   snmpget -v2c -c netcheck-ro 10.90.90.90 1.3.6.1.2.1.1.1.0
   ```

Notes:

- **SNMP v3:** the built-in client speaks only SNMP v1/v2c. If policy requires
  v3, install `pysnmp` (`uv run --with pysnmp netcheck.py`) and configure
  `SNMP User` / `SNMP Group Table` / `SNMP View` accordingly; otherwise stay on
  read-only v2c.
- **What the tool reads:** interface counters, the bridge/Q-BRIDGE forwarding
  tables, and D-Link private objects under `1.3.6.1.4.1.171…` — the read-only
  view above covers all of them.
- **Security:** use a read-only community distinct from the admin password and
  never reuse a guessable default. Secrets live only in env/INI (§12).
- **Reachability:** allow UDP 161 from the management laptop, which must carry
  the `10.90.90.0/8` alias from §3.3.

### 4.4 Telnet has no runtime use

The DGS-1210 Telnet CLI exists on this firmware, but the tool does **not** use
it at runtime. In particular, the device inventory (check 7) has **no Telnet
fallback**: if the SNMP FDB walk returns nothing, the switch's rows are simply
empty. SNMP (§4.3) is the only way the tool reads switch state.

Telnet cannot configure LBD/STP/Storm/DHCP-screening, which is why all
remediation is in the web UI.

### 4.5 Save

`Save > Save Configuration` after every change. Unsaved changes are lost on
reboot.

---

## 5. Switch hardening configuration (web UI)

All settings below are applied by hand in the web UI and verified read-only by
the tool's check 9. Apply them to **all five switches** unless a row says
otherwise. Do a **staged rollout**: configure dlink2–dlink5 first, then dlink1,
or one switch at a time, re-running the tool after each to confirm checks stay
green.

> **Brief disruption is expected** when enabling STP or shutting a looped port.
> Schedule changes for a quiet period.

### 5.1 Loopback Detection — `L2 Functions > Loopback Detection`

| Field | Value |
|---|---|
| Loopback Detection | **Enabled** |
| Mode | **Port-based** |
| Interval | **2** seconds |
| Recover Time | **0** (port stays down until you physically fix the loop) |
| State on access ports (1–22) | **Enabled** |
| State on uplink/cascade ports (23–27) | **Disabled** |

Use **From Port / To Port** to set `1`–`22`, **State = Enabled**, then **Apply**;
repeat with the uplink/cascade ports set to **Disabled**.

**Why:** catches edge loops STP cannot see — both ends of a cable into two wall
ports, or a looped unmanaged switch/hub — and shuts the offending port.
`Recover Time = 0` matters: `60` would flap the port back into the loop every
minute.

A port reporting **loop state** is direct evidence of a live loop. The tool shows
this as `[FAIL] 9. Hardening audit … loop port N`.

### 5.2 Spanning Tree — `L2 Functions > Spanning Tree`

**Global Settings:**

| Field | dlink1 | dlink2–dlink5 |
|---|---|---|
| STP Version | **RSTP** | **RSTP** |
| Bridge Priority | **4096** | **32768** |

Global STP must be **Enabled**. Forcing dlink1 to priority `4096` makes it the
root; otherwise the switch with the lowest MAC wins and a downstream switch can
become root.

**Port Settings** (`STP Port Settings`, set per port range):

| Port type | Edge | P2P | Migrate | Restricted Role | Restricted TCN |
|---|---|---|---|---|---|
| Access (1–22) | **True** | **Auto** | No | **True** | **True** |
| Uplink / cascade (23–27) | **False** | **True** | **Yes** | False | False |

**Why:** a safety net for loops between managed switches and fast link-failure
recovery. In this tree it is mostly dormant — Loopback Detection and Storm
Control are the features that actually matter here.

### 5.3 Storm Control — `Security > Storm Control`

| Field | Access ports (1–22) | Uplink / cascade (23–27) |
|---|---|---|
| State | **Enabled** | **Disabled**, or a high backstop (~`500000` Kbit/s) |
| Storm Control Type | **Multicast & Broadcast & Unknown Unicast** | same |
| Threshold (Kbit/s) | **the baseline-measured value** (§2.2); static fallback `20000` | `500000` backstop if enabled |

Threshold is in Kbit/s in steps of 64 (range 64–1,024,000). Enter the value you
measured, rounded to a multiple of 64.

**Why:** caps the blast radius of a storm so one bad port cannot saturate the
uplink and take down the office. It is mitigation, not root-cause repair — pair
it with Loopback Detection. Never set an aggressive threshold on the uplink: a
legitimate burst above the cap would be dropped.

### 5.4 Safeguard Engine — `Security > Safeguard Engine`

**Enabled** (this is the factory default; the tool warns if it has been turned
off). It throttles CPU-bound packet floods.

### 5.5 DHCP Server Screening — `Security > DHCP Server Screening`

1. Select the **access ports (1–22)** → **Apply** (enable screening on them).
2. **Trusted DHCP Server IP Settings**: select **IPv4**, enter `192.168.1.1`,
   **Add** / **Apply**.

**Do NOT screen** the uplink (port 23) or the inter-switch ports (24–27), or the
ISP router's DHCP replies get dropped.

**Why:** prevents a rogue DHCP server on an access port from handing out leases.
The tool's check 6 detects rogues; screening stops the next one.

### 5.6 DoS Prevention — `Security > DoS Prevention Settings`

**Enabled** (recommended; optional). Blocks hardware-matched DoS attack
patterns.

### 5.7 Optional extras

- **ARP Spoofing Prevention** (`Security > ARP Spoofing Prevention`): add a
  static rule mapping `192.168.1.1` to the router's MAC address.
- **Port Security**: **not recommended** here — it breaks normal device moves in
  an office.

### 5.8 Apply order and save

1. Configure access-port settings first (LBD, Storm Control, DHCP Screening),
   then STP.
2. **Save > Save Configuration** on each switch.
3. Re-run the tool: `python3 netcheck.py --log`. Check 9 should drop the
   findings for the switches you fixed.

---

## 6. Get the tool and first run

### 6.1 Clone and run (quickstart)

The fastest path — see [§0](#0-quickstart). Three commands, no extra
installation beyond `uv`:

```bash
git clone https://github.com/CountElqyd/netcheck.git
cd netcheck
uv run netcheck.py --no-fix
```

### 6.2 Download-and-run from a GitHub Release

Use this when you want a single pinned file without cloning. The links below
resolve **after the first tagged release** (`v0.1.0` or later).

```bash
# Linux / macOS
curl -sSLO https://github.com/CountElqyd/netcheck/releases/latest/download/netcheck.py
curl -sSLO https://github.com/CountElqyd/netcheck/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
python3 netcheck.py
```

```powershell
# Windows PowerShell
iwr -useb https://github.com/CountElqyd/netcheck/releases/latest/download/netcheck.py -OutFile netcheck.py
Get-FileHash netcheck.py -Algorithm SHA256   # compare with the published SHA256SUMS
py netcheck.py
```

### 6.3 Optional: `uv` (no pre-installed Python)

`uv run` works from either the cloned directory or alongside a downloaded
`netcheck.py`:

```bash
uv run netcheck.py                       # uv fetches a suitable Python
uv run --with scapy netcheck.py          # + rogue-DHCP probe
uv run --with pysnmp netcheck.py         # + SNMP v3
```

### 6.4 First run

```bash
cp netcheck.ini.example netcheck.ini     # then set snmp_community etc.
python3 netcheck.py                      # or: uv run netcheck.py
```

Expect one `[PASS]`/`[WARN]`/`[FAIL]` line per check. Use `--log` to keep a
timestamped report alongside the console output.

---

## 7. Interpreting output

Each check prints a status line, then optional `Likely cause:` / `Suggested fix:`
lines. **Exit codes:** `0` = clean, `1` = at least one `WARN`, `2` = at least one
`FAIL` (highest wins). When run interactively, the tool then offers optional
fixes (§10).

### 7.1 Check catalog

| # | Check | What it does | PASS / WARN / FAIL |
|---|---|---|---|
| 1 | Local config | Reads IP, mask, gateway, DNS | FAIL: no IP, APIPA (`169.254.x.x`), or gateway ≠ `192.168.1.1`. WARN: no DNS servers |
| 2 | Gateway | Pings `192.168.1.1` (10 packets) | FAIL: 100% loss. WARN: >20% loss or jitter >30 ms. FAIL skips 3–4 |
| 3 | Internet by IP | Pings `1.1.1.1` and `8.8.8.8` | PASS: both. WARN: one. FAIL: neither |
| 4 | DNS | Resolves the test domain on ISP DNS and public DNS | FAIL: public works but ISP fails (**ISP DNS problem**). WARN: ISP works, public fails. FAIL: none |
| 5 | Switches | Pings all five management IPs | PASS: all answer. WARN: any down (with cascade-port hint) |
| 6 | Rogue DHCP | scapy broadcast discover (5 s); states whether it ran and the reason if not | PASS: only the trusted gateway. WARN: probe unavailable (reason) or no server answered. FAIL: any other responder |
| 7 | Device inventory | SNMP FDB walk (Q-BRIDGE, BRIDGE fallback) on every switch; lists all MACs with physical port, grouped by switch, always in full | PASS: no rogue responder present. FAIL: a listed MAC is a confirmed rogue-DHCP responder. WARN: SNMP not configured or no switch returned an FDB |
| 8 | Loop/storm hints | LBD loop ports + gateway loss/jitter | FAIL: a port is in loop state. WARN: loss >5% or jitter >30 ms. PASS: quiet |
| 9 | Hardening audit | Read-only per-switch audit vs §5 baseline | PASS: all switches meet baseline. FAIL: a port in loop state. WARN: findings or SNMP unavailable |
| 99 | Fixes applied | Present only if you accepted a fix | — |
| 98 | Internal error | Present on an unexpected exception | WARN; re-run with `--verbose` |

**Emission order:** checks 1–4 (short-circuit on a `FAIL`), then 5, 6, 9, 8, 7.
Check 7 always prints the full per-switch device table. Rows for MACs confirmed as
non-gateway DHCP responders (check 6) are marked `ROGUE`.

### 7.2 Status meanings

- `PASS` — expected and healthy.
- `WARN` — degraded, unusual, or **could not be determined** (missing rights, no
  SNMP). Not necessarily broken.
- `FAIL` — definitively broken.

### 7.3 Sample output

```
[PASS]  1. Local config   - 192.168.1.50 gw 192.168.1.1 dns 58.71.2.8,45.63.30.117
[FAIL]  6. Rogue DHCP     - via scapy: 192.168.1.77 (aa:bb:cc:dd:ee:ff, TP-Link)
    Likely cause: A non-gateway DHCP server is handing out leases.
    Suggested fix: Find the responder in the device inventory (check 7) and unplug
                   it; enable DHCP Server Screening (Security) with 192.168.1.1
                   trusted.
[FAIL]  7. Device inventory - 139 devices; rogue on dlink1 port 5
    dlink1  port  5   AA:BB:CC:DD:EE:FF  TP-Link  ROGUE
    dlink1  port 12   00:1E:58:11:22:33  D-Link
    dlink2  port  3   3C:07:54:9A:BC:DE  Apple
[WARN]  9. Hardening audit - dlink1: Loopback Detection: disabled (recommended: enabled, recover time 0)
    Likely cause: -
    Suggested fix: Apply the baseline in USAGE.md.

Summary: 1 PASS · 1 WARN · 2 FAIL  (exit code 2)
Legend:  PASS healthy  ·  WARN needs attention  ·  FAIL broken — fix FAILs first
```

Each result's cause/fix block prints only when at least one is set; a missing
line shows `-`.

---

## 8. Scenario playbooks

**No internet, gateway fails (check 2 FAIL).** The local or uplink path is the
problem; checks 3–4 are skipped because they cannot succeed. Verify the laptop's
cable/switch port, then the router's link. The router itself is out of scope.

**Gateway passes, internet by IP fails (check 3 FAIL).** The LAN is fine; the
upstream/ISP is the problem. You cannot fix this from the switches.

**Internet by IP passes, DNS fails (check 4).** If public DNS works but ISP DNS
fails, it is an **ISP DNS problem** — switch the PC to `1.1.1.1`/`8.8.8.8`. The
tool's DNS "fix" only **requests** this change; apply it in your OS network
settings (see §10).

**Rogue DHCP (check 6 FAIL).** The report lists each rogue server's IP, MAC, and
vendor. Check 7 lists the device table and marks the rogue MAC's switch and port.
Unplug that device, then confirm DHCP Server Screening is enabled with
`192.168.1.1` trusted (§5.5).

**Loop or storm (check 8 FAIL, or check 9 loop port).** A port is in loop state.
Trace it to the switch/port, unplug the cable (or the looped unmanaged switch),
then re-check hardening. Check 8 also warns on gateway loss >5% or jitter
>30 ms — corroborate with the LBD loop status and error/broadcast counters before
declaring a storm.

**A switch is unreachable (check 5 WARN).** The hint names the likely cascade
port on dlink1 (`dlink2`→24, `dlink3`→25, `dlink4`→26, `dlink5`→27). Reseat that
cable and confirm the management IP. `dlink1` unreachable points at the
management path or switch 1 itself.

**Hardening below baseline (check 9 WARN).** The detail lists every finding per
switch with the recommended value. Apply §5 to the named features, save, and
re-run.

**No devices listed (check 7 WARN).** SNMP is unconfigured or the FDB walk
returned no rows; confirm SNMP is enabled.

---

## 9. Flags

| Flag | Effect |
|---|---|
| `-h`, `--help` | Show the help message and exit |
| `--quick` | Connectivity layers only (checks 1–4); skips fabric checks and fixes |
| `--log` | Save a timestamped report (`netcheck-YYYYmmdd-HHMMSS.log`); written without ANSI color |
| `--config PATH` | Use a specific INI file (default `netcheck.ini`) |
| `--no-fix` | Never prompt for fixes (also automatic when not a TTY) |
| `--sample SECONDS` | Counter-sampling window for the storm-threshold recommendation (default `30`; must be `> 0`) |
| `--no-measure` | Skip rate sampling; use the static storm baseline |
| `--timeout N` | Per-network-operation timeout in seconds (default `3`; must be `> 0`) |
| `--verbose` | Show full tracebacks and raw errors on internal failures |
| `--no-color` | Disable ANSI color (also auto-off when not a TTY) |
| `--version` | Print the tool version and exit |

---

## 10. Optional fixes

After a non-`--quick` run, when run interactively (a TTY), the tool offers three
per-action `y/N` prompts. Skip all with `--no-fix`. Prompts are auto-skipped when
input is piped, so scripted runs never hang.

| Fix | Applies locally? | What it runs |
|---|---|---|
| Flush the DNS cache | **Yes** | Windows `ipconfig /flushdns`; macOS `dscacheutil -flushcache` + `killall -HUP mDNSResponder`; Linux `resolvectl flush-caches` |
| Renew the DHCP lease | **Yes** | Windows `ipconfig /renew`; macOS `ipconfig set en0 DHCP`; Linux `dhclient -r` then `dhclient` |
| Set this PC's DNS to `1.1.1.1`/`8.8.8.8` | **No** | The tool only *requests/records* this change; it does **not** modify the OS. Apply it yourself in your network settings. |

The tool never changes the router or any switch.

---

## 11. Troubleshooting the tool

- **Check 9 says "SNMP community not set".** `snmp_community` is empty. Set it in
  `netcheck.ini` or `NETCHECK_SNMP_COMMUNITY`.
- **Check 9 shows "SNMP unavailable" for a switch.** SNMP is disabled on that
  switch, the community is wrong/non-matching, a view blocks the MIBs, the
  management subnet is unreachable, or the host firewall blocks UDP 161. See
  [§4.3](#43-enable-snmp-read-only) for the full setup and verification.
- **Check 6 WARN "not tested: ...".** The detail names the reason (`scapy not
  installed`, `raw sockets denied`, ...). Install `scapy`
  (`uv run --with scapy netcheck.py`) and run as root/administrator, or accept
  the WARN.
- **Check 7 shows a switch with no rows.** The FDB walk returned nothing on that
  firmware; confirm SNMP visibility. The inventory has no Telnet fallback.
- **Colors look wrong / garbled.** Use `--no-color` (auto-off when not a TTY).
- **Need more detail on an internal error.** Re-run with `--verbose`.

---

## 12. Security notes

- The tool is **read-only**: no SNMP SET, no CLI `config`/`save`, no router
  changes.
- SNMP community and switch credentials come only from env/INI; they are never
  hardcoded, echoed, or written to logs/reports.
- The real `netcheck.ini` is gitignored — never commit secrets.
- Capture files used as parser fixtures must be scrubbed of secrets before
  commit.

---

## Appendix A — Configuration worksheet

### Baseline measurements

| Switch | Baseline log file | Measured peak (Kbit/s) | Recommended threshold |
|---|---|---|---|
| dlink1 | | | |
| dlink2 | | | |
| dlink3 | | | |
| dlink4 | | | |
| dlink5 | | | |

### Hardening settings applied

| Feature | dlink1 | dlink2 | dlink3 | dlink4 | dlink5 |
|---|---|---|---|---|---|
| LBD enabled (access 1–22) | | | | | |
| LBD off (23–27) | | | | | |
| LBD interval / recover | 2 / 0 | 2 / 0 | 2 / 0 | 2 / 0 | 2 / 0 |
| STP version / priority | RSTP / 4096 | RSTP / 32768 | RSTP / 32768 | RSTP / 32768 | RSTP / 32768 |
| Storm Control threshold | | | | | |
| Safeguard enabled | | | | | |
| DHCP screening (access) | | | | | |
| DoS Prevention | | | | | |

### Post-hardening verification

| Switch | Re-run log file | Check 9 status | Notes |
|---|---|---|---|
| dlink1 | | | |
| dlink2 | | | |
| dlink3 | | | |
| dlink4 | | | |
| dlink5 | | | |

---

## Appendix B — Web-UI menu quick reference

| Task | Menu path |
|---|---|
| Set management IP | `System > System Settings > IP Information` |
| Change password | `System > Password` |
| Save config | `Save > Save Configuration` |
| Enable SNMP | `SNMP > SNMP > SNMP Global Settings` |
| Create SNMP community | `SNMP > SNMP > SNMP Community` |
| SNMP view (if required) | `SNMP > SNMP > SNMP View` |
| Loopback Detection | `L2 Functions > Loopback Detection` |
| STP global (version/priority) | `L2 Functions > Spanning Tree > STP Global Settings` |
| STP per-port (Edge/P2P/etc.) | `L2 Functions > Spanning Tree > STP Port Settings` |
| Safeguard Engine | `Security > Safeguard Engine` |
| Storm Control | `Security > Storm Control` |
| DHCP Server Screening | `Security > DHCP Server Screening` |
| DoS Prevention | `Security > DoS Prevention Settings` |
| ARP Spoofing Prevention (optional) | `Security > ARP Spoofing Prevention` |
