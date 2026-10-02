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
uv run netcheck.py
```

That is install (once) → clone → enter → run. If you already have **Python
3.10+**, the last command can instead be `python3 netcheck.py`.

**Enable the rogue-DHCP probe (check 6) and SNMP extras:**

```bash
uv run --with scapy netcheck.py   # + rogue-DHCP broadcast probe (needs admin/root)
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
>
> If `10.90.90.100/24` is not on the wired NIC, netcheck prints the exact
> command to add it and **stops before the switch checks**. Add the address,
> then run netcheck again.

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
10. [Read-only guarantee](#10-read-only-guarantee)
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
> Without it, check 8 cannot list devices and the opt-in storm measurement has
> nothing to read.

### 2.1 Capture a connectivity baseline

On a normal working day (and again at a busy time if the office has one):

```bash
python3 netcheck.py --log          # full run, writes netcheck-<timestamp>.log
python3 netcheck.py --quick --log  # connectivity layers only (checks 1-4)
```

Keep the logs. A healthy baseline should show `[PASS]` on checks 1–5, `[PASS]`
on 6 (only the gateway answers DHCP), and `[PASS]` on 7 (loop/storm). The device
inventory (check 8), hardening audit (check 9), and storm measurement (check 10)
are **opt-in** and run alone — `--inventory`, `--hardening`, and `--sample`,
respectively (§2.2, §9).

### 2.2 Measure the storm-control rates (opt-in)

Storm sampling is **off by default**. Enable it with `--sample SECONDS`; the tool
then prints a per-switch recommendation (check 10) instead of guessing. The
measurement is read-only: it polls each switch's broadcast and multicast counters
twice, `--sample` seconds apart, in parallel across switches.

```bash
python3 netcheck.py --sample 30      # quick sample
python3 netcheck.py --sample 300     # 5-minute sample, use during peak hours
```

How the recommendation is computed (so you can sanity-check it):

- Counters read: `ifHCInBroadcastPkts` and `ifHCInMulticastPkts` per port.
- `peak_kbps = max rate × 512 / 1000` — 512 bits assumes a conservative 64-byte
  frame, which suits broadcast/multicast.
- Recommended threshold per port:
  `clamp( ceil_to_64(peak_kbps × factor), ceil_to_64(floor), 0.8 × 1,000,000 ) Kbit/s`
  - `factor` = `storm_safety_factor` (default `4`) — headroom over the peak.
  - `floor` = `storm_floor_kbps` (default `10000`) — never recommend below this.
  - The `0.8 × 1 GbE` cap keeps a recommendation from exceeding 80% of the link.
  - The result is always a multiple of 64 Kbit/s, so the web-UI step count is
    simply `N = result / 64` (§5.3).

Tune the knobs if needed (INI keys `storm_safety_factor` / `storm_floor_kbps`, or
env `NETCHECK_STORM_SAFETY_FACTOR` / `NETCHECK_STORM_FLOOR_KBPS`).

Guidance:

- **30 s** is fine for a first look, but small.
- **300 s or more, during the busiest period**, gives a representative number.
- The tool samples every switch and reports a **per-switch** recommendation.
- Convert the recommendation to the web-UI field: it is `64Kbps × N`, so
  **`N = round(recommended Kbit/s / 64)`** (`N` = 1–16000). See §5.3.
- With `--hardening`, `--sample` also feeds the audit; without it, the audit
  compares against the static fallback **N = 313** (20,032 Kbit/s) — see §5.3.

Record the recommended threshold per switch in the worksheet (Appendix A).

### 2.3 Pre/post-hardening comparison

1. Baseline: save a `--log` run from §2.1 **before** changing switch settings.
2. Apply the hardening configuration (§5), one switch at a time.
3. Re-run `python3 netcheck.py --log` (checks 1–7) and
   `python3 netcheck.py --hardening --log` (check 9) after each switch.
4. Diff the logs. Expected outcome: check 9 stops reporting findings for the
   switches you fixed, checks 1–7 stay `[PASS]`, and no new `[WARN]`/`[FAIL]`
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

The switches live on `10.90.90.0/8`. netcheck auto-detects the wired NIC — the
one holding `192.168.1.x` or `10.90.90.x` — and pins checks 5–9 to it. Wi-Fi can
stay connected and keeps the default route; force a specific NIC with
`lan_interface` in `netcheck.ini`.

Before checks 5–9, if that NIC has no `10.90.90.x` address, netcheck prints the
exact command to add `10.90.90.100/24` as a secondary address and **stops before
the switch checks**. Add the address, then run netcheck again.
`--remove-mgmt-ip` removes a leftover transient address and exits.

To add it manually instead, on Linux run `sudo ip addr add 10.90.90.100/24 dev
eth0` (replace `eth0`; macOS: `sudo ifconfig en0 alias 10.90.90.100
255.255.255.0`).

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
| `uplink_ports` | `23-27` | Ports facing another switch or the router; check 8 hides FDB entries learned here. Global ranges plus per-switch overrides — an override **replaces** the global for that switch. Spoke example: `23-27,dlink2:24,dlink3:25,dlink4:25,dlink5:25` |

For the spoke layout in this guide, set the uplinks explicitly so each
downstream switch hides only its own inter-switch port:

```ini
uplink_ports = 23-27,dlink2:24,dlink3:25,dlink4:25,dlink5:25
```

The global `23-27` is dlink1 (its cascade ports 24–27 plus the ISP uplink on
23); each override replaces that for dlink2–dlink5, which each have a single
uplink port.
| `switches` | `dlink1=10.90.90.90,...` | `name=ip` list, comma-separated |

Equivalent environment variables (override the file):
`NETCHECK_GATEWAY`, `NETCHECK_DNS`, `NETCHECK_DOMAIN`,
`NETCHECK_SNMP_COMMUNITY`, `NETCHECK_SNMP_VERSION`, `NETCHECK_SWITCH_USER`,
`NETCHECK_SWITCH_PASS`, `NETCHECK_SWITCHES`, `NETCHECK_STORM_SAFETY_FACTOR`,
`NETCHECK_STORM_FLOOR_KBPS`, `NETCHECK_UPLINK_PORTS`.

Secrets are never printed and never written to the report.

If `netcheck.ini` is missing, netcheck warns on stderr and runs with the built-in
defaults (copy `netcheck.ini.example` to `netcheck.ini` and fill it in). Check 1's
`dns` line shows the wired NIC's own DNS when the platform exposes it
(`resolvectl dns <iface>` / `nmcli` on Linux); otherwise it falls back to the host
resolver list with Wi-Fi-only servers filtered out. Check 4 always tests the `dns`
list from this config.

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
the device inventory (check 8), the opt-in hardening audit (check 9), and the
opt-in storm measurement (check 10). Configure each switch as follows, then
repeat steps 2–3 on all five using the **same** community string.

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
6. **Verify.** Run `python3 netcheck.py --inventory`; check 8 must list devices.
   With net-snmp installed you can also probe directly:

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
- **If check 9 (with `--hardening`) reports "hardening MIB not exposed by this
  firmware."** The switch answered SNMP but returned `noSuchObject` for the
  hardening objects (this tool reads them with their scalar `.0` instance). That
  happens when the community's view excludes `1.3.6.1.4.1.171` (fix: step 3
  above) or when the firmware does not implement those objects. The audit then
  reports the features as **unauditable** rather than guessing. Verify a single
  object directly:
  `snmpget -v2c -c netcheck-ro 10.90.90.90 1.3.6.1.4.1.171.10.76.20.1.1.8.0`
  (Safeguard Engine state; returns an integer, not `noSuchObject`).
- **Security:** use a read-only community distinct from the admin password and
  never reuse a guessable default. Secrets live only in env/INI (§12).
- **Reachability:** allow UDP 161 from the management laptop, which must carry
  the `10.90.90.0/8` alias from §3.3.

### 4.4 Telnet has no runtime use

The DGS-1210 Telnet CLI exists on this firmware, but the tool does **not** use
it at runtime. In particular, the device inventory (check 8) has **no Telnet
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
the tool's opt-in check 9 (`--hardening`). Apply them to **all five switches**
unless a row says otherwise. Do a **staged rollout**: configure dlink2–dlink5
first, then dlink1, or one switch at a time, re-running the tool after each to
confirm checks stay green.

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

> **LBD and STP are mutually exclusive on the same port** on this switch — the
> manual describes LBD as detecting loops "while Spanning Tree Protocol (STP) is
> not enabled in the network" (`DGS-1210-28_REVC_MANUAL_4.00_EN.md` ch. 4,
> *Jumbo Frame / Loopback Detection*). This baseline **prioritizes LBD on the
> access ports**, so in §5.2 keep STP **port State = Disabled on 1–22** and
> enable STP only on the uplink/cascade ports (23–27). Global RSTP stays enabled
> so the inter-switch tree is still protected.

**Why:** catches edge loops STP cannot see — both ends of a cable into two wall
ports, or a looped unmanaged switch/hub — and shuts the offending port.
`Recover Time = 0` matters: `60` would flap the port back into the loop every
minute.

A port reporting **loop state** is direct evidence of a live loop. The tool
**cannot read loop state on this firmware** — the DGS-1210 exposes LBD's global
enable/recover time and a per-port *mode* (access/uplink), but no pollable
per-port loop status, so the audit reports LBD configuration only and relies on
check 7's gateway loss/jitter heuristics to flag a live storm. Check the LBD
table in the web UI (`L2 Functions > Loopback Detection`) for loop state.

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

| Port type | State | Edge | P2P | Migrate | Restricted Role | Restricted TCN |
|---|---|---|---|---|---|---|
| Access (1–22) | **Disabled** | — | — | — | — | — |
| Uplink / cascade (23–27) | **Enabled** | **False** | **True** | **Yes** | False | False |

Access ports are left with **STP port State = Disabled** because LBD and STP are
mutually exclusive on the same port and this baseline gives the access ports to
LBD (§5.1). Global RSTP still runs, so the cascade links are protected.

> **Exception:** if an access port connects to another **managed** switch or a
> segment that needs STP, enable STP on that single port and leave LBD off
> there instead.

**Why:** a safety net for loops between managed switches and fast link-failure
recovery. In this tree it is mostly dormant — Loopback Detection and Storm
Control are the features that actually matter here.

### 5.3 Storm Control — `Security > Storm Control`

| Field | Access ports (1–22) | Uplink / cascade (23–27) |
|---|---|---|
| State | **Enabled** | **Disabled**, or a high backstop |
| Storm Control Type | **Multicast & Broadcast & Unknown Unicast** | same |
| Threshold | **N from §2.2** = `round(recommended Kbit/s / 64)` | high backstop if enabled |

The web field is `Threshold (64Kbps × N)`: **N = 1–16000**, so the real threshold
is `64 × N` Kbit/s (max 1,024,000) and must be a multiple of 64 Kbit/s
(`DGS-1210-28_REVC_MANUAL_4.00_EN.md`, *Security > Storm Control*).

- Static fallback when you don't measure: **N = 313** (20,032 Kbit/s ≈ 20 Mbit/s).
- The tool's floor (`storm_floor_kbps = 10000`) maps to **N = 157** (10,048 Kbit/s).
- Enter the value measured in §2.2, rounded to a multiple of 64 → N.
- Uplink backstop, if you enable one: ~`N = 7813` (≈500,000 Kbit/s).

**Why:** caps the blast radius of a storm so one bad port cannot saturate the
uplink and take down the office. It is mitigation, not root-cause repair — pair
it with Loopback Detection. Never set an aggressive threshold on the uplink: a
legitimate burst above the cap would be dropped.

### 5.4 Safeguard Engine — `Security > Safeguard Engine`

**Enabled** (this is the factory default; the tool warns if it has been turned
off). It throttles CPU-bound packet floods.

### 5.5 DHCP Server Screening — `Security > DHCP Server Screening`

On the DGS-1210 this page is **`DHCP Trusted Port Settings`**: a **checked** port
is **trusted** (DHCP-server replies are allowed); the ports you leave
**unchecked** are the ones screening blocks. There is no global on/off — the
per-port checkboxes are the whole control. Screening is **ingress**: it drops
DHCP-server messages that enter on an untrusted port.

1. Check the **server-facing/uplink ports** (per switch):
   - **dlink1: 23–27** (23 = ISP router/trusted server, 24–27 = cascade)
   - **dlink2: 24**; **dlink3/4/5: 25**
2. Leave the **access ports unchecked** on every switch (dlink1: 1–22;
   dlink2: all but 24; dlink3–5: all but 25) — that is what screens rogue
   servers.
3. **Trusted DHCP Server IP Settings**: select **IPv4**, enter `192.168.1.1`,
   **Add/Apply**. Do this on **every** switch.

> **Never trust the access ports**: a rogue server there must be blocked.
> The trusted-IP list is a second layer, not a rescue for a wrongly screened
> uplink.

**Read-back (dlink1):** the trusted-server table `…14.7.3.1.2` returns
`192.168.1.1`, and the global state `…14.1.1.0` is set. **Per-port trust is not
exposed over SNMP on this firmware** — the `…14.2.1.1` table's per-port column
reads `0` for every port regardless of the web-UI checkboxes, so the tool does
**not** infer port trust and will not raise false "access port trusted" findings.
Check 9 therefore verifies only what SNMP exposes:

- `DHCP Server Screening: disabled` — the global screening state is off.
- `no trusted DHCP server IP configured` — the trusted-server list is empty.

Run `python3 netcheck.py --hardening --verbose`; check 9 prints `DHCP
screening enabled=… ; trusted servers …`. Confirm the per-port trust in the web
UI and use **check 6** (rogue DHCP) for actual rogue detection.

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
   then STP. Expect the §5.1/§5.2 port conflict: a port cannot be both
   LBD-enabled and STP-enabled, so set STP **port State = Disabled** on the
   access ports (1–22) and enable STP only on 23–27.
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
uv run netcheck.py
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

Expect one `[PASS]`/`[WARN]`/`[FAIL]` line per check, with the detail wrapped on
the following indented lines and any `Likely cause:` / `Suggested fix:` beneath.
Long output wraps to the terminal width; set `COLUMNS` to control it. Use
`--log` to keep a timestamped report, `--quiet` for just the summary line, or
`--json` to pipe a structured report into other tools.

---

## 7. Interpreting output

Each check prints a status line, then optional `Likely cause:` / `Suggested fix:`
lines. **Exit codes:** `0` = clean, `1` = at least one `WARN`, `2` = at least one
`FAIL` (highest wins). netcheck is read-only and applies no changes (§10).

### 7.1 Check catalog

| # | Check | What it does | PASS / WARN / FAIL |
|---|---|---|---|
| 1 | Local config | Reads wired NIC IP, mask, gateway, DNS | FAIL: no IP, APIPA (`169.254.x.x`), or wired NIC not on `192.168.1.0/24`. WARN: no DNS servers. A Wi-Fi-primary host whose wired NIC is on `192.168.1.0/24` stays PASS |
| 2 | Gateway | Pings `192.168.1.1` (10 packets) | FAIL: 100% loss. WARN: >20% loss or jitter >30 ms. FAIL skips 3–4 |
| 3 | Internet by IP | Pings `1.1.1.1` and `8.8.8.8` | PASS: both. WARN: one. FAIL: neither |
| 4 | DNS | Resolves the test domain on ISP DNS and public DNS | FAIL: public works but ISP fails (**ISP DNS problem**). WARN: ISP works, public fails. FAIL: none |
| 5 | Switches | Pings all five management IPs | PASS: all answer. WARN: any down (with cascade-port hint) |
| 6 | Rogue DHCP | scapy broadcast discover (real NIC MAC + broadcast reply flag, one retry, 5 s); states whether it ran and the reason if not | PASS: only the trusted gateway. WARN: probe unavailable (reason) or no server answered. FAIL: any other responder |
| 7 | Loop/storm hints | Gateway loss/jitter heuristics | WARN: loss >5% or jitter >30 ms. PASS: quiet |
| 8 | Device inventory *(opt-in, `--inventory`)* | SNMP FDB walk (Q-BRIDGE, BRIDGE fallback) on every switch; lists end devices on access ports, grouped by switch. `uplink_ports` plus auto-detected trunks are hidden; the local host's own MAC is tagged `this host` | PASS: table produced. WARN: SNMP not configured or no switch returned an FDB |
| 9 | Hardening audit *(opt-in, `--hardening`)* | Read-only per-switch audit vs §5 baseline | PASS: all switches meet baseline. WARN: findings, SNMP unavailable, or MIB not exposed |
| 10 | Storm thresholds *(opt-in, `--sample SECONDS`)* | Samples per-switch storm counters and prints the recommended `64Kbps × N` | PASS: per-switch recommendation printed. WARN: no samples collected |
| 98 | Internal error | Present on an unexpected exception | WARN; re-run with `--verbose` |

**Emission order:** the default run emits checks 1–4 (short-circuit on a `FAIL`),
then 5, 6, 7. The opt-in checks run **alone** and only when requested — 8
(`--inventory`), 9 (`--hardening`), 10 (`--sample`) — and combine in numeric order
when several are given. `--quick` (checks 1–4) applies to the default run only and
is ignored when an opt-in flag is present.

Because check 8 runs alone, it does not see check 6's rogue-DHCP result, so its
table never carries `ROGUE` marks. To localize a rogue responder, use the MAC that
check 6 prints (its IP, MAC, and vendor) and find that MAC in the check 8 table.

Check 8 prints the full per-switch device table, but shows only end devices:
FDB entries learned on `uplink_ports` (cascade/uplink ports) or on auto-detected
trunk ports (any port learning many MACs — e.g. an inter-switch link not listed in
`uplink_ports`) are hidden, as are all-zero and multicast/broadcast MACs. A MAC
seen on more than one access port is attributed to its physical access port; if it
still appears on several, the least-populated port wins. The local host's own wired
NIC is tagged `this host`. With `--verbose`, check 8 also prints each switch's raw
FDB rows and the trunk ports it classified, which makes a "N physical vs M listed"
mismatch easy to explain.

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
    Suggested fix: Find the responder's MAC in the device inventory (check 8)
                   and unplug it; enable DHCP Server Screening (Security) with
                   192.168.1.1 trusted.
[PASS]  8. Device inventory - 139 devices on 5 switches
    dlink1
        port  5   AA:BB:CC:DD:EE:FF  TP-Link
        port 12   00:1E:58:11:22:33  D-Link
    dlink2
        port  3   3C:07:54:9A:BC:DE  Apple
[WARN]  9. Hardening audit - dlink1: Loopback Detection: disabled (recommended: enabled, recover time 0)
    Likely cause: -
    Suggested fix: Apply the baseline in USAGE.md.

Summary: 2 PASS · 1 WARN · 1 FAIL  (exit code 2)
Legend:  PASS healthy  ·  WARN needs attention  ·  FAIL broken — fix FAILs first
```

(Check 9 appears only when you pass `--hardening`.) Each result's cause/fix
block prints only when at least one is set.

---

## 8. Scenario playbooks

**No internet, gateway fails (check 2 FAIL).** The local or uplink path is the
problem; checks 3–4 are skipped because they cannot succeed. Verify the laptop's
cable/switch port, then the router's link. The router itself is out of scope.

**Gateway passes, internet by IP fails (check 3 FAIL).** The LAN is fine; the
upstream/ISP is the problem. You cannot fix this from the switches.

**Internet by IP passes, DNS fails (check 4).** If public DNS works but ISP DNS
fails, it is an **ISP DNS problem** — switch the PC to `1.1.1.1`/`8.8.8.8` in
your OS network settings.

**Rogue DHCP (check 6 FAIL).** The report lists each rogue server's IP, MAC, and
vendor. Check 8 lists the device table and marks the rogue MAC's switch and port.
Unplug that device, then confirm DHCP Server Screening is enabled with
`192.168.1.1` trusted (§5.5).

**Loop or storm (check 7 WARN).** Check 7 warns on gateway loss >5% or jitter
>30 ms — corroborate with LBD loop status in the web UI (`L2 Functions > Loopback
Detection`) and with error/broadcast counters before declaring a storm. Trace the
looped port, unplug the cable (or the looped unmanaged switch), then re-check.

**A switch is unreachable (check 5 WARN).** The hint names that switch's own
uplink port(s) toward dlink1, taken from `uplink_ports`. Reseat that cable and
confirm the management IP. `dlink1` unreachable points at the management path or
switch 1 itself.

**Hardening below baseline (check 9 WARN, with `--hardening`).** The detail lists
every finding per switch with the recommended value. Apply §5 to the named
features, save, and re-run.

**No devices listed (check 8 WARN).** SNMP is unconfigured or the FDB walk
returned no rows; confirm SNMP is enabled.

---

## 9. Flags

| Flag | Effect |
|---|---|
| `-h`, `--help` | Show the help message and exit |
| `--quick` | Default run only: connectivity layers (checks 1–4); ignored when an opt-in flag is present |
| `--log` | Save a timestamped report (`netcheck-YYYYmmdd-HHMMSS.log`); written without ANSI color |
| `--config PATH` | Use a specific INI file (default `netcheck.ini`) |
| `--inventory` | Run only the opt-in device inventory (check 8) |
| `--sample SECONDS` | Run only the opt-in storm sampling and print per-switch `64Kbps × N` recommendations (check 10). Must be `> 0`; also feeds `--hardening` when both are given |
| `--hardening` | Run only the opt-in hardening audit (check 9) |
| `--timeout N` | Per-network-operation timeout in seconds (default `3`; must be `> 0`) |
| `--verbose` | Print diagnostics to stderr: a config/platform preamble, per-check markers, and a Python traceback for any error — including handled degradations (SNMP, `scapy`, storm sampling) |
| `--quiet` | Print only the one-line summary (hide per-check output) |
| `--json` | Emit a machine-readable JSON report (`summary` + `checks`) instead of the human report |
| `--no-color` | Disable ANSI color (also auto-off when not a TTY) |
| `--remove-mgmt-ip` | Remove the transient switch-management address and exit — the only write path |
| `--version` | Print the tool version and exit |

---

## 10. Read-only guarantee

netcheck never changes this machine. It runs only diagnostics: pings, DNS
queries, a read-only SNMP walk, and (with `--hardening`) read-only SNMP gets.
It does not add or remove addresses, flush caches, renew leases, or modify DNS.

The single exception is the explicit `--remove-mgmt-ip` maintenance flag, which
removes the transient `10.90.90.100/24` address if one is still present. Nothing
else writes to the system, the switches, or the router.

---

## 11. Troubleshooting the tool

- **Check 9 says "SNMP community not set".** `snmp_community` is empty. Set it in
  `netcheck.ini` or `NETCHECK_SNMP_COMMUNITY`.
- **Check 9 (with `--hardening`) shows "SNMP unavailable" for a switch.** SNMP is
  disabled on that switch, the community is wrong/non-matching, a view blocks the
  MIBs, the management subnet is unreachable, or the host firewall blocks UDP
  161. See [§4.3](#43-enable-snmp-read-only) for the full setup and verification.
- **Check 9 (with `--hardening`) says "hardening MIB not exposed by this
  firmware".** SNMP answered but returned `noSuchObject` for every hardening
  object — the community's view excludes `1.3.6.1.4.1.171`, or the firmware lacks
  those objects. The audit reports the features as unauditable instead of
  guessing. Widen the view ([§4.3](#43-enable-snmp-read-only) step 3) and confirm
  with `snmpget -v2c -c <community> <switch> 1.3.6.1.4.1.171.10.76.20.1.1.8.0`.
- **Check 6 WARN "not tested: ...".** The detail names the reason (`scapy not
  installed`, `raw sockets denied`, ...). Install `scapy`
  (`uv run --with scapy netcheck.py`) and grant raw-socket rights: run as
  root/administrator (`sudo -E env "PATH=$PATH" uv run --with scapy netcheck.py`), or on Linux
  grant the interpreter the capability once
  (`sudo setcap cap_net_raw+ep "$(readlink -f "$(command -v python3)")"`), or
  accept the WARN. See [§3.4](#34-privileges-and-optional-tools).
- **Check 6 WARN "no DHCP server answered on this segment".** The probe is an active
  broadcast DISCOVER sent with the wired NIC's real MAC, so it does not depend on a
  client renewing. No OFFER means no DHCP server/relay serves that VLAN, or the server
  ignored the probe — confirm DHCP is reachable on the wired segment.
- **Check 8 shows a switch with no rows.** The FDB walk returned nothing on that
  firmware; confirm SNMP visibility. The inventory has no Telnet fallback.
- **Colors look wrong / garbled.** Use `--no-color` (auto-off when not a TTY).
- **Need more detail on an internal error or a degraded check.** Re-run with
  `--verbose`: it prints a config/platform preamble, per-check markers, and a Python
  traceback for every error it handles — including gracefully-degraded ones (per-switch
  SNMP failures, the `scapy` probe, storm sampling) that would otherwise be reduced to
  a one-line detail. Diagnostics go to **stderr** and are not written to the `--log`
  report.

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
| STP port state (access 1–22 / uplink 23–27) | | | | | |
| Storm Control threshold (N) | | | | | |
| Safeguard enabled | | | | | |
| DHCP screening (trusted ports / `192.168.1.1`) | | | | | |
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
