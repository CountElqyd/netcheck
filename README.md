# netcheck

A single-file, read-only CLI that diagnoses *why the internet is broken* on the
office network, then audits the D-Link DGS-1210 switch fabric for the conditions
that cause intermittent outages: rogue DHCP servers, loops/broadcast storms, and
(opt-in) the device inventory plus switch settings that drift below a hardening
baseline.

> **Read-only guarantee.** `netcheck` changes nothing: not this machine, not the
> ISP router, not the switch configuration (no SNMP SET, no CLI `config`/`save`).
> It only reads state and pings. Every change it suggests is applied **by you, by
> hand.**

It runs on Windows, Linux, and macOS (Python 3.10+). `python3 netcheck.py` needs
no third-party packages; `uv run netcheck.py` fetches `scapy` automatically for
the check-6 rogue-DHCP probe. It prints one `PASS`/`WARN`/`FAIL` line per check
with a likely cause and a suggested fix. The default run is checks 1–7; device
inventory (8), hardening audit (9), and storm sampling (10) are **opt-in**.

## Quickstart

One-time setup, then run the checks.

**You'll need:**

| Need | For |
|---|---|
| Wired LAN on the switches' Layer-2 segment | checks 1–7 |
| Admin/root (Administrator / sudo) | check 6 (rogue-DHCP probe) |
| Read-only SNMP community on the switches | checks 8 (inventory) and 9 (hardening) |

Switch-side SNMP setup is in [`USAGE.md`](USAGE.md) §4.

### 1. Install `uv`

`uv` fetches a suitable Python itself — no `pip`, no virtualenv, and no
pre-installed Python.

```bash
# Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# macOS (alternative, via Homebrew)
brew install uv
```

```powershell
# Windows (PowerShell)
winget install --id=astral-sh.uv
```

Confirm it is on your PATH with `uv --version`.

### 2. Get the tool

```bash
git clone https://github.com/CountElqyd/netcheck.git
cd netcheck
```

(Or just download the single `netcheck.py` — nothing else is required to run it.)

### 3. Wired LAN + switch-management address

Checks 1–4 use the wired NIC's `192.168.1.x` address; checks 5–10 need a
`10.90.90.x` address on the same NIC. netcheck auto-detects the wired NIC (the one
holding `192.168.1.x` or `10.90.90.x`), so Wi-Fi can stay connected and keeps the
default route. If the `10.90.90.x` address is missing, netcheck prints the exact
command for your OS and **stops before the switch checks** — add the address, then
run netcheck again. To do it by hand (or to force a NIC), use the commands below;
set `lan_interface` in `netcheck.ini` if the NIC name differs.

```bash
# Linux  (replace eth0 with your wired NIC)
sudo ip addr add 10.90.90.100/24 dev eth0
```

```bash
# macOS  (replace en0 with your wired NIC)
sudo ifconfig en0 alias 10.90.90.100 255.255.255.0
```

```powershell
# Windows (run PowerShell as Administrator; replace "Ethernet" with the adapter name)
netsh interface ipv4 add address "Ethernet" 10.90.90.100 255.255.255.0
```

### 4. Configure

Secrets stay out of git — the real file is gitignored.

```bash
cp netcheck.ini.example netcheck.ini    # set snmp_community for checks 8-9
```

### 5. Run

```bash
uv run netcheck.py                 # default run, checks 1-7
uv run netcheck.py --inventory     # only check 8
uv run netcheck.py --hardening     # only check 9
uv run netcheck.py --sample 300    # only check 10
```

`uv run` installs `scapy` (declared in the script's PEP 723 header), so the
check-6 rogue-DHCP probe runs by default. Without raw-socket rights, or if you run
`python3 netcheck.py` without `pip install scapy`, check 6 reports
`WARN: not tested` and prints the exact command to enable it. On Python 3.10+ you
can use `python3 netcheck.py` instead of `uv run`.

### Check 6 (rogue DHCP) — exact command

The probe crafts DHCP packets, which needs `scapy` **and** raw-socket rights. Use
one of these:

```bash
# Linux / macOS: sudo strips uv from PATH, so re-inject it with env
sudo -E env "PATH=$PATH" uv run netcheck.py

# Linux alternative: grant the Python binary raw-socket capability once,
# then run normally (no sudo) afterward
sudo setcap cap_net_raw+ep "$(readlink -f "$(command -v python3)")"
```

```powershell
# Windows: open PowerShell as Administrator, then run normally
uv run netcheck.py
```

If neither is set up, check 6 prints `WARN: not tested` with this same command in
its suggested fix.

## What it checks

| # | Check | What it does |
|---|---|---|
| 1 | Local config | Wired NIC IP, mask, gateway, DNS; flags APIPA or a wired NIC not on `192.168.1.0/24` |
| 2 | Gateway | Pings `192.168.1.1` (loss %, latency, jitter) |
| 3 | Internet by IP | Pings `1.1.1.1` and `8.8.8.8` |
| 4 | DNS | Resolves a test domain on ISP DNS and public DNS |
| 5 | Switches | Pings all five management IPs |
| 6 | Rogue DHCP | scapy broadcast discover; flags any non-gateway responder |
| 7 | Loop/storm hints | LBD loop ports + gateway loss/jitter |
| 8 | Device inventory | **Opt-in** (`--inventory`): SNMP FDB walk per switch; lists end devices on access ports (uplink/trunk ports hidden, the host's own NIC tagged `this host`) |
| 9 | Hardening audit | **Opt-in** (`--hardening`): read-only per-switch audit vs the hardening baseline |
| 10 | Storm thresholds | **Opt-in** (`--sample SECONDS`): per-switch storm-threshold recommendations |

**Opt-in checks run alone.** Passing `--inventory`, `--hardening`, and/or
`--sample` skips the default 1–7 suite and prints only the requested check(s); the
flags combine and run in numeric order. Because check 8 runs alone it does not see
check 6's result, so to locate a rogue responder, match the MAC that check 6 prints
against the check 8 table.

**Exit codes:** `0` clean, `1` at least one `WARN`, `2` at least one `FAIL`. The
operator guide lists every check's exact criteria, the sample output, scenario
playbooks, flags, and the manual hardening settings.

## Documentation

- [`USAGE.md`](USAGE.md) — the full operator guide (prerequisites, first run,
  interpreting output, playbooks, flags, read-only guarantee).
- [`MAINTAINING.md`](MAINTAINING.md) — the maintainer runbook (layout, tests,
  releasing).

## Development

Run the standard-library test suite before any change:

```bash
python3 -m unittest discover -s tests -v
```

Keep `netcheck.py` single-file. It stays standard-library for the `python3` path;
`scapy` is declared in the PEP 723 header so `uv run` fetches it for the check-6
probe, and `pysnmp` remains a fully optional extra. New behavior needs tests under
`tests/` and a docs update in `USAGE.md`.
