# netcheck

A single-file, read-only CLI that diagnoses *why the internet is broken* on the
office network, then audits the D-Link DGS-1210 switch fabric for the conditions
that cause intermittent outages: rogue DHCP servers, loops/broadcast storms, and
(opt-in) switch settings that drift below a hardening baseline.

> **Read-only guarantee.** `netcheck` never changes the ISP router and never
> writes switch configuration (no SNMP SET, no CLI `config`/`save`). It only reads
> switch state. Every change it suggests is applied **by you, by hand, in the
> switch web UI.**

It runs on Windows, Linux, and macOS; is standard-library only (Python 3.10+);
needs no installation; and prints one `PASS`/`WARN`/`FAIL` line per check with a
likely cause and a suggested fix.

## Quickstart

One-time setup, then four steps to a full run (checks 1–9).

**You'll need:** the office LAN (same Layer-2 segment as the switches); admin/root
for the rogue-DHCP probe; and read-only SNMP on the switches for the inventory and
hardening checks — switch-side setup is in [`USAGE.md`](USAGE.md) §4.

**Install `uv` (once).** It fetches a suitable Python itself — no `pip`, no
virtualenv, and no pre-installed Python.

```bash
# Linux / macOS
curl -LsSf https://astral.sh/uv/install.sh | sh

# macOS (alternative, via Homebrew)
brew install uv

# Windows PowerShell
winget install --id=astral-sh.uv
```

Confirm it is on your PATH with `uv --version`.

**1. Clone**

```bash
git clone https://github.com/CountElqyd/netcheck.git
cd netcheck
```

**2. Wired LAN + switch management address.** Checks 1–4 use the wired NIC's
`192.168.1.x` address; checks 5–9 need a `10.90.90.x` address. netcheck
auto-detects the wired NIC (the one holding `192.168.1.x` or `10.90.90.x`) —
Wi-Fi can stay connected and keeps the default route. Before checks 5–9, if the
`10.90.90.x` address is missing, netcheck prints the exact command to add
`10.90.90.100/24` to that NIC and **stops before the switch checks**. Add the
address, then run netcheck again.

To set it up manually instead (or force the NIC), use `lan_interface` in
`netcheck.ini` and run e.g. `sudo ip addr add 10.90.90.100/24 dev eth0`.

**3. Configure** (secrets stay out of git — the real file is gitignored)

```bash
cp netcheck.ini.example netcheck.ini    # set snmp_community for the switch audit
```

**4. Run every check**

```bash
uv run --with scapy netcheck.py
```

`--with scapy` enables the rogue-DHCP probe (check 6) and needs admin/root. Without
admin/root or `scapy`, check 6 reports `WARN: not tested`; run
`uv run netcheck.py` to skip it. On Python 3.10+ you can use
`python3 netcheck.py` instead.

## What it checks

| # | Check | What it does |
|---|---|---|
| 1 | Local config | Wired NIC IP, mask, gateway, DNS; flags APIPA or a wired NIC not on `192.168.1.0/24` |
| 2 | Gateway | Pings `192.168.1.1` (loss %, latency, jitter) |
| 3 | Internet by IP | Pings `1.1.1.1` and `8.8.8.8` |
| 4 | DNS | Resolves a test domain on ISP DNS and public DNS |
| 5 | Switches | Pings all five management IPs |
| 6 | Rogue DHCP | scapy broadcast discover; flags any non-gateway responder |
| 7 | Device inventory | SNMP FDB walk per switch; lists end devices on access ports (uplink/trunk ports are hidden) |
| 8 | Loop/storm hints | LBD loop ports + gateway loss/jitter |
| 9 | Hardening audit | **Opt-in** (`--hardening`): read-only per-switch audit vs the hardening baseline |
| 10 | Storm thresholds | **Opt-in** (`--sample SECONDS`): per-switch storm-threshold recommendations |

Exit codes: `0` clean, `1` at least one `WARN`, `2` at least one `FAIL`. The
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

Keep `netcheck.py` single-file and standard-library only; optional features
(`scapy`, `pysnmp`) are opt-in extras, never hard dependencies. New behavior needs
tests under `tests/` and a docs update in `USAGE.md`.
