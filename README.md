# netcheck

A single-file, read-only CLI that diagnoses *why the internet is broken* on the
office network, then audits the D-Link DGS-1210 switch fabric for the conditions
that cause intermittent outages: rogue DHCP servers, loops/broadcast storms, and
switch settings that drift below a hardening baseline.

> **Read-only guarantee.** `netcheck` never changes the ISP router and never
> writes switch configuration (no SNMP SET, no CLI `config`/`save`). It only reads
> switch state. Every change it suggests is applied **by you, by hand, in the
> switch web UI.**

It runs on Windows, Linux, and macOS; is standard-library only (Python 3.10+);
needs no installation; and prints one `PASS`/`WARN`/`FAIL` line per check with a
likely cause and a suggested fix.

## Quickstart

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

Confirm it is on your PATH with `uv --version`. **Then the 3 commands:**

```bash
git clone https://github.com/CountElqyd/netcheck.git
cd netcheck
uv run netcheck.py --no-fix
```

That is install (once) → clone → enter → run. If you already have **Python 3.10+**,
the last command can instead be `python3 netcheck.py --no-fix`.

**Enable the rogue-DHCP probe (check 6):** `uv run --with scapy netcheck.py --no-fix`
(needs admin/root).

**Configure before a real run** (secrets stay out of git — the file is gitignored):

```bash
cp netcheck.ini.example netcheck.ini       # then set snmp_community etc.
```

Before checks 1–4 pass you must be on the office LAN; before checks 6–9 work you
need the one-time laptop and switch prerequisites in
[`USAGE.md`](USAGE.md) (§3 and §4).

## Prerequisites at a glance

- **On the office LAN**, in the same Layer-2 broadcast domain as the switches and
  router (a normal DHCP lease on `192.168.1.0/24`).
- **A secondary IPv4 address on `10.90.90.0/8`** so the switch management IPs
  (`10.90.90.90`–`10.90.90.94`) answer — see
  [Reach the switch management subnet](#reach-the-switch-management-subnet-10909008).
- **Admin/root** for the scapy rogue-DHCP probe (check 6); without it, check 6
  reports `WARN: not tested` and the rest still works.
- **Read-only SNMP** enabled on each switch for the hardening audit (check 9) and
  device inventory (check 7).

Full setup steps: [`USAGE.md`](USAGE.md) §3 (laptop) and §4 (switches).

## Reach the switch management subnet (10.90.90.0/8)

Checks 5–9 talk to the switches on `10.90.90.90`–`10.90.90.94`. Add a secondary
address in that range to your LAN NIC; your normal `192.168.1.0/24` lease is
unaffected.

```bash
# Linux (replace eth0; list with `ip link`)
sudo ip addr add 10.90.90.100/8 dev eth0

# macOS (replace en0; list with `networksetup -listallhardwareports`)
sudo ifconfig en0 alias 10.90.90.100 255.0.0.0

# Windows, as Administrator (replace "Ethernet"; list with `netsh interface show interface`)
netsh interface ipv4 add address "Ethernet" 10.90.90.100 255.0.0.0
```

## What it checks

| # | Check | What it does |
|---|---|---|
| 1 | Local config | IP, mask, gateway, DNS; flags APIPA or a non-`192.168.1.1` gateway |
| 2 | Gateway | Pings `192.168.1.1` (loss %, latency, jitter) |
| 3 | Internet by IP | Pings `1.1.1.1` and `8.8.8.8` |
| 4 | DNS | Resolves a test domain on ISP DNS and public DNS |
| 5 | Switches | Pings all five management IPs |
| 6 | Rogue DHCP | scapy broadcast discover; flags any non-gateway responder |
| 7 | Device inventory | SNMP FDB walk per switch; maps MACs to physical ports |
| 8 | Loop/storm hints | LBD loop ports + gateway loss/jitter |
| 9 | Hardening audit | Read-only per-switch audit vs the hardening baseline |

Exit codes: `0` clean, `1` at least one `WARN`, `2` at least one `FAIL`. The
operator guide lists every check's exact criteria, the sample output, scenario
playbooks, flags, and the manual hardening settings.

## Documentation

- [`USAGE.md`](USAGE.md) — the full operator guide (prerequisites, first run,
  interpreting output, playbooks, flags, optional fixes).
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
