# simple-netcheck - Usage Guide

Read-only diagnostic: it never changes the ISP router or any switch configuration.

## 1. Get the tool

Download-then-run from a GitHub Release (recommended):

```bash
curl -sSLO https://github.com/<owner>/<repo>/releases/latest/download/netcheck.py
curl -sSLO https://github.com/<owner>/<repo>/releases/latest/download/SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
python3 netcheck.py
```

Optional: `uv` needs no pre-installed Python (`uv run netcheck.py`); add the
rogue-DHCP probe with `uv run --with scapy netcheck.py`.

## 2. Management-laptop prerequisites

- Python 3.10+ (3.12+ recommended), or `uv`.
- Plugged into the office LAN behind `dlink1`-`dlink5` (same L2 segment).
- Reachability to the switch subnet: add a secondary IPv4 address
  `10.90.90.100 / 255.0.0.0` to the NIC so `10.90.90.90`-`10.90.90.94` answers.
- Elevated rights for the rogue-DHCP probe (Administrator / root / `setcap
  cap_net_raw+ep`); optional `pip install scapy` and/or `nmap`.
- Host firewall allows outbound UDP 161 (SNMP) and ICMP.
- Copy `netcheck.ini.example` to `netcheck.ini` (gitignored) or export `NETCHECK_*`.

## 3. Switch prerequisites (one-time, web UI)

- Unique management IPs `dlink1` `.90` ... `dlink5` `.94`, mask `255.0.0.0`.
- Change the default `admin`/`admin` password (the tool warns if unchanged).
- Enable SNMP (disabled by default): SNMP Global on, a read-only v2c community (or
  v3 user) that can read the standard and private MIBs from the management subnet.
- Keep Telnet enabled for the `debug info` fallback; confirm it prints ARP + FDB.
- Apply the hardening baseline below.

## 4. Hardening baseline (web UI)

| Feature | Path | Values |
|---|---|---|
| Loopback Detection | L2 Functions > Loopback Detection | enabled, port mode, interval 2s, recover 0, access ports only |
| Storm Control | Security > Storm Control | enabled, type 3, auto-measured threshold (static 20000 Kbit/s) |
| RSTP | L2 Functions > Spanning Tree | enabled, RSTP, dlink1 priority 4096, edge on access, restricted role/TCN |
| DHCP Server Screening | Security > DHCP Server Screening | enabled on access ports, trusted 192.168.1.1, not on port 23 |
| Safeguard / DoS | Security | Safeguard on (default), DoS prevention on |

## 5. Flags

`--quick` (checks 1-4) · `--log` · `--config PATH` · `--no-fix` · `--sample SECONDS`
· `--no-measure` · `--timeout N` · `--verbose` · `--no-color` · `--version`.

## 6. Optional fixes

After a failing run the tool offers three per-action `y/N` fixes (skip all with
`--no-fix`): flush the DNS cache, renew the DHCP lease, and set this PC's DNS to
`1.1.1.1`/`8.8.8.8`. It never changes the router or any switch.

## 7. Interpreting output

One `[PASS]/[WARN]/[FAIL]` line per check, then "Likely cause" and "Suggested fix".
Exit codes: `0` clean, `1` warnings, `2` failures. Scenarios:

- **No internet, gateway fails**: fix the local/uplink path; the router is out of scope.
- **Internet by IP fails, gateway passes**: upstream/ISP problem; you cannot fix it.
- **DNS fails while IP works**: ISP DNS problem - switch the PC to 1.1.1.1/8.8.8.8.
- **Rogue DHCP FAIL**: trace the reported MAC, unplug that device, enable screening.
- **Loop/storm FAIL**: a port is in loop state; unplug it, then re-check hardening.

## 8. Troubleshooting the tool

- SNMP errors: confirm SNMP is enabled and the community/management subnet is right.
- scapy without rights: the probe degrades to `nmap`, then to WARN.
- Telnet format drift: `--verbose` captures a sample; do not trust an unverified parse.

## 9. Security

Credentials/community never leave env/INI and are never logged; the tool is read-only.
