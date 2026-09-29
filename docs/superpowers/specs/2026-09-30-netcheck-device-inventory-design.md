# simple-netcheck — Check 7 Device Inventory Design

- **Status:** Approved in chat 2026-09-30
- **Date:** 2026-09-30
- **Supersedes:** check 7 ("MAC trace") in
  `docs/superpowers/specs/2026-09-29-simple-netcheck-design.md`
- **Source request:** list every connected device MAC per switch and the port it
  is connected to, then indicate whether the device is a rogue DHCP server.

## 1. Goal

Replace check 7's per-MAC trace with a **fabric-wide device inventory**: for every
switch, list every MAC learned in its forwarding database together with the
physical port, and mark each entry `ROGUE` when that MAC was seen answering DHCP
as a non-gateway server (check 6). The full table is always printed.

## 2. Scope and non-goals

In scope:
- Collect all FDB entries from all five switches (read-only SNMP).
- Map each MAC to a physical port.
- Render one aligned table, grouped by switch, always printed in full.
- Flag confirmed rogue-DHCP responders.

Non-goals:
- No new dependencies; no switch/router writes (SNMP read-only only).
- No per-MAC hop tracing (the old `trace_mac` is removed).
- No Telnet `debug info` fallback for the inventory — it is a per-MAC lookup, not
  a full-table dump. A switch whose FDB walk is empty simply shows no rows.

## 3. Behavior

Check 6 (Rogue DHCP) is unchanged: it still returns the one-line summary and the
list of rogue MACs. Check 7 consumes that MAC list.

### 3.1 Collection

`collect_devices(cfg, client_factory=SnmpClient) -> Devicelist`

- For each switch in `cfg.switches`, open one SNMP client.
- Walk `QB_FDB_OID` (`1.3.6.1.2.1.17.7.1.2.2.1.2`); if that returns no rows, fall
  back to `BRIDGE_FDB_OID` (`1.3.6.1.2.1.17.4.3.1.2`) — same precedence as the old
  `find_fdb_port`.
- Recover the MAC from the OID suffix by taking the 6 octets after the base OID
  and formatting them `AA:BB:CC:DD:EE:FF`.
- Translate the FDB port value to a physical port via
  `resolve_ifindex_ports(client)` (existing helper).
- Record `{switch_name: {mac: port}}`. On `SnmpError` for a switch, record that
  switch with an empty map and remember the failure.
- Never raises; returns the partial map plus an `errors: list[str]` of
  `"<switch>: SNMP unavailable (<reason>)"`.

A new helper `mac_from_oid_suffix(oid, base) -> str | None` inverts the existing
`mac_to_oid_suffix`: strip the base OID prefix, require exactly 6 remaining
integer parts, format them as hex octets. Returns `None` on anything else.

### 3.2 Rogue matching

- Normalize MACs to uppercase colon-separated form.
- A device is `ROGUE` iff its MAC is in `rogue_macs` (the list returned by
  `check_rogue_dhcp`).
- If check 6 did not run, `rogue_macs` is empty and nothing is flagged (all
  entries `ok`); check 6 already carries the WARN reason.

### 3.3 Rendering

`format_inventory(devices, rogue_macs, errors) -> str` is pure and unit-testable:

- Group by switch (in `cfg.switches` order), then sort rows by port number.
- Aligned columns: `switch  port  mac  vendor  [ROGUE]`.
- Vendor from the embedded OUI table (`lookup_vendor`), blank when unknown.
- `ROGUE` suffix only for flagged entries; `ok` otherwise is omitted to keep the
  table narrow.
- A trailing line lists any per-switch collection errors.

Sketch:

```
[PASS]  7. Device inventory  - 139 devices on 5 switches
    dlink1  port  5   AA:BB:CC:DD:EE:FF  TP-Link  ROGUE
    dlink1  port 12   00:1E:58:11:22:33  D-Link
    dlink2  port  3   3C:07:54:9A:BC:DE  Apple
```

### 3.4 Status semantics

- **PASS** — inventory collected; no device flagged.
- **FAIL** — inventory collected; at least one device flagged `ROGUE`
  (`likely_cause`: a non-gateway DHCP server is on the fabric; `suggested_fix`:
  unplug the flagged `switch, port` and enable DHCP Server Screening).
- **WARN** — no SNMP community, or every switch errored; detail names the reason.
  When only some switches error, status reflects the collected devices and the
  errors are appended to the detail.

## 4. Wiring

In `run_all`, check 7 keeps its position and `_run_check(7, ...)` isolation but
calls the new function:

```python
def _inventory() -> None:
    reporter.add(check_device_inventory(cfg, rogue_macs))
_run_check(7, "Device inventory", _inventory)
```

The old "no rogue devices to trace" / "skipped: no rogue MACs" branches are
removed.

## 5. Removals

- Delete `trace_mac` and its hop logic from `netcheck.py`.
- Delete `tests/test_trace.py`.
- `CASCADE` and `debug_info_lookup` are still used by nothing after this change
  except `debug_info_lookup` (kept only if referenced elsewhere; otherwise
  removed). Confirm by grep before deleting.
- `BASE_PORT_IFINDEX_OID`, `QB_FDB_OID`, `BRIDGE_FDB_OID`, `mac_to_oid_suffix`
  and `resolve_ifindex_ports` stay — the inventory reuses them.

## 6. Tests

- **New** `tests/test_inventory.py`:
  - `mac_from_oid_suffix` round-trips and rejects malformed suffixes.
  - `collect_devices` with a fake client returning Q-BRIDGE rows on two switches
    returns `{switch: {mac: port}}`.
  - BRIDGE fallback used when Q-BRIDGE is empty.
  - An `SnmpError` on one switch yields a partial map plus an error string.
  - `format_inventory` flags a rogue MAC and leaves others unflagged.
  - `check_device_inventory` returns FAIL when a listed MAC is rogue, PASS when
    none is, WARN when SNMP is unconfigured.
- **Delete** `tests/test_trace.py`.
- **Update** `tests/test_orchestration.py`: check 7 assertions no longer expect
  "no rogue devices"; assert the new title/behavior.
- Run `python3 -m unittest discover -s tests -v` — all pass.

## 7. Docs

- `USAGE.md` §7.1 catalog row for check 7, §9.3 sample output, and §7 scenario
  walkthrough (rogue DHCP) updated to describe the inventory table.
- `docs/superpowers/specs/2026-09-29-simple-netcheck-design.md` check 7 section
  marked superseded (a pointer to this document), or updated in place.

## 8. Risks

- **Long output.** The full table is always printed by decision; on a busy switch
  this can be hundreds of lines. Accepted.
- **Empty FDB on some firmware.** Covered by the WARN/partial path; documented.
- **Port semantics.** FDB ports are physical switch ports after
  `dot1dBasePortIfIndex` mapping; port 23 on `dlink1` is the ISP/uplink side and
  24–27 are inter-switch, and these will appear as ordinary rows (no special
  label) unless flagged.
