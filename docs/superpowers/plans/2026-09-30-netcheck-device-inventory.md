# Check 7 Device Inventory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace check 7's per-MAC trace with a fabric-wide device inventory: list every MAC learned on every switch with its physical port, and mark confirmed rogue-DHCP responders.

**Architecture:** All changes stay inside the single-file `netcheck.py` plus its tests and docs. Three units change: a new SNMP collection helper (`collect_devices`), a new rendering + result function (`check_device_inventory` / `format_inventory`), and the `run_all` wiring. The old `trace_mac`/`find_fdb_port`/`debug_info_lookup`/`CASCADE` hop logic and `tests/test_trace.py` are deleted. Read-only guarantees are unchanged.

**Tech Stack:** Python 3.10+ standard library (`dataclasses`, `enum`, `unittest`); existing hand-rolled SNMP client; no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-30-netcheck-device-inventory-design.md`

## Global Constraints

- Python floor 3.10; standard library only; no new dependencies.
- The tool remains **read-only** against switches, router, and OS: no SNMP SET, no CLI config, no config writes.
- Result lines keep the ASCII ` - ` detail separator (Windows-console safe). The inventory table is printed **in full, always** — no `--verbose` gate, no row cap.
- A device is flagged `ROGUE` **only** when its MAC is in the `rogue_macs` list returned by `check_rogue_dhcp` (check 6). If check 6 did not run, nothing is flagged.
- Secrets (SNMP community, switch password) are never printed or logged.
- All tests run with stdlib `unittest`: `python3 -m unittest discover -s tests -v`.
- Commit steps are included per the writing-plans convention; do not run `git commit` unless your human partner has approved committing.

---

### Task 1: Recover a MAC from an FDB OID suffix

**Files:**
- Modify: `netcheck.py` (add `mac_from_oid_suffix` immediately after `mac_to_oid_suffix`, ~line 1027)
- Test: `tests/test_inventory.py` (create)

**Interfaces:**
- Consumes: `mac_to_oid_suffix` (existing).
- Produces: `mac_from_oid_suffix(oid: str, base: str) -> str | None` — given a full FDB OID and its base OID, return the 6-octet MAC formatted `AA:BB:CC:DD:EE:FF`; return `None` if the OID is not under `base` or does not carry exactly 6 trailing integer parts.

- [ ] **Step 1: Write the failing test**

Create `tests/test_inventory.py`:

```python
import unittest

from netcheck import BRIDGE_FDB_OID, QB_FDB_OID, mac_from_oid_suffix, mac_to_oid_suffix


class TestMacFromOidSuffix(unittest.TestCase):
    def test_recovers_mac_from_qbridge_oid(self):
        mac = "00:1E:58:AA:BB:CC"
        oid = f"{QB_FDB_OID}.{mac_to_oid_suffix(mac)}"
        self.assertEqual(mac_from_oid_suffix(oid, QB_FDB_OID), mac)

    def test_recovers_mac_from_bridge_oid(self):
        mac = "3C:07:54:9A:BC:DE"
        oid = f"{BRIDGE_FDB_OID}.{mac_to_oid_suffix(mac)}"
        self.assertEqual(mac_from_oid_suffix(oid, BRIDGE_FDB_OID), mac)

    def test_returns_none_when_not_under_base(self):
        oid = f"{QB_FDB_OID}.0.30.88.170.187.204"
        self.assertIsNone(mac_from_oid_suffix(oid, BRIDGE_FDB_OID))

    def test_returns_none_on_wrong_octet_count(self):
        oid = f"{QB_FDB_OID}.0.30.88"
        self.assertIsNone(mac_from_oid_suffix(oid, QB_FDB_OID))

    def test_returns_none_on_non_integer_suffix(self):
        oid = f"{QB_FDB_OID}.0.30.88.170.187.x"
        self.assertIsNone(mac_from_oid_suffix(oid, QB_FDB_OID))


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m unittest tests.test_inventory -v`
Expected: FAIL/ERROR — `mac_from_oid_suffix` is not importable.

- [ ] **Step 3: Implement `mac_from_oid_suffix`**

In `netcheck.py`, immediately after `mac_to_oid_suffix`:

```python
def mac_from_oid_suffix(oid: str, base: str) -> str | None:
    if not oid.startswith(base + "."):
        return None
    parts = oid[len(base) + 1:].split(".")
    if len(parts) != 6:
        return None
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return None
    if any(o < 0 or o > 255 for o in octets):
        return None
    return ":".join(f"{o:02X}" for o in octets)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m unittest tests.test_inventory -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_inventory.py
git commit -m "feat(inventory): recover MACs from FDB OID suffixes"
```

---

### Task 2: Collect all devices across all switches

**Files:**
- Modify: `netcheck.py` (add `Devicelist` dataclass and `collect_devices` after `find_fdb_port`, ~line 1049)
- Test: `tests/test_inventory.py` (append)

**Interfaces:**
- Consumes: `Config`, `SnmpClient`, `SnmpError`, `QB_FDB_OID`, `BRIDGE_FDB_OID`, `resolve_ifindex_ports`, `mac_from_oid_suffix` (Task 1).
- Produces:
  - `@dataclass Devicelist(devices: dict[str, dict[str, int]] = field(default_factory=dict), errors: list[str] = field(default_factory=list))` — `devices[switch][MAC] = port`.
  - `collect_devices(cfg: Config, client_factory=SnmpClient) -> Devicelist` — never raises; per-switch `SnmpError` becomes an `errors` entry and an empty map for that switch.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_inventory.py`:

```python
from netcheck import (
    BASE_PORT_IFINDEX_OID,
    Config,
    Devicelist,
    SnmpError,
    collect_devices,
)

MAC_A = "00:1E:58:AA:BB:CC"
MAC_B = "3C:07:54:9A:BC:DE"


def _suffix(mac):
    return mac_to_oid_suffix(mac)


class FakeClient:
    def __init__(self, host, community, **kw):
        self.host = host

    def walk(self, base_oid):
        if base_oid == QB_FDB_OID:
            if self.host == "10.90.90.90":
                return [(f"{QB_FDB_OID}.{_suffix(MAC_A)}", 5)]
            if self.host == "10.90.90.91":
                return [(f"{QB_FDB_OID}.{_suffix(MAC_B)}", 8)]
            return []
        if base_oid == BASE_PORT_IFINDEX_OID:
            return [(f"{BASE_PORT_IFINDEX_OID}.5", 5),
                    (f"{BASE_PORT_IFINDEX_OID}.8", 8)]
        return []


class BridgeOnlyClient(FakeClient):
    def walk(self, base_oid):
        if base_oid == QB_FDB_OID:
            return []
        if base_oid == BRIDGE_FDB_OID:
            return [(f"{BRIDGE_FDB_OID}.{_suffix(MAC_A)}", 5)]
        if base_oid == BASE_PORT_IFINDEX_OID:
            return [(f"{BASE_PORT_IFINDEX_OID}.5", 5)]
        return []


class ExplodingClient(FakeClient):
    def __init__(self, host, community, **kw):
        super().__init__(host, community, **kw)
        self.bad = host == "10.90.90.91"

    def walk(self, base_oid):
        if self.bad:
            raise SnmpError("timeout")
        return super().walk(base_oid)


class TestCollectDevices(unittest.TestCase):
    def test_collects_macs_and_ports_per_switch(self):
        cfg = Config(switches={"dlink1": "10.90.90.90", "dlink2": "10.90.90.91"},
                     snmp_community="public")
        result = collect_devices(cfg, client_factory=FakeClient)
        self.assertIsInstance(result, Devicelist)
        self.assertEqual(result.devices["dlink1"], {MAC_A: 5})
        self.assertEqual(result.devices["dlink2"], {MAC_B: 8})
        self.assertEqual(result.errors, [])

    def test_bridge_fallback_when_qbridge_empty(self):
        cfg = Config(switches={"dlink1": "10.90.90.90"}, snmp_community="public")
        result = collect_devices(cfg, client_factory=BridgeOnlyClient)
        self.assertEqual(result.devices["dlink1"], {MAC_A: 5})

    def test_switch_error_yields_partial_result(self):
        cfg = Config(switches={"dlink1": "10.90.90.90", "dlink2": "10.90.90.91"},
                     snmp_community="public")
        result = collect_devices(cfg, client_factory=ExplodingClient)
        self.assertEqual(result.devices["dlink1"], {MAC_A: 5})
        self.assertEqual(result.devices["dlink2"], {})
        self.assertTrue(any("dlink2" in e for e in result.errors))

    def test_no_community_returns_empty(self):
        result = collect_devices(Config(), client_factory=FakeClient)
        self.assertEqual(result.devices, {})
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_inventory -v`
Expected: ERROR — `Devicelist` / `collect_devices` not importable.

- [ ] **Step 3: Implement `Devicelist` and `collect_devices`**

In `netcheck.py`, immediately after `find_fdb_port`:

```python
@dataclass
class Devicelist:
    devices: dict[str, dict[str, int]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def _walk_fdb(client) -> list[tuple[str, object]]:
    for base in (QB_FDB_OID, BRIDGE_FDB_OID):
        try:
            rows = client.walk(base)
        except SnmpError:
            rows = []
        if rows:
            return [(oid, value, base) for oid, value in rows]
    return []


def collect_devices(cfg: Config, client_factory=SnmpClient) -> Devicelist:
    result = Devicelist()
    if not cfg.snmp_community:
        return result
    for name, host in cfg.switches.items():
        result.devices[name] = {}
        try:
            client = client_factory(host, cfg.snmp_community, timeout=cfg.timeout)
            rows = _walk_fdb(client)
            if not rows:
                continue
            ifindex_map = resolve_ifindex_ports(client)
            for oid, value, base in rows:
                mac = mac_from_oid_suffix(oid, base)
                if mac is None or not isinstance(value, int):
                    continue
                result.devices[name][mac] = ifindex_map.get(value, value)
        except (SnmpError, ValueError) as exc:
            result.errors.append(f"{name}: SNMP unavailable ({exc})")
    return result
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_inventory -v`
Expected: PASS (9 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_inventory.py
git commit -m "feat(inventory): collect per-switch FDB MACs and ports"
```

---

### Task 3: Render the inventory and build the check-7 result

**Files:**
- Modify: `netcheck.py` (replace `trace_mac` with `format_inventory` and `check_device_inventory`; delete `find_fdb_port`, `debug_info_lookup`, `CASCADE`, `_walk_fdb` stays)
- Test: `tests/test_inventory.py` (append)

**Interfaces:**
- Consumes: `Devicelist`, `collect_devices` (Task 2), `lookup_vendor`, `CheckResult`, `Status`, `Config`.
- Produces:
  - `format_inventory(devs: Devicelist, rogue_macs: list[str]) -> str` — pure; one aligned row per device grouped in `devs.devices` iteration order, sorted by `(switch, port)`; `ROGUE` suffix on flagged rows; trailing error lines.
  - `check_device_inventory(cfg: Config, rogue_macs: list[str], client_factory=SnmpClient) -> CheckResult` — `CheckResult(7, "Device inventory", ...)`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_inventory.py`:

```python
from netcheck import (
    CheckResult,
    Status,
    check_device_inventory,
    format_inventory,
)


class TestFormatInventory(unittest.TestCase):
    def test_marks_only_rogue_mac(self):
        devs = Devicelist(devices={"dlink1": {MAC_A: 5, MAC_B: 8}})
        text = format_inventory(devs, [MAC_A])
        lines = [ln for ln in text.splitlines() if "port" in ln]
        self.assertEqual(len(lines), 2)
        rogue_line = next(ln for ln in lines if "AA:BB:CC" in ln)
        ok_line = next(ln for ln in lines if "9A:BC:DE" in ln)
        self.assertIn("ROGUE", rogue_line)
        self.assertNotIn("ROGUE", ok_line)

    def test_sorts_rows_by_port(self):
        devs = Devicelist(devices={"dlink1": {MAC_A: 9, MAC_B: 3}})
        lines = [ln for ln in format_inventory(devs, []).splitlines() if "port" in ln]
        self.assertIn(" 3 ", lines[0])
        self.assertIn(" 9 ", lines[1])

    def test_includes_vendor(self):
        devs = Devicelist(devices={"dlink1": {"00:1E:58:11:22:33": 5}})
        self.assertIn("D-Link", format_inventory(devs, []))

    def test_error_lines_are_appended(self):
        devs = Devicelist(devices={"dlink2": {}}, errors=["dlink2: SNMP unavailable (x)"])
        self.assertIn("dlink2: SNMP unavailable", format_inventory(devs, []))


class TestCheckDeviceInventory(unittest.TestCase):
    def test_fail_when_rogue_present(self):
        cfg = Config(switches={"dlink1": "10.90.90.90"}, snmp_community="public")
        result = check_device_inventory(cfg, [MAC_A], client_factory=FakeClient)
        self.assertIs(result.status, Status.FAIL)
        self.assertEqual(result.id, 7)
        self.assertIn("Device inventory", result.title)

    def test_pass_when_no_rogue(self):
        cfg = Config(switches={"dlink1": "10.90.90.90"}, snmp_community="public")
        result = check_device_inventory(cfg, [], client_factory=FakeClient)
        self.assertIs(result.status, Status.PASS)

    def test_warn_without_snmp(self):
        result = check_device_inventory(Config(), [], client_factory=FakeClient)
        self.assertIs(result.status, Status.WARN)

    def test_warn_when_all_switches_error(self):
        cfg = Config(switches={"dlink1": "10.90.90.90"}, snmp_community="public")
        result = check_device_inventory(cfg, [], client_factory=ExplodingClient)
        self.assertIs(result.status, Status.WARN)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_inventory -v`
Expected: ERROR — `format_inventory` / `check_device_inventory` not importable.

- [ ] **Step 3: Delete the old trace machinery**

In `netcheck.py`:

- Delete `CASCADE` (line ~1022) — only `trace_mac` used it.
- Delete `find_fdb_port` (lines ~1037-1049) — only `trace_mac` used it.
- Delete `debug_info_lookup` (lines ~1052-1064) — only `trace_mac` used it.
- Delete `trace_mac` (lines ~1067-1101).
- Leave `mac_to_oid_suffix`, `resolve_ifindex_ports`, `parse_debug_info`, `TelnetConnection`, and the `*_FDB_OID` / `BASE_PORT_IFINDEX_OID` constants — later tasks and other checks still need `parse_debug_info`/Telnet? Confirm with `grep -n "debug_info_lookup\|find_fdb_port\|trace_mac\|CASCADE" netcheck.py` and remove only what is now unreferenced. `parse_debug_info` and `TelnetConnection` have no other caller after this change and must also be deleted; `_MAC_LINE` and `TelnetError` go with them.

- [ ] **Step 4: Implement `format_inventory` and `check_device_inventory`**

In `netcheck.py`, where `trace_mac` used to be:

```python
def format_inventory(devs: Devicelist, rogue_macs: list[str]) -> str:
    rogue = {m.replace("-", ":").upper() for m in rogue_macs}
    rows: list[tuple[str, int, str]] = []
    for switch, macs in devs.devices.items():
        for mac, port in macs.items():
            rows.append((switch, port, mac))
    rows.sort(key=lambda r: (list(devs.devices).index(r[0]), r[1], r[2]))
    switch_w = max((len(r[0]) for r in rows), default=0)
    port_w = max((len(str(r[1])) for r in rows), default=0)
    lines: list[str] = []
    for switch, port, mac in rows:
        vendor = lookup_vendor(mac) or ""
        flag = "  ROGUE" if mac.upper() in rogue else ""
        lines.append(f"    {switch:<{switch_w}}  port {port:>{port_w}}  "
                     f"{mac}  {vendor}{flag}")
    lines.extend(f"    {err}" for err in devs.errors)
    return "\n".join(lines)


def check_device_inventory(cfg: Config, rogue_macs: list[str],
                           client_factory=SnmpClient) -> CheckResult:
    title = "Device inventory"
    if not cfg.snmp_community:
        return CheckResult(7, title, Status.WARN,
                           detail="SNMP community not set; cannot list devices",
                           likely_cause="The inventory needs read-only SNMP on each switch.",
                           suggested_fix="Set the SNMP community (NETCHECK_SNMP_COMMUNITY "
                                         "or netcheck.ini).")
    devs = collect_devices(cfg, client_factory=client_factory)
    total = sum(len(m) for m in devs.devices.values())
    table = format_inventory(devs, rogue_macs)
    rogue = {m.replace("-", ":").upper() for m in rogue_macs}
    hits = [(switch, port, mac) for switch, macs in devs.devices.items()
            for mac, port in macs.items() if mac.upper() in rogue]
    if hits:
        where = ", ".join(f"{switch} port {port}" for switch, port, _ in hits)
        return CheckResult(7, title, Status.FAIL,
                           detail=f"{total} devices; rogue on {where}\n{table}",
                           likely_cause="A non-gateway DHCP server is attached to the fabric.",
                           suggested_fix=f"Unplug the flagged device ({where}); enable DHCP "
                                         "Server Screening with 192.168.1.1 trusted.")
    if total == 0 and devs.errors:
        return CheckResult(7, title, Status.WARN,
                           detail="inventory unavailable\n" + table,
                           likely_cause="No switch returned an FDB.",
                           suggested_fix="Confirm SNMP is enabled and reachable on each switch.")
    detail = f"{total} devices on {len(devs.devices)} switches"
    if devs.errors:
        detail += "\n" + table
    return CheckResult(7, title, Status.PASS, detail=detail + ("\n" + table if table else ""))
```

(Keep the rendering consistent: the table always prints in full; `detail` is `header\n<table>` — `Reporter.render` appends `detail` after ` - `, so the first row sits on the check line and the rest follow on new lines.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_inventory -v`
Expected: PASS.

- [ ] **Step 6: Delete `tests/test_trace.py`**

```bash
git rm tests/test_trace.py
```

- [ ] **Step 7: Run the full suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS, except `tests/test_orchestration.py` may fail if it still asserts the old check-7 text — Task 4 fixes that. If it fails only on check-7 wording, proceed to Task 4.

- [ ] **Step 8: Commit**

```bash
git add netcheck.py tests/test_inventory.py tests/test_trace.py
git commit -m "feat(inventory): render per-switch device table with rogue flags; drop MAC trace"
```

---

### Task 4: Wire check 7 in `run_all` and update orchestration tests

**Files:**
- Modify: `netcheck.py` (`run_all`, the `_trace` block ~lines 1401-1412)
- Test: `tests/test_orchestration.py`

**Interfaces:**
- Consumes: `check_device_inventory` (Task 3), `rogue_macs` from check 6 (existing).
- Produces: `run_all` unchanged signature; check 7 always emits exactly one result via `check_device_inventory`.

- [ ] **Step 1: Update the orchestration tests**

In `tests/test_orchestration.py`, the stub of `check_rogue_dhcp` stays. Replace the check-7 assertions in `test_failing_check_does_not_stop_later_checks`:

```python
        check7 = next(r for r in reporter.results if r.id == 7)
        self.assertIs(check7.status, netcheck.Status.WARN)
```

Add a new test:

```python
    def test_check7_always_emits_inventory(self):
        reporter = netcheck.Reporter(color=False)
        orig = netcheck.check_device_inventory
        netcheck.check_device_inventory = lambda *a, **k: netcheck.CheckResult(
            7, "Device inventory", netcheck.Status.PASS, detail="0 devices")
        try:
            netcheck.run_all(netcheck.Config(), reporter, no_measure=True,
                             runner=lambda *a, **k: (0, "", ""))
        finally:
            netcheck.check_device_inventory = orig
        check7 = [r for r in reporter.results if r.id == 7]
        self.assertEqual(len(check7), 1)
        self.assertIn("Device inventory", check7[0].title)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_orchestration -v`
Expected: FAIL — `run_all` still calls `trace_mac`; `check_device_inventory` is not referenced.

- [ ] **Step 3: Replace the `_trace` block in `run_all`**

```python
        def _inventory() -> None:
            reporter.add(check_device_inventory(cfg, rogue_macs))

        _run_check(7, "Device inventory", _inventory)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_orchestration -v`
Expected: PASS.

- [ ] **Step 5: Run the full suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add netcheck.py tests/test_orchestration.py
git commit -m "feat(run): check 7 emits the device inventory"
```

---

### Task 5: Update the operator guide

**Files:**
- Modify: `USAGE.md` (§3.4 SNMP note, §7.1 catalog rows, §9.3 sample output, §11 troubleshooting, scenario walkthrough)
- Test: `tests/test_docs.py` (regression guard only)

**Interfaces:**
- Consumes: shipped behavior from Tasks 1-4.
- Produces: docs consistent with the inventory output. No code changes.

- [ ] **Step 1: Update the SNMP notes**

At USAGE.md line ~96 and ~288, change "check 7 cannot trace" / "the MAC trace (check 7)" to reference the device inventory ("check 7 cannot list devices" / "the device inventory (check 7)").

- [ ] **Step 2: Replace the §7.1 catalog row for check 7**

```markdown
| 7 | Device inventory | SNMP FDB walk (Q-BRIDGE, BRIDGE fallback) on every switch; lists all MACs with physical port, grouped by switch, always in full | PASS: no rogue responder present. FAIL: a listed MAC is a confirmed rogue-DHCP responder. WARN: SNMP not configured or no switch returned an FDB |
```

Delete the note at lines ~527-528 (`Check 7 emits once per run: a trace line per rogue MAC...`), replacing it with:

```markdown
Check 7 always prints the full per-switch device table. Rows for MACs confirmed as
non-gateway DHCP responders (check 6) are marked `ROGUE`.
```

- [ ] **Step 3: Refresh the §9.3 sample output**

Replace the check-7 line (line ~546, `[PASS] 7. Trace aa:bb:... - dlink1 port 5`) with a table block:

````markdown
```
[PASS]  7. Device inventory - 139 devices on 5 switches
    dlink1  port  5   AA:BB:CC:DD:EE:FF  TP-Link  ROGUE
    dlink1  port 12   00:1E:58:11:22:33  D-Link
    dlink2  port  3   3C:07:54:9A:BC:DE  Apple
```
````

- [ ] **Step 4: Update the rogue-DHCP walkthrough and troubleshooting**

- §scenario (~line 575): "runs check 7 for each rogue MAC" → "check 7 lists the device table and marks the rogue MAC's switch and port".
- §troubleshooting line ~594 ("MAC not found (check 7 WARN)") → "**No devices listed (check 7 WARN).** SNMP is unconfigured or the FDB walk returned no rows; confirm SNMP is enabled."
- §troubleshooting line ~644 ("Check 7 falls back to Telnet") → "**Check 7 shows a switch with no rows.** The FDB walk returned nothing on that firmware; confirm SNMP visibility. The inventory has no Telnet fallback."

- [ ] **Step 5: Run the docs and full tests**

Run: `python3 -m unittest tests.test_docs -v`
Expected: PASS.
Run: `python3 -m unittest discover -s tests -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add USAGE.md
git commit -m "docs: document the check 7 device inventory"
```

---

### Task 6: Mark the original spec's check 7 as superseded

**Files:**
- Modify: `docs/superpowers/specs/2026-09-29-netcheck-design.md` (§6 check 7, ~lines 159-171; §9.3 output sample)
- No test changes.

**Interfaces:**
- Consumes: the new design doc.
- Produces: a pointer in the original spec so the two documents do not conflict.

- [ ] **Step 1: Add the superseded pointer**

At the top of §6's "**7. Trace to port**" block, prepend:

```markdown
> **Superseded 2026-09-30:** check 7 is now the fabric-wide device inventory
> described in `docs/superpowers/specs/2026-09-30-netcheck-device-inventory-design.md`.
> The per-MAC trace below is retained for historical context only.
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/specs/2026-09-29-netcheck-design.md
git commit -m "docs(spec): mark the per-MAC trace superseded by the device inventory"
```

---

### Task 7: End-to-end verification

**Files:**
- No file changes.

**Interfaces:**
- Consumes: the finished tool.
- Produces: a live run confirming check 7 prints the inventory and no internal error.

- [ ] **Step 1: Run the tool**

Run: `uv run --with scapy netcheck.py --no-fix --no-color --sample 2`
Expected: checks 1, 5, 6, 9, 8, 7 each printed. Check 7 prints `Device inventory`; on a host with SNMP it lists rows, otherwise it prints `WARN: SNMP community not set; cannot list devices`. No `[WARN] 98. Internal error`.

- [ ] **Step 2: Confirm the rogue flag path**

If a rogue DHCP responder is present, check 7's status is FAIL and its table marks that MAC's row `ROGUE` with the switch/port named in the fix line.

- [ ] **Step 3: Confirm the full suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS.

---

## Self-Review

- **Spec coverage:** FDB collection across all switches → Task 2; MAC recovery from OID → Task 1; physical-port translation via existing `resolve_ifindex_ports` → Task 2; rogue matching against `rogue_macs` only → Task 3; aligned full table always printed → Task 3; PASS/FAIL/WARN semantics → Task 3; `run_all` wiring → Task 4; delete `trace_mac` and `tests/test_trace.py` → Task 3; docs → Task 5; original-spec pointer → Task 6; verification → Task 7. All spec sections covered.
- **Placeholder scan:** every code step contains runnable code; no TBD/TODO. Task 3 Step 3 instructs a grep-confirm before deleting the now-unreferenced Telnet helpers, with the exact removal list named.
- **Type consistency:** `Devicelist(devices, errors)` and `collect_devices(cfg, client_factory) -> Devicelist` are used identically in Tasks 2-4; `mac_from_oid_suffix(oid, base) -> str | None` is defined in Task 1 and consumed in Task 2; `format_inventory(Devicelist, list[str])` and `check_device_inventory(Config, list[str], client_factory) -> CheckResult` are defined in Task 3 and consumed in Task 4; check id is always `7` and title `"Device inventory"`.
- **Dead code:** `CASCADE`, `find_fdb_port`, `debug_info_lookup`, `trace_mac`, and (after grep confirmation) `parse_debug_info`/`TelnetConnection`/`TelnetError`/`_MAC_LINE` are removed in Task 3; `tests/test_trace.py` is removed.
