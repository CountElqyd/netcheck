# netcheck Whole-Script Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Improve `netcheck.py`'s readability and robustness — imports at the top, sectioned structure, docstrings/comments, decomposed long functions — and fix the confirmed bugs, without changing the tool's contract.

**Architecture:** Single stdlib-only file stays single. Work is mechanical and incremental: hoist imports, add section banners, decompose `run_all`, document symbols, then fix `check_switches`' hardcoded cascade hint and the Windows DNS aggregation. Full test suite is the regression contract after every commit.

**Tech Stack:** Python 3.10+ stdlib only; `unittest`; optional scapy/pysnmp remain optional.

**Spec:** `docs/superpowers/specs/2026-10-02-netcheck-audit-design.md`

## Global Constraints

- `netcheck.py` stays a single file; **no new dependencies** (stdlib only).
- **Do not change:** public function/class names and signatures, CLI flags, JSON schema (`summary` + `checks`), check ids (1–7 default, 8 inventory, 9 hardening, 10 thresholds), or exit codes (0/1/2) — except the documented bug fix in Task 3.
- **Green gate:** run `python3 -m unittest discover -s tests` before and after every commit; it must stay at 231 tests and `OK` (Task 3/6 add tests, so the count rises).
- Python floor is 3.10 (`from __future__ import annotations`, PEP 604 `|` unions are used).
- Comments convention (spec §4.5): docstring on every top-level `def`/`class`, one-line summary; inline comments only for non-obvious logic (BER, SNMP, trunk heuristics, platform parsing); no commented-out code.

---

## Before you start

The working tree already contains the uncommitted opt-in (`--inventory`) and inventory-accuracy (null-OUI host) work. Commit it first so this audit starts from a clean base:

```bash
git status --short
git add netcheck.py USAGE.md README.md tests/
git commit -m "feat: opt-in device inventory, accurate MAC filtering, host tagging"
git status --short   # expect clean except untracked files
```

If the user prefers to review that commit first, stop and ask before continuing.

---

## Task 1: Hoist imports and expand the module docstring

**Files:**
- Modify: `netcheck.py` (top import block lines 8–21; mid-file imports at 246–248, 489–490, 716–718, 982–983; module docstring at the top)
- Test: `tests/` (existing suite is the regression)

**Interfaces:**
- Consumes: nothing.
- Produces: unchanged public names. No behavior change.

- [ ] **Step 1: Baseline — confirm the suite is green**

Run: `python3 -m unittest discover -s tests`
Expected: `Ran 231 tests ... OK`

- [ ] **Step 2: Replace the top import block**

Replace lines 8–21 (everything between `from __future__ import annotations` and `class Status`) with this single sorted block, preserving the `from __future__` line and any following blank lines:

```python
import argparse
import configparser
import enum
import ipaddress
import json
import os
import random
import re
import shlex
import shutil
import socket
import struct
import subprocess
import sys
import textwrap
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
```

- [ ] **Step 3: Delete the mid-file import statements**

Remove each of these standalone import lines and any blank-line cluster they leave behind (keep exactly one blank line between surrounding definitions):

```python
# around line 246
import configparser
import os
from collections.abc import Mapping

# around line 489
import random
import socket

# around line 716
import re
import shlex
import subprocess

# around line 982
import struct
import time
```

- [ ] **Step 4: Expand the module docstring**

At the very top (above `from __future__ import annotations`), set the module docstring to summarize purpose, the read-only guarantee, the default check list, and the opt-in flags. Use exactly:

```python
"""netcheck — read-only audit of a small wired office LAN.

Runs a fixed sequence of diagnostics from the wired NIC: local configuration,
gateway, internet-by-IP, DNS, switch reachability, rogue DHCP, and loop/storm
hints (checks 1-7). Device inventory (8), the hardening audit (9), and storm
threshold sampling (10) are opt-in and run alone.

The tool is read-only: it only pings, queries DNS, and walks SNMP. The single
write path is the explicit ``--remove-mgmt-ip`` maintenance flag. See USAGE.md
for the operator guide.
"""
```

- [ ] **Step 5: Verify**

Run: `python3 -m compileall -q netcheck.py && python3 -m unittest discover -s tests`
Expected: no output from compileall, then `Ran 231 tests ... OK`.

- [ ] **Step 6: Commit**

```bash
git add netcheck.py
git commit -m "refactor: hoist stdlib imports and expand module docstring"
```

---

## Task 2: Section banners and top-of-file table of contents

**Files:**
- Modify: `netcheck.py` (insert comment banners; no code changes)
- Test: `tests/` (existing suite is the regression)

**Interfaces:**
- Consumes: Task 1's import block.
- Produces: no behavior change.

- [ ] **Step 1: Insert the table of contents**

Immediately after the module docstring (before `from __future__`), add:

```python
# --- Contents ---------------------------------------------------------------
#   Types and constants        Status, CheckResult, Reporter
#   Configuration              Config, load_config, uplink port helpers
#   BER + SNMP                 encoding/decoding, SnmpClient
#   Values and identifiers     OUI vendor lookup, result codes
#   Shell + interfaces         run_command, interface parsing, LAN selection
#   Checks 1-10                layer checks, fabric checks, hardening, sampling
#   Device inventory           FDB walk, trunk detection, attribution
#   CLI                        build_parser, main, run_all
# ---------------------------------------------------------------------------
```

- [ ] **Step 2: Insert section banners immediately above these symbols**

Each banner is three comment lines (`#` rule, `# SECTION NAME`, `#` rule). Insert one immediately above the named symbol:

- `class Status` → `# --- Types and constants ---`
- `class Config` → `# --- Configuration ---`
- `def ber_encode_length` → `# --- BER + SNMP ---`
- `def lookup_vendor` → `# --- Values and identifiers ---`
- `def run_command` → `# --- Shell + interfaces ---`
- `def run_layer_checks` → `# --- Checks 1-10 ---`
- `def collect_devices` → `# --- Device inventory ---`
- `def build_parser` → `# --- CLI ---`

Example for the first one:

```python
# --- Types and constants ----------------------------------------------------
class Status(enum.Enum):
```

- [ ] **Step 3: Verify**

Run: `python3 -m unittest discover -s tests`
Expected: `Ran 231 tests ... OK`

- [ ] **Step 4: Commit**

```bash
git add netcheck.py
git commit -m "docs: add section banners and file contents map"
```

---

## Task 3: Fix the hardcoded cascade hint in `check_switches`

**Files:**
- Modify: `netcheck.py` (`check_switches`, ~line 1326)
- Modify: `USAGE.md` (check-5 troubleshooting line listing `dlink4`→26, `dlink5`→27)
- Test: `tests/test_switches.py`

**Interfaces:**
- Consumes: `uplink_ports_for(cfg, switch) -> set[int]` (already defined ~line 348).
- Produces: `check_switches(cfg, ping_fn=ping) -> CheckResult` — unchanged signature; only the WARN `detail` wording/ports change.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_switches.py` inside `TestSwitches`:

```python
    def test_cascade_hint_uses_configured_uplink(self):
        cfg = Config(uplink_ports={23, 24, 25, 26, 27},
                     uplink_ports_by_switch={"dlink4": {25}})
        result = check_switches(cfg, ping_fn=_ping)  # dlink4 is down in _ping
        self.assertIn("25", result.detail)
        self.assertNotIn("26", result.detail)
```

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest tests.test_switches.TestSwitches.test_cascade_hint_uses_configured_uplink -v`
Expected: FAIL — detail contains `26` from the hardcoded map.

- [ ] **Step 3: Replace the hardcoded map**

In `netcheck.py`, replace the body from `cascade = {...}` through the return with:

```python
    hints: list[str] = []
    for name in down:
        if name == "dlink1":
            hints.append("dlink1 unreachable (management path or switch 1 problem)")
            continue
        ports = sorted(uplink_ports_for(cfg, name))
        where = ", ".join(str(port) for port in ports) if ports else "its uplink"
        hints.append(f"{name} unreachable (check its uplink port(s) {where} to dlink1)")
    return CheckResult(5, "Switches", Status.WARN, detail="\n".join(hints),
                       likely_cause="One or more switches are not answering management pings.",
                       suggested_fix="Reseat the cascade/uplink cable and confirm the mgmt IP.")
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `python3 -m unittest tests.test_switches -v`
Expected: all `TestSwitches` tests pass (existing ones assert `dlink4` and newline separation, still true).

- [ ] **Step 5: Update the doc**

In `USAGE.md`, change the check-5 troubleshooting sentence that names the cascade ports:

```markdown
**A switch is unreachable (check 5 WARN).** The hint names that switch's own
uplink port(s) toward dlink1, taken from `uplink_ports`. Reseat that cable and
confirm the management IP. `dlink1` unreachable points at the management path or
switch 1 itself.
```

- [ ] **Step 6: Verify**

Run: `python3 -m unittest discover -s tests`
Expected: `Ran 232 tests ... OK`

- [ ] **Step 7: Commit**

```bash
git add netcheck.py USAGE.md tests/test_switches.py
git commit -m "fix: derive switch cascade hint from configured uplink ports"
```

---

## Task 4: Decompose `run_all`

**Files:**
- Modify: `netcheck.py` (`run_all`, ~line 2120)
- Test: `tests/test_orchestration.py` (existing orchestration tests are the contract)

**Interfaces:**
- Consumes: `ensure_mgmt_address`, `format_command`, `_report_mgmt`, `check_switches`, `check_rogue_dhcp`, `check_storm_hints`, `check_device_inventory`, `check_hardening`, `measure_storm_threshold`, `format_threshold_samples`, `run_layer_checks`, `resolve_lan_interface`.
- Produces: `run_all(...)` unchanged signature and behavior; two new nested helpers `_optin_checks()` and `_default_checks()`.

- [ ] **Step 1: Baseline — orchestration tests green**

Run: `python3 -m unittest tests.test_orchestration -v`
Expected: all pass.

- [ ] **Step 2: Restructure the body**

Inside `run_all`, keep the existing `_run_check` and `_mgmt_gate` nested helpers, the `_diag` preamble, and the `if lan is None:` block exactly as they are. Replace the `try:` block body with two nested functions plus a two-line dispatch, so the whole `try` becomes:

```python
    def _optin_checks() -> None:
        """Opt-in checks (8 inventory, 9 hardening, 10 thresholds) run alone."""
        if inventory:
            first_id, first_title = 8, "Device inventory"
        elif hardening:
            first_id, first_title = 9, "Hardening audit"
        else:
            first_id, first_title = 10, "Storm thresholds"
        if not _mgmt_gate(first_id, first_title):
            return

        measured: dict[str, dict] = {}

        def _measure() -> None:
            measured.update(measure_storm_threshold(
                cfg, sample_seconds=sample, source=source_for("10.90.90.90")))

        if inventory:
            local_macs = read_interface_macs(lan.name) if lan else set()

            def _inventory_optin() -> None:
                reporter.add(check_device_inventory(
                    cfg, [], source=source_for("10.90.90.90"),
                    local_macs=local_macs))

            _run_check(8, "Device inventory", _inventory_optin)

        if hardening:
            def _hardening() -> None:
                if sample is not None and not measured:
                    _measure()
                reporter.add(check_hardening(cfg, measured=measured,
                                             source=source_for("10.90.90.90")))

            _run_check(9, "Hardening audit", _hardening)

        if sample is not None:
            def _thresholds() -> None:
                if not measured:
                    _measure()
                reporter.add(format_threshold_samples(measured))

            _run_check(10, "Storm thresholds", _thresholds)

    def _default_checks() -> None:
        """The default suite: checks 1-4 then 5, 6, 7."""
        layer_ping = lambda host, **kw: ping(host, runner=runner,  # noqa: E731
                                             source=source_for(host), **kw)
        layer_query = lambda server, name, **kw: dns_query(  # noqa: E731
            server, name, timeout=kw.get("timeout", cfg.timeout),
            source=source_for(server))
        run_layer_checks(cfg, reporter,
                         local_fn=lambda: detect_local_config(cfg, runner, lan=lan),
                         ping_fn=layer_ping, query_fn=layer_query)
        if quick:
            return
        if not _mgmt_gate(5, "Switches"):
            return

        _run_check(5, "Switches",
                   lambda: reporter.add(check_switches(cfg, ping_fn=layer_ping)))

        def _rogue() -> None:
            result, _macs = check_rogue_dhcp(cfg, iface=lan.name if lan else None)
            reporter.add(result)

        _run_check(6, "Rogue DHCP", _rogue)

        def _storm() -> None:
            gateway_ping = ping(cfg.gateway, count=4, timeout=cfg.timeout,
                                runner=runner, source=source_for(cfg.gateway))
            reporter.add(check_storm_hints(cfg, gateway_ping))

        _run_check(7, "Loop/storm hints", _storm)

    try:
        if inventory or hardening or sample is not None:
            _optin_checks()
        else:
            _default_checks()
    except Exception as exc:  # noqa: BLE001 - last-resort guard
        if verbose:
            import traceback
            traceback.print_exc()
        reporter.add(CheckResult(98, "Internal error", Status.WARN, detail=str(exc),
                                 likely_cause="An unexpected error interrupted the checks.",
                                 suggested_fix="Re-run with --verbose for details."))
```

- [ ] **Step 3: Verify behavior is unchanged**

Run: `python3 -m unittest tests.test_orchestration -v`
Expected: all pass (default order `[1..7]`, opt-in `[8,9]`, sample `[10]`, inventory absence, mgmt gate, internal error).

- [ ] **Step 4: Full suite**

Run: `python3 -m unittest discover -s tests`
Expected: `Ran 232 tests ... OK`

- [ ] **Step 5: Commit**

```bash
git add netcheck.py
git commit -m "refactor: split run_all into opt-in and default check groups"
```

---

## Task 5: Docstrings and comments for the non-obvious internals

**Files:**
- Modify: `netcheck.py` (BER/SNMP block, interface helpers, inventory helpers, `Reporter`)
- Test: `tests/` (existing suite is the regression)

**Interfaces:**
- Consumes: Task 4's structure.
- Produces: no behavior change; documentation only.

- [ ] **Step 1: Add docstrings to every top-level `def` and `class` that lacks one**

Apply the convention: a one-line imperative summary; add a second paragraph only for the tricky ones. The tricky ones MUST explain intent, not restate code:

```python
def ber_encode_length(n: int) -> bytes:
    """Encode a BER length in short or long form."""

def resolve_ifindex_ports(client) -> dict[int, int]:
    """Map FDB ifindex values to bridge port numbers."""

def _trunk_ports(devs, switch, configured, min_macs=_TRUNK_MIN_MACS):
    """Configured uplinks plus ports that learn enough MACs to be a trunk.

    A port carrying an inter-switch cascade or the router sees many MACs; that
    makes it infrastructure even when it is missing from uplink_ports.
    """

def read_interface_dns(iface, runner=run_command):
    """Per-interface DNS when the platform tracks it, else None (use global)."""

def _dhcp_chaddr(mac):
    """BOOTP chaddr: a real NIC MAC padded to 16 bytes, else zeros."""
```

Also add a brief comment in `scapy_dhcp_discover` above the packet build:

```python
        # Use the NIC's real MAC and request a broadcast reply (flag 0x8000):
        # servers often unicast the OFFER to chaddr, which a zero MAC never receives.
```

- [ ] **Step 2: Verify every top-level symbol has a docstring**

Run:

```bash
python3 - <<'PY'
import ast
src = open("netcheck.py").read()
missing = [(n.lineno, n.name) for n in ast.walk(ast.parse(src))
           if isinstance(n, (ast.FunctionDef, ast.ClassDef))
           and ast.get_docstring(n) is None]
print(missing or "all documented")
PY
```

Expected: `all documented`

- [ ] **Step 3: Verify tests**

Run: `python3 -m unittest discover -s tests`
Expected: `Ran 232 tests ... OK`

- [ ] **Step 4: Commit**

```bash
git add netcheck.py
git commit -m "docs: docstring and comment the non-obvious internals"
```

---

## Task 6: Static sweep and Windows DNS aggregation

**Files:**
- Modify: `netcheck.py` (`read_dns_servers`, add `parse_windows_dns`)
- Test: `tests/test_local_config.py`

**Interfaces:**
- Consumes: `read_dns_servers(runner=run_command) -> list[str]`.
- Produces: `parse_windows_dns(text: str) -> list[str]` — all DNS servers across every adapter, de-duplicated, order preserved. `read_dns_servers` uses it on Windows.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_local_config.py`:

```python
    def test_windows_dns_aggregates_all_adapters(self):
        text = (
            "Ethernet adapter Ethernet:\n"
            "   DNS Servers . . . . . . . . . . . : 58.71.2.8\n"
            "                                       45.63.30.117\n"
            "Ethernet adapter Wi-Fi:\n"
            "   DNS Servers . . . . . . . . . . . : 192.168.68.1\n"
        )
        self.assertEqual(parse_windows_dns(text),
                         ["58.71.2.8", "45.63.30.117", "192.168.68.1"])

    def test_windows_dns_deduplicates(self):
        text = ("DNS Servers . . . . . . . . . . . : 1.1.1.1\n"
                "DNS Servers . . . . . . . . . . . : 1.1.1.1\n")
        self.assertEqual(parse_windows_dns(text), ["1.1.1.1"])
```

Add `parse_windows_dns` to the import list at the top of the file.

- [ ] **Step 2: Run it to verify it fails**

Run: `python3 -m unittest tests.test_local_config.TestWiredCheckOne.test_windows_dns_aggregates_all_adapters -v`
Expected: FAIL — `ImportError: cannot import name 'parse_windows_dns'`.

- [ ] **Step 3: Implement the aggregator and use it**

Add directly above `read_dns_servers` in `netcheck.py`:

```python
def parse_windows_dns(text: str) -> list[str]:
    """Every DNS server across all adapters in ``ipconfig /all`` output."""
    servers: list[str] = []
    for block in re.findall(r"DNS Servers[^:]*:\s*((?:[\d.\s])+)", text):
        for ip in re.findall(r"\d+\.\d+\.\d+\.\d+", block):
            if ip not in servers:
                servers.append(ip)
    return servers
```

Then change the Windows branch of `read_dns_servers` from `return parse_ipconfig_windows(out).dns` to:

```python
    if sys.platform.startswith("win"):
        _, out, _ = runner(["ipconfig", "/all"])
        return parse_windows_dns(out) or parse_ipconfig_windows(out).dns
```

The fallback keeps the old behavior if the shared-adapter output format ever fails to match.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_local_config -v`
Expected: all pass, including the two new tests.

- [ ] **Step 5: Unused-import / dead-code scan**

Run: `python3 -m compileall -q netcheck.py` then scan for imports that are never referenced:

```bash
for m in argparse configparser enum ipaddress json os random re shlex shutil socket struct subprocess sys textwrap time; do
  n=$(grep -c "\b$m\b" netcheck.py)
  [ "$n" -le 1 ] && echo "possibly unused: $m ($n)"
done
```

Expected: no output. If any module is reported, remove its import line and re-run the full suite. Do not remove `parse_debug_info` — it is retained and unit-tested on purpose (see its comment).

- [ ] **Step 6: Full suite**

Run: `python3 -m unittest discover -s tests`
Expected: `Ran 234 tests ... OK`

- [ ] **Step 7: Commit**

```bash
git add netcheck.py tests/test_local_config.py
git commit -m "fix: aggregate Windows DNS across all adapters"
```

---

## Final verification (after all tasks)

- [ ] `python3 -m compileall -q netcheck.py` — no output.
- [ ] `python3 -m unittest discover -s tests` — all tests `OK`.
- [ ] Live smoke where the fabric is reachable:
  - `python3 netcheck.py --quick` → checks 1–4
  - `python3 netcheck.py` → checks 1–7
  - `python3 netcheck.py --inventory --verbose` → check 8 only, with FDB dump
  - `python3 netcheck.py --hardening` → check 9 only
  - `python3 netcheck.py --sample 5` → check 10 only
  - `python3 netcheck.py --json | python3 -m json.tool` → valid JSON
- [ ] `git log --oneline` shows one commit per task; `git diff <first-task-parent>..HEAD -- netcheck.py` contains no unintended output/behavior changes beyond Task 3 and Task 6.

## Self-review notes

- Spec coverage: §4.2 → Tasks 1–2; §4.3 → Tasks 4–5; §4.4 → Tasks 3 and 6; §4.5 → Task 5; §4.6 → per-task verify + Final verification.
- Placeholders: none; every step has concrete code/commands.
- Type consistency: `parse_windows_dns(text: str) -> list[str]` is defined in Task 6 and imported by its test; `uplink_ports_for(cfg, switch) -> set[int]` (pre-existing) is the only new dependency in Task 3; `run_all`'s signature is unchanged in Task 4.
