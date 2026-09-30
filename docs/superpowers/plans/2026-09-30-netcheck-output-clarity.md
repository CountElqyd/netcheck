# netcheck Output Clarity + Diagnostics Honesty Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `netcheck`'s output aligned and scannable, make check 6 state plainly whether the rogue-DHCP probe ran and why, always emit check 7, and stop one failing fabric check from silently dropping the checks after it.

**Architecture:** All changes stay inside the single-file `netcheck.py` plus its test files. Four units change: `Reporter.render` (presentation), the check-6 probe (`scapy_dhcp_discover` + `check_rogue_dhcp`), the check-7 emission, and the `run_all` orchestrator (per-check isolation). `nmap` is removed; check 6 is scapy-only. Read-only guarantees are unchanged.

**Tech Stack:** Python 3.10+ standard library (`dataclasses`, `enum`, `unittest`), optional `scapy` for check 6, no new dependencies.

**Spec:** `docs/superpowers/specs/2026-09-29-netcheck-design.md` (original tool design; this plan is the change design, agreed in chat on 2026-09-30).

## Global Constraints

- Python floor 3.10; standard library only for the default path; `scapy` stays optional and lazily imported.
- The tool remains **read-only** against switches, router, and OS: no SNMP SET, no CLI config, no config writes.
- Check 6 is **scapy-only**. The `nmap` fallback is removed everywhere (code, tests, docs).
- Result lines keep the ASCII ` - ` detail separator (Windows-console safe). Middle dot `·` and em dash `—` are used only in the Summary/Legend footer.
- Secrets (SNMP community, switch password) are never printed or logged.
- All tests run with stdlib `unittest`: `python3 -m unittest discover -s tests -v`.
- Commit steps are included per the writing-plans convention; do not run `git commit` unless your human partner has approved committing.

---

### Task 1: Aligned, summarized render

**Files:**
- Modify: `netcheck.py` (`_RESET`/`_COLORS` block ~line 36; `Reporter.render` ~lines 55-69)
- Test: `tests/test_reporter.py`

**Interfaces:**
- Consumes: `CheckResult`, `Status`, `Reporter` (existing).
- Produces: `Reporter.render() -> str` unchanged signature; output now aligned with a Summary/Legend footer. `_TITLE_COL = 24` module constant.

- [ ] **Step 1: Update the existing render assertion and add the new failing tests**

Replace `test_render_contains_lines_and_fix` in `tests/test_reporter.py` and append four tests:

```python
    def test_render_contains_lines_and_fix(self):
        r = Reporter(color=False)
        r.add(CheckResult(6, "Rogue DHCP", Status.FAIL, detail="192.168.1.77",
                          likely_cause="rogue server", suggested_fix="unplug it"))
        text = r.render()
        self.assertIn("[FAIL]", text)
        self.assertIn("6. Rogue DHCP", text)
        self.assertIn("Likely cause: rogue server", text)
        self.assertIn("Suggested fix: unplug it", text)

    def test_render_has_legend_and_summary(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "Local config", Status.PASS, detail="ok"))
        r.add(CheckResult(2, "Gateway", Status.WARN, detail="loss"))
        r.add(CheckResult(3, "Internet by IP", Status.FAIL, detail="down"))
        text = r.render()
        self.assertIn("Legend:", text)
        self.assertIn("1 PASS", text)
        self.assertIn("1 WARN", text)
        self.assertIn("1 FAIL", text)
        self.assertIn("exit code 2", text)

    def test_render_aligns_detail_column(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "A", Status.PASS, detail="one"))
        r.add(CheckResult(2, "Long title here", Status.PASS, detail="two"))
        lines = [ln for ln in r.render().splitlines() if ln.startswith("[PASS]")]
        self.assertEqual(lines[0].index(" - "), lines[1].index(" - "))

    def test_render_placeholders_missing_cause(self):
        r = Reporter(color=False)
        r.add(CheckResult(9, "Hardening audit", Status.WARN, suggested_fix="do x"))
        text = r.render()
        self.assertIn("Likely cause: -", text)
        self.assertIn("Suggested fix: do x", text)

    def test_render_omits_cause_block_when_absent(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "Local config", Status.PASS, detail="ok"))
        text = r.render()
        self.assertNotIn("Likely cause:", text)
        self.assertNotIn("Suggested fix:", text)
```

- [ ] **Step 2: Run the reporter tests to verify they fail**

Run: `python3 -m unittest tests.test_reporter -v`
Expected: `test_render_contains_lines_and_fix` fails (`"[FAIL] 6. Rogue DHCP"` no longer present because of the padded id column), and the three new structural tests fail (`Legend:`/`Summary:` absent, columns unaligned, no `-` placeholder).

- [ ] **Step 3: Add the title-width constant**

In `netcheck.py`, below `_RESET`:

```python
_RESET = "\033[0m"
_TITLE_COL = 24
```

- [ ] **Step 4: Replace `Reporter.render`**

```python
    def render(self) -> str:
        lines: list[str] = []
        heads = [f"{r.id:>2}. {r.title}" for r in self.results]
        title_width = min(max((len(h) for h in heads), default=0), _TITLE_COL)
        for head, r in zip(heads, self.results):
            plain_tag = f"[{r.status.value}]"
            tag = plain_tag
            if self.color:
                tag = f"{_COLORS[r.status]}{plain_tag}{_RESET}"
            line = f"{tag} {head:<{title_width}}"
            if r.detail:
                line += f" - {r.detail}"
            lines.append(line)
            if r.likely_cause or r.suggested_fix:
                lines.append("    Likely cause: " + (r.likely_cause or "-"))
                lines.append("    Suggested fix: " + (r.suggested_fix or "-"))
        if self.results:
            counts = {s: sum(1 for r in self.results if r.status is s) for s in Status}
            lines.append("")
            lines.append(f"Summary: {counts[Status.PASS]} PASS · {counts[Status.WARN]} WARN · "
                         f"{counts[Status.FAIL]} FAIL  (exit code {self.exit_code()})")
            lines.append("Legend:  PASS healthy  ·  WARN needs attention  ·  "
                         "FAIL broken — fix FAILs first")
        return "\n".join(lines)
```

- [ ] **Step 5: Run the reporter tests to verify they pass**

Run: `python3 -m unittest tests.test_reporter -v`
Expected: PASS (all reporter tests).

- [ ] **Step 6: Run the full suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS. (`test_docs.py`, `test_orchestration.py`, and `test_cli.py` do not assert on render text.)

- [ ] **Step 7: Commit**

```bash
git add netcheck.py tests/test_reporter.py
git commit -m "feat(output): align columns, add legend and summary footer"
```

---

### Task 2: Honest, scapy-only check 6

**Files:**
- Modify: `netcheck.py` (remove `parse_nmap_dhcp` ~lines 864-871; add `DhcpProbe` after `RogueResponder` ~line 861; rewrite `scapy_dhcp_discover` ~lines 874-892 and `check_rogue_dhcp` ~lines 895-919)
- Test: `tests/test_dhcp.py`
- Modify: `netcheck.py` `run_all` call site (`check_rogue_dhcp(cfg, runner=runner)` → `check_rogue_dhcp(cfg)`) — the surrounding restructure is Task 3, this is the one-line call fix so the file imports/tests stay green.

**Interfaces:**
- Consumes: `RogueResponder`, `Config`, `Status`, `CheckResult`, `lookup_vendor` (existing).
- Produces:
  - `@dataclass DhcpProbe(responders: list[RogueResponder] | None, reason: str = "")`
  - `scapy_dhcp_discover(timeout: float = 5.0) -> DhcpProbe` (never returns `None`)
  - `check_rogue_dhcp(cfg: Config, discover_fn=None) -> tuple[CheckResult, list[str]]`
  - `parse_nmap_dhcp` is **deleted**.

- [ ] **Step 1: Rewrite `tests/test_dhcp.py`**

```python
import builtins
import unittest
from unittest import mock

from netcheck import (
    Config,
    DhcpProbe,
    RogueResponder,
    Status,
    check_rogue_dhcp,
    scapy_dhcp_discover,
)


class TestDhcp(unittest.TestCase):
    def test_rogue_fails(self):
        rogue = RogueResponder("192.168.1.77", "AA:BB:CC:DD:EE:FF", "TP-Link")
        result, macs = check_rogue_dhcp(
            Config(), discover_fn=lambda cfg=None: DhcpProbe([rogue]))
        self.assertIs(result.status, Status.FAIL)
        self.assertEqual(macs, ["AA:BB:CC:DD:EE:FF"])
        self.assertIn("via scapy", result.detail)

    def test_clean_passes_with_method(self):
        gw = RogueResponder("192.168.1.1", "00:1E:58:00:00:01", "D-Link")
        result, macs = check_rogue_dhcp(
            Config(), discover_fn=lambda cfg=None: DhcpProbe([gw]))
        self.assertIs(result.status, Status.PASS)
        self.assertEqual(macs, [])
        self.assertIn("probed via scapy", result.detail)
        self.assertIn("192.168.1.1", result.detail)

    def test_unavailable_warns_with_reason(self):
        result, _ = check_rogue_dhcp(
            Config(), discover_fn=lambda cfg=None: DhcpProbe(None, "scapy not installed"))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("not tested", result.detail)
        self.assertIn("scapy not installed", result.detail)

    def test_no_responders_warns(self):
        result, _ = check_rogue_dhcp(
            Config(), discover_fn=lambda cfg=None: DhcpProbe([]))
        self.assertIs(result.status, Status.WARN)
        self.assertIn("no DHCP server answered", result.detail)

    def test_scapy_missing_reports_reason(self):
        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "scapy.all":
                raise ImportError("no scapy")
            return real_import(name, *args, **kwargs)

        with mock.patch("builtins.__import__", side_effect=fake_import):
            probe = scapy_dhcp_discover()
        self.assertIsInstance(probe, DhcpProbe)
        self.assertIsNone(probe.responders)
        self.assertIn("scapy not installed", probe.reason)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the DHCP tests to verify they fail**

Run: `python3 -m unittest tests.test_dhcp -v`
Expected: FAIL/ERROR — `DhcpProbe` is not importable and `check_rogue_dhcp` rejects a plain `[]`/`None` return under the new contract.

- [ ] **Step 3: Add the `DhcpProbe` dataclass**

In `netcheck.py`, immediately after the `RogueResponder` dataclass:

```python
@dataclass
class DhcpProbe:
    responders: list[RogueResponder] | None
    reason: str = ""
```

- [ ] **Step 4: Delete `parse_nmap_dhcp`**

Remove the whole `parse_nmap_dhcp` function (the `def parse_nmap_dhcp(text: str) -> list[RogueResponder]:` block). Nothing else may reference it after this task.

- [ ] **Step 5: Replace `scapy_dhcp_discover`**

```python
def scapy_dhcp_discover(timeout: float = 5.0) -> DhcpProbe:
    try:
        from scapy.all import DHCP, BOOTP, Ether, IP, UDP, srp
    except ImportError:
        return DhcpProbe(None, "scapy not installed")
    try:
        packet = (Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
                  / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=b"\x00" * 16)
                  / DHCP(options=[("message-type", "discover"), "end"]))
        answered, _ = srp(packet, timeout=timeout, verbose=False)
    except PermissionError:
        return DhcpProbe(None, "raw sockets denied (needs root or CAP_NET_RAW)")
    except OSError as exc:
        return DhcpProbe(None, f"raw sockets unavailable ({exc})")
    except Exception as exc:  # noqa: BLE001 - scapy raises assorted types
        return DhcpProbe(None, f"scapy probe failed: {exc}")
    found: dict[str, RogueResponder] = {}
    for _sent, received in answered:
        if received.haslayer(DHCP):
            server_ip = received[IP].src
            mac = received[Ether].src
            found[server_ip] = RogueResponder(server_ip, mac, lookup_vendor(mac))
    return DhcpProbe(list(found.values()))
```

- [ ] **Step 6: Replace `check_rogue_dhcp`**

```python
def check_rogue_dhcp(cfg: Config, discover_fn=None) -> tuple[CheckResult, list[str]]:
    if discover_fn is None:
        discover_fn = lambda cfg=None: scapy_dhcp_discover()
    probe = discover_fn(cfg)
    if probe.responders is None:
        return (CheckResult(6, "Rogue DHCP", Status.WARN,
                            detail=f"not tested: {probe.reason}",
                            likely_cause="The rogue-DHCP probe could not run.",
                            suggested_fix="Install scapy (uv run --with scapy netcheck.py) "
                                          "and run as root/administrator."),
                [])
    responders = probe.responders
    if not responders:
        return (CheckResult(6, "Rogue DHCP", Status.WARN,
                            detail="probed via scapy; no DHCP server answered on this segment",
                            likely_cause="No DHCP offer was seen, though this host holds a lease.",
                            suggested_fix="Re-run while a client renews; confirm the tool runs "
                                          "as root/administrator."),
                [])
    rogues = [r for r in responders if r.server_ip != cfg.gateway]
    if not rogues:
        return (CheckResult(6, "Rogue DHCP", Status.PASS,
                            detail=f"probed via scapy; only the trusted gateway {cfg.gateway} "
                                   "answered"),
                [])
    listing = ", ".join(f"{r.server_ip} ({r.mac}{', ' + r.vendor if r.vendor else ''})"
                        for r in rogues)
    return (CheckResult(6, "Rogue DHCP", Status.FAIL, detail=f"via scapy: {listing}",
                        likely_cause="A non-gateway DHCP server is handing out leases.",
                        suggested_fix="Trace the responder MAC (check 7) and unplug it; "
                                      "enable DHCP Server Screening on access ports."),
            [r.mac for r in rogues if r.mac])
```

- [ ] **Step 7: Fix the `run_all` call site so the module still runs**

In `run_all`, change:

```python
        rogue_result, rogue_macs = check_rogue_dhcp(cfg, runner=runner)
```

to:

```python
        rogue_result, rogue_macs = check_rogue_dhcp(cfg)
```

(Task 3 replaces the surrounding block; this keeps the module consistent in the meantime.)

- [ ] **Step 8: Run the DHCP and full tests**

Run: `python3 -m unittest tests.test_dhcp -v`
Expected: PASS.
Run: `python3 -m unittest discover -s tests -v`
Expected: PASS (no remaining `parse_nmap_dhcp` references).

- [ ] **Step 9: Commit**

```bash
git add netcheck.py tests/test_dhcp.py
git commit -m "feat(dhcp): scapy-only probe with explicit unavailable/no-answer outcomes"
```

---

### Task 3: Always-on check 7 and per-check isolation in `run_all`

**Files:**
- Modify: `netcheck.py` (`run_all`, ~lines 1325-1363)
- Test: `tests/test_orchestration.py`

**Interfaces:**
- Consumes: `check_switches`, `check_rogue_dhcp`, `check_hardening`, `check_storm_hints`, `trace_mac`, `measure_storm_threshold`, `apply_fixes`, `CheckResult`, `Status`, `ping` (existing).
- Produces: `run_all` unchanged signature; new behavior — each fabric check (5, 6, 9, 8, 7) is individually guarded, check 7 always emits exactly once, and a single check failure emits that check's `WARN` instead of aborting the rest.

- [ ] **Step 1: Update `tests/test_orchestration.py`**

Replace `test_run_all_contains_unexpected_error` with the two tests below (keep the rest of the file):

```python
    def test_failing_check_does_not_stop_later_checks(self):
        reporter = netcheck.Reporter(color=False)
        orig_switches = netcheck.check_switches
        orig_rogue = netcheck.check_rogue_dhcp
        netcheck.check_switches = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("boom"))
        netcheck.check_rogue_dhcp = lambda *a, **k: (
            netcheck.CheckResult(6, "Rogue DHCP", netcheck.Status.PASS, detail="stub"), [])
        try:
            netcheck.run_all(netcheck.Config(), reporter, no_measure=True,
                             runner=lambda *a, **k: (0, "", ""))
        finally:
            netcheck.check_switches = orig_switches
            netcheck.check_rogue_dhcp = orig_rogue
        ids = [r.id for r in reporter.results]
        self.assertIn(5, ids)
        self.assertIn(7, ids)
        self.assertIn(8, ids)
        self.assertIn(9, ids)
        check5 = next(r for r in reporter.results if r.id == 5)
        self.assertIs(check5.status, netcheck.Status.WARN)
        self.assertIn("check failed", check5.detail)
        check7 = next(r for r in reporter.results if r.id == 7)
        self.assertIs(check7.status, netcheck.Status.PASS)
        self.assertIn("no rogue devices", check7.detail)

    def test_outer_handler_reports_internal_error(self):
        reporter = netcheck.Reporter(color=False)
        orig = netcheck.run_layer_checks
        netcheck.run_layer_checks = lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("phase-a boom"))
        try:
            netcheck.run_all(netcheck.Config(), reporter,
                             runner=lambda *a, **k: (0, "", ""))
        finally:
            netcheck.run_layer_checks = orig
        self.assertTrue(any(r.id == 98 for r in reporter.results))
```

- [ ] **Step 2: Run the orchestration tests to verify they fail**

Run: `python3 -m unittest tests.test_orchestration -v`
Expected: `test_failing_check_does_not_stop_later_checks` fails — without isolation, the `check_switches` raise produces a single id-98 result and no 5/7/8/9.

- [ ] **Step 3: Replace the body of `run_all`**

```python
def run_all(cfg: Config, reporter: Reporter, quick: bool = False,
            no_measure: bool = False, sample: float = 30.0, allow_fix: bool = True,
            tty=None, runner=run_command, verbose: bool = False) -> None:
    def _run_check(check_id: int, title: str, fn) -> None:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - isolate each fabric check
            if verbose:
                import traceback
                traceback.print_exc()
            reporter.add(CheckResult(check_id, title, Status.WARN,
                                     detail=f"check failed: {exc}",
                                     likely_cause="An unexpected error interrupted this check.",
                                     suggested_fix="Re-run with --verbose for details."))

    try:
        layer_ping = lambda host, **kw: ping(host, runner=runner, **kw)  # noqa: E731
        layer_query = lambda server, name, **kw: dns_query(  # noqa: E731
            server, name, timeout=kw.get("timeout", cfg.timeout))
        run_layer_checks(cfg, reporter,
                         local_fn=lambda: detect_local_config(runner),
                         ping_fn=layer_ping, query_fn=layer_query)
        if quick:
            return

        _run_check(5, "Switches",
                   lambda: reporter.add(check_switches(cfg, ping_fn=layer_ping)))

        rogue_macs: list[str] = []
        rogue_status: Status | None = None

        def _rogue() -> None:
            nonlocal rogue_status
            result, macs = check_rogue_dhcp(cfg)
            reporter.add(result)
            rogue_status = result.status
            rogue_macs.extend(macs)

        _run_check(6, "Rogue DHCP", _rogue)

        loop_ports: dict[str, list[int]] = {}

        def _hardening() -> None:
            measured = ({} if no_measure
                        else measure_storm_threshold(cfg, sample_seconds=sample))
            per_switch_measured = next(iter(measured.values()), None)
            result, ports = check_hardening(cfg, measured=per_switch_measured)
            reporter.add(result)
            loop_ports.update(ports)

        _run_check(9, "Hardening audit", _hardening)

        def _storm() -> None:
            gateway_ping = ping(cfg.gateway, count=4, timeout=cfg.timeout, runner=runner)
            reporter.add(check_storm_hints(cfg, gateway_ping, loop_ports))

        _run_check(8, "Loop/storm hints", _storm)

        def _trace() -> None:
            if rogue_macs:
                for mac in rogue_macs:
                    reporter.add(trace_mac(cfg, mac))
            elif rogue_status is Status.PASS:
                reporter.add(CheckResult(7, "MAC trace", Status.PASS,
                                         detail="no rogue devices to trace"))
            else:
                reporter.add(CheckResult(7, "MAC trace", Status.WARN,
                                         detail="skipped: no rogue MACs to trace"))

        _run_check(7, "MAC trace", _trace)

        fixed = apply_fixes(cfg, allow_fix=allow_fix, tty=tty, runner=runner)
        if fixed:
            reporter.add(CheckResult(99, "Fixes applied", Status.PASS,
                                     detail="; ".join(fixed)))
    except Exception as exc:  # noqa: BLE001 - last-resort guard (Phase A, fixes)
        if verbose:
            import traceback
            traceback.print_exc()
        reporter.add(CheckResult(98, "Internal error", Status.WARN, detail=str(exc),
                                 likely_cause="An unexpected error interrupted the checks.",
                                 suggested_fix="Re-run with --verbose for details."))
```

- [ ] **Step 4: Run the orchestration tests to verify they pass**

Run: `python3 -m unittest tests.test_orchestration -v`
Expected: PASS.

- [ ] **Step 5: Run the full suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS. `test_trace.py` is unchanged and must still pass.

- [ ] **Step 6: Commit**

```bash
git add netcheck.py tests/test_orchestration.py
git commit -m "feat(run): isolate fabric checks and always emit the MAC-trace line"
```

---

### Task 4: Update the operator guide

**Files:**
- Modify: `USAGE.md` (§3.4 table + note, §7.1 catalog rows 6 and 7, §9.3 sample output, §11 troubleshooting)
- Test: `tests/test_docs.py` (existing; run as a regression guard)

**Interfaces:**
- Consumes: the shipped behavior from Tasks 1-3.
- Produces: docs consistent with the new output and scapy-only check 6. No code changes.

- [ ] **Step 1: Remove the nmap fallback from §3.4**

In the "Privileges and optional tools" table, delete the `nmap` row:

```markdown
| `nmap` | Fallback rogue-DHCP probe | Install `nmap`; used automatically if scapy is absent |
```

Change the following note from:

```markdown
Without raw-socket rights, check 6 degrades to `nmap`, then to `WARN` — the rest
of the tool still works.
```

to:

```markdown
Without raw-socket rights (or without `scapy`), check 6 reports `WARN: not tested`
with the exact reason — the rest of the tool still works.
```

- [ ] **Step 2: Update the §7.1 catalog rows for checks 6 and 7**

Replace the `| 6 | ... |` and `| 7 | ... |` rows with:

```markdown
| 6 | Rogue DHCP | scapy broadcast discover (5 s); states whether it ran and the reason if not | PASS: only the trusted gateway. WARN: probe unavailable (reason) or no server answered. FAIL: any other responder |
| 7 | MAC trace | SNMP FDB walk from dlink1 (Telnet `debug info` fallback); always emits once | PASS: *Switch, port Y* (or port 23 = ISP side), or "no rogue devices to trace". WARN: MAC not learned, or skipped when no rogue MACs |
```

- [ ] **Step 3: Refresh the §9.3 sample output**

Replace the fenced sample with output matching the new renderer:

````markdown
```
[PASS]  1. Local config   - 192.168.1.50 gw 192.168.1.1 dns 58.71.2.8,45.63.30.117
[FAIL]  6. Rogue DHCP     - via scapy: 192.168.1.77 (aa:bb:cc:dd:ee:ff, TP-Link)
    Likely cause: A non-gateway DHCP server is handing out leases.
    Suggested fix: Trace the responder MAC (check 7) and unplug it; enable DHCP
                   Server Screening (Security) with 192.168.1.1 trusted.
[PASS]  7. Trace aa:bb:cc:dd:ee:ff - dlink1 port 5
[WARN]  9. Hardening audit - dlink1: Loopback Detection: disabled (recommended: enabled, recover time 0)
    Likely cause: -
    Suggested fix: Apply the baseline in USAGE.md.

Summary: 2 PASS · 1 WARN · 1 FAIL  (exit code 2)
Legend:  PASS healthy  ·  WARN needs attention  ·  FAIL broken — fix FAILs first
```

Each result's cause/fix block prints only when at least one is set; a missing
line shows `-`.
````

- [ ] **Step 4: Update §11 troubleshooting**

Replace the check-6 bullet:

```markdown
- **Check 6 WARN "needs root/scapy/nmap".** Run elevated, install `scapy` (or
  `nmap`), or accept the WARN.
```

with:

```markdown
- **Check 6 WARN "not tested: ...".** The detail names the reason (`scapy not
  installed`, `raw sockets denied`, ...). Install `scapy`
  (`uv run --with scapy netcheck.py`) and run as root/administrator, or accept
  the WARN.
```

- [ ] **Step 5: Run the docs and full tests**

Run: `python3 -m unittest tests.test_docs -v`
Expected: PASS.
Run: `python3 -m unittest discover -s tests -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add USAGE.md
git commit -m "docs: drop nmap fallback and document the clarified output"
```

---

### Task 5: End-to-end verification

**Files:**
- No file changes.

**Interfaces:**
- Consumes: the finished tool.
- Produces: a live run confirming no internal error and a complete check list.

- [ ] **Step 1: Run the tool**

Run: `uv run --with scapy netcheck.py --no-fix --no-color --sample 2`
Expected: checks 1, 5, 6, 9, 8, 7 every printed; **no** `[WARN] 98. Internal error`. On a non-office host, check 1 stays FAIL (by design) and check 6 prints a specific reason rather than "could not determine". Check 7 always prints.

- [ ] **Step 2: Confirm check 6 is self-explanatory**

Read the check-6 line. Expected: either `not tested: <reason>` with a concrete reason, `probed via scapy; no DHCP server answered on this segment`, or a PASS/FAIL naming the method (`via scapy`). If the reason is empty or the old "could not determine" text appears, the task is incomplete.

- [ ] **Step 3: Confirm the summary footer**

Expected footer, e.g.:

```
Summary: 2 PASS · 2 WARN · 1 FAIL  (exit code 2)
Legend:  PASS healthy  ·  WARN needs attention  ·  FAIL broken — fix FAILs first
```

---

## Self-Review

- **Spec coverage:** aligned output + legend + summary footer → Task 1; check 6 honesty + scapy-only (nmap removed) → Task 2 (code/tests) and Task 4 (docs); always-emit check 7 → Task 3; per-check isolation → Task 3; verification → Task 5. All agreed items (A–E) are covered.
- **Placeholder scan:** every code step contains runnable code; no TBD/TODO.
- **Type consistency:** `DhcpProbe(responders, reason)` is used identically in `scapy_dhcp_discover`, `check_rogue_dhcp`, and `tests/test_dhcp.py`; `check_rogue_dhcp(cfg, discover_fn=None)` returns `tuple[CheckResult, list[str]]` everywhere; `run_all` keeps its signature and the `Status` enum is used consistently.
- **Dead code:** `parse_nmap_dhcp` and its test are removed; no other reference remains (verified by grep before planning).
