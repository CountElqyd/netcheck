# netcheck Read-Only + Management Gate + Output Ordering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make netcheck strictly read-only (no local fixes), stop cleanly before the switch checks when `10.90.90.100/24` is absent, and clean up check ordering and multi-line output.

**Architecture:** All changes stay in the single-file `netcheck.py`. The management-address step becomes a pure presence check that prints the OS/interface-specific command and halts the fabric checks; the optional post-run local fixes and their `--no-fix`/`prompt_yes_no`/`open_tty` machinery are deleted. Fabric checks are reordered to ascending check-id, and the reporter becomes newline-aware so multi-line details (inventory, findings, hints) render without being collapsed.

**Tech Stack:** Python 3.10+ standard library only (`argparse`, `ipaddress`, `shlex`, `subprocess`, `textwrap`, `unittest`). Optional extras (`scapy`, `pysnmp`) remain untouched.

**Spec:** `docs/superpowers/specs/2026-10-02-netcheck-lan-pinning-design.md` §6 (management address) — this plan **modifies** that section (presence-only; no auto-add, no exit removal) and removes §10 "Optional fixes". User-approved deltas come from the 2026-10-02 planning conversation.

## Global Constraints

- `netcheck.py` stays a single file, standard-library only. No new dependencies.
- Strictly read-only: no SNMP SET, no switch/router config changes, and (new) no local OS changes. The only state-changing entry point that remains is the explicit `--remove-mgmt-ip` maintenance flag.
- Test command (must pass after every task): `python3 -m unittest discover -s tests -v`.
- New behavior needs tests under `tests/` and a docs update in `USAGE.md` (per `MAINTAINING.md`).
- Report check IDs in use: 1–10, 98 (internal error). ID 99 (fixes applied) is removed. Check 9 stays opt-in (`--hardening`); check 10 stays opt-in (`--sample`).
- Version bumps via git tags; also bump `__version__` in `netcheck.py` to `0.6.0`.

---

### Task 1: `format_command` display helper

**Files:**
- Modify: `netcheck.py` (add `import shlex` near line 688; add `format_command` immediately before `_report_mgmt`, currently line 1996)
- Test: `tests/test_mgmt_ip.py`

**Interfaces:**
- Produces: `format_command(argv: list[str], platform: str | None = None) -> str` — display-only command rendering; Windows uses `subprocess.list2cmdline` (quotes args with spaces), POSIX uses `shlex.join`. Execution paths are unaffected (they keep passing argv lists to `run_command`).

- [ ] **Step 1: Write the failing test**

Add to `tests/test_mgmt_ip.py` (import `format_command` in the existing `from netcheck import (...)` block):

```python
class TestFormatCommand(unittest.TestCase):
    def test_posix_default_has_no_quotes(self):
        self.assertEqual(
            format_command(["ifconfig", "en0", "alias", "10.90.90.100",
                            "255.255.255.0"], platform="linux"),
            "ifconfig en0 alias 10.90.90.100 255.255.255.0")

    def test_posix_quotes_argument_with_space(self):
        self.assertEqual(
            format_command(["ip", "addr", "replace", "a b"], platform="linux"),
            "ip addr replace 'a b'")

    def test_windows_quotes_interface_with_spaces(self):
        self.assertEqual(
            format_command(["netsh", "interface", "ipv4", "add", "address",
                            "Local Area Connection", "10.90.90.100",
                            "255.255.255.0"], platform="win32"),
            'netsh interface ipv4 add address "Local Area Connection" '
            "10.90.90.100 255.255.255.0")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_mgmt_ip.TestFormatCommand -v`
Expected: FAIL/ERROR with `ImportError: cannot import name 'format_command'`.

- [ ] **Step 3: Implement `format_command`**

Change the import block at `netcheck.py:688-689` from:

```python
import re
import subprocess
```

to:

```python
import re
import shlex
import subprocess
```

Then add immediately before `def _report_mgmt(...)` (currently line 1996):

```python
def format_command(argv: list[str], platform: str | None = None) -> str:
    """Render an argv list for display (never for execution)."""
    platform = platform or sys.platform
    if platform.startswith("win"):
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m unittest tests.test_mgmt_ip -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_mgmt_ip.py
git commit -m "feat: add format_command display helper"
```

---

### Task 2: Management-address gate becomes presence-only

**Files:**
- Modify: `netcheck.py` (`ensure_mgmt_address` at 1930-1950, `_report_mgmt` at 1996-2005, the `ensure_mgmt_address(...)` call inside `run_all` at 2054-2055)
- Test: `tests/test_mgmt_ip.py`

**Interfaces:**
- Consumes: `format_command` (Task 1); `_lan_has_mgmt`, `_validate_mgmt_address`, `mgmt_add_argv`.
- Produces: `ensure_mgmt_address(cfg: Config, lan: LanInterface | None) -> MgmtAddressResult` (no `allow_fix`/`tty`/`runner`; never writes). `result.detail` is one of `"present"`, `"missing"`, `"no wired LAN interface"`; `result.command` is the add argv only when `"missing"`.

- [ ] **Step 1: Write the failing tests**

Replace the obsolete add/decline tests in `tests/test_mgmt_ip.py` (`test_present_does_not_prompt_or_run`, `test_missing_prompt_yes_adds_and_verifies`, `test_permission_failure_returns_command`, `test_declined_returns_command`, `test_no_fix_returns_command`) with:

```python
class TestEnsureMgmtAddress(unittest.TestCase):
    def test_present_returns_present_and_no_command(self):
        result = ensure_mgmt_address(
            Config(), _lan("192.168.1.50", "10.90.90.100"))
        self.assertFalse(result.added)
        self.assertEqual(result.detail, "present")
        self.assertIsNone(result.command)

    def test_missing_returns_add_command_without_running(self):
        result = ensure_mgmt_address(Config(), _lan("192.168.1.50"))
        self.assertFalse(result.added)
        self.assertEqual(result.detail, "missing")
        self.assertEqual(result.command,
                         ["ip", "addr", "replace", "10.90.90.100/24",
                          "dev", "eth0"])

    def test_no_lan_is_a_no_op(self):
        result = ensure_mgmt_address(Config(), None)
        self.assertFalse(result.added)
        self.assertIsNone(result.command)

    def test_invalid_mgmt_address_raises(self):
        with self.assertRaises(ValueError):
            ensure_mgmt_address(Config(mgmt_address="8.8.8.8"),
                                _lan("192.168.1.50"))
```

(Remove the now-unused `from unittest import mock` import only if nothing else in the file uses it; `remove_mgmt_address` tests do not. Keep it if lint is not enforced — but prefer removing.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_mgmt_ip.TestEnsureMgmtAddress -v`
Expected: FAIL — TypeError (unexpected kwargs) / `detail` mismatch.

- [ ] **Step 3: Rewrite `ensure_mgmt_address`**

Replace `netcheck.py:1930-1950` with:

```python
def ensure_mgmt_address(cfg: Config, lan: LanInterface | None) -> MgmtAddressResult:
    if lan is None:
        return MgmtAddressResult(False, detail="no wired LAN interface")
    addr = _validate_mgmt_address(cfg)
    if lan.name.startswith("-"):
        raise ValueError(f"invalid interface name {lan.name!r}")
    if _lan_has_mgmt(lan, cfg):
        return MgmtAddressResult(False, addr, lan.name, None, "present")
    return MgmtAddressResult(False, addr, lan.name,
                             mgmt_add_argv(lan.name, addr), "missing")
```

- [ ] **Step 4: Rewrite `_report_mgmt`**

Replace `netcheck.py:1996-2005` with:

```python
def _report_mgmt(result: MgmtAddressResult) -> None:
    if result.detail != "missing" or not result.command:
        return
    command = format_command(result.command)
    print(f"add {result.address}/24 to {result.interface} for switch access, "
          "then re-run netcheck:")
    if sys.platform.startswith("win"):
        print(f"  run as Administrator: {command}")
    else:
        print(f"  sudo {command}")
```

- [ ] **Step 5: Update the call site in `run_all`**

In `netcheck.py`, change the block at 2054-2055 from:

```python
        mgmt = ensure_mgmt_address(cfg, lan, allow_fix=allow_fix, tty=tty,
                                   runner=runner)
```

to:

```python
        mgmt = ensure_mgmt_address(cfg, lan)
```

(The surrounding `added_mgmt`/`_report_mgmt`/`if mgmt.added:`/`finally` logic remains until Task 3; `mgmt.added` is now always `False`.)

- [ ] **Step 6: Run the suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS (run_all tests still pass because they mock `ensure_mgmt_address` or land `lan=None`).

- [ ] **Step 7: Commit**

```bash
git add netcheck.py tests/test_mgmt_ip.py
git commit -m "refactor: make management-address gate presence-only"
```

---

### Task 3: Read-only run, gate stop, and numeric check order

**Files:**
- Modify: `netcheck.py` (parser `--no-fix` at 141; `main` call at 202; `run_all` at 2008-2125; delete `apply_fixes` 1967-1993, `dns_servers` 1963-1964, `prompt_yes_no` 1870-1880, `open_tty` 1861-1867, `from typing import TextIO` 1858)
- Modify: `tests/test_orchestration.py`
- Delete: `tests/test_fixes.py`

**Interfaces:**
- Consumes: `ensure_mgmt_address(cfg, lan)` (Task 2), `_report_mgmt` (Task 2).
- Produces: `run_all(cfg, reporter, quick=False, sample=None, hardening=False, runner=run_command, verbose=False, lan=None) -> None` — no `allow_fix`, no `tty`. Fabric checks run/report in order `5, 6, 7, 8, [9], [10]`; on missing management address, `CheckResult(5, "Switches", WARN, detail="not run: <addr>/24 is not on <iface>")` is added and checks 6–10 are skipped.

- [ ] **Step 1: Write/adjust the failing orchestration tests**

In `tests/test_orchestration.py`:

1. Change `test_parser_has_flags` (lines 16-21) to drop `--no-fix`:

```python
    def test_parser_has_flags(self):
        parser = netcheck.build_parser()
        args = parser.parse_args(["--quick", "--hardening"])
        self.assertTrue(args.quick)
        self.assertTrue(args.hardening)
```

2. In `test_run_all_sources_pings_from_management_address` (line 243), change `allow_fix=False, runner=runner` to `runner=runner`.

3. Replace `test_run_all_removes_added_management_address` and `test_run_all_removes_management_address_when_reporting_fails` (250-293) with a gate test and an ordering test:

```python
    def test_run_all_stops_before_switch_checks_when_mgmt_missing(self):
        lan = netcheck.LanInterface(
            "eth0", "192.168.1.50", [netcheck.InterfaceAddr("192.168.1.50", 24)])
        reporter = netcheck.Reporter(color=False)
        orig_resolve = netcheck.resolve_lan_interface
        netcheck.resolve_lan_interface = lambda *a, **k: lan
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                netcheck.run_all(netcheck.Config(), reporter,
                                 runner=lambda *a, **k: (0, "", ""))
        finally:
            netcheck.resolve_lan_interface = orig_resolve
        ids = [r.id for r in reporter.results]
        self.assertNotIn(6, ids)
        check5 = next(r for r in reporter.results if r.id == 5)
        self.assertIs(check5.status, netcheck.Status.WARN)
        self.assertIn("not run", check5.detail)

    def test_run_all_runs_checks_in_numeric_order(self):
        lan = netcheck.LanInterface(
            "eth0", "192.168.1.50",
            [netcheck.InterfaceAddr("192.168.1.50", 24),
             netcheck.InterfaceAddr("10.90.90.100", 24)])
        reporter = netcheck.Reporter(color=False)
        orig = {name: getattr(netcheck, name) for name in (
            "resolve_lan_interface", "run_layer_checks", "check_switches",
            "check_rogue_dhcp", "check_device_inventory", "check_storm_hints")}

        def layer(cfg, rep, **k):
            for i in (1, 2, 3, 4):
                rep.add(netcheck.CheckResult(i, f"c{i}", netcheck.Status.PASS))

        netcheck.resolve_lan_interface = lambda *a, **k: lan
        netcheck.run_layer_checks = layer
        netcheck.check_switches = lambda *a, **k: netcheck.CheckResult(
            5, "Switches", netcheck.Status.PASS, detail="stub")
        netcheck.check_rogue_dhcp = lambda *a, **k: (
            netcheck.CheckResult(6, "Rogue DHCP", netcheck.Status.PASS,
                                 detail="stub"), [])
        netcheck.check_device_inventory = lambda *a, **k: netcheck.CheckResult(
            7, "Device inventory", netcheck.Status.PASS, detail="stub")
        netcheck.check_storm_hints = lambda *a, **k: netcheck.CheckResult(
            8, "Loop/storm hints", netcheck.Status.PASS, detail="stub")
        try:
            netcheck.run_all(netcheck.Config(), reporter,
                             runner=lambda *a, **k: (0, "", ""))
        finally:
            for name, fn in orig.items():
                setattr(netcheck, name, fn)
        self.assertEqual([r.id for r in reporter.results], [1, 2, 3, 4, 5, 6, 7, 8])
```

4. Delete `tests/test_fixes.py`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_orchestration -v`
Expected: FAIL — parser rejects/ignores `--no-fix` expectation, gate test fails (checks 6 present or no skip entry).

- [ ] **Step 3: Remove `--no-fix` from the parser and `main`**

Delete `netcheck.py:141`:

```python
    parser.add_argument("--no-fix", action="store_true", help="never prompt for fixes")
```

Change the `main` call at 201-203 from:

```python
        run_all(cfg, reporter, quick=args.quick, sample=args.sample,
                hardening=args.hardening, allow_fix=not args.no_fix,
                verbose=args.verbose)
```

to:

```python
        run_all(cfg, reporter, quick=args.quick, sample=args.sample,
                hardening=args.hardening, verbose=args.verbose)
```

- [ ] **Step 4: Delete the dead fix machinery**

Delete these blocks from `netcheck.py`:

- `from typing import TextIO` (line 1858)
- `open_tty` (1861-1867)
- `prompt_yes_no` (1870-1880)
- `dns_servers` (1963-1964)
- `apply_fixes` (1967-1993)

Note: `# noqa: BLE001` comments elsewhere are unaffected; `TextIO` has no other users in the file.

- [ ] **Step 5: Rewrite `run_all`**

Replace `netcheck.py:2008-2125` with:

```python
def run_all(cfg: Config, reporter: Reporter, quick: bool = False,
            sample: float | None = None, hardening: bool = False,
            runner=run_command, verbose: bool = False, lan=None) -> None:
    def _run_check(check_id: int, title: str, fn) -> None:
        _diag(cfg, f"check {check_id}: {title}")
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

    _diag(cfg, f"netcheck {__version__} on {sys.platform}, "
               f"python {sys.version.split()[0]}")
    _diag(cfg, f"gateway={cfg.gateway} dns={','.join(cfg.dns_servers)} "
               f"domain={cfg.domain} timeout={cfg.timeout} "
               f"switches={len(cfg.switches)} sample={sample} "
               f"quick={quick} hardening={hardening}")
    _diag(cfg, "snmp_community=" + ("set" if cfg.snmp_community else "not set"))

    if lan is None:
        lan = resolve_lan_interface(cfg, runner)
    source_for = lan.source_for if lan is not None else (lambda dst: None)
    _diag(cfg, f"lan_interface={lan.name} ({lan.primary_ip})" if lan
               else "lan_interface=none")

    try:
        layer_ping = lambda host, **kw: ping(host, runner=runner,  # noqa: E731
                                             source=source_for(host), **kw)
        layer_query = lambda server, name, **kw: dns_query(  # noqa: E731
            server, name, timeout=kw.get("timeout", cfg.timeout),
            source=source_for(server))
        _diag(cfg, "checks 1-4: local config, gateway, internet, DNS")
        run_layer_checks(cfg, reporter,
                         local_fn=lambda: detect_local_config(cfg, runner, lan=lan),
                         ping_fn=layer_ping, query_fn=layer_query)
        if quick:
            return

        mgmt = ensure_mgmt_address(cfg, lan)
        _report_mgmt(mgmt)
        if lan is not None and mgmt.detail != "present":
            reporter.add(CheckResult(
                5, "Switches", Status.WARN,
                detail=f"not run: {mgmt.address}/24 is not on {mgmt.interface}",
                likely_cause="The laptop has no address on the switch-management LAN.",
                suggested_fix="Add the address shown above, then run netcheck again."))
            return

        _run_check(5, "Switches",
                   lambda: reporter.add(check_switches(cfg, ping_fn=layer_ping)))

        rogue_macs: list[str] = []

        def _rogue() -> None:
            result, macs = check_rogue_dhcp(cfg, iface=lan.name if lan else None)
            reporter.add(result)
            rogue_macs.extend(macs)

        _run_check(6, "Rogue DHCP", _rogue)

        def _inventory() -> None:
            reporter.add(check_device_inventory(
                cfg, rogue_macs, source=source_for("10.90.90.90")))

        _run_check(7, "Device inventory", _inventory)

        def _storm() -> None:
            gateway_ping = ping(cfg.gateway, count=4, timeout=cfg.timeout,
                                runner=runner, source=source_for(cfg.gateway))
            reporter.add(check_storm_hints(cfg, gateway_ping))

        _run_check(8, "Loop/storm hints", _storm)

        if hardening:
            def _hardening() -> None:
                measured = (measure_storm_threshold(
                                cfg, sample_seconds=sample,
                                source=source_for("10.90.90.90"))
                            if sample is not None else {})
                reporter.add(check_hardening(cfg, measured=measured,
                                             source=source_for("10.90.90.90")))

            _run_check(9, "Hardening audit", _hardening)

        if sample is not None:
            def _sample_only() -> None:
                measured = measure_storm_threshold(
                    cfg, sample_seconds=sample,
                    source=source_for("10.90.90.90"))
                reporter.add(format_threshold_samples(measured))
            _run_check(10, "Storm thresholds", _sample_only)
    except Exception as exc:  # noqa: BLE001 - last-resort guard
        if verbose:
            import traceback
            traceback.print_exc()
        reporter.add(CheckResult(98, "Internal error", Status.WARN, detail=str(exc),
                                 likely_cause="An unexpected error interrupted the checks.",
                                 suggested_fix="Re-run with --verbose for details."))
```

- [ ] **Step 6: Run the full suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS. (`test_fixes.py` is deleted, so `apply_fixes`/`prompt_yes_no` have no importers; `test_orchestration` uses the new signatures.)

- [ ] **Step 7: Commit**

```bash
git add netcheck.py tests/test_orchestration.py
git rm tests/test_fixes.py
git commit -m "refactor: read-only run, mgmt gate stop, numeric check order"
```

---

### Task 4: Per-check verbose start/done markers

**Files:**
- Modify: `netcheck.py` (`_run_check` inside `run_all`; `run_layer_checks` at 1221-1235)
- Test: `tests/test_orchestration.py`

**Interfaces:**
- Produces: under `--verbose`, stderr lines `[verbose] starting check N: <Title>` and `[verbose] check N done` for each check that runs.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_orchestration.py`:

```python
    def test_verbose_marks_each_layer_check(self):
        reporter = netcheck.Reporter(color=False)
        stderr = io.StringIO()
        local = netcheck.LocalConfig(ip="192.168.1.50",
                                     gateway="192.168.1.1", dns=["1.1.1.1"])
        ping_ok = lambda h, **k: netcheck.PingResult(
            host=h, transmitted=10, received=10, loss_pct=0.0,
            min_ms=1.0, avg_ms=1.0, max_ms=1.0)
        query_ok = lambda s, n, **k: (True, 1.0, ["1.2.3.4"])
        with contextlib.redirect_stderr(stderr):
            netcheck.run_layer_checks(netcheck.Config(verbose=True), reporter,
                                      local_fn=lambda: local,
                                      ping_fn=ping_ok, query_fn=query_ok)
        out = stderr.getvalue()
        for n in (1, 2, 3, 4):
            self.assertIn(f"starting check {n}", out)
            self.assertIn(f"check {n} done", out)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_orchestration.TestOrchestration.test_verbose_marks_each_layer_check -v`
Expected: FAIL — `starting check 1` not in stderr.

- [ ] **Step 3: Add markers to `run_layer_checks`**

Replace `netcheck.py:1221-1235` with:

```python
def run_layer_checks(cfg: Config, reporter: Reporter, local_fn=None,
                     ping_fn=ping, query_fn=dns_query) -> None:
    if local_fn is None:
        local_fn = lambda: detect_local_config(cfg)
    _diag(cfg, "starting check 1: Local config")
    local = check_local_config(cfg, local_fn=local_fn)
    reporter.add(local)
    _diag(cfg, "check 1 done")
    if local.status is Status.FAIL:
        return
    _diag(cfg, "starting check 2: Gateway")
    gateway = check_gateway(cfg, ping_fn=ping_fn)
    reporter.add(gateway)
    _diag(cfg, "check 2 done")
    if gateway.status is Status.FAIL:
        return
    _diag(cfg, "starting check 3: Internet by IP")
    reporter.add(check_internet(cfg, ping_fn=ping_fn))
    _diag(cfg, "check 3 done")
    _diag(cfg, "starting check 4: DNS")
    reporter.add(check_dns(cfg, query_fn=query_fn))
    _diag(cfg, "check 4 done")
```

- [ ] **Step 4: Update `_run_check` to start/done wording**

In `run_all`, change:

```python
        _diag(cfg, f"check {check_id}: {title}")
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - isolate each fabric check
            ...
                                     suggested_fix="Re-run with --verbose for details."))
```

to add a done marker and rename the start marker:

```python
        _diag(cfg, f"starting check {check_id}: {title}")
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
        _diag(cfg, f"check {check_id} done")
```

Also delete the grouped line in `run_all`:

```python
        _diag(cfg, "checks 1-4: local config, gateway, internet, DNS")
```

- [ ] **Step 5: Run the suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS. (`test_verbose_preamble_reports_effective_config` and `test_no_verbose_emits_no_diagnostics` still pass; they only assert `[verbose]` and absence.)

- [ ] **Step 6: Commit**

```bash
git add netcheck.py tests/test_orchestration.py
git commit -m "feat: per-check verbose start/done markers"
```

---

### Task 5: Newline-aware reporter

**Files:**
- Modify: `netcheck.py` (`Reporter._render_check` at 81-98)
- Test: `tests/test_reporter.py`

**Interfaces:**
- Produces: `Reporter._render_check` renders each field by splitting on `\n` and wrapping every logical line independently; blank lines are preserved. Single-line detail rendering is unchanged.

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_reporter.py`:

```python
    def test_render_preserves_detail_newlines(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "A", Status.PASS, detail="first\nsecond"))
        lines = r.render().splitlines()
        self.assertEqual(lines[1], "      first")
        self.assertEqual(lines[2], "      second")

    def test_render_indents_each_block_line(self):
        r = Reporter(color=False)
        r.add(CheckResult(7, "Device inventory", Status.PASS,
                          detail="2 end devices\ndlink1\n    port 5  AA:BB"))
        text = r.render()
        self.assertIn("\n      dlink1", text)
        self.assertIn("\n          port 5  AA:BB", text)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m unittest tests.test_reporter.TestReporter.test_render_preserves_detail_newlines -v`
Expected: FAIL — newline collapsed to a space.

- [ ] **Step 3: Make `_render_check` newline-aware**

Replace `netcheck.py:81-98` with:

```python
    def _wrap_block(self, value: str, width: int, initial_indent: str,
                    subsequent_indent: str) -> list[str]:
        lines: list[str] = []
        for raw in value.splitlines():
            if not raw.strip():
                lines.append("")
                continue
            lines.extend(textwrap.wrap(raw, width=width,
                                       initial_indent=initial_indent,
                                       subsequent_indent=subsequent_indent) or [""])
        return lines

    def _render_check(self, r: CheckResult, head: str, title_width: int,
                      width: int, use_color: bool) -> list[str]:
        plain_tag = f"[{r.status.value}]"
        tag = f"{_COLORS[r.status]}{plain_tag}{_RESET}" if use_color else plain_tag
        lines = [f"{tag} {head:<{title_width}}".rstrip()]
        if r.detail:
            lines.extend(self._wrap_block(r.detail, width, "      ", "      "))
        for label, value in (("Likely cause", r.likely_cause),
                             ("Suggested fix", r.suggested_fix)):
            if value:
                indent = " " * (5 + len(label) + 2)
                lines.extend(self._wrap_block(value, width,
                                              f"    {label}: ", indent))
        return lines
```

- [ ] **Step 4: Run the suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS. (`test_render_detail_on_its_own_indented_line` → `"      one"`; `test_long_detail_wraps` still ≤ 100 cols.)

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_reporter.py
git commit -m "fix: render multi-line detail without collapsing"
```

---

### Task 6: Newline-separate structural detail lists

**Files:**
- Modify: `netcheck.py` (`check_switches` 1248; `check_local_config` 1138; `check_device_inventory` 1573; `check_hardening` 1754; `format_threshold_samples` 1854-1855)
- Test: `tests/test_switches.py`

**Interfaces:**
- Consumes: newline-aware reporter (Task 5).
- Produces: list-style details joined with `\n` instead of `; `. Prose semicolons are unchanged.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_switches.py`:

```python
    def test_multiple_unreachable_are_newline_separated(self):
        def all_down(host, **kw):
            return PingResult(host=host, transmitted=2, received=0, loss_pct=100.0)
        result = check_switches(Config(), ping_fn=all_down)
        self.assertIn("\n", result.detail)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_switches.TestSwitches.test_multiple_unreachable_are_newline_separated -v`
Expected: FAIL — detail joined with `"; "`.

- [ ] **Step 3: Apply the separator changes**

Make these exact edits in `netcheck.py`:

`check_local_config` (line 1138) from:
```python
        detail += f"; default route via Wi-Fi ({lc.default_route_interface}); wired LAN checked"
```
to:
```python
        detail += (f"\ndefault route via Wi-Fi ({lc.default_route_interface})"
                   "; wired LAN checked")
```

`check_switches` (line 1248) from:
```python
    return CheckResult(5, "Switches", Status.WARN, detail="; ".join(hints),
```
to:
```python
    return CheckResult(5, "Switches", Status.WARN, detail="\n".join(hints),
```

`check_device_inventory` (line 1573) from:
```python
                           detail=f"{summary}; rogue on {where}\n{table}",
```
to:
```python
                           detail=f"{summary}\nrogue on {where}\n{table}",
```

`check_hardening` (line 1754) from:
```python
    return CheckResult(9, "Hardening audit", Status.WARN, detail="; ".join(findings),
```
to:
```python
    return CheckResult(9, "Hardening audit", Status.WARN, detail="\n".join(findings),
```

`format_threshold_samples` (lines 1854-1855) from:
```python
    return CheckResult(10, "Storm thresholds", Status.PASS,
                       detail="set Threshold (64Kbps x N): " + "; ".join(lines))
```
to:
```python
    return CheckResult(10, "Storm thresholds", Status.PASS,
                       detail="set Threshold (64Kbps x N):\n" + "\n".join(lines))
```

- [ ] **Step 4: Run the suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS. (`test_pass_with_wifi_primary_note` still finds "wired LAN checked" in `detail`; hardening tests assert on `evaluate_hardening`, not the joined detail.)

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_switches.py
git commit -m "fix: newline-separate report detail lists"
```

---

### Task 7: Inventory grouped under per-switch headers

**Files:**
- Modify: `netcheck.py` (`format_inventory` at 1525-1542)
- Test: `tests/test_inventory.py`

**Interfaces:**
- Produces: `format_inventory(devs, rogue_macs)` emits `    <switch>` header lines followed by `        port <n>  <MAC>  <vendor>[  ROGUE]` rows; error lines unchanged.

- [ ] **Step 1: Update the failing test**

Replace `test_groups_rows_by_switch_before_sorting_by_port` in `tests/test_inventory.py` (lines 219-232) with:

```python
    def test_headers_per_switch_then_rows_sorted_by_port(self):
        mac_c = "00:1E:58:11:22:33"
        devs = Devicelist(devices={
            "dlink1": {MAC_A: 9, mac_c: 1},
            "dlink2": {MAC_B: 3},
        })
        lines = format_inventory(devs, []).splitlines()
        headers = [ln.strip() for ln in lines
                   if ln.startswith("    ") and "port" not in ln]
        port_lines = [ln for ln in lines if "port" in ln]
        self.assertEqual(headers, ["dlink1", "dlink2"])
        self.assertEqual(len(port_lines), 3)
        self.assertIn(" 1 ", port_lines[0])
        self.assertIn(" 9 ", port_lines[1])
        self.assertIn(" 3 ", port_lines[2])
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_inventory.TestFormatInventory.test_headers_per_switch_then_rows_sorted_by_port -v`
Expected: FAIL — headers list is empty (switch is currently a row column).

- [ ] **Step 3: Rewrite `format_inventory`**

Replace `netcheck.py:1525-1542` with:

```python
def format_inventory(devs: Devicelist, rogue_macs: list[str]) -> str:
    rogue = {m.replace("-", ":").upper() for m in rogue_macs}
    port_w = max((len(str(port)) for macs in devs.devices.values()
                  for port in macs.values()), default=0)
    lines: list[str] = []
    for switch, macs in devs.devices.items():
        if not macs:
            continue
        lines.append(f"    {switch}")
        for port, mac in sorted((p, m) for m, p in macs.items()):
            vendor = lookup_vendor(mac) or ""
            flag = "  ROGUE" if mac.upper() in rogue else ""
            lines.append(f"        port {port:>{port_w}}  {mac}  {vendor}{flag}")
    lines.extend(f"    {err}" for err in devs.errors)
    return "\n".join(lines)
```

- [ ] **Step 4: Run the suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS. (`test_marks_only_rogue_mac`, `test_sorts_rows_by_port`, `test_includes_vendor`, `test_error_lines_are_appended`, and `test_pass_with_partial_error_prints_table_once` still hold.)

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_inventory.py
git commit -m "fix: group inventory rows under per-switch headers"
```

---

### Task 8: Documentation and version

**Files:**
- Modify: `USAGE.md`, `README.md`, `netcheck.py` (`__version__` at 17)

**Interfaces:**
- Consumes: all behavior from Tasks 1–7. No code interfaces produced.

- [ ] **Step 1: Update `USAGE.md` quickstart and flag table**

- Line 43: `uv run netcheck.py --no-fix` → `uv run netcheck.py`
- Line 47: `python3 netcheck.py --no-fix` → `python3 netcheck.py`
- Line 52: `uv run --with scapy netcheck.py --no-fix` → `uv run --with scapy netcheck.py`
- Line 379: `python3 netcheck.py --no-fix` → `python3 netcheck.py`
- Line 561: `python3 netcheck.py --hardening --verbose --no-fix` → `python3 netcheck.py --hardening --verbose`
- Line 602: `uv run netcheck.py --no-fix` → `uv run netcheck.py`
- Line 761: delete the row `| `--no-fix` | Never prompt for fixes (also automatic when not a TTY) |`

- [ ] **Step 2: Replace §10 "Optional fixes" and renumber**

Replace `USAGE.md:771-789` with:

```markdown
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
```

(Keep the existing §11 body; the heading stays `## 11.` so downstream anchors are unchanged.)

- [ ] **Step 3: Update the Contents list**

In `USAGE.md`, change line 82 from:

```markdown
10. [Optional fixes](#10-optional-fixes)
```

to:

```markdown
10. [Read-only guarantee](#10-read-only-guarantee)
```

- [ ] **Step 4: Add the management-gate note to the prerequisites**

In `USAGE.md` around lines 62-66, after the existing blockquote, add:

```markdown
> If `10.90.90.100/24` is not on the wired NIC, netcheck prints the exact
> command to add it and **stops before the switch checks**. Add the address,
> then run netcheck again.
```

- [ ] **Step 5: Update `README.md`**

- Line 69: `uv run --with scapy netcheck.py --no-fix` → `uv run --with scapy netcheck.py`
- Lines 74-75: rewrite to:

```markdown
`uv run netcheck.py` to skip it. On Python 3.10+ you can use
`python3 netcheck.py` instead.
```

- Line 99: `interpreting output, playbooks, flags, optional fixes).` → `interpreting output, playbooks, flags, read-only guarantee).`

- [ ] **Step 6: Bump the version**

In `netcheck.py:17`, change:

```python
__version__ = "0.5.0"
```

to:

```python
__version__ = "0.6.0"
```

- [ ] **Step 7: Run the suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS (`test_docs` only checks `netcheck.ini.example`; no doc-content assertions).

- [ ] **Step 8: Commit**

```bash
git add USAGE.md README.md netcheck.py
git commit -m "docs: document read-only behavior and mgmt gate; v0.6.0"
```

---

## Self-Review Notes

- **Spec coverage:** read-only (Tasks 2, 3, 8), gate stop + printed OS/interface command (Tasks 1, 2, 3), check order 5→8→9→10 (Task 3), verbose per-check (Task 4), newline formatting (Tasks 5, 6), inventory headers (Task 7), docs/version (Task 8). `--remove-mgmt-ip` intentionally retained as the one explicit write.
- **Type consistency:** `ensure_mgmt_address(cfg, lan)` and `run_all(..., runner=..., verbose=..., lan=...)` are used consistently across Tasks 2–4; `format_command(argv, platform=None)` is defined in Task 1 and consumed in Task 2.
- **No placeholders:** every step shows the exact code and command.
