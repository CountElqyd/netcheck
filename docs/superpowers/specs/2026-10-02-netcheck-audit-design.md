# netcheck — Whole-Script Audit (single-file readability + robustness)

- **Status:** Approved in chat 2026-10-02
- **Date:** 2026-10-02
- **Target:** `netcheck.py` (~2257 lines), `USAGE.md`, `README.md`, `tests/`
- **Source request:** "audit the whole script, let's make the code solid and robust
  (without breaking it), add proper commenting, make it more human readable."
- **Related, already shipped (out of scope here):**
  - Inventory is now opt-in (`--inventory`) and numbered 8; the default run is
    checks 1–7 (loop/storm moved 8→7). Hardening stays 9, thresholds stay 10.
  - The inventory MAC filter no longer drops null-OUI unicast, and the local
    host's own MAC is tagged `this host`.

## 1. Goal

Raise the codebase's readability and robustness without changing what the tool
does, except where a concrete bug is fixed. Every change keeps the behavior
contract stable: same checks, same CLI flags, same JSON shape, same exit codes
unless a documented bug fix requires otherwise.

Concretely:

- One clear top-to-bottom structure, with imports at the top and section banners.
- A docstring on every public function/class; inline comments only where the
  logic is non-obvious.
- Oversized functions decomposed into named helpers with single purposes.
- The known bugs found during the opt-in work fixed and covered by tests.

## 2. Scope and non-goals

In scope:

- Mechanical hygiene: import placement, section banners, module docstring.
- Readability: docstrings, decomposition of long functions, naming.
- Bug fixes: the `check_switches` cascade hint and other findings confirmed by a
  static sweep.
- Tests for every bug fix; full suite green after every atomic commit.
- Documentation touched only where behavior/messages change.

Non-goals:

- **No module split.** `netcheck.py` stays a single stdlib-only file; the
  copy-one-file deployment property is preserved.
- **No new dependencies.** scapy remains optional for check 6; pysnmp optional
  for SNMP v3.
- **No output-format rework.** Column layout, JSON schema, and exit codes are
  frozen (they were settled in earlier work).
- **No unrelated refactors.** Only what serves readability/robustness in code we
  are already touching.
- **No behavior change for its own sake.** A change that alters output must map
  to a bug fix listed in §4.4 and carry a test.

## 3. Current-state findings (evidence)

| Finding | Location | Notes |
|---|---|---|
| Imports scattered mid-file | `configparser`/`os`/`Mapping` at 246-248; `random`/`socket` at 489-490; `re`/`shlex`/`subprocess` at 716-718; `struct`/`time` at 982-983 | Each cluster was added where first used. All stdlib; safe to hoist to the top. |
| Very large `run_all` | `netcheck.py:2120` | Mixes config preamble, opt-in dispatch, default checks, mgmt gate, error guard. |
| Hardcoded cascade hint, inconsistent with config | `check_switches`, `netcheck.py:1332` | `{"dlink2":"24","dlink3":"25","dlink4":"26","dlink5":"27"}` while `netcheck.ini.example` sets `dlink4:25,dlink5:25`. Message claims the port is "on dlink1". |
| Missing docstrings | many functions/classes | e.g. parsers, SNMP helpers, checks, inventory. |
| Windows DNS reads only the first adapter | `read_dns_servers` / `parse_ipconfig_windows` (`netcheck.py:1051,1105`) | Global resolver list may miss adapters 2..N. To be confirmed and fixed to aggregate. |
| Stray `random`/`socket`/`struct` cluster | 489-490, 982-983 | Confirm each is still used; remove if dead. |

## 4. Design

### 4.1 Execution strategy

Work proceeds in the order below, one atomic commit per subsection, with
`python3 -m unittest discover -s tests` green before each commit. If any change
turns out larger than a subsection (hidden complexity), stop and re-scope rather
than bundling it.

### 4.2 Section 1 — Mechanical hygiene

1. Hoist every stdlib import to a single top block, sorted (alphabetical within
   `import`, then `from ... import ...`). Keep the `from __future__ import
   annotations` first.
2. Add a top-of-file table-of-contents comment and section banners. Proposed
   order:
   constants/enums → data types → config → BER + SNMP → vendor lookup → shell +
   interface parsing → checks 1–10 → inventory → reporter → CLI.
   No code moves between sections in this section; banners only.
3. Expand the module docstring: one-paragraph purpose, the read-only guarantee,
   the default vs opt-in check list, and a pointer to `USAGE.md`.

Exit criteria: no logic changes; file imports cleanly; suite green.

### 4.3 Section 2 — Decomposition and docstrings

1. `run_all` → extract:
   - `_optin_checks(...)` — the `inventory or hardening or sample` branch.
   - `_default_checks(...)` — checks 5–7 after the layer checks.
   `run_all` keeps the narrative (preamble, LAN resolution, dispatch, outer
   error guard). `_run_check` and `_mgmt_gate` stay as local helpers.
2. Add docstrings to every public function/class, and comments for the
   non-obvious algorithms: BER encode/decode, `resolve_ifindex_ports` (ifindex →
   port number), `_trunk_ports` / `access_devices` (trunk detection and physical
   attribution), `_wired_dns`, `read_interface_dns`, `_dhcp_chaddr` and the
   broadcast-flag rationale, `check_dns` alignment.
3. No signature changes to public names. Private helpers may move within the
   file.

Exit criteria: suite green; every public symbol has a docstring.

### 4.4 Section 3 — Bug fixes (each with a test)

1. **Cascade hint (confirmed).** Replace the hardcoded map in `check_switches`
   with config-derived ports:
   - For each down switch other than `dlink1`, compute
     `ports = sorted(uplink_ports_for(cfg, name))`.
   - Message: `f"{name} unreachable (check its uplink port(s) {ports} to dlink1)"`,
     falling back to `"its uplink"` when the config lists no ports.
   - Keep the `dlink1 unreachable` branch.
   - Test: a Config with a per-switch override (`dlink4:25`) must surface `25`,
     not `26`; multiple down switches stay newline-separated.
   - Docs: update the check-5 troubleshooting line in `USAGE.md` that currently
     repeats `dlink4`→26, `dlink5`→27.
2. **Static sweep.** Run `python3 -m compileall -q netcheck.py` and an
   unused-import/dead-code scan; remove or wire up anything found. Confirm and,
   if broken, fix Windows `read_dns_servers` to aggregate DNS across adapters.
   Any finding too large to fix safely is recorded in this spec's status notes
   rather than silently changed.

Exit criteria: suite green; each fix has a regression test.

### 4.5 Section 4 — Comment convention

- Docstring on every public function, class, and module. One-line summary; add
  "why" only where it is not obvious.
- Inline comments explain intent for non-trivial logic (SNMP/BER, trunk
  heuristics, platform parsing), never restate the code.
- Section banners separate the file's concerns; a top-of-file TOC mirrors them.
- No commented-out code; no TODO without an owner and a note.

### 4.6 Section 5 — Verification

- `python3 -m unittest discover -s tests` (all green) after every commit.
- `python3 -m compileall -q netcheck.py`.
- Live smoke where the fabric is reachable:
  `python3 netcheck.py --quick` (1–4), `python3 netcheck.py` (1–7),
  `python3 netcheck.py --inventory --verbose` (8), `python3 netcheck.py
  --hardening` (9), `python3 netcheck.py --sample 5` (10),
  `python3 netcheck.py --json | python3 -m json.tool`.
- Diff review of the final commit series to confirm no unintended output changes.

## 5. Risks and mitigations

- **Silent behavior change during refactor.** Mitigation: decomposition only in
  §4.3 with the existing tests as the contract; any output change is confined to
  §4.4 and tested.
- **Import hoist exposing name-shadowing.** Mitigation: alphabetical single
  block, run suite immediately.
- **Scope creep ("while we're here").** Mitigation: non-goals in §2; unrelated
  improvements are noted for a future change, not done.
- **Disk/tooling hiccups in the environment.** Mitigation: small commits;
  compileall and the suite are the gate.

## 6. Test plan

- Existing 231 tests remain green throughout.
- New tests:
  - `check_switches` uses `uplink_ports_for` (config-driven port; fallback text).
  - Windows DNS aggregation (if the finding is confirmed).
  - Any dead-code removal that touches behavior.

## 7. Done criteria

- Imports consolidated; module docstring and section banners present.
- `run_all` decomposed; every public function/class documented.
- Confirmed bugs fixed with tests; suite green.
- `USAGE.md`/`README.md` updated where a message changed.
- Final commit series reviewed for unintended output changes.
