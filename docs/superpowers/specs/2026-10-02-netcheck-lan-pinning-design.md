# netcheck — Wired-LAN Pinning and Transient Management Address

- **Status:** Approved in chat 2026-10-02
- **Date:** 2026-10-02
- **Supersedes:** the manual management-address prerequisite in `README.md` §2 and
  `USAGE.md` §3.3, and the default-route-based interface discovery in
  `detect_local_config` (`netcheck.py:860`).
- **Source request:** run netcheck against the **wired office LAN** while Wi-Fi
  stays connected and primary for the host; stop failing check 1 on Wi-Fi
  settings; auto-add the `10.90.90.x` switch-management address on a prompt
  instead of running `sudo ip addr add` by hand; assess practicality/security and
  offer a better approach.

## 1. Goal

Every check runs against the wired office LAN NIC, chosen by address, with no
need to disable or disconnect Wi-Fi:

- **Checks 1–4** source from the wired NIC's `192.168.1.x` address.
- **Checks 5–9** source from a `10.90.90.x` address added to that same NIC.
- Wi-Fi keeps its default route and stays usable throughout; netcheck never
  changes routes or the Wi-Fi interface.
- If the `10.90.90.x` address is missing, prompt; try to add it transiently;
  if it cannot be added, print the exact privileged command and **continue** with
  checks 5–9 anyway. If netcheck added it, remove it on exit.

## 2. Scope and non-goals

In scope:
- Cross-platform interface enumeration and selection by IPv4 address.
- Source-interface binding for ping, DNS, SNMP, and scapy.
- Check 1 redefined to inspect the wired LAN NIC instead of the default-route
  NIC.
- A transient management-address pre-flight with a prompt, direct add, printed
  fallback command, and removal at exit.
- Tests and documentation for all of the above.

Non-goals:
- No disabling/downing Wi-Fi, no route changes, no default-route manipulation.
- No persistent network configuration (no nmcli/netplan/netsh persistence). The
  address is transient and removed at exit.
- No new third-party dependencies; stdlib only, with scapy still optional for
  check 6.
- No change to what checks 2–10 measure, only to where their packets egress.
- No support for multiple simultaneous wired LAN NICs beyond deterministic
  selection (documented tie-break; verbose note on ambiguity).

## 3. Interface model

### 3.1 Data types

```
@dataclass
class InterfaceAddr:
    ip: str
    prefix: int

@dataclass
class InterfaceInfo:
    name: str
    addrs: list[InterfaceAddr]

@dataclass
class LanInterface:
    name: str
    primary_ip: str          # the 192.168.1.x address
    addrs: list[InterfaceAddr]
    def source_for(self, dst: str) -> str: ...
```

- `source_for(dst)` returns the interface address whose subnet contains `dst`;
  if none matches, it returns `primary_ip`. This makes SNMP to `10.90.90.x`
  source from `10.90.90.100` and internet/DNS source from `192.168.1.x`, while
  the caller always binds one interface.
- `primary_ip` is the first address on the interface in `192.168.1.0/24`. If the
  interface holds only `10.90.90.x`, `primary_ip` is the first `10.90.90.x`
  address (check 1 will then FAIL as "not on the office LAN").

### 3.2 `iter_interfaces(runner=run_command) -> list[InterfaceInfo]`

Platform dispatch, stdlib only:

- **Linux:** parse `ip -4 -o addr show` lines of the form
  `2: eth0    inet 192.168.1.50/24 brd ...`. Skip `lo`.
- **macOS:** parse `ifconfig -a` blocks, collecting `inet A.B.C.D` and the
  following `netmask 0x...` (convert to a prefix). Skip `lo0`, `utun*`, `awdl*`,
  `llw*`, `bridge*`, `ap*`, `anpi*`.
- **Windows:** parse `ipconfig /all` per-adapter blocks. Extend the existing
  parser so every adapter yields `(name, ip, mask)` rather than only the first
  IPv4. Skip adapters whose description contains "Loopback". The existing
  English-string assumption (`IPv4 Address`, `Subnet Mask`) is unchanged.

Returns `[]` on any command failure (never raises).

### 3.3 `resolve_lan_interface(cfg, runner=run_command) -> LanInterface | None`

- Enumerate interfaces; keep those with at least one address in the **office
  LAN** (`cfg.gateway`'s `/24`, default `192.168.1.0/24`) or the **management
  subnet** (`10.90.90.0/24`).
- Selection order:
  1. A NIC holding a `192.168.1.x` address.
  2. Else a NIC holding a `10.90.90.x` address.
- If more than one candidate holds a `192.168.1.x` address (e.g. Wi-Fi is also
  on `192.168.1.0/24`), prefer the candidate that also holds a `10.90.90.x`
  address; otherwise take the first in platform order and emit a
  `_diag(cfg, ...)` note about the ambiguity.
- Return `None` when no candidate exists.
- If `cfg.lan_interface` is set, validate it against the enumerated interfaces
  (reject unknown names and names beginning with `-`) and return that interface
  regardless of the address-based selection above.

The office-LAN and management subnets are derived from `cfg.gateway`
(`ipaddress.ip_network(f"{cfg.gateway}/24", strict=False)`) and the
`10.90.90.0/24` constant respectively, so a non-default `gateway=` is honored.

## 4. Source-interface pinning

Every outbound socket used by a check gains an optional source so packets egress
the wired NIC while Wi-Fi stays primary.

### 4.1 Ping (checks 2, 3, 5, 8)

```
def ping_argv(host, count, source=None) -> list[str]
def ping(host, count=10, timeout=3.0, runner=run_command, source=None) -> PingResult
```

- Linux: append `-I <source>`.
- Windows/macOS: append `-S <source>`.
- `source=None` preserves the current argv exactly (existing tests unchanged).

### 4.2 DNS (check 4)

```
def dns_query(server, name, timeout=3.0, source=None)
```

- When `source` is set, `sock.bind((source, 0))` before `sendto`, so the query
  egresses the wired NIC. `source=None` is byte-for-byte today's behavior.

### 4.3 SNMP (checks 7, 9, 10)

```
class SnmpClient(host, community, version="2c", timeout=3.0, retries=2, source=None)
```

- `_exchange` binds `(self.source, 0)` when set.
- `collect_devices`, `check_hardening`, and `measure_storm_threshold` pass
  `source=` (default `None`) into their `client_factory(...)` calls:
  `client_factory(host, cfg.snmp_community, timeout=cfg.timeout, source=source)`.
- Existing test factories accept `**kw`, so they keep working; any that do not
  are updated to accept and ignore `source`.

### 4.4 Rogue DHCP (check 6, optional scapy)

```
def scapy_dhcp_discover(timeout=5.0, cfg=None, iface=None) -> DhcpProbe
```

- Pass `iface=iface` to `srp`. When `iface` is `None`, resolve it from the
  management subnet via `scapy.conf.route.route(mgmt_ip)[0]`; if that fails,
  fall back to scapy's default interface.
- `check_rogue_dhcp` forwards the resolved interface into `discover_fn`.
  Scapy remains optional; failures still produce the existing WARN.

### 4.5 Wiring in `run_all`

- Resolve `lan = resolve_lan_interface(cfg, runner)` once at the start.
- Build a single source rule used everywhere: define
  `source_for = lan.source_for if lan else (lambda dst: None)`. For a
  destination `dst`, the source is then the on-subnet address when the interface
  holds one (e.g. `10.90.90.100` for `10.90.90.90`) and `primary_ip` otherwise.
- `layer_ping = lambda host, **kw: ping(host, runner=runner, source=source_for(host), **kw)`.
- `local_fn = lambda: detect_local_config(cfg, runner, lan=lan)` (see §5).
- Checks 5, 8 pass `source=source_for(host)`.
- Checks 7, 9, 10 pass `source=source_for("10.90.90.90")`. When the management
  address is absent, this is `primary_ip`; the switch/SNMP checks then fail or
  WARN as expected, which is the correct diagnostic outcome.
- If `lan is None`, check 1 FAILs and short-circuits, so no fabric check runs.

## 5. Check 1 semantics

`detect_local_config(cfg, runner=run_command, lan=None) -> LocalConfig` now
targets the wired NIC:

- If `lan` is `None`, call `resolve_lan_interface(cfg, runner)`. If still
  `None`, return an empty `LocalConfig` (check 1 then FAILs).
- Parse only the chosen interface's IPv4/mask (extend
  `parse_linux`/`parse_macos`/the Windows parser to accept a specific interface
  or adapter).
- Set `LocalConfig.interface` to the wired NIC name, `LocalConfig.ip`/`mask` to
  its office-LAN address, and add `LocalConfig.default_route_interface` (from
  the existing default-route parse) for the informational note.
- `LocalConfig.gateway` is `cfg.gateway` when the NIC address is inside
  `cfg.gateway`'s `/24`; otherwise `None`. The DNS list stays the system
  resolver's (check 4 queries `cfg.dns_servers` explicitly regardless).

`check_local_config(cfg, local_fn=None) -> CheckResult`: when `local_fn` is
`None`, use `lambda: detect_local_config(cfg)`. Existing callers that pass an
explicit `local_fn` (the tests) are unaffected. `run_layer_checks`'s default
`local_fn` becomes `None` with the same resolution, so its existing explicit-args
tests keep working.

- **FAIL** — no IPv4 on the wired NIC, or no wired NIC on the office LAN.
  - `likely_cause`: "No wired address on the office LAN (`192.168.1.0/24`)."
  - `suggested_fix`: "Plug in the LAN cable and renew DHCP on the wired NIC;
    Wi-Fi does not satisfy this check."
- **FAIL** — APIPA (`169.254.x.x`): unchanged wording.
- **WARN** — no DNS servers: unchanged.
- **PASS** — office-LAN address present. When
  `default_route_interface != interface`, the detail notes
  "default route via Wi-Fi (`<name>`); wired LAN checked" but the status stays
  PASS, because checks 2–9 are source-pinned to the wired NIC and the Wi-Fi
  route is irrelevant to their result.
- The old `lc.gateway != cfg.gateway` FAIL (`netcheck.py:897`) is removed; it is
  what currently fires when Wi-Fi is primary.

### 5.1 Example output

```
[PASS]  1. Local config   - eth0 192.168.1.50/24 (office LAN) gw 192.168.1.1 dns 58.71.2.8,45.63.30.117; default route via Wi-Fi (wlan0); wired LAN checked
```

## 6. Transient management address

### 6.1 Pre-flight (between checks 4 and 5)

Function:

```
def ensure_mgmt_address(cfg, lan, allow_fix=True, tty=None, runner=run_command) -> MgmtAddressResult
```

`MgmtAddressResult(added: bool, address: str | None, interface: str | None, command: list[str] | None, detail: str)`.

Logic:
1. If `lan is None` → return `added=False`, detail "no wired LAN interface".
2. If `lan` already has an address in `10.90.90.0/24` → return that address,
   `added=False`, no prompt.
3. Else, if `allow_fix` and `prompt_yes_no(f"Add {addr}/24 to {lan.name} for switch access?", tty=tty)`:
   - Build the per-platform argv (see §6.2) and call `runner(argv)`.
   - Re-run `resolve_lan_interface`; if the `10.90.90.x` address now exists,
     return `added=True` with the address and interface.
   - If it did not appear (permission denied, etc.), return `added=False` with
     `command=argv` and detail "could not add (run the printed command with
     sudo/administrator)".
4. Else (declined or `allow_fix=False`) → return `added=False` with
   `command=argv` and detail "declined".

The caller then prints one short line to stdout (the same channel as the fix
prompts) and continues:

- Added: `added 10.90.90.100/24 to eth0 (removed on exit)`.
- Already present: `using 10.90.90.100/24 on eth0` (in verbose only).
- Declined or failed: `could not add 10.90.90.100/24; run:` followed by the
  exact argv as a copy-pasteable command with `sudo` (Linux/macOS) or "as
  Administrator" (Windows).

Checks 5–9 always run afterward. Missing management connectivity surfaces as
the existing check 5 WARN / checks 7–9 WARN, which is the correct diagnostic
outcome.

### 6.2 Commands (argv lists, never shell strings)

- **Linux:** `["ip", "addr", "replace", "<addr>/24", "dev", "<iface>"]`
  (`replace` is idempotent) and removal
  `["ip", "addr", "del", "<addr>/24", "dev", "<iface>"]`.
- **macOS:** add `["ifconfig", "<iface>", "alias", "<addr>", "255.255.255.0"]`;
  remove `["ifconfig", "<iface>", "-alias", "<addr>"]`.
- **Windows:** add `["netsh", "interface", "ipv4", "add", "address", "<name>",
  "<addr>", "255.255.255.0"]`; remove `["netsh", "interface", "ipv4", "delete",
  "address", "<name>", "<addr>"]`.

The address is a config value (`mgmt_address`, default `10.90.90.100`) and the
prefix is `/24` — **not** README's `/8`, so the whole `10.0.0.0/8` is not claimed
on-link and other `10.x`/VPN routes are not shadowed.

### 6.3 Removal at exit

- `run_all` records whether `ensure_mgmt_address` added the address and wraps the
  fabric checks in `try/finally`. In `finally`, if it added the address, run the
  platform removal argv. Removal failures are ignored (the address is transient
  and also clears on reboot/link reset).
- Ctrl-C still runs the `finally` (the existing `KeyboardInterrupt` handler in
  `main` catches after `run_all` unwinds).
- If the address was already present before the run, netcheck never removes it.

### 6.4 Configuration surface

New `Config` fields:
- `mgmt_address: str = "10.90.90.100"`
- `lan_interface: str | None = None` (advanced override; when set, it is
  validated against `iter_interfaces` and used instead of auto-detection)

New CLI flag:
- `--remove-mgmt-ip` — skip checks and only remove `mgmt_address` from the
  auto-detected interface (convenience for a leaked address).

New INI keys: `mgmt_address`, `lan_interface`. No env vars required.

## 7. Security

- **No shell.** All commands are argv lists passed to `run_command`, which uses
  `subprocess.run(list)` without `shell=True`. No metacharacter injection.
- **Option-injection guard.** The interface name must be one returned by
  `iter_interfaces`; names beginning with `-` are rejected. `lan_interface` from
  config is validated against the enumerated set before use.
- **Address validation.** `mgmt_address` must parse with
  `ipaddress.ip_address`, be inside `10.90.90.0/24`, and not be the network or
  broadcast address, before any command is built.
- **Least privilege / no auto-escalation.** netcheck never invokes `sudo` or
  requests elevation itself. It attempts the command directly; on failure it
  prints the exact command for the operator to run with sudo/administrator.
- **Least state.** The address is `/24`, not `/8`; it is removed at exit if
  netcheck added it; routes and Wi-Fi are never modified.
- **No secrets.** The management address is not sensitive; SNMP community /
  switch credentials handling is unchanged.

## 8. Tests

New `tests/test_interfaces.py`:
- `iter_interfaces` parses representative Linux/macOS/Windows fixture strings
  (including multiple adapters and skipped virtual interfaces).
- `resolve_lan_interface` picks the `192.168.1.x` NIC when Wi-Fi is on another
  subnet; picks the `10.90.90.x`-carrying NIC on a tie; returns `None` when no
  candidate.
- `LanInterface.source_for` selects the on-subnet address and falls back to
  `primary_ip`.

New `tests/test_mgmt_ip.py`:
- Address already present → `added=False`, no prompt.
- Missing + prompt "yes" → `replace` argv invoked and verified after re-resolve.
- Permission failure → `added=False`, command returned, no exception.
- Prompt "no" / `allow_fix=False` → `added=False`, command returned.
- IPv4/subnet/interface validation rejects bad address and `-x` interface name.
- Removal argv per platform.

Extend `tests/test_local_config.py`:
- Wired NIC on `192.168.1.x` with Wi-Fi primary → PASS with the Wi-Fi note.
- Wired NIC not on the office LAN → FAIL, message names `192.168.1.0/24`.
- No wired NIC → FAIL.
- Update `test_gateway_mismatch_message_uses_configured_gateway` to the new
  semantics (assert the office-LAN FAIL message) or replace it.

Extend source-arg tests:
- `test_ping.py`: `ping_argv` with `source` gives `-I`/`-S` per platform;
  default argv unchanged.
- `test_dns.py`: `dns_query` binds the source (assert via a fake socket or an
  injected socket factory).
- `test_snmp.py`: `SnmpClient(source=...)` binds before send.

Orchestration:
- `tests/test_orchestration.py`: `run_all` with a stub `resolve_lan_interface`
  injects the chosen interface into ping/DNS/SNMP factories, and verifies the
  management address is removed in `finally`.

Run `python3 -m unittest discover -s tests -v` — all pass.

## 9. Docs

- `README.md` §2: replace the manual `ip addr add` instructions with the
  auto-detect + prompt behavior, noting Wi-Fi may stay connected and the address
  is removed on exit. Keep the manual command as a footnote fallback.
- `USAGE.md` §3.3: same; add a "how the LAN interface is chosen" paragraph and
  the `lan_interface` / `mgmt_address` keys.
- `README.md` check table row 1 and `USAGE.md` §check-1 criteria: update to the
  wired-NIC semantics and the Wi-Fi note.
- `netcheck.ini.example`: add `mgmt_address` and commented `lan_interface`.

## 10. Risks

- **Localized Windows output.** `ipconfig /all` parsing keeps the existing
  English-string assumption; non-English Windows may not be detected. Documented
  limitation; `lan_interface` override is the workaround.
- **Scapy interface naming.** On Windows, scapy's device naming can differ from
  the `ipconfig` adapter name; resolution falls back to
  `conf.route.route(mgmt_ip)` and then scapy's default, with check 6 already
  degrading to WARN.
- **Ambiguous office LAN.** If Wi-Fi is also on `192.168.1.0/24`, selection may
  pick the wrong NIC; the tie-break prefers the NIC carrying `10.90.90.x`, and a
  verbose note is emitted. `lan_interface` lets the operator force the choice.
- **/24 vs switch /8.** The switches use `255.0.0.0`, but the host only needs
  `/24` to reach `.90`–`.94`; this is intentional to avoid route pollution.
- **Removal timing.** A hard kill (`SIGKILL`) skips the `finally`, leaving the
  address until reboot/link reset; `--remove-mgmt-ip` cleans it up manually.
</content>
