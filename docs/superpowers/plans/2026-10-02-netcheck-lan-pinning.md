# Wired-LAN Pinning and Transient Management Address Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make netcheck run every check against the wired office LAN NIC (auto-detected by address) while Wi-Fi stays connected, and transiently add/remove the `10.90.90.x` switch-management address with a prompt.

**Architecture:** Add an interface-enumeration layer (`iter_interfaces`/`resolve_lan_interface`) that picks the NIC holding `192.168.1.x` or `10.90.90.x`; thread an optional `source` into every outbound socket (`ping`, `dns_query`, `SnmpClient`, scapy); rewrite check 1 to inspect that NIC; add a pre-check-5 `ensure_mgmt_address` step that prompts, adds the address directly, prints the privileged command on failure, and a `finally` that removes what it added. All changes stay in the single `netcheck.py`.

**Tech Stack:** Python 3.10+ standard library (`ipaddress`, `socket`, `subprocess`, `dataclasses`, `argparse`, `configparser`), `unittest`; scapy remains optional for check 6.

**Spec:** `docs/superpowers/specs/2026-10-02-netcheck-lan-pinning-design.md`

## Global Constraints

- Python 3.10+; stdlib only. Scapy stays optional and check 6 still degrades to WARN.
- Never disable/down Wi-Fi, never add/remove routes, never change the default route.
- Never invoke `sudo`/elevation. Attempt commands directly; on failure print the command for the operator.
- All external commands are argv lists passed to `run_command` (no shell).
- Management prefix is `/24` (`10.90.90.0/24`), never `/8`.
- Support Linux/macOS/Windows; `ipconfig /all` parsing is English-only (existing limitation).
- Keep everything in `netcheck.py`; add tests under `tests/`; run `python3 -m unittest discover -s tests -v`.
- Do not add code comments.
- Remove the transient management address on exit if netcheck added it.

---

### Task 1: Interface enumeration and LAN resolution

**Files:**
- Modify: `netcheck.py` (add `import ipaddress`; add dataclasses/parsers after `ping_argv`, around line 674; add `lan_interface: str | None = None` and `mgmt_address: str = "10.90.90.100"` to `Config`; add INI keys in `load_config`)
- Test: `tests/test_interfaces.py` (create)

**Interfaces:**
- Consumes: `run_command(args, timeout=10.0) -> tuple[int, str, str]` (existing, `netcheck.py:662`); `Config`.
- Produces: `InterfaceAddr(ip: str, prefix: int)`, `InterfaceInfo(name: str, addrs: list[InterfaceAddr], gateway: str | None)`, `LanInterface(name: str, primary_ip: str, addrs: list[InterfaceAddr])` with `source_for(dst: str) -> str`; `parse_linux_interfaces(text)`, `parse_macos_interfaces(text)`, `parse_windows_interfaces(text)`, `iter_interfaces(runner=run_command)`, `office_network(cfg)`, `resolve_lan_interface(cfg, runner=run_command, interfaces=None)`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_interfaces.py`:

```python
import unittest

from netcheck import (
    Config,
    InterfaceAddr,
    LanInterface,
    parse_linux_interfaces,
    parse_macos_interfaces,
    parse_windows_interfaces,
    resolve_lan_interface,
)

LINUX = """1: lo    inet 127.0.0.1/8 scope host lo
2: eth0    inet 192.168.1.50/24 brd 192.168.1.255 scope global dynamic eth0
3: wlan0    inet 192.168.68.160/24 brd 192.168.68.255 scope global dynamic wlan0
4: eth0    inet 10.90.90.100/24 scope global eth0
"""

MACOS = """lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255
en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 10.90.90.100 netmask 0xffffff00 broadcast 10.90.90.255
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 10.8.0.2 netmask 0xffffff00
"""

WINDOWS = """
Windows IP Configuration

Ethernet adapter Ethernet:

   Description . . . . . . . . . . . : Realtek PCIe GbE Family Controller
   IPv4 Address. . . . . . . . . . . : 192.168.1.50(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1

Wireless LAN adapter Wi-Fi:

   Description . . . . . . . . . . . : Intel(R) Wi-Fi 6 AX201
   IPv4 Address. . . . . . . . . . . : 192.168.68.160(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.68.1

Ethernet adapter Ethernet 2:

   Description . . . . . . . . . . . : Realtek USB GbE Family Controller
   IPv4 Address. . . . . . . . . . . : 10.90.90.100(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
"""


class TestParsers(unittest.TestCase):
    def test_linux_parses_and_skips_loopback(self):
        ifaces = {i.name: i for i in parse_linux_interfaces(LINUX)}
        self.assertNotIn("lo", ifaces)
        self.assertEqual([a.ip for a in ifaces["eth0"].addrs],
                         ["192.168.1.50", "10.90.90.100"])
        self.assertEqual(ifaces["wlan0"].addrs[0].prefix, 24)

    def test_macos_parses_and_skips_virtual(self):
        ifaces = {i.name: i for i in parse_macos_interfaces(MACOS)}
        self.assertNotIn("lo0", ifaces)
        self.assertNotIn("utun0", ifaces)
        self.assertEqual(ifaces["en0"].addrs[0].ip, "192.168.1.50")
        self.assertEqual(ifaces["en0"].addrs[0].prefix, 24)

    def test_windows_parses_adapters_and_gateway(self):
        ifaces = {i.name: i for i in parse_windows_interfaces(WINDOWS)}
        self.assertEqual(ifaces["Ethernet"].addrs[0].ip, "192.168.1.50")
        self.assertEqual(ifaces["Ethernet"].gateway, "192.168.1.1")
        self.assertEqual(ifaces["Ethernet 2"].addrs[0].ip, "10.90.90.100")


class TestResolveLan(unittest.TestCase):
    def test_picks_wired_office_nic_over_wifi(self):
        lan = resolve_lan_interface(Config(), interfaces=parse_linux_interfaces(LINUX))
        self.assertEqual(lan.name, "eth0")
        self.assertEqual(lan.primary_ip, "192.168.1.50")

    def test_macos_picks_en0(self):
        lan = resolve_lan_interface(Config(), interfaces=parse_macos_interfaces(MACOS))
        self.assertEqual(lan.name, "en0")
        self.assertEqual(lan.primary_ip, "192.168.1.50")

    def test_windows_picks_named_ethernet(self):
        lan = resolve_lan_interface(Config(), interfaces=parse_windows_interfaces(WINDOWS))
        self.assertEqual(lan.name, "Ethernet")
        self.assertEqual(lan.primary_ip, "192.168.1.50")

    def test_returns_none_without_candidate(self):
        only_wifi = [i for i in parse_linux_interfaces(LINUX) if i.name == "wlan0"]
        self.assertIsNone(resolve_lan_interface(Config(), interfaces=only_wifi))

    def test_override_selects_named_interface(self):
        cfg = Config(lan_interface="en1")
        lan = resolve_lan_interface(cfg, interfaces=parse_macos_interfaces(MACOS))
        self.assertEqual(lan.name, "en1")
        self.assertEqual(lan.primary_ip, "10.90.90.100")


class TestSourceFor(unittest.TestCase):
    def test_source_for_selects_on_subnet_address(self):
        lan = LanInterface("eth0", "192.168.1.50",
                           [InterfaceAddr("192.168.1.50", 24),
                            InterfaceAddr("10.90.90.100", 24)])
        self.assertEqual(lan.source_for("10.90.90.90"), "10.90.90.100")
        self.assertEqual(lan.source_for("1.1.1.1"), "192.168.1.50")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_interfaces -v`
Expected: FAIL with `ImportError: cannot import name 'InterfaceAddr'`.

- [ ] **Step 3: Add `Config` fields and INI keys**

In `Config` (`netcheck.py:203`), after `verbose: bool = False`, add:

```python
    mgmt_address: str = "10.90.90.100"
    lan_interface: str | None = None
```

In `load_config` (`netcheck.py:301`), inside `if parser.has_section("netcheck"):`, after the `domain` line, add:

```python
            cfg.mgmt_address = section.get("mgmt_address", cfg.mgmt_address)
            cfg.lan_interface = section.get("lan_interface", cfg.lan_interface)
```

- [ ] **Step 4: Implement the interface layer**

Add `import ipaddress` near the other imports at the top of `netcheck.py`. Then add the following after `ping_argv` (`netcheck.py:674`). `re` and `dataclasses.field` are already imported.

```python
_MGMT_NETWORK = ipaddress.ip_network("10.90.90.0/24")
_OFFICE_PREFIX = 24

_LINUX_IFACE_RE = re.compile(
    r"^\d+:\s+(\S+)\s+inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)", re.MULTILINE)
_MACOS_IFACE_RE = re.compile(r"^(\S+):\s+flags=.*$", re.MULTILINE)
_MACOS_INET_RE = re.compile(
    r"inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+)")
_MACOS_SKIP = ("lo", "utun", "awdl", "llw", "bridge", "ap", "anpi")
_WIN_ADAPTER_RE = re.compile(r"^[A-Za-z][^\r\n]*\badapter\s+(.+?):\s*$", re.MULTILINE)
_WIN_IPV4_RE = re.compile(r"IPv4 Address[^:]*:\s*(\d+\.\d+\.\d+\.\d+)")
_WIN_MASK_RE = re.compile(r"Subnet Mask[^:]*:\s*(\d+\.\d+\.\d+\.\d+)")
_WIN_GW_RE = re.compile(r"Default Gateway[^:]*:\s*(\d+\.\d+\.\d+\.\d+)")
_WIN_DESC_RE = re.compile(r"Description[^:]*:\s*(.+)")


@dataclass
class InterfaceAddr:
    ip: str
    prefix: int


@dataclass
class InterfaceInfo:
    name: str
    addrs: list[InterfaceAddr] = field(default_factory=list)
    gateway: str | None = None


@dataclass
class LanInterface:
    name: str
    primary_ip: str
    addrs: list[InterfaceAddr]

    def source_for(self, dst: str) -> str:
        for addr in self.addrs:
            if _ip_in_network(dst, addr.ip, addr.prefix):
                return addr.ip
        return self.primary_ip


def _ip_in_network(ip: str, net_ip: str, prefix: int) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(
            f"{net_ip}/{prefix}", strict=False)
    except ValueError:
        return False


def office_network(cfg: Config):
    return ipaddress.ip_network(f"{cfg.gateway}/{_OFFICE_PREFIX}", strict=False)


def _has_addr_in(info: InterfaceInfo, network) -> bool:
    for addr in info.addrs:
        try:
            if ipaddress.ip_address(addr.ip) in network:
                return True
        except ValueError:
            continue
    return False


def _prefix_from_mask(mask: str) -> int:
    try:
        return bin(int(ipaddress.IPv4Address(mask))).count("1")
    except (ipaddress.AddressValueError, ValueError):
        return 32


def parse_linux_interfaces(text: str) -> list[InterfaceInfo]:
    out: dict[str, InterfaceInfo] = {}
    for name, ip, prefix in _LINUX_IFACE_RE.findall(text):
        if name == "lo":
            continue
        info = out.setdefault(name, InterfaceInfo(name))
        info.addrs.append(InterfaceAddr(ip, int(prefix)))
    return list(out.values())


def parse_macos_interfaces(text: str) -> list[InterfaceInfo]:
    out: list[InterfaceInfo] = []
    current: InterfaceInfo | None = None
    for line in text.splitlines():
        header = _MACOS_IFACE_RE.match(line)
        if header:
            name = header.group(1)
            current = None if name.startswith(_MACOS_SKIP) else InterfaceInfo(name)
            if current is not None:
                out.append(current)
            continue
        if current is None:
            continue
        found = _MACOS_INET_RE.search(line)
        if found:
            current.addrs.append(
                InterfaceAddr(found.group(1), bin(int(found.group(2), 16)).count("1")))
    return out


def parse_windows_interfaces(text: str) -> list[InterfaceInfo]:
    out: list[InterfaceInfo] = []
    matches = list(_WIN_ADAPTER_RE.finditer(text))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        block = text[match.end():end]
        desc = _WIN_DESC_RE.search(block)
        if desc and "loopback" in desc.group(1).lower():
            continue
        info = InterfaceInfo(match.group(1).strip())
        ip = _WIN_IPV4_RE.search(block)
        mask = _WIN_MASK_RE.search(block)
        gateway = _WIN_GW_RE.search(block)
        if ip:
            info.addrs.append(InterfaceAddr(
                ip.group(1), _prefix_from_mask(mask.group(1)) if mask else 32))
        if gateway:
            info.gateway = gateway.group(1)
        out.append(info)
    return out


def iter_interfaces(runner=run_command) -> list[InterfaceInfo]:
    if sys.platform.startswith("win"):
        _, out, _ = runner(["ipconfig", "/all"])
        return parse_windows_interfaces(out)
    if sys.platform == "darwin":
        _, out, _ = runner(["ifconfig", "-a"])
        return parse_macos_interfaces(out)
    _, out, _ = runner(["ip", "-4", "-o", "addr", "show"])
    return parse_linux_interfaces(out)


def resolve_lan_interface(cfg: Config, runner=run_command,
                          interfaces: list[InterfaceInfo] | None = None
                          ) -> LanInterface | None:
    if interfaces is None:
        interfaces = iter_interfaces(runner)
    override = getattr(cfg, "lan_interface", None)
    if override:
        if override.startswith("-"):
            return None
        chosen = next((i for i in interfaces if i.name == override), None)
        if chosen is None:
            return None
        return LanInterface(chosen.name, _primary_ip(chosen, office_network(cfg)),
                            list(chosen.addrs))
    office = office_network(cfg)
    candidates = [i for i in interfaces
                  if _has_addr_in(i, office) or _has_addr_in(i, _MGMT_NETWORK)]
    if not candidates:
        return None
    office_ifaces = [i for i in candidates if _has_addr_in(i, office)]
    pool = office_ifaces or candidates
    if len(pool) > 1:
        carrying = [i for i in pool if _has_addr_in(i, _MGMT_NETWORK)]
        pool = carrying or pool
    chosen = pool[0]
    if len(office_ifaces) > 1:
        _diag(cfg, f"multiple office-LAN interfaces; using {chosen.name}")
    return LanInterface(chosen.name, _primary_ip(chosen, office), list(chosen.addrs))


def _primary_ip(info: InterfaceInfo, office) -> str:
    for addr in info.addrs:
        try:
            if ipaddress.ip_address(addr.ip) in office:
                return addr.ip
        except ValueError:
            continue
    return info.addrs[0].ip if info.addrs else ""
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_interfaces -v`
Expected: PASS (all 11 tests).

- [ ] **Step 6: Run the full suite for regressions**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS (new `Config` fields are additive; no existing test asserts the exact field set).

- [ ] **Step 7: Commit**

```bash
git add netcheck.py tests/test_interfaces.py
git commit -m "feat: add wired-LAN interface resolution layer"
```

---

### Task 2: Ping source pinning

**Files:**
- Modify: `netcheck.py` (`ping_argv` at line 671, `ping` at line 735)
- Test: `tests/test_ping.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `ping_argv(host, count, source=None) -> list[str]`; `ping(host, count=10, timeout=3.0, runner=run_command, source=None) -> PingResult`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_ping.py` inside `TestPing`:

```python
    def test_ping_argv_with_source_per_platform(self):
        with mock.patch("sys.platform", "linux"):
            self.assertEqual(
                ping_argv("8.8.8.8", 3, source="192.168.1.50"),
                ["ping", "-c", "3", "-I", "192.168.1.50", "8.8.8.8"])
        with mock.patch("sys.platform", "darwin"):
            self.assertEqual(
                ping_argv("8.8.8.8", 3, source="192.168.1.50"),
                ["ping", "-c", "3", "-S", "192.168.1.50", "8.8.8.8"])
        with mock.patch("sys.platform", "win32"):
            self.assertEqual(
                ping_argv("8.8.8.8", 3, source="192.168.1.50"),
                ["ping", "-n", "3", "-S", "192.168.1.50", "8.8.8.8"])
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m unittest tests.test_ping.TestPing.test_ping_argv_with_source_per_platform -v`
Expected: FAIL with `TypeError: ping_argv() got an unexpected keyword argument 'source'`.

- [ ] **Step 3: Implement**

Replace `ping_argv` (`netcheck.py:671`) with:

```python
def ping_argv(host: str, count: int, source: str | None = None) -> list[str]:
    if sys.platform.startswith("win"):
        argv = ["ping", "-n", str(count)]
        if source:
            argv += ["-S", source]
    else:
        argv = ["ping", "-c", str(count)]
        if source:
            argv += (["-I", source] if sys.platform == "linux" else ["-S", source])
    argv.append(host)
    return argv
```

Replace the body of `ping` (`netcheck.py:735`) with:

```python
def ping(host: str, count: int = 10, timeout: float = 3.0,
         runner=run_command, source: str | None = None) -> PingResult:
    _, out, _ = runner(ping_argv(host, count, source=source),
                       timeout=count * timeout + 5)
    return parse_ping_output(host, out)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_ping -v`
Expected: PASS (existing `test_ping_argv_per_platform` still passes because `source=None` yields the old argv).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_ping.py
git commit -m "feat: allow ping to bind a source address"
```

---

### Task 3: DNS source pinning

**Files:**
- Modify: `netcheck.py` (`dns_query` at line 785)
- Test: `tests/test_dns.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `dns_query(server, name, timeout=3.0, source=None) -> tuple[bool, float, list[str]]`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_dns.py`; add the `mock` import at the top (`from unittest import mock`) and extend the import from `netcheck` with `dns_query`.

```python
    def test_dns_query_binds_source(self):
        with mock.patch("netcheck.socket.socket") as sock_cls:
            sock = sock_cls.return_value
            sock.recvfrom.side_effect = OSError("no reply")
            ok, _ms, answers = dns_query("1.1.1.1", "example.com",
                                         source="192.168.1.50")
            self.assertFalse(ok)
            self.assertEqual(answers, [])
            sock.bind.assert_called_once_with(("192.168.1.50", 0))

    def test_dns_query_without_source_does_not_bind(self):
        with mock.patch("netcheck.socket.socket") as sock_cls:
            sock = sock_cls.return_value
            sock.recvfrom.side_effect = OSError("no reply")
            dns_query("1.1.1.1", "example.com")
            sock.bind.assert_not_called()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_dns -v`
Expected: FAIL with `TypeError: dns_query() got an unexpected keyword argument 'source'`.

- [ ] **Step 3: Implement**

In `dns_query` (`netcheck.py:785`), change the signature to
`def dns_query(server: str, name: str, timeout: float = 3.0, source: str | None = None) -> tuple[bool, float, list[str]]:`
and, inside the `try:` before `sock.sendto(...)`, add:

```python
        if source:
            sock.bind((source, 0))
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_dns -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_dns.py
git commit -m "feat: allow dns_query to bind a source address"
```

---

### Task 4: SNMP source pinning

**Files:**
- Modify: `netcheck.py` (`SnmpClient` at line 555, `collect_devices` at line 1209, `check_device_inventory` at line 1280, `check_hardening` at line 1461, `measure_storm_threshold` at line 1542)
- Test: `tests/test_snmp.py`, `tests/test_inventory.py`

**Interfaces:**
- Consumes: nothing new.
- Produces: `SnmpClient(host, community, version="2c", timeout=3.0, retries=2, source=None)`; `collect_devices(cfg, client_factory=SnmpClient, source=None)`; `check_device_inventory(cfg, rogue_macs, client_factory=SnmpClient, source=None)`; `check_hardening(cfg, measured=None, client_factory=SnmpClient, source=None)`; `measure_storm_threshold(cfg, sample_seconds=30, client_factory=SnmpClient, source=None)`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_snmp.py` inside `TestSnmp` (extend the top import with `SnmpError` and add `from unittest import mock`):

```python
    def test_client_binds_source(self):
        with mock.patch("netcheck.socket.socket") as sock_cls:
            sock = sock_cls.return_value
            sock.recvfrom.side_effect = OSError("timeout")
            client = SnmpClient("10.90.90.90", "public",
                                source="10.90.90.100", retries=0)
            with self.assertRaises(SnmpError):
                client._exchange(b"\x00")
            sock.bind.assert_called_once_with(("10.90.90.100", 0))
```

Append to `tests/test_inventory.py` inside `TestCollectDevices`:

```python
    def test_source_is_forwarded_to_client_factory(self):
        seen = {}

        class CapturingClient(FakeClient):
            def __init__(self, host, community, **kw):
                super().__init__(host, community, **kw)
                seen["source"] = kw.get("source")

        cfg = Config(switches={"dlink1": "10.90.90.90"}, snmp_community="public")
        collect_devices(cfg, client_factory=CapturingClient, source="10.90.90.100")
        self.assertEqual(seen["source"], "10.90.90.100")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_snmp.TestSnmp.test_client_binds_source tests.test_inventory.TestCollectDevices.test_source_is_forwarded_to_client_factory -v`
Expected: FAIL (`SnmpClient() got an unexpected keyword argument 'source'` / `collect_devices() got an unexpected keyword argument 'source'`).

- [ ] **Step 3: Implement `SnmpClient`**

Change `SnmpClient.__init__` (`netcheck.py:556`) to add `source: str | None = None` and store it:

```python
    def __init__(self, host: str, community: str, version: str = "2c",
                 timeout: float = 3.0, retries: int = 2,
                 source: str | None = None):
        self.host = host
        self.community = community
        self.version = version
        self.timeout = timeout
        self.retries = retries
        self.source = source
        self.version_int = _VERSION_INT.get(version, 1)
        self.request_id = random.randint(1, 2 ** 31 - 1)
```

In `_exchange` (`netcheck.py:566`), inside the `try:` before `sock.sendto(...)`, add:

```python
                if self.source:
                    sock.bind((self.source, 0))
```

- [ ] **Step 4: Implement the factory plumbing**

`collect_devices` (`netcheck.py:1209`): add `source: str | None = None` to the signature and pass it:

```python
def collect_devices(cfg: Config, client_factory=SnmpClient,
                    source: str | None = None) -> Devicelist:
```

```python
            client = client_factory(host, cfg.snmp_community,
                                    timeout=cfg.timeout, source=source)
```

`check_device_inventory` (`netcheck.py:1280`): add `source: str | None = None` and forward it:

```python
def check_device_inventory(cfg: Config, rogue_macs: list[str],
                           client_factory=SnmpClient,
                           source: str | None = None) -> CheckResult:
```

```python
    devs = collect_devices(cfg, client_factory=client_factory, source=source)
```

`check_hardening` (`netcheck.py:1461`): add `source: str | None = None`; change the client line to:

```python
            client = client_factory(host, cfg.snmp_community,
                                    timeout=cfg.timeout, source=source)
```

`measure_storm_threshold` (`netcheck.py:1542`): same signature addition and client line.

- [ ] **Step 5: Update test factories that reject `source`**

Run `python3 -m unittest discover -s tests -v` and, for any fake client whose
`__init__` does not accept `**kw`, add `**kw` to its signature (the inventory
fakes already do). Keep the change minimal.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add netcheck.py tests/test_snmp.py tests/test_inventory.py
git commit -m "feat: allow SNMP client to bind a source address"
```

---

### Task 5: Scapy interface pinning

**Files:**
- Modify: `netcheck.py` (`scapy_dhcp_discover` at line 1012, `check_rogue_dhcp` at line 1039)
- Test: `tests/test_rogue.py` (create) or append to `tests/test_storm_hints.py` if present — create `tests/test_rogue.py`.

**Interfaces:**
- Consumes: nothing new.
- Produces: `scapy_dhcp_discover(timeout=5.0, cfg=None, iface=None) -> DhcpProbe`; `check_rogue_dhcp(cfg, discover_fn=None, iface=None) -> tuple[CheckResult, list[str]]`.

- [ ] **Step 1: Write the failing test**

Create `tests/test_rogue.py`:

```python
import unittest

from netcheck import Config, Status, check_rogue_dhcp, DhcpProbe


class TestRogueIfaceForwarding(unittest.TestCase):
    def test_iface_is_forwarded_to_discover_fn(self):
        seen = {}

        def fake_discover(cfg=None, iface=None):
            seen["iface"] = iface
            return DhcpProbe(None, "stub")

        check_rogue_dhcp(Config(), discover_fn=fake_discover, iface="eth0")
        self.assertEqual(seen["iface"], "eth0")

    def test_no_iface_passes_none(self):
        seen = {}

        def fake_discover(cfg=None, iface=None):
            seen["iface"] = iface
            return DhcpProbe(None, "stub")

        check_rogue_dhcp(Config(), discover_fn=fake_discover)
        self.assertIsNone(seen["iface"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m unittest tests.test_rogue -v`
Expected: FAIL with `TypeError: check_rogue_dhcp() got an unexpected keyword argument 'iface'`.

- [ ] **Step 3: Implement**

Change `scapy_dhcp_discover` (`netcheck.py:1012`) signature to
`def scapy_dhcp_discover(timeout: float = 5.0, cfg=None, iface: str | None = None) -> DhcpProbe:`.
Right after the `from scapy.all import ...` line, add interface resolution:

```python
    if iface is None:
        try:
            from scapy.all import conf
            iface = conf.route.route("10.90.90.90")[0]
        except Exception:  # noqa: BLE001 - scapy routing is best-effort
            iface = None
```

Change the `srp(...)` call to include the interface:

```python
        answered, _ = srp(packet, timeout=timeout, verbose=False, iface=iface)
```

Change `check_rogue_dhcp` (`netcheck.py:1039`) to
`def check_rogue_dhcp(cfg: Config, discover_fn=None, iface: str | None = None) -> tuple[CheckResult, list[str]]:`
and change the default discover wiring to:

```python
    if discover_fn is None:
        discover_fn = lambda cfg=None, iface=iface: scapy_dhcp_discover(
            cfg=cfg, iface=iface)
```

Then change the call site to `probe = discover_fn(cfg, iface)`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_rogue -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_rogue.py
git commit -m "feat: pin the rogue-DHCP probe to the wired interface"
```

---

### Task 6: Check 1 rewrite (wired NIC, Wi-Fi note)

**Files:**
- Modify: `netcheck.py` (`LocalConfig` at line 805, add `read_dns_servers`/`default_route_interface`, `detect_local_config` at line 860, `check_local_config` at line 886, `run_layer_checks` at line 969)
- Test: `tests/test_local_config.py`, `tests/test_checks_layer.py`

**Interfaces:**
- Consumes: `resolve_lan_interface`, `office_network`, `LanInterface` (Task 1).
- Produces: `LocalConfig(..., default_route_interface: str | None = None)`; `detect_local_config(cfg, runner=run_command, lan=None) -> LocalConfig`; `check_local_config(cfg, local_fn=None) -> CheckResult`; `read_dns_servers(runner=run_command) -> list[str]`; `default_route_interface(runner=run_command) -> str | None`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_local_config.py` (extend the `netcheck` import with `detect_local_config`, `office_network`, `InterfaceAddr`, `LanInterface`; add `from unittest import mock`):

```python
class TestWiredCheckOne(unittest.TestCase):
    def _lan(self, ip):
        return LanInterface("eth0", ip, [InterfaceAddr(ip, 24)])

    def test_detect_uses_wired_nic(self):
        cfg = Config()
        lan = self._lan("192.168.1.50")
        with mock.patch("netcheck.read_dns_servers", return_value=["1.1.1.1"]), \
             mock.patch("netcheck.default_route_interface", return_value="wlan0"):
            lc = detect_local_config(cfg, lan=lan)
        self.assertEqual(lc.interface, "eth0")
        self.assertEqual(lc.ip, "192.168.1.50")
        self.assertEqual(lc.gateway, "192.168.1.1")
        self.assertEqual(lc.default_route_interface, "wlan0")

    def test_pass_with_wifi_primary_note(self):
        cfg = Config()
        lan = self._lan("192.168.1.50")
        with mock.patch("netcheck.read_dns_servers", return_value=["1.1.1.1"]), \
             mock.patch("netcheck.default_route_interface", return_value="wlan0"):
            result = check_local_config(
                cfg, local_fn=lambda: detect_local_config(cfg, lan=lan))
        self.assertIs(result.status, Status.PASS)
        self.assertIn("wired LAN checked", result.detail)

    def test_fail_when_not_on_office_lan(self):
        cfg = Config()
        lan = self._lan("10.90.90.100")
        with mock.patch("netcheck.read_dns_servers", return_value=["1.1.1.1"]), \
             mock.patch("netcheck.default_route_interface", return_value="wlan0"):
            result = check_local_config(
                cfg, local_fn=lambda: detect_local_config(cfg, lan=lan))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("192.168.1.0/24", result.likely_cause or "")

    def test_fail_without_lan(self):
        with mock.patch("netcheck.resolve_lan_interface", return_value=None):
            result = check_local_config(
                Config(), local_fn=lambda: detect_local_config(Config()))
        self.assertIs(result.status, Status.FAIL)

    def test_no_wired_nic_returns_empty(self):
        with mock.patch("netcheck.resolve_lan_interface", return_value=None):
            lc = detect_local_config(Config())
        self.assertIsNone(lc.ip)
```

Replace the existing `test_gateway_mismatch_message_uses_configured_gateway`
(`tests/test_local_config.py:52`) with:

```python
    def test_off_subnet_address_fails_against_configured_gateway(self):
        cfg = Config(gateway="10.20.30.1")
        lc = LocalConfig(ip="192.168.68.160", gateway="192.168.68.1", dns=["1.1.1.1"])
        result = check_local_config(cfg, local_fn=lambda: lc)
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("10.20.30.0/24", result.likely_cause or "")
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_local_config -v`
Expected: FAIL (`ImportError: cannot import name 'detect_local_config'` is fine; the import exists already, so expect `TypeError` for `lan=`/new semantics).

- [ ] **Step 3: Add the `default_route_interface` field and helpers**

In `LocalConfig` (`netcheck.py:805`), after `interface: str | None = None`, add:

```python
    default_route_interface: str | None = None
```

Add these helpers just above `detect_local_config` (`netcheck.py:860`):

```python
def read_dns_servers(runner=run_command) -> list[str]:
    if sys.platform.startswith("win"):
        _, out, _ = runner(["ipconfig", "/all"])
        return parse_ipconfig_windows(out).dns
    if sys.platform == "darwin":
        _, out, _ = runner(["scutil", "--dns"])
        return re.findall(r"nameserver\[[^\]]+\]\s*:\s*([\d.]+)", out)
    try:
        with open("/etc/resolv.conf") as fh:
            return re.findall(r"^nameserver\s+([\d.]+)", fh.read(), re.MULTILINE)
    except OSError:
        return []


def default_route_interface(runner=run_command) -> str | None:
    if sys.platform.startswith("win"):
        _, out, _ = runner(["ipconfig", "/all"])
        for info in parse_windows_interfaces(out):
            if info.gateway:
                return info.name
        return None
    if sys.platform == "darwin":
        _, out, _ = runner(["route", "-n", "get", "default"])
    else:
        _, out, _ = runner(["ip", "route"])
    match = re.search(r"(?:interface:\s*(\S+))|(?:default\b.*\bdev\s+(\S+))", out)
    if not match:
        return None
    return match.group(1) or match.group(2)
```

- [ ] **Step 4: Rewrite `detect_local_config`**

Replace `detect_local_config` (`netcheck.py:860`) with:

```python
def detect_local_config(cfg: Config, runner=run_command, lan=None) -> LocalConfig:
    if lan is None:
        lan = resolve_lan_interface(cfg, runner)
    if lan is None:
        return LocalConfig()
    lc = LocalConfig(interface=lan.name)
    office = office_network(cfg)
    for addr in lan.addrs:
        try:
            if ipaddress.ip_address(addr.ip) in office:
                lc.ip = addr.ip
                lc.mask = f"/{addr.prefix}"
                lc.gateway = cfg.gateway
                break
        except ValueError:
            continue
    if lc.ip is None and lan.primary_ip:
        lc.ip = lan.primary_ip
    lc.dns = read_dns_servers(runner)
    lc.default_route_interface = default_route_interface(runner)
    return lc
```

- [ ] **Step 5: Rewrite `check_local_config`**

Replace `check_local_config` (`netcheck.py:886`) with:

```python
def check_local_config(cfg: Config, local_fn=None) -> CheckResult:
    if local_fn is None:
        local_fn = lambda: detect_local_config(cfg)
    lc = local_fn()
    prefix = f"{lc.interface} " if lc.interface else ""
    detail = f"{prefix}{lc.ip or 'no IP'} {lc.mask or ''} " \
             f"gw {lc.gateway or 'none'} dns {','.join(lc.dns) or 'none'}"
    if lc.default_route_interface and lc.interface \
            and lc.default_route_interface != lc.interface:
        detail += f"; default route via Wi-Fi ({lc.default_route_interface}); wired LAN checked"
    if not lc.ip:
        return CheckResult(1, "Local config", Status.FAIL, detail=detail,
                           likely_cause="No IPv4 address on the wired LAN interface.",
                           suggested_fix="Plug in the LAN cable and renew DHCP on the wired NIC.")
    if lc.ip.startswith("169.254."):
        return CheckResult(1, "Local config", Status.FAIL, detail=detail,
                           likely_cause="APIPA address: DHCP did not answer.",
                           suggested_fix="Check the switch port/uplink, then renew the lease.")
    if not _ip_in_network(lc.ip, cfg.gateway, _OFFICE_PREFIX):
        net = office_network(cfg)
        return CheckResult(1, "Local config", Status.FAIL, detail=detail,
                           likely_cause=f"No wired address on the office LAN ({net}).",
                           suggested_fix="Plug in the LAN cable and renew DHCP on the "
                                         "wired NIC; Wi-Fi does not satisfy this check.")
    if not lc.dns:
        return CheckResult(1, "Local config", Status.WARN, detail=detail,
                           likely_cause="No DNS servers configured.",
                           suggested_fix="Set DNS to 1.1.1.1/8.8.8.8 or the ISP DNS.")
    return CheckResult(1, "Local config", Status.PASS, detail=detail)
```

- [ ] **Step 6: Update `run_layer_checks` default**

In `run_layer_checks` (`netcheck.py:969`), change the signature to
`def run_layer_checks(cfg: Config, reporter: Reporter, local_fn=None, ping_fn=ping, query_fn=dns_query) -> None:`
and add at the top of the function:

```python
    if local_fn is None:
        local_fn = lambda: detect_local_config(cfg)
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_local_config tests.test_checks_layer -v`
Expected: PASS.
Then run the full suite: `python3 -m unittest discover -s tests -v`.
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add netcheck.py tests/test_local_config.py
git commit -m "fix: check 1 inspects the wired NIC, not the Wi-Fi default route"
```

---

### Task 7: Transient management address

**Files:**
- Modify: `netcheck.py` (add `MgmtAddressResult`, argv builders, `ensure_mgmt_address`, `remove_mgmt_address` after `prompt_yes_no` at line 1600)
- Test: `tests/test_mgmt_ip.py` (create)

**Interfaces:**
- Consumes: `Config.mgmt_address`, `resolve_lan_interface`, `LanInterface`, `prompt_yes_no` (existing, `netcheck.py:1600`), `run_command`, `_MGMT_NETWORK`.
- Produces: `MgmtAddressResult(added: bool, address: str | None, interface: str | None, command: list[str] | None, detail: str)`; `mgmt_add_argv(iface, addr, platform=None) -> list[str]`; `mgmt_del_argv(iface, addr, platform=None) -> list[str]`; `ensure_mgmt_address(cfg, lan, allow_fix=True, tty=None, runner=run_command) -> MgmtAddressResult`; `remove_mgmt_address(cfg, iface, runner=run_command) -> None`.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_mgmt_ip.py`:

```python
import io
import unittest
from unittest import mock

from netcheck import (
    Config,
    InterfaceAddr,
    LanInterface,
    ensure_mgmt_address,
    mgmt_add_argv,
    mgmt_del_argv,
    remove_mgmt_address,
)


def _lan(*ips):
    return LanInterface("eth0", ips[0], [InterfaceAddr(ip, 24) for ip in ips])


class TestArgv(unittest.TestCase):
    def test_add_argv_per_platform(self):
        self.assertEqual(
            mgmt_add_argv("eth0", "10.90.90.100", platform="linux"),
            ["ip", "addr", "replace", "10.90.90.100/24", "dev", "eth0"])
        self.assertEqual(
            mgmt_add_argv("en0", "10.90.90.100", platform="darwin"),
            ["ifconfig", "en0", "alias", "10.90.90.100", "255.255.255.0"])
        self.assertEqual(
            mgmt_add_argv("Ethernet", "10.90.90.100", platform="win32"),
            ["netsh", "interface", "ipv4", "add", "address", "Ethernet",
             "10.90.90.100", "255.255.255.0"])

    def test_del_argv_per_platform(self):
        self.assertEqual(
            mgmt_del_argv("eth0", "10.90.90.100", platform="linux"),
            ["ip", "addr", "del", "10.90.90.100/24", "dev", "eth0"])
        self.assertEqual(
            mgmt_del_argv("en0", "10.90.90.100", platform="darwin"),
            ["ifconfig", "en0", "-alias", "10.90.90.100"])
        self.assertEqual(
            mgmt_del_argv("Ethernet", "10.90.90.100", platform="win32"),
            ["netsh", "interface", "ipv4", "delete", "address", "Ethernet",
             "10.90.90.100"])


class TestEnsureMgmtAddress(unittest.TestCase):
    def test_present_does_not_prompt_or_run(self):
        calls = []
        result = ensure_mgmt_address(
            Config(), _lan("192.168.1.50", "10.90.90.100"),
            tty=io.StringIO("y\n"), runner=lambda *a, **k: calls.append(a) or (0, "", ""))
        self.assertFalse(result.added)
        self.assertEqual(calls, [])

    def test_missing_prompt_yes_adds_and_verifies(self):
        added = _lan("192.168.1.50", "10.90.90.100")
        with mock.patch("netcheck.resolve_lan_interface", return_value=added):
            result = ensure_mgmt_address(
                Config(), _lan("192.168.1.50"),
                tty=io.StringIO("y\n"),
                runner=lambda *a, **k: (0, "", ""))
        self.assertTrue(result.added)
        self.assertEqual(result.address, "10.90.90.100")

    def test_permission_failure_returns_command(self):
        with mock.patch("netcheck.resolve_lan_interface",
                        return_value=_lan("192.168.1.50")):
            result = ensure_mgmt_address(
                Config(), _lan("192.168.1.50"),
                tty=io.StringIO("y\n"),
                runner=lambda *a, **k: (1, "", "Operation not permitted"))
        self.assertFalse(result.added)
        self.assertEqual(result.command,
                         ["ip", "addr", "replace", "10.90.90.100/24", "dev", "eth0"])

    def test_declined_returns_command(self):
        result = ensure_mgmt_address(
            Config(), _lan("192.168.1.50"),
            tty=io.StringIO("n\n"), runner=lambda *a, **k: (0, "", ""))
        self.assertFalse(result.added)
        self.assertIsNotNone(result.command)

    def test_no_fix_returns_command(self):
        result = ensure_mgmt_address(
            Config(), _lan("192.168.1.50"), allow_fix=False,
            tty=io.StringIO("y\n"), runner=lambda *a, **k: (0, "", ""))
        self.assertFalse(result.added)
        self.assertIsNotNone(result.command)

    def test_no_lan_is_a_no_op(self):
        result = ensure_mgmt_address(Config(), None, tty=io.StringIO("y\n"))
        self.assertFalse(result.added)
        self.assertIsNone(result.command)

    def test_invalid_mgmt_address_raises(self):
        with self.assertRaises(ValueError):
            ensure_mgmt_address(Config(mgmt_address="8.8.8.8"), _lan("192.168.1.50"),
                                tty=io.StringIO("y\n"))

    def test_remove_runs_del_argv(self):
        calls = []
        remove_mgmt_address(Config(), "eth0",
                            runner=lambda *a, **k: calls.append(a) or (0, "", ""))
        self.assertEqual(calls[0][0], ["ip", "addr", "del", "10.90.90.100/24",
                                       "dev", "eth0"])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_mgmt_ip -v`
Expected: FAIL with `ImportError: cannot import name 'ensure_mgmt_address'`.

- [ ] **Step 3: Implement the argv builders and validation**

Add after `prompt_yes_no` (`netcheck.py:1611`):

```python
@dataclass
class MgmtAddressResult:
    added: bool
    address: str | None = None
    interface: str | None = None
    command: list[str] | None = None
    detail: str = ""


def _validate_mgmt_address(cfg: Config) -> str:
    addr = ipaddress.ip_address(cfg.mgmt_address)
    if addr not in _MGMT_NETWORK:
        raise ValueError(f"{cfg.mgmt_address} is outside {_MGMT_NETWORK}")
    if addr == _MGMT_NETWORK.network_address or addr == _MGMT_NETWORK.broadcast_address:
        raise ValueError(f"{cfg.mgmt_address} is not a usable host address")
    return str(addr)


def mgmt_add_argv(iface: str, addr: str, platform: str | None = None) -> list[str]:
    platform = platform or sys.platform
    if platform.startswith("win"):
        return ["netsh", "interface", "ipv4", "add", "address", iface, addr,
                "255.255.255.0"]
    if platform == "darwin":
        return ["ifconfig", iface, "alias", addr, "255.255.255.0"]
    return ["ip", "addr", "replace", f"{addr}/24", "dev", iface]


def mgmt_del_argv(iface: str, addr: str, platform: str | None = None) -> list[str]:
    platform = platform or sys.platform
    if platform.startswith("win"):
        return ["netsh", "interface", "ipv4", "delete", "address", iface, addr]
    if platform == "darwin":
        return ["ifconfig", iface, "-alias", addr]
    return ["ip", "addr", "del", f"{addr}/24", "dev", iface]


def _lan_has_mgmt(lan: LanInterface, cfg: Config) -> bool:
    for addr in lan.addrs:
        try:
            if ipaddress.ip_address(addr.ip) in _MGMT_NETWORK:
                return True
        except ValueError:
            continue
    return False
```

- [ ] **Step 4: Implement `ensure_mgmt_address` and `remove_mgmt_address`**

Add below the functions from Step 3:

```python
def ensure_mgmt_address(cfg: Config, lan: LanInterface | None,
                        allow_fix: bool = True, tty=None,
                        runner=run_command) -> MgmtAddressResult:
    if lan is None:
        return MgmtAddressResult(False, detail="no wired LAN interface")
    addr = _validate_mgmt_address(cfg)
    if lan.name.startswith("-"):
        raise ValueError(f"invalid interface name {lan.name!r}")
    if _lan_has_mgmt(lan, cfg):
        return MgmtAddressResult(False, addr, lan.name, None, "present")
    argv = mgmt_add_argv(lan.name, addr)
    if not allow_fix:
        return MgmtAddressResult(False, addr, lan.name, argv, "declined")
    question = f"Add {addr}/24 to {lan.name} for switch access?"
    if not prompt_yes_no(question, tty=tty):
        return MgmtAddressResult(False, addr, lan.name, argv, "declined")
    runner(argv)
    refreshed = resolve_lan_interface(cfg, runner=runner)
    if refreshed is not None and _lan_has_mgmt(refreshed, cfg):
        return MgmtAddressResult(True, addr, lan.name, argv, "added")
    return MgmtAddressResult(False, addr, lan.name, argv, "could not add")


def remove_mgmt_address(cfg: Config, iface: str, runner=run_command) -> None:
    try:
        addr = _validate_mgmt_address(cfg)
    except ValueError:
        return
    runner(mgmt_del_argv(iface, addr))
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_mgmt_ip -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add netcheck.py tests/test_mgmt_ip.py
git commit -m "feat: transient management-address add/remove with prompt"
```

---

### Task 8: Wire everything into `run_all` and add `--remove-mgmt-ip`

**Files:**
- Modify: `netcheck.py` (`build_parser` at line 134, `main` at line 168, `run_all` at line 1646)
- Test: `tests/test_orchestration.py`

**Interfaces:**
- Consumes: everything from Tasks 1–7.
- Produces: `run_all(cfg, reporter, quick=False, sample=None, hardening=False, allow_fix=True, tty=None, runner=run_command, verbose=False, lan=None) -> None`; `--remove-mgmt-ip` CLI flag; `_report_mgmt(result) -> None`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_orchestration.py`:

```python
    def test_parser_has_remove_mgmt_ip(self):
        self.assertFalse(netcheck.build_parser().parse_args([]).remove_mgmt_ip)
        self.assertTrue(
            netcheck.build_parser().parse_args(["--remove-mgmt-ip"]).remove_mgmt_ip)

    def test_run_all_sources_pings_from_management_address(self):
        lan = netcheck.LanInterface(
            "eth0", "192.168.1.50",
            [netcheck.InterfaceAddr("192.168.1.50", 24),
             netcheck.InterfaceAddr("10.90.90.100", 24)])
        seen = []

        def runner(args, timeout=10.0):
            seen.append(list(args))
            return 0, "", ""

        reporter = netcheck.Reporter(color=False)
        orig_resolve = netcheck.resolve_lan_interface
        orig_rogue = netcheck.check_rogue_dhcp
        netcheck.resolve_lan_interface = lambda *a, **k: lan
        netcheck.check_rogue_dhcp = lambda *a, **k: (
            netcheck.CheckResult(6, "Rogue DHCP", netcheck.Status.PASS, detail="stub"), [])
        try:
            netcheck.run_all(netcheck.Config(), reporter, allow_fix=False, runner=runner)
        finally:
            netcheck.resolve_lan_interface = orig_resolve
            netcheck.check_rogue_dhcp = orig_rogue
        pings = [a for a in seen if a and a[0] == "ping"]
        self.assertTrue(any("10.90.90.100" in a for a in pings))
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python3 -m unittest tests.test_orchestration.TestOrchestration.test_parser_has_remove_mgmt_ip tests.test_orchestration.TestOrchestration.test_run_all_sources_pings_from_management_address -v`
Expected: FAIL (`AttributeError: 'Namespace' object has no attribute 'remove_mgmt_ip'`; no ping sourced from `10.90.90.100`).

- [ ] **Step 3: Add the CLI flag and `_report_mgmt`**

In `build_parser` (`netcheck.py:134`), after the `--json` argument, add:

```python
    parser.add_argument("--remove-mgmt-ip", action="store_true",
                        help="remove the transient switch-management address and exit")
```

Add `_report_mgmt` just above `run_all` (`netcheck.py:1646`):

```python
def _report_mgmt(result: MgmtAddressResult) -> None:
    if result.added:
        print(f"added {result.address}/24 to {result.interface} (removed on exit)")
        return
    if result.command and result.detail in ("declined", "could not add"):
        command = " ".join(result.command)
        if sys.platform.startswith("win"):
            print(f"could not add {result.address}/24; run as Administrator: {command}")
        else:
            print(f"could not add {result.address}/24; run: sudo {command}")
```

- [ ] **Step 4: Update `main` for `--remove-mgmt-ip`**

In `main` (`netcheck.py:174`), right after `cfg = load_config(path=args.config)` and the `cfg.timeout`/`cfg.verbose` lines, add:

```python
    if args.remove_mgmt_ip:
        lan = resolve_lan_interface(cfg)
        if lan is None:
            print("no wired LAN interface found", file=sys.stderr)
            return 1
        remove_mgmt_address(cfg, lan.name)
        print(f"removed {cfg.mgmt_address}/24 from {lan.name}")
        return 0
```

- [ ] **Step 5: Rewrite the body of `run_all`**

Change the `run_all` signature (`netcheck.py:1646`) to add `lan=None`:

```python
def run_all(cfg: Config, reporter: Reporter, quick: bool = False,
            sample: float | None = None, hardening: bool = False,
            allow_fix: bool = True, tty=None, runner=run_command,
            verbose: bool = False, lan=None) -> None:
```

Then, immediately after the `_run_check` helper and the existing `_diag` preamble
lines (keep those lines), insert before `try:`:

```python
    if lan is None:
        lan = resolve_lan_interface(cfg, runner)
    source_for = lan.source_for if lan is not None else (lambda dst: None)
    _diag(cfg, f"lan_interface={lan.name} ({lan.primary_ip})" if lan
               else "lan_interface=none")
    added_mgmt = False
    mgmt_iface: str | None = None
```

Change the `layer_ping` and add `layer_query` source binding:

```python
        layer_ping = lambda host, **kw: ping(host, runner=runner,
                                             source=source_for(host), **kw)
        layer_query = lambda server, name, **kw: dns_query(
            server, name, timeout=kw.get("timeout", cfg.timeout),
            source=source_for(server))
        run_layer_checks(cfg, reporter,
                         local_fn=lambda: detect_local_config(cfg, runner, lan=lan),
                         ping_fn=layer_ping, query_fn=layer_query)
```

After `if quick: return`, add the management-address pre-flight:

```python
        mgmt = ensure_mgmt_address(cfg, lan, allow_fix=allow_fix, tty=tty,
                                   runner=runner)
        _report_mgmt(mgmt)
        added_mgmt = mgmt.added
        mgmt_iface = mgmt.interface
        if mgmt.added:
            refreshed = resolve_lan_interface(cfg, runner)
            if refreshed is not None:
                lan = refreshed
                source_for = lan.source_for
```

Thread the interface into rogue DHCP:

```python
        def _rogue() -> None:
            result, macs = check_rogue_dhcp(cfg, iface=lan.name if lan else None)
            reporter.add(result)
            rogue_macs.extend(macs)
```

Thread `source` into the SNMP checks:

```python
            def _sample_only() -> None:
                measured = measure_storm_threshold(
                    cfg, sample_seconds=sample,
                    source=source_for("10.90.90.90"))
                reporter.add(format_threshold_samples(measured))
```

```python
            def _hardening() -> None:
                measured = (measure_storm_threshold(
                                cfg, sample_seconds=sample,
                                source=source_for("10.90.90.90"))
                            if sample is not None else {})
                reporter.add(check_hardening(cfg, measured=measured,
                                             source=source_for("10.90.90.90")))
```

```python
        def _inventory() -> None:
            reporter.add(check_device_inventory(
                cfg, rogue_macs, source=source_for("10.90.90.90")))
```

Bind check 8's gateway ping to the wired NIC as well (replace the existing
`gateway_ping = ping(...)` line in `_storm`):

```python
            gateway_ping = ping(cfg.gateway, count=4, timeout=cfg.timeout,
                                runner=runner, source=source_for(cfg.gateway))
```

Add the `finally` after the existing `except Exception as exc:` block that adds
the check-98 result:

```python
    finally:
        if added_mgmt and mgmt_iface:
            remove_mgmt_address(cfg, mgmt_iface, runner=runner)
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `python3 -m unittest tests.test_orchestration -v`
Expected: PASS.
Then run the full suite: `python3 -m unittest discover -s tests -v`.
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add netcheck.py tests/test_orchestration.py
git commit -m "feat: pin all checks to the wired LAN and add --remove-mgmt-ip"
```

---

### Task 9: Documentation

**Files:**
- Modify: `README.md` (§2 at line 48, check table row 1 at line 84), `USAGE.md` (§3.3 at line 241, check-1 criteria at line 663), `netcheck.ini.example`
- Test: `tests/test_docs.py`

**Interfaces:**
- Consumes: `Config.mgmt_address` (Task 1).
- Produces: no code; docs match behavior.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_docs.py` in `TestDocs`:

```python
    def test_example_config_lists_mgmt_keys(self):
        with open("netcheck.ini.example") as fh:
            text = fh.read()
        self.assertIn("mgmt_address", text)
        self.assertIn("lan_interface", text)
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m unittest tests.test_docs -v`
Expected: FAIL (`AssertionError` — the example file has no `mgmt_address`/`lan_interface` yet).

- [ ] **Step 3: Update `netcheck.ini.example`**

After the `switches = ...` line (`netcheck.ini.example:19`), add:

```
# Transient switch-management address: netcheck prompts, adds this on the wired
# NIC before checks 5-9, and removes it when done. Override the NIC autodetect
# (normally the NIC holding 192.168.1.x or 10.90.90.x) with lan_interface.
mgmt_address = 10.90.90.100
# lan_interface = eth0
```

- [ ] **Step 4: Update `README.md` §2**

Replace the heading and body of §2 (`README.md:48-61`) with:

```markdown
**2. Wired LAN + switch management address.** Checks 1–4 use the wired NIC's
`192.168.1.x` address; checks 5–9 need a `10.90.90.x` address. netcheck
auto-detects the wired NIC (the one holding `192.168.1.x` or `10.90.90.x`) —
Wi-Fi can stay connected and keeps the default route. Before checks 5–9, if the
`10.90.90.x` address is missing, netcheck prompts and adds `10.90.90.100/24` to
that NIC, then **removes it when the run ends**. If it cannot add the address it
prints the exact command to run as root/Administrator and continues.

To set it up manually instead (or force the NIC), use `lan_interface` in
`netcheck.ini` and run e.g. `sudo ip addr add 10.90.90.100/24 dev eth0`.
```

- [ ] **Step 5: Update `README.md` check table row 1**

Change row 1 (`README.md:84`) to:

```markdown
| 1 | Local config | Wired NIC IP, mask, gateway, DNS; flags APIPA or a wired NIC not on `192.168.1.0/24` |
```

- [ ] **Step 6: Update `USAGE.md` §3.3 and check-1 criteria**

Replace the manual-instructions body of §3.3 (`USAGE.md:241-259`) with a
description of auto-detection, the prompt, `/24`, and removal at exit; keep a
manual `ip addr add` one-liner as a fallback. In the criteria table row for
check 1 (`USAGE.md:663`), replace the gateway-mismatch wording with "wired NIC
not on `192.168.1.0/24`" and note the Wi-Fi-primary case stays PASS.

- [ ] **Step 7: Run the docs test and the full suite**

Run: `python3 -m unittest tests.test_docs -v`
Expected: PASS.
Run: `python3 -m unittest discover -s tests -v`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add README.md USAGE.md netcheck.ini.example tests/test_docs.py
git commit -m "docs: describe wired-LAN pinning and transient management address"
```

---

## Self-Review

**Spec coverage:** §3 interface model → Task 1. §4.1 ping → Task 2. §4.2 DNS →
Task 3. §4.3 SNMP → Task 4. §4.4 scapy → Task 5. §4.5 wiring → Task 8. §5 check 1
→ Task 6. §6.1–§6.3 mgmt address → Tasks 7 (functions) and 8 (wiring/finally).
§6.4 config/CLI → Tasks 1 (`Config`) and 8 (`--remove-mgmt-ip`). §7 security →
validation in Tasks 1/7, argv-only throughout, no escalation. §8 tests → each
task. §9 docs → Task 9. §10 risks → accepted/documented.

**Placeholder scan:** No "TBD"/"TODO"; every code step contains concrete code.

**Type consistency:** `LanInterface.source_for`, `InterfaceAddr.ip/prefix`,
`InterfaceInfo.name/addrs/gateway`, `MgmtAddressResult.added/address/interface/
command/detail`, `detect_local_config(cfg, runner, lan)`,
`ensure_mgmt_address(cfg, lan, allow_fix, tty, runner)`,
`mgmt_add_argv`/`mgmt_del_argv(iface, addr, platform)` are used with the same
names and signatures in every task that references them. `source_for` returns a
`str`; `ping_argv`/`ping`/`dns_query`/`SnmpClient` all receive that `str` as
`source`.
