# simple-netcheck Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `netcheck.py`, a single-file Python 3.10+ CLI that diagnoses internet problems in the office network, audits the D-Link switch fabric, and reports PASS/WARN/FAIL with likely causes and fixes.

**Architecture:** One stdlib-only file (`netcheck.py`) containing bottom-up units (BER codec → SNMP v2c client → shell-out/parse helpers → checks 1–9 → reporter → CLI). Tests live in `tests/` and run with `python -m unittest`. Optional third-party packages (`scapy`, `pysnmp`) are imported lazily and never required.

**Tech Stack:** Python 3.10+ standard library (`socket`, `struct`, `subprocess`, `argparse`, `configparser`, `dataclasses`, `concurrent.futures`, `unittest`). Optional: `scapy`, `pysnmp`, `nmap`.

**Spec:** `docs/superpowers/specs/2026-09-29-simple-netcheck-design.md`

## Global Constraints

- **Python floor:** `>=3.10` (3.12+ recommended). Declared in the PEP 723 header.
- **Single file:** all runtime code in `netcheck.py`; no sibling imports.
- **Standard library preferred:** `scapy`, `pysnmp`, `nmap` are optional and must be imported/used lazily with graceful fallback.
- **Read-only:** never SNMP SET, never CLI `config`/`save`, never touch the ISP router.
- **Secrets:** SNMP community and credentials only from env/INI; never hardcoded, echoed, or logged.
- **Defaults:** gateway `192.168.1.1`; ISP DNS `58.71.2.8`,`45.63.30.117`; public DNS `1.1.1.1`,`8.8.8.8`; switches `dlink1`–`dlink5` = `10.90.90.90`–`10.90.90.94`; default login `admin`/`admin`.
- **Hardening baseline values** are copied from spec §7 exactly (LBD recover time `0`, storm type `3`, `factor=4`, `floor=10000`, RSTP `dlink1` priority `4096`).
- **Exit codes:** `0` = no FAIL, `1` = WARN present, `2` = FAIL present.
- **No placeholders:** every step below contains real code.

---

### Task 1: Repo bootstrap, PEP 723 header, CLI skeleton

**Files:**
- Create: `netcheck.py`
- Create: `.gitignore`
- Create: `tests/__init__.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `__version__: str`; `build_parser() -> argparse.ArgumentParser`; `main(argv: list[str] | None = None) -> int`.

- [ ] **Step 1: Initialize the repository**

```bash
cd /home/floyddan/dev/simple-netcheck
git init
printf '__pycache__/\n*.pyc\nnetcheck.ini\nnetcheck-*.log\nSHA256SUMS\n' > .gitignore
git add .gitignore && git commit -m "chore: initialize repository"
```

- [ ] **Step 2: Write the failing test**

```python
# tests/test_cli.py
import unittest

import netcheck


class TestCli(unittest.TestCase):
    def test_version_exits_zero(self):
        self.assertEqual(netcheck.main(["--version"]), 0)

    def test_version_value(self):
        self.assertRegex(netcheck.__version__, r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python -m unittest tests.test_cli -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'netcheck'`.

- [ ] **Step 4: Write the skeleton**

```python
#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""simple-netcheck - diagnose office internet problems and audit the switch fabric."""

from __future__ import annotations

import argparse
import sys

__version__ = "0.1.0"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netcheck", description=__doc__)
    parser.add_argument("--version", action="version", version=f"netcheck {__version__}")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Add `tests/__init__.py`**

```bash
printf '' > tests/__init__.py
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `python -m unittest tests.test_cli -v`
Expected: PASS (2 tests).

- [ ] **Step 7: Commit**

```bash
git add netcheck.py tests/__init__.py tests/test_cli.py
git commit -m "feat: add single-file CLI skeleton with PEP 723 header"
```

---

### Task 2: `Status`, `CheckResult`, `Reporter`

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_reporter.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Status` (enum: `PASS`, `WARN`, `FAIL`); `CheckResult(id, title, status, detail="", likely_cause="", suggested_fix="")`; `Reporter(color: bool = True)` with `.add(result)`, `.render() -> str`, `.exit_code() -> int`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_reporter.py
import unittest

from netcheck import CheckResult, Reporter, Status


class TestReporter(unittest.TestCase):
    def test_exit_code_no_fail(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "Local config", Status.PASS, detail="ok"))
        r.add(CheckResult(2, "Gateway", Status.WARN, detail="loss"))
        self.assertEqual(r.exit_code(), 1)

    def test_exit_code_fail_wins(self):
        r = Reporter(color=False)
        r.add(CheckResult(1, "Local config", Status.WARN))
        r.add(CheckResult(2, "Gateway", Status.FAIL))
        self.assertEqual(r.exit_code(), 2)

    def test_render_contains_lines_and_fix(self):
        r = Reporter(color=False)
        r.add(CheckResult(6, "Rogue DHCP", Status.FAIL, detail="192.168.1.77",
                          likely_cause="rogue server", suggested_fix="unplug it"))
        text = r.render()
        self.assertIn("[FAIL] 6. Rogue DHCP", text)
        self.assertIn("Likely cause: rogue server", text)
        self.assertIn("Suggested fix: unplug it", text)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_reporter -v`
Expected: FAIL with `ImportError` (`CheckResult` not defined).

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py, above build_parser
import enum
from dataclasses import dataclass, field


class Status(enum.Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"


@dataclass
class CheckResult:
    id: int
    title: str
    status: Status
    detail: str = ""
    likely_cause: str = ""
    suggested_fix: str = ""


_COLORS = {Status.PASS: "\033[32m", Status.WARN: "\033[33m", Status.FAIL: "\033[31m"}
_RESET = "\033[0m"


class Reporter:
    def __init__(self, color: bool = True):
        self.color = color
        self.results: list[CheckResult] = []

    def add(self, result: CheckResult) -> None:
        self.results.append(result)

    def exit_code(self) -> int:
        if any(r.status is Status.FAIL for r in self.results):
            return 2
        if any(r.status is Status.WARN for r in self.results):
            return 1
        return 0

    def render(self) -> str:
        lines: list[str] = []
        for r in self.results:
            tag = f"[{r.status.value}]"
            if self.color:
                tag = f"{_COLORS[r.status]}{tag}{_RESET}"
            line = f"{tag} {r.id}. {r.title}"
            if r.detail:
                line += f"  - {r.detail}"
            lines.append(line)
        causes = [r for r in self.results if r.likely_cause]
        fixes = [r for r in self.results if r.suggested_fix]
        if causes:
            lines.append("")
            lines.append("Likely cause: " + causes[0].likely_cause)
        if fixes:
            lines.append("Suggested fix: " + fixes[0].suggested_fix)
        return "\n".join(lines)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_reporter -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_reporter.py
git commit -m "feat: add Status, CheckResult, and Reporter"
```

---

### Task 3: `Config` loader (env + INI + defaults)

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `Config` dataclass and `load_config(path: str | None = None, env: Mapping[str, str] | None = None) -> Config`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_config.py
import os
import tempfile
import unittest

from netcheck import Config, load_config


class TestConfig(unittest.TestCase):
    def test_defaults(self):
        cfg = load_config(env={})
        self.assertEqual(cfg.gateway, "192.168.1.1")
        self.assertEqual(cfg.switches["dlink1"], "10.90.90.90")
        self.assertEqual(cfg.switches["dlink5"], "10.90.90.94")
        self.assertEqual(cfg.storm_safety_factor, 4)
        self.assertEqual(cfg.storm_floor_kbps, 10000)

    def test_env_overrides(self):
        cfg = load_config(env={"NETCHECK_SNMP_COMMUNITY": "ro", "NETCHECK_GATEWAY": "10.0.0.1"})
        self.assertEqual(cfg.snmp_community, "ro")
        self.assertEqual(cfg.gateway, "10.0.0.1")

    def test_ini_then_env_precedence(self):
        with tempfile.NamedTemporaryFile("w", suffix=".ini", delete=False) as fh:
            fh.write("[netcheck]\ngateway = 172.16.0.1\nsnmp_community = filecomm\n")
            path = fh.name
        try:
            cfg = load_config(path=path, env={"NETCHECK_SNMP_COMMUNITY": "envcomm"})
            self.assertEqual(cfg.gateway, "172.16.0.1")          # file wins over default
            self.assertEqual(cfg.snmp_community, "envcomm")      # env wins over file
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_config -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
import configparser
import os
from collections.abc import Mapping

_DEFAULT_SWITCHES = {f"dlink{i}": f"10.90.90.{89 + i}" for i in range(1, 6)}


@dataclass
class Config:
    switches: dict[str, str] = field(default_factory=lambda: dict(_DEFAULT_SWITCHES))
    gateway: str = "192.168.1.1"
    dns_servers: list[str] = field(default_factory=lambda: ["58.71.2.8", "45.63.30.117"])
    public_dns: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    domain: str = "example.com"
    snmp_community: str = ""
    snmp_version: str = "2c"
    switch_user: str = "admin"
    switch_pass: str = ""
    storm_safety_factor: int = 4
    storm_floor_kbps: int = 10000
    timeout: float = 3.0


_ENV_MAP = {
    "NETCHECK_SNMP_COMMUNITY": "snmp_community",
    "NETCHECK_SNMP_VERSION": "snmp_version",
    "NETCHECK_SWITCH_USER": "switch_user",
    "NETCHECK_SWITCH_PASS": "switch_pass",
    "NETCHECK_GATEWAY": "gateway",
    "NETCHECK_DOMAIN": "domain",
    "NETCHECK_STORM_SAFETY_FACTOR": "storm_safety_factor",
    "NETCHECK_STORM_FLOOR_KBPS": "storm_floor_kbps",
}


def load_config(path: str | None = None, env: Mapping[str, str] | None = None) -> Config:
    env = os.environ if env is None else env
    cfg = Config()

    if path:
        parser = configparser.ConfigParser()
        parser.read(path)
        if parser.has_section("netcheck"):
            section = parser["netcheck"]
            cfg.gateway = section.get("gateway", cfg.gateway)
            cfg.snmp_community = section.get("snmp_community", cfg.snmp_community)
            cfg.snmp_version = section.get("snmp_version", cfg.snmp_version)
            cfg.switch_user = section.get("switch_user", cfg.switch_user)
            cfg.switch_pass = section.get("switch_pass", cfg.switch_pass)
            cfg.domain = section.get("domain", cfg.domain)
            cfg.storm_safety_factor = int(section.get("storm_safety_factor", cfg.storm_safety_factor))
            cfg.storm_floor_kbps = int(section.get("storm_floor_kbps", cfg.storm_floor_kbps))
            if section.get("switches"):
                cfg.switches = dict(
                    item.split("=", 1) for item in section["switches"].replace(" ", "").split(",")
                )
            if section.get("dns"):
                cfg.dns_servers = section["dns"].replace(" ", "").split(",")

    for env_key, attr in _ENV_MAP.items():
        if env_key in env:
            value: object = env[env_key]
            if attr in ("storm_safety_factor", "storm_floor_kbps"):
                value = int(value)
            setattr(cfg, attr, value)
    if "NETCHECK_SWITCHES" in env:
        cfg.switches = dict(
            item.split("=", 1) for item in env["NETCHECK_SWITCHES"].replace(" ", "").split(",")
        )
    if "NETCHECK_DNS" in env:
        cfg.dns_servers = env["NETCHECK_DNS"].replace(" ", "").split(",")
    return cfg
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_config -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_config.py
git commit -m "feat: add Config loader with env and INI precedence"
```

---

### Task 4: BER/ASN.1 codec

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_ber.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `ber_encode_length(n) -> bytes`; `ber_encode_integer(n) -> bytes`; `ber_encode_octet_string(b) -> bytes`; `ber_encode_null() -> bytes`; `ber_encode_oid(oid) -> bytes`; `ber_encode_sequence(items) -> bytes`; `ber_decode_tlv(data, offset=0) -> tuple[int, bytes, int]`; `ber_decode_integer(value) -> int`; `ber_decode_oid(value) -> str`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ber.py
import unittest

from netcheck import (
    ber_decode_integer,
    ber_decode_oid,
    ber_decode_tlv,
    ber_encode_integer,
    ber_encode_length,
    ber_encode_oid,
    ber_encode_sequence,
)


class TestBer(unittest.TestCase):
    def test_length_short_and_long(self):
        self.assertEqual(ber_encode_length(5), b"\x05")
        self.assertEqual(ber_encode_length(200), b"\x81\xc8")

    def test_integer_round_trip(self):
        for n in (0, 1, 127, 128, 32768, 2_000_000_000):
            tag, value, nxt = ber_decode_tlv(ber_encode_integer(n))
            self.assertEqual(tag, 0x02)
            self.assertEqual(ber_decode_integer(value), n)
            self.assertEqual(nxt, len(ber_encode_integer(n)))

    def test_oid_round_trip(self):
        for oid in ("1.3.6.1", "1.3.6.1.4.1.171.10.76.20.1.17.5.1.3"):
            tag, value, _ = ber_decode_tlv(ber_encode_oid(oid))
            self.assertEqual(tag, 0x06)
            self.assertEqual(ber_decode_oid(value), oid)

    def test_sequence_integer(self):
        encoded = ber_encode_sequence([ber_encode_integer(7)])
        tag, value, _ = ber_decode_tlv(encoded)
        self.assertEqual(tag, 0x30)
        _, inner, _ = ber_decode_tlv(value)
        self.assertEqual(ber_decode_integer(inner), 7)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_ber -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
def ber_encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = b""
    while n:
        body = bytes([n & 0xFF]) + body
        n >>= 8
    return bytes([0x80 | len(body)]) + body


def ber_encode_integer(n: int) -> bytes:
    if n == 0:
        body = b"\x00"
    else:
        body = b""
        while n > 0:
            body = bytes([n & 0xFF]) + body
            n >>= 8
        if body[0] & 0x80:
            body = b"\x00" + body
    return b"\x02" + ber_encode_length(len(body)) + body


def ber_encode_octet_string(data: bytes) -> bytes:
    return b"\x04" + ber_encode_length(len(data)) + data


def ber_encode_null() -> bytes:
    return b"\x05\x00"


def ber_encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    body = [parts[0] * 40 + parts[1]]
    for n in parts[2:]:
        if n < 0x80:
            body.append(n)
            continue
        chunk = [n & 0x7F]
        n >>= 7
        while n:
            chunk.append((n & 0x7F) | 0x80)
            n >>= 7
        body.extend(reversed(chunk))
    return b"\x06" + ber_encode_length(len(body)) + bytes(body)


def ber_encode_sequence(items: list[bytes]) -> bytes:
    body = b"".join(items)
    return b"\x30" + ber_encode_length(len(body)) + body


def ber_decode_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        num = length & 0x7F
        length = int.from_bytes(data[offset:offset + num], "big")
        offset += num
    value = data[offset:offset + length]
    return tag, value, offset + length


def ber_decode_integer(value: bytes) -> int:
    n = int.from_bytes(value, "big")
    if value and value[0] & 0x80:
        n -= 1 << (8 * len(value))
    return n


def ber_decode_oid(value: bytes) -> str:
    if not value:
        return ""
    parts = [value[0] // 40, value[0] % 40]
    i = 1
    while i < len(value):
        n = 0
        while True:
            byte = value[i]
            i += 1
            n = (n << 7) | (byte & 0x7F)
            if not byte & 0x80:
                break
        parts.append(n)
    return ".".join(str(p) for p in parts)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_ber -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_ber.py
git commit -m "feat: add minimal BER/ASN.1 codec"
```

---

### Task 5: SNMP v2c client (GET / GETNEXT / GETBULK / WALK)

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_snmp.py`

**Interfaces:**
- Consumes: BER functions from Task 4.
- Produces: `SnmpError`; `decode_value(tag, value) -> object`; `decode_port_list(value: bytes) -> list[int]`; `SnmpClient(host, community, version="2c", timeout=3.0, retries=2)` with `.get(oids) -> dict`, `.get_next(oid) -> tuple[str, object] | None`, `.get_bulk(base_oid, max_repetitions=25) -> list`, `.walk(base_oid) -> list[tuple[str, object]]`; `_encode_request(community, version_int, request_id, pdu_type, oids, max_repetitions=None) -> bytes`; `_parse_response(data) -> tuple[int, int, list[tuple[str, object]]]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_snmp.py
import unittest

from netcheck import (
    SnmpClient,
    _encode_request,
    _parse_response,
    decode_port_list,
    decode_value,
)


class TestSnmp(unittest.TestCase):
    def test_port_list_decode(self):
        # 0b1000_0001, 0b0000_0001 => bit0 of octet0 = port1, bit7 of octet0 = port8, port9
        self.assertEqual(decode_port_list(b"\x81\x01"), [1, 8, 9])
        self.assertEqual(decode_port_list(b"\x00\x00"), [])

    def test_decode_value_integer(self):
        self.assertEqual(decode_value(0x02, b"\x01"), 1)
        self.assertEqual(decode_value(0x41, b"\x00\x64"), 100)

    def test_encode_request_round_trip(self):
        packed = _encode_request("public", 1, 42, 0xA0, ["1.3.6.1.2.1.1.1.0"])
        version, req_id, varbinds = _parse_response(packed)
        self.assertEqual(version, 1)
        self.assertEqual(req_id, 42)
        self.assertEqual(varbinds[0][0], "1.3.6.1.2.1.1.1.0")

    def test_client_construction(self):
        client = SnmpClient("10.90.90.90", "public")
        self.assertEqual(client.host, "10.90.90.90")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_snmp -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
import random
import socket

TAG_INTEGER = 0x02
TAG_OCTET = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_IPADDRESS = 0x40
TAG_COUNTER = 0x41
TAG_GAUGE = 0x42
TAG_TIMETICKS = 0x43
_INTEGER_TAGS = {TAG_INTEGER, TAG_COUNTER, TAG_GAUGE, TAG_TIMETICKS, TAG_IPADDRESS}

PDU_GET = 0xA0
PDU_GET_NEXT = 0xA1
PDU_GET_BULK = 0xA5

_VERSION_INT = {"1": 0, "2c": 1}


class SnmpError(Exception):
    pass


def decode_value(tag: int, value: bytes) -> object:
    if tag in _INTEGER_TAGS:
        return ber_decode_integer(value)
    if tag == TAG_OCTET:
        return value
    if tag == TAG_NULL:
        return None
    if tag == TAG_OID:
        return ber_decode_oid(value)
    return value


def decode_port_list(value: bytes) -> list[int]:
    ports: list[int] = []
    for octet_index, byte in enumerate(value):
        for bit in range(8):
            if byte & (0x80 >> bit):
                ports.append(octet_index * 8 + bit + 1)
    return ports


def _apply_pdu(pdu_type: int, request_id: int, oids: list[str],
               max_repetitions: int | None) -> bytes:
    if pdu_type == PDU_GET_BULK:
        head = [
            ber_encode_integer(pdu_type),
            ber_encode_integer(request_id),
            ber_encode_integer(0),
            ber_encode_integer(max_repetitions or 25),
            ber_encode_integer(0),
        ]
    else:
        head = [
            ber_encode_integer(pdu_type),
            ber_encode_integer(request_id),
            ber_encode_integer(0),
            ber_encode_integer(0),
        ]
    varbinds = b"".join(
        ber_encode_sequence([ber_encode_oid(oid), ber_encode_null()]) for oid in oids
    )
    head.append(ber_encode_sequence([varbinds]))
    return ber_encode_sequence(head)


def _encode_request(community: str, version_int: int, request_id: int, pdu_type: int,
                    oids: list[str], max_repetitions: int | None = None) -> bytes:
    return ber_encode_sequence([
        ber_encode_integer(version_int),
        ber_encode_octet_string(community.encode()),
        _apply_pdu(pdu_type, request_id, oids, max_repetitions),
    ])


def _parse_varbinds(payload: bytes) -> list[tuple[str, object]]:
    out: list[tuple[str, object]] = []
    offset = 0
    while offset < len(payload):
        _, vb, offset = ber_decode_tlv(payload, offset)
        inner = 0
        _, oid_bytes, inner = ber_decode_tlv(vb, inner)
        tag, value, _ = ber_decode_tlv(vb, inner)
        out.append((ber_decode_oid(oid_bytes), decode_value(tag, value)))
    return out


def _parse_response(data: bytes) -> tuple[int, int, list[tuple[str, object]]]:
    _, message, _ = ber_decode_tlv(data)
    offset = 0
    _, version_bytes, offset = ber_decode_tlv(message, offset)
    _, _community, offset = ber_decode_tlv(message, offset)
    _, pdu, _ = ber_decode_tlv(message, offset)
    pdu_offset = 0
    _, _pdu_type, pdu_offset = ber_decode_tlv(pdu, pdu_offset)
    _, request_bytes, pdu_offset = ber_decode_tlv(pdu, pdu_offset)
    _, _err_status, pdu_offset = ber_decode_tlv(pdu, pdu_offset)
    _, _err_index, pdu_offset = ber_decode_tlv(pdu, pdu_offset)
    _, varbind_list_bytes, _ = ber_decode_tlv(pdu, pdu_offset)
    return (ber_decode_integer(version_bytes), ber_decode_integer(request_bytes),
            _parse_varbinds(varbind_list_bytes))


def _oid_in_subtree(oid: str, base: str) -> bool:
    return oid == base or oid.startswith(base + ".")


class SnmpClient:
    def __init__(self, host: str, community: str, version: str = "2c",
                 timeout: float = 3.0, retries: int = 2):
        self.host = host
        self.community = community
        self.version = version
        self.timeout = timeout
        self.retries = retries
        self.version_int = _VERSION_INT.get(version, 1)
        self.request_id = random.randint(1, 2 ** 31 - 1)

    def _exchange(self, packet: bytes) -> bytes:
        last_error = "timeout"
        for _ in range(self.retries + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            try:
                sock.sendto(packet, (self.host, 161))
                data, _ = sock.recvfrom(65535)
                return data
            except OSError as exc:
                last_error = str(exc)
            finally:
                sock.close()
        raise SnmpError(f"no response from {self.host}: {last_error}")

    def _request(self, pdu_type: int, oids: list[str],
                 max_repetitions: int | None = None) -> list[tuple[str, object]]:
        self.request_id = (self.request_id + 1) & 0x7FFFFFFF
        packet = _encode_request(self.community, self.version_int, self.request_id,
                                 pdu_type, oids, max_repetitions)
        _version, _req_id, varbinds = _parse_response(self._exchange(packet))
        return varbinds

    def get(self, oids: list[str]) -> dict[str, object]:
        return dict(self._request(PDU_GET, oids))

    def get_next(self, oid: str) -> tuple[str, object] | None:
        varbinds = self._request(PDU_GET_NEXT, [oid])
        if not varbinds:
            return None
        next_oid, value = varbinds[0]
        if value is None or next_oid <= oid:
            return None
        return next_oid, value

    def get_bulk(self, base_oid: str, max_repetitions: int = 25) -> list[tuple[str, object]]:
        return self._request(PDU_GET_BULK, [base_oid], max_repetitions)

    def walk(self, base_oid: str) -> list[tuple[str, object]]:
        results: list[tuple[str, object]] = []
        current = base_oid
        for _ in range(5000):
            step = self.get_next(current)
            if step is None:
                break
            oid, value = step
            if not _oid_in_subtree(oid, base_oid):
                break
            results.append((oid, value))
            current = oid
        return results
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_snmp -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_snmp.py
git commit -m "feat: add minimal SNMP v2c client with BER round-trip tests"
```

---

### Task 6: Embedded OUI vendor table

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_oui.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `OUI_TABLE: dict[str, str]`; `lookup_vendor(mac: str) -> str | None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_oui.py
import unittest

from netcheck import lookup_vendor


class TestOui(unittest.TestCase):
    def test_known_vendor(self):
        self.assertEqual(lookup_vendor("00:1e:58:aa:bb:cc"), "D-Link")

    def test_unknown_vendor(self):
        self.assertIsNone(lookup_vendor("02:00:00:00:00:00"))

    def test_case_and_separator_tolerant(self):
        self.assertEqual(lookup_vendor("001E58AABBCC"), "D-Link")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_oui -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
OUI_TABLE: dict[str, str] = {
    "001B11": "D-Link", "001E58": "D-Link", "001CF0": "D-Link", "14D64D": "D-Link",
    "1CBDB9": "D-Link", "340804": "D-Link", "5CD998": "D-Link", "909448": "D-Link",
    "B8A386": "D-Link", "C8BE19": "D-Link", "F07D68": "D-Link", "FCF8AE": "D-Link",
    "000C29": "VMware", "005056": "VMware", "080027": "VirtualBox",
    "00000C": "Cisco", "001A2F": "Cisco", "001B0C": "Cisco", "001E13": "Cisco",
    "00235E": "Cisco", "001A8C": "Cisco", "E4AA5D": "Cisco", "F4CFE2": "Cisco",
    "000FB5": "Netgear", "001B2F": "Netgear", "204E7F": "Netgear", "A040A0": "Netgear",
    "50C7BF": "TP-Link", "A42BB0": "TP-Link", "B0BE76": "TP-Link", "EC086B": "TP-Link",
    "F4EC38": "TP-Link", "14CC20": "TP-Link", "60A4D0": "TP-Link",
    "0418D6": "Ubiquiti", "24A43C": "Ubiquiti", "44D9E7": "Ubiquiti", "788A20": "Ubiquiti",
    "F09FC2": "Ubiquiti",
    "001CB3": "Apple", "3C0754": "Apple", "F0DBF8": "Apple", "A4C361": "Apple",
    "000D3A": "Microsoft", "0017FA": "Microsoft", "7C1E52": "Microsoft",
    "002248": "Microsoft", "00155D": "Microsoft",
    "001132": "Synology", "0011D8": "ASUS", "002215": "ASUS", "9C5C8E": "ASUS",
    "001E8C": "HP", "0025B3": "HP", "3C4A92": "HP", "9457A5": "HP",
    "001B78": "Dell", "002219": "Dell", "1866DA": "Dell", "B8CA3A": "Dell",
    "525400": "QEMU/KVM", "00163E": "Xen", "001C42": "Parallels",
    "0009B0": "Raspberry Pi", "B827EB": "Raspberry Pi", "DCA632": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    "24EE9A": "Intel", "3C9509": "Intel", "7CB27D": "Intel", "A0369F": "Intel",
    "1868CB": "Intel",
    "1C1B0D": "GIGA-BYTE", "B42E99": "GIGA-BYTE", "94DE80": "GIGA-BYTE",
    "0024E8": "Dell", "001E4F": "Dell",
    "6C5AB0": "Tenda", "C83A35": "Tenda", "D8320E": "Tenda",
    "B0958E": "Ruckus", "001392": "Ruckus", "C0C520": "Ruckus",
}


def lookup_vendor(mac: str) -> str | None:
    normalized = mac.replace(":", "").replace("-", "").replace(".", "").upper()
    if len(normalized) < 6:
        return None
    return OUI_TABLE.get(normalized[:6])
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_oui -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_oui.py
git commit -m "feat: add embedded OUI vendor table"
```

---

### Task 7: Shell-out helper and ping parser

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_ping.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `PingResult(host, transmitted, received, loss_pct, min_ms, avg_ms, max_ms)`; `parse_ping_output(host, output) -> PingResult`; `ping_argv(host, count) -> list[str]`; `ping(host, count=10, timeout=3.0, runner=run_command) -> PingResult`; `run_command(args, timeout=10.0) -> tuple[int, str, str]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_ping.py
import unittest

from netcheck import PingResult, parse_ping_output

LINUX = """PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.23 ms

--- 192.168.1.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 1.000/1.500/2.000/0.500 ms
"""

MACOS = """PING 1.1.1.1 (1.1.1.1): 56 data bytes
64 bytes from 1.1.1.1: icmp_seq=0 ttl=57 time=9.1 ms

--- 1.1.1.1 ping statistics ---
3 packets transmitted, 2 packets received, 33.3% packet loss
round-trip min/avg/max/stddev = 9.100/9.500/9.900/0.400 ms
"""

WINDOWS = """
Pinging 8.8.8.8 with 32 bytes of data:
Reply from 8.8.8.8: bytes=32 time=11ms TTL=118

Ping statistics for 8.8.8.8:
    Packets: Sent = 4, Received = 3, Lost = 1 (25% loss),
Approximate round trip times in milli-seconds:
    Minimum = 10ms, Maximum = 12ms, Average = 11ms
"""


class TestPing(unittest.TestCase):
    def test_linux(self):
        r = parse_ping_output("192.168.1.1", LINUX)
        self.assertEqual((r.transmitted, r.received), (3, 3))
        self.assertEqual(r.loss_pct, 0.0)
        self.assertEqual(r.avg_ms, 1.5)

    def test_macos_loss(self):
        r = parse_ping_output("1.1.1.1", MACOS)
        self.assertEqual(r.loss_pct, 33.3)
        self.assertEqual(r.max_ms, 9.9)

    def test_windows(self):
        r = parse_ping_output("8.8.8.8", WINDOWS)
        self.assertEqual((r.transmitted, r.received), (4, 3))
        self.assertEqual(r.loss_pct, 25.0)
        self.assertEqual(r.avg_ms, 11.0)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_ping -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
import re
import subprocess


def run_command(args: list[str], timeout: float = 10.0) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=timeout,
                              check=False)
        return proc.returncode, proc.stdout, proc.stderr
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)


def ping_argv(host: str, count: int) -> list[str]:
    if sys.platform.startswith("win"):
        return ["ping", "-n", str(count), host]
    if sys.platform == "darwin":
        return ["ping", "-c", str(count), "-t", "5", host]
    return ["ping", "-c", str(count), "-w", "5", host]


@dataclass
class PingResult:
    host: str
    transmitted: int = 0
    received: int = 0
    loss_pct: float = 100.0
    min_ms: float | None = None
    avg_ms: float | None = None
    max_ms: float | None = None


def parse_ping_output(host: str, output: str) -> PingResult:
    result = PingResult(host=host)

    loss = re.search(r"(\d+(?:\.\d+)?)%\s*(?:packet\s+)?loss", output, re.IGNORECASE)
    if not loss:
        loss = re.search(r"\((\d+(?:\.\d+)?)%\s*loss\)", output, re.IGNORECASE)
    if loss:
        result.loss_pct = float(loss.group(1))

    sent = re.search(r"(\d+)\s+packets?\s+transmitted", output, re.IGNORECASE)
    if sent:
        result.transmitted = int(sent.group(1))
    else:
        sent = re.search(r"Sent\s*=\s*(\d+)", output, re.IGNORECASE)
        if sent:
            result.transmitted = int(sent.group(1))

    recv = re.search(r"(\d+)\s+(?:packets?\s+)?received", output, re.IGNORECASE)
    if recv:
        result.received = int(recv.group(1))
    else:
        recv = re.search(r"Received\s*=\s*(\d+)", output, re.IGNORECASE)
        if recv:
            result.received = int(recv.group(1))

    rtt = re.search(
        r"(?:rtt|round-trip)\s+min/avg/max/(?:mdev|stddev)\s*=\s*"
        r"([\d.]+)/([\d.]+)/([\d.]+)",
        output, re.IGNORECASE,
    )
    if rtt:
        result.min_ms, result.avg_ms, result.max_ms = (float(x) for x in rtt.groups())
    else:
        win = re.search(
            r"Minimum\s*=\s*(\d+)ms,\s*Maximum\s*=\s*(\d+)ms,\s*Average\s*=\s*(\d+)ms",
            output, re.IGNORECASE,
        )
        if win:
            result.min_ms = float(win.group(1))
            result.max_ms = float(win.group(2))
            result.avg_ms = float(win.group(3))

    if result.transmitted and not result.received:
        result.received = round(result.transmitted * (1 - result.loss_pct / 100))
    return result


def ping(host: str, count: int = 10, timeout: float = 3.0,
         runner=run_command) -> PingResult:
    _, out, _ = runner(ping_argv(host, count), timeout=count * timeout + 5)
    return parse_ping_output(host, out)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_ping -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_ping.py
git commit -m "feat: add shell-out helper and cross-platform ping parser"
```

---

### Task 8: Raw DNS query and parser

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_dns.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `build_dns_query(name, txid) -> bytes`; `parse_dns_a(data) -> list[str]`; `dns_query(server, name, timeout=3.0) -> tuple[bool, float, list[str]]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_dns.py
import struct
import unittest

from netcheck import build_dns_query, parse_dns_a


def _response(txid: int, name: str, ip: bytes) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x8180, 1, 1, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    q += struct.pack(">HH", 1, 1)
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + ip
    return header + q + answer


class TestDns(unittest.TestCase):
    def test_build_query_header(self):
        packet = build_dns_query("example.com", 0x1234)
        self.assertEqual(packet[:2], b"\x12\x34")
        self.assertEqual(struct.unpack(">H", packet[4:6])[0], 1)  # QDCOUNT

    def test_parse_a_record(self):
        packet = _response(0x1234, "example.com", bytes([93, 184, 216, 34]))
        self.assertEqual(parse_dns_a(packet), ["93.184.216.34"])

    def test_parse_no_answer(self):
        header = struct.pack(">HHHHHH", 1, 0x8180, 0, 0, 0, 0)
        self.assertEqual(parse_dns_a(header), [])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_dns -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
import time


def build_dns_query(name: str, txid: int) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + question + struct.pack(">HH", 1, 1)


def _skip_dns_name(data: bytes, offset: int) -> int:
    while True:
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0:
            return offset + 2
        offset += 1 + length


def parse_dns_a(data: bytes) -> list[str]:
    if len(data) < 12:
        return []
    _txid, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if flags & 0x000F:  # RCODE != 0
        return []
    offset = 12
    for _ in range(qdcount):
        offset = _skip_dns_name(data, offset) + 4
    answers: list[str] = []
    for _ in range(ancount):
        offset = _skip_dns_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:
            answers.append(socket.inet_ntoa(rdata))
    return answers


def dns_query(server: str, name: str, timeout: float = 3.0) -> tuple[bool, float, list[str]]:
    txid = random.randint(0, 0xFFFF)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    started = time.monotonic()
    try:
        sock.sendto(build_dns_query(name, txid), (server, 53))
        data, _ = sock.recvfrom(2048)
    except OSError:
        return False, 0.0, []
    finally:
        sock.close()
    elapsed = (time.monotonic() - started) * 1000
    answers = parse_dns_a(data)
    return bool(answers), elapsed, answers
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_dns -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_dns.py
git commit -m "feat: add raw UDP DNS query and A-record parser"
```

---

### Task 9: Local config detection and Check 1

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_local_config.py`

**Interfaces:**
- Consumes: `Config`, `CheckResult`, `Status`, `run_command`.
- Produces: `LocalConfig(ip, mask, gateway, dns, interface)`; `parse_ipconfig_windows(text) -> LocalConfig`; `parse_linux(route_text, addr_text, resolv_text) -> LocalConfig`; `parse_macos(route_text, dns_text, ifaddr) -> LocalConfig`; `detect_local_config(runner=run_command) -> LocalConfig`; `check_local_config(cfg, local_fn=detect_local_config) -> CheckResult`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_local_config.py
import unittest

from netcheck import Config, Status, check_local_config, parse_ipconfig_windows


IPCONFIG = """
Ethernet adapter Ethernet:
   IPv4 Address. . . . . . . . . . . : 192.168.1.50(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.1.1
   DNS Servers . . . . . . . . . . . : 58.71.2.8
                                       45.63.30.117
"""

IPCONFIG_APIPA = """
   IPv4 Address. . . . . . . . . . . : 169.254.10.10(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.0.0
   Default Gateway . . . . . . . . . :
"""


class TestLocalConfig(unittest.TestCase):
    def test_parse_windows(self):
        lc = parse_ipconfig_windows(IPCONFIG)
        self.assertEqual(lc.ip, "192.168.1.50")
        self.assertEqual(lc.gateway, "192.168.1.1")
        self.assertEqual(lc.dns, ["58.71.2.8", "45.63.30.117"])

    def test_check_pass(self):
        result = check_local_config(Config(), local_fn=lambda: parse_ipconfig_windows(IPCONFIG))
        self.assertIs(result.status, Status.PASS)

    def test_check_apipa_fails(self):
        result = check_local_config(Config(), local_fn=lambda: parse_ipconfig_windows(IPCONFIG_APIPA))
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("169.254", result.detail or "")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_local_config -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
@dataclass
class LocalConfig:
    ip: str | None = None
    mask: str | None = None
    gateway: str | None = None
    dns: list[str] = field(default_factory=list)
    interface: str | None = None


def parse_ipconfig_windows(text: str) -> LocalConfig:
    lc = LocalConfig()
    ip = re.search(r"IPv4 Address[^:]*:\s*([\d.]+)", text)
    if ip:
        lc.ip = ip.group(1)
    mask = re.search(r"Subnet Mask[^:]*:\s*([\d.]+)", text)
    if mask:
        lc.mask = mask.group(1)
    gw = re.search(r"Default Gateway[^:]*:\s*([\d.]+)", text)
    if gw:
        lc.gateway = gw.group(1)
    dns_block = re.search(r"DNS Servers[^:]*:\s*([\d.\s]+)", text)
    if dns_block:
        lc.dns = re.findall(r"\d+\.\d+\.\d+\.\d+", dns_block.group(1))
    return lc


def parse_linux(route_text: str, addr_text: str, resolv_text: str) -> LocalConfig:
    lc = LocalConfig()
    gw = re.search(r"default via ([\d.]+)", route_text)
    if gw:
        lc.gateway = gw.group(1)
    dev = re.search(r"default via [\d.]+ dev (\S+)", route_text)
    if dev:
        lc.interface = dev.group(1)
    addr = re.search(r"inet ([\d.]+)/(\d+)", addr_text)
    if addr:
        lc.ip = addr.group(1)
        lc.mask = "/" + addr.group(2)
    lc.dns = re.findall(r"^nameserver\s+([\d.]+)", resolv_text, re.MULTILINE)
    return lc


def parse_macos(route_text: str, dns_text: str, ifaddr: str) -> LocalConfig:
    lc = LocalConfig()
    gw = re.search(r"gateway:\s*([\d.]+)", route_text)
    if gw:
        lc.gateway = gw.group(1)
    iface = re.search(r"interface:\s*(\S+)", route_text)
    if iface:
        lc.interface = iface.group(1)
    lc.ip = ifaddr.strip() or None
    lc.dns = re.findall(r"nameserver\[[^\]]+\]\s*:\s*([\d.]+)", dns_text)
    return lc


def detect_local_config(runner=run_command) -> LocalConfig:
    if sys.platform.startswith("win"):
        _, out, _ = runner(["ipconfig", "/all"])
        return parse_ipconfig_windows(out)
    if sys.platform == "darwin":
        _, route, _ = runner(["route", "-n", "get", "default"])
        _, dns, _ = runner(["scutil", "--dns"])
        iface = None
        m = re.search(r"interface:\s*(\S+)", route)
        if m:
            iface = m.group(1)
        ifaddr = ""
        if iface:
            _, ifaddr, _ = runner(["ipconfig", "getifaddr", iface])
        return parse_macos(route, dns, ifaddr)
    _, route, _ = runner(["ip", "route"])
    _, addr, _ = runner(["ip", "-4", "addr"])
    resolv = ""
    try:
        with open("/etc/resolv.conf") as fh:
            resolv = fh.read()
    except OSError:
        pass
    return parse_linux(route, addr, resolv)


def check_local_config(cfg: Config, local_fn=detect_local_config) -> CheckResult:
    lc = local_fn()
    detail = f"{lc.ip or 'no IP'} gw {lc.gateway or 'none'} dns {','.join(lc.dns) or 'none'}"
    if not lc.ip:
        return CheckResult(1, "Local config", Status.FAIL, detail=detail,
                           likely_cause="No IPv4 address on the active interface.",
                           suggested_fix="Connect the cable/join Wi-Fi and renew DHCP.")
    if lc.ip.startswith("169.254."):
        return CheckResult(1, "Local config", Status.FAIL, detail=detail,
                           likely_cause="APIPA address: DHCP did not answer.",
                           suggested_fix="Check the switch port/uplink, then renew the lease.")
    if lc.gateway != cfg.gateway:
        return CheckResult(1, "Local config", Status.FAIL, detail=detail,
                           likely_cause=f"Gateway is not {cfg.gateway}.",
                           suggested_fix="Set the default gateway to 192.168.1.1.")
    if not lc.dns:
        return CheckResult(1, "Local config", Status.WARN, detail=detail,
                           likely_cause="No DNS servers configured.",
                           suggested_fix="Set DNS to 1.1.1.1/8.8.8.8 or the ISP DNS.")
    return CheckResult(1, "Local config", Status.PASS, detail=detail)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_local_config -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_local_config.py
git commit -m "feat: add local config detection and check 1"
```

---

### Task 10: Checks 2–4 (gateway, internet, DNS)

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_checks_layer.py`

**Interfaces:**
- Consumes: `Config`, `CheckResult`, `Status`, `ping`, `dns_query`.
- Produces: `check_gateway(cfg, ping_fn=ping) -> CheckResult`; `check_internet(cfg, ping_fn=ping) -> CheckResult`; `check_dns(cfg, query_fn=dns_query) -> CheckResult`; `run_layer_checks(cfg, reporter, local_fn=detect_local_config, ping_fn=ping, query_fn=dns_query) -> None`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_checks_layer.py
import unittest

from netcheck import Config, PingResult, Status, check_dns, check_gateway, check_internet


def _ping(host, **kw):
    return PingResult(host=host, transmitted=10, received=10, loss_pct=0.0,
                      min_ms=1.0, avg_ms=1.5, max_ms=2.0)


class TestLayerChecks(unittest.TestCase):
    def test_gateway_pass(self):
        self.assertIs(check_gateway(Config(), ping_fn=_ping).status, Status.PASS)

    def test_gateway_fail(self):
        bad = lambda h, **k: PingResult(host=h, transmitted=10, received=0, loss_pct=100.0)
        self.assertIs(check_gateway(Config(), ping_fn=bad).status, Status.FAIL)

    def test_internet_warn_one(self):
        def one(host, **kw):
            ok = host == "1.1.1.1"
            return PingResult(host=host, transmitted=4, received=4 if ok else 0,
                              loss_pct=0.0 if ok else 100.0)
        self.assertIs(check_internet(Config(), ping_fn=one).status, Status.WARN)

    def test_dns_isp_down_public_up(self):
        def q(server, name, **kw):
            return (server in ("1.1.1.1", "8.8.8.8")), 10.0, ["93.184.216.34"]
        result = check_dns(Config(), query_fn=q)
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("ISP DNS", result.likely_cause or "")


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_checks_layer -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
def _ping_verdict(result: PingResult, warn_loss: float = 20.0) -> Status:
    if result.loss_pct >= 100.0 or result.received == 0:
        return Status.FAIL
    if result.loss_pct > warn_loss or (result.max_ms is not None and result.min_ms is not None
                                       and result.max_ms - result.min_ms > 30):
        return Status.WARN
    return Status.PASS


def check_gateway(cfg: Config, ping_fn=ping) -> CheckResult:
    result = ping_fn(cfg.gateway, count=10, timeout=cfg.timeout)
    status = _ping_verdict(result)
    detail = (f"loss {result.loss_pct:.0f}% avg {result.avg_ms} ms "
              f"jitter {(result.max_ms - result.min_ms) if result.max_ms is not None and result.min_ms is not None else 'n/a'}")
    if status is Status.FAIL:
        return CheckResult(2, "Gateway", status, detail=detail,
                           likely_cause="The default gateway is not answering.",
                           suggested_fix="Verify the switch/uplink path to the router, then retry.")
    return CheckResult(2, "Gateway", status, detail=detail)


def check_internet(cfg: Config, ping_fn=ping) -> CheckResult:
    reachable = [h for h in cfg.public_dns if ping_fn(h, count=4, timeout=cfg.timeout).received > 0]
    detail = "reachable: " + (",".join(reachable) or "none")
    if len(reachable) == len(cfg.public_dns):
        return CheckResult(3, "Internet by IP", Status.PASS, detail=detail)
    if reachable:
        return CheckResult(3, "Internet by IP", Status.WARN, detail=detail,
                           likely_cause="Only some public IPs answer; upstream path is unstable.",
                           suggested_fix="Check the ISP router/uplink and run the fabric checks.")
    return CheckResult(3, "Internet by IP", Status.FAIL, detail=detail,
                       likely_cause="No public IP answers; the upstream is down.",
                       suggested_fix="Check the ISP router WAN/link; you cannot fix it from the switches.")


def check_dns(cfg: Config, query_fn=dns_query) -> CheckResult:
    rows: list[str] = []
    isp_ok = False
    public_ok = False
    for server in cfg.dns_servers:
        ok, ms, _ = query_fn(server, cfg.domain, timeout=cfg.timeout)
        isp_ok = isp_ok or ok
        rows.append(f"{server}:{'ok' if ok else 'fail'} {ms:.0f}ms")
    for server in cfg.public_dns:
        ok, ms, _ = query_fn(server, cfg.domain, timeout=cfg.timeout)
        public_ok = public_ok or ok
        rows.append(f"{server}:{'ok' if ok else 'fail'} {ms:.0f}ms")
    detail = " ".join(rows)
    if isp_ok and public_ok:
        return CheckResult(4, "DNS", Status.PASS, detail=detail)
    if public_ok and not isp_ok:
        return CheckResult(4, "DNS", Status.FAIL, detail=detail,
                           likely_cause="ISP DNS servers fail while public DNS works (ISP DNS problem).",
                           suggested_fix="Set this PC's DNS to 1.1.1.1/8.8.8.8.")
    if isp_ok and not public_ok:
        return CheckResult(4, "DNS", Status.WARN, detail=detail)
    return CheckResult(4, "DNS", Status.FAIL, detail=detail,
                       likely_cause="No DNS server answered.",
                       suggested_fix="Check the gateway/uplink; try public DNS 1.1.1.1.")


def run_layer_checks(cfg: Config, reporter: Reporter, local_fn=detect_local_config,
                     ping_fn=ping, query_fn=dns_query) -> None:
    local = check_local_config(cfg, local_fn=local_fn)
    reporter.add(local)
    if local.status is Status.FAIL:
        return
    gateway = check_gateway(cfg, ping_fn=ping_fn)
    reporter.add(gateway)
    if gateway.status is Status.FAIL:
        return
    reporter.add(check_internet(cfg, ping_fn=ping_fn))
    reporter.add(check_dns(cfg, query_fn=query_fn))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_checks_layer -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_checks_layer.py
git commit -m "feat: add checks 2-4 and layered short-circuit runner"
```

---

### Task 11: Check 5 (switch reachability)

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_switches.py`

**Interfaces:**
- Consumes: `Config`, `CheckResult`, `Status`, `ping`.
- Produces: `check_switches(cfg, ping_fn=ping) -> CheckResult`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_switches.py
import unittest

from netcheck import Config, PingResult, Status, check_switches


def _ping(host, **kw):
    ok = host != "10.90.90.93"
    return PingResult(host=host, transmitted=2, received=2 if ok else 0,
                      loss_pct=0.0 if ok else 100.0)


class TestSwitches(unittest.TestCase):
    def test_one_unreachable_warns(self):
        result = check_switches(Config(), ping_fn=_ping)
        self.assertIs(result.status, Status.WARN)
        self.assertIn("dlink4", result.detail)

    def test_all_reachable_passes(self):
        good = lambda h, **k: PingResult(host=h, transmitted=2, received=2, loss_pct=0.0)
        self.assertIs(check_switches(Config(), ping_fn=good).status, Status.PASS)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_switches -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
def check_switches(cfg: Config, ping_fn=ping) -> CheckResult:
    down = [name for name, ip in cfg.switches.items()
            if ping_fn(ip, count=2, timeout=cfg.timeout).received == 0]
    if not down:
        return CheckResult(5, "Switches", Status.PASS,
                           detail=f"all {len(cfg.switches)} management IPs reachable")
    cascade = {"dlink2": "24", "dlink3": "25", "dlink4": "26", "dlink5": "27"}
    hints = [f"{name} unreachable (check cascade port {cascade[name]} on dlink1)"
             for name in down if name in cascade]
    if "dlink1" in down:
        hints.append("dlink1 unreachable (management path or switch 1 problem)")
    return CheckResult(5, "Switches", Status.WARN, detail="; ".join(hints),
                       likely_cause="One or more switches are not answering management pings.",
                       suggested_fix="Reseat the cascade/uplink cable and confirm the mgmt IP.")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_switches -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_switches.py
git commit -m "feat: add check 5 switch reachability"
```

---

### Task 12: Check 6 (rogue DHCP)

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_dhcp.py`

**Interfaces:**
- Consumes: `Config`, `CheckResult`, `Status`, `lookup_vendor`, `run_command`.
- Produces: `RogueResponder(server_ip, mac, vendor)`; `parse_nmap_dhcp(text) -> list[RogueResponder]`; `scapy_dhcp_discover(timeout=5.0) -> list[RogueResponder] | None`; `check_rogue_dhcp(cfg, discover_fn=None, runner=run_command) -> tuple[CheckResult, list[str]]`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_dhcp.py
import unittest

from netcheck import Config, RogueResponder, Status, check_rogue_dhcp, parse_nmap_dhcp

NMAP = """
| DHCP-Discover:
|   IP Offered: 192.168.1.77
|   Server IP: 192.168.1.77
|_  MAC: AA:BB:CC:DD:EE:FF (TP-Link)
"""


class TestDhcp(unittest.TestCase):
    def test_parse_nmap(self):
        rows = parse_nmap_dhcp(NMAP)
        self.assertEqual(rows[0].server_ip, "192.168.1.77")
        self.assertEqual(rows[0].mac, "AA:BB:CC:DD:EE:FF")

    def test_rogue_fails(self):
        rogue = RogueResponder("192.168.1.77", "AA:BB:CC:DD:EE:FF", "TP-Link")

        def discover(cfg=None):
            return [rogue]

        result, macs = check_rogue_dhcp(Config(), discover_fn=discover)
        self.assertIs(result.status, Status.FAIL)
        self.assertEqual(macs, ["AA:BB:CC:DD:EE:FF"])

    def test_clean_passes(self):
        gw = RogueResponder("192.168.1.1", "00:1E:58:00:00:01", "D-Link")

        def discover(cfg=None):
            return [gw]

        result, _ = check_rogue_dhcp(Config(), discover_fn=discover)
        self.assertIs(result.status, Status.PASS)

    def test_unknown_warns(self):
        result, _ = check_rogue_dhcp(Config(), discover_fn=lambda cfg=None: None)
        self.assertIs(result.status, Status.WARN)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_dhcp -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
@dataclass
class RogueResponder:
    server_ip: str
    mac: str = ""
    vendor: str | None = None


def parse_nmap_dhcp(text: str) -> list[RogueResponder]:
    rows: list[RogueResponder] = []
    server = re.findall(r"Server IP:\s*([\d.]+)", text)
    macs = re.findall(r"MAC:\s*([0-9A-Fa-f:]{11,17})", text)
    for index, ip in enumerate(server):
        mac = macs[index] if index < len(macs) else ""
        rows.append(RogueResponder(ip, mac, lookup_vendor(mac) if mac else None))
    return rows


def scapy_dhcp_discover(timeout: float = 5.0) -> list[RogueResponder] | None:
    try:
        from scapy.all import DHCP, BOOTP, Ether, IP, UDP, srp  # noqa: WPS433
    except ImportError:
        return None
    try:
        packet = (Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
                  / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=b"\x00" * 16)
                  / DHCP(options=[("message-type", "discover"), "end"]))
        answered, _ = srp(packet, timeout=timeout, verbose=False)
    except Exception:
        return None
    found: dict[str, RogueResponder] = {}
    for _sent, received in answered:
        if received.haslayer(DHCP):
            server_ip = received[IP].src
            mac = received[Ether].src
            found[server_ip] = RogueResponder(server_ip, mac, lookup_vendor(mac))
    return list(found.values())


def check_rogue_dhcp(cfg: Config, discover_fn=None, runner=run_command
                      ) -> tuple[CheckResult, list[str]]:
    if discover_fn is None:
        discover_fn = scapy_dhcp_discover
    responders = discover_fn(cfg)
    if responders is None:
        responders = []
        _, out, _ = runner(["nmap", "--script", "broadcast-dhcp-discover",
                            "-e", "any"], timeout=15)
        responders = parse_nmap_dhcp(out)
        if not responders:
            return (CheckResult(6, "Rogue DHCP", Status.WARN,
                                detail="could not determine (needs root/scapy/nmap)"),
                    [])
    rogues = [r for r in responders if r.server_ip != cfg.gateway]
    if not rogues:
        return (CheckResult(6, "Rogue DHCP", Status.PASS,
                            detail="only the gateway answered"), [])
    listing = ", ".join(f"{r.server_ip} ({r.mac}{', ' + r.vendor if r.vendor else ''})"
                        for r in rogues)
    return (CheckResult(6, "Rogue DHCP", Status.FAIL, detail=listing,
                        likely_cause="A non-gateway DHCP server is handing out leases.",
                        suggested_fix="Trace the responder MAC (check 7) and unplug it; "
                                      "enable DHCP Server Screening on access ports."),
            [r.mac for r in rogues if r.mac])
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_dhcp -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_dhcp.py
git commit -m "feat: add check 6 rogue DHCP detection with fallbacks"
```

---

### Task 13: Telnet helper and `debug info` parser

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_telnet.py`

**Interfaces:**
- Consumes: nothing.
- Produces: `TelnetError`; `TelnetConnection(host, timeout=5.0)` with `.connect()`, `.login(user, password)`, `.run_command(cmd, wait=1.0)`, `.close()`; `parse_debug_info(text) -> dict[str, int]` mapping MAC → port number.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_telnet.py
import unittest

from netcheck import parse_debug_info

SAMPLE = """
ARP Table
IP Address       MAC Address        Port
192.168.1.77     aa-bb-cc-dd-ee-ff  eth1.5
MAC Address Table
VLAN  MAC Address        Port
1     aa-bb-cc-dd-ee-ff  5
1     00-1e-58-00-00-01  23
"""


class TestDebugInfo(unittest.TestCase):
    def test_parse_mac_to_port(self):
        table = parse_debug_info(SAMPLE)
        self.assertEqual(table["AA:BB:CC:DD:EE:FF"], 5)
        self.assertEqual(table["00:1E:58:00:00:01"], 23)

    def test_empty(self):
        self.assertEqual(parse_debug_info("nothing here"), {})


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_telnet -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
class TelnetError(Exception):
    pass


_MAC_LINE = re.compile(
    r"([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\s+(?:eth\S+\s+)?(\d+)\b"
)


def parse_debug_info(text: str) -> dict[str, int]:
    table: dict[str, int] = {}
    for mac, port in _MAC_LINE.findall(text):
        normalized = mac.replace("-", ":").upper()
        table[normalized] = int(port)
    return table


class TelnetConnection:
    IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240

    def __init__(self, host: str, timeout: float = 5.0):
        self.host = host
        self.timeout = timeout
        self.sock: socket.socket | None = None

    def connect(self) -> None:
        self.sock = socket.create_connection((self.host, 23), timeout=self.timeout)
        self._negotiate(self._read_until_idle())

    def _read_until_idle(self, idle: float = 0.5) -> bytes:
        assert self.sock is not None
        self.sock.settimeout(idle)
        chunks: list[bytes] = []
        try:
            while True:
                data = self.sock.recv(4096)
                if not data:
                    break
                chunks.append(data)
        except socket.timeout:
            pass
        return b"".join(chunks)

    def _negotiate(self, data: bytes) -> None:
        assert self.sock is not None
        response = bytearray()
        i = 0
        while i < len(data):
            if data[i] == self.IAC and i + 2 < len(data):
                command, option = data[i + 1], data[i + 2]
                if command in (self.DO, self.DONT):
                    response += bytes([self.IAC, self.WONT, option])
                elif command in (self.WILL, self.WONT):
                    response += bytes([self.IAC, self.DONT, option])
                i += 3
            else:
                i += 1
        if response:
            self.sock.sendall(bytes(response))

    def login(self, user: str, password: str) -> str:
        banner = self._read_until_idle()
        if b"assword" not in banner and b"ogin" not in banner:
            self.run_command(user, wait=0.5)
        else:
            self.run_command(user, wait=0.5)
        return self.run_command(password, wait=1.0).decode(errors="replace")

    def run_command(self, cmd: str, wait: float = 1.0) -> bytes:
        if self.sock is None:
            raise TelnetError("not connected")
        self.sock.sendall(cmd.encode() + b"\r\n")
        import time as _time
        _time.sleep(wait)
        return self._read_until_idle()

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_telnet -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_telnet.py
git commit -m "feat: add socket Telnet helper and debug info parser"
```

---

### Task 14: Check 7 (trace MAC to switch/port)

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_trace.py`

**Interfaces:**
- Consumes: `Config`, `CheckResult`, `Status`, `SnmpClient`, `TelnetConnection`, `parse_debug_info`, `dot1dBasePortIfIndex` mapping.
- Produces: `CASCADE = {"24": "dlink2", "25": "dlink3", "26": "dlink4", "27": "dlink5"}`; `find_fdb_port(client, mac) -> int | None`; `resolve_ifindex_ports(client) -> dict[int, int]`; `trace_mac(cfg, mac, client_factory=SnmpClient, telnet_factory=TelnetConnection) -> CheckResult`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_trace.py
import unittest

from netcheck import Status, trace_mac

FDB_OID = "1.3.6.1.2.1.17.4.3.1.2"
BASE_OID = "1.3.6.1.2.1.17.1.4.1.2"


class FakeClient:
    def __init__(self, host, community, **kw):
        self.host = host

    def walk(self, base_oid):
        if base_oid == FDB_OID:
            return [("1.3.6.1.2.1.17.4.3.1.2.0.30.88.170.187.204", 5)]
        if base_oid == BASE_OID:
            return [(f"{BASE_OID}.5", 5)]
        return []


class TestTrace(unittest.TestCase):
    def test_trace_lands_on_edge_port(self):
        cfg = type("C", (), {"switches": {"dlink1": "10.90.90.90"},
                             "snmp_community": "public", "timeout": 3.0,
                             "switch_user": "admin", "switch_pass": "x"})()
        result = trace_mac(cfg, "00:1E:58:AA:BB:CC", client_factory=FakeClient)
        self.assertIs(result.status, Status.PASS)
        self.assertIn("dlink1", result.detail)
        self.assertIn("port 5", result.detail)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_trace -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
BRIDGE_FDB_OID = "1.3.6.1.2.1.17.4.3.1.2"
QB_FDB_OID = "1.3.6.1.2.1.17.7.1.2.2.1.2"
BASE_PORT_IFINDEX_OID = "1.3.6.1.2.1.17.1.4.1.2"

CASCADE = {"24": "dlink2", "25": "dlink3", "26": "dlink4", "27": "dlink5"}


def mac_to_oid_suffix(mac: str) -> str:
    return ".".join(str(int(byte, 16)) for byte in mac.replace("-", ":").split(":"))


def resolve_ifindex_ports(client) -> dict[int, int]:
    mapping: dict[int, int] = {}
    for oid, value in client.walk(BASE_PORT_IFINDEX_OID):
        if isinstance(value, int):
            mapping[int(oid.rsplit(".", 1)[1])] = value
    return mapping


def find_fdb_port(client, mac: str) -> int | None:
    suffix = "." + mac_to_oid_suffix(mac)
    for base in (BRIDGE_FDB_OID, QB_FDB_OID):
        try:
            rows = client.walk(base)
        except SnmpError:
            rows = []
        if rows:
            ifindex_map = resolve_ifindex_ports(client)
            for oid, value in rows:
                if oid.endswith(suffix) and isinstance(value, int):
                    return ifindex_map.get(value, value)
    return None


def debug_info_lookup(cfg: Config, host: str, mac: str) -> int | None:
    conn = TelnetConnection(host, timeout=cfg.timeout)
    try:
        conn.connect()
        conn.login(cfg.switch_user, cfg.switch_pass)
        output = conn.run_command("debug info", wait=2.0).decode(errors="replace")
    except (OSError, TelnetError):
        return None
    finally:
        conn.close()
    return parse_debug_info(output).get(mac.replace("-", ":").upper())


def trace_mac(cfg: Config, mac: str, client_factory=SnmpClient,
              telnet_factory=None) -> CheckResult:
    name = "dlink1"
    hops: list[str] = []
    for _ in range(len(cfg.switches)):
        host = cfg.switches[name]
        port: int | None = None
        if cfg.snmp_community:
            try:
                port = find_fdb_port(client_factory(host, cfg.snmp_community,
                                                    timeout=cfg.timeout), mac)
            except SnmpError:
                port = None
        if port is None:
            port = debug_info_lookup(cfg, host, mac)
        if port is None:
            return CheckResult(7, f"Trace {mac}", Status.WARN,
                               detail="; ".join(hops) + f" not found on {name}",
                               likely_cause="MAC not learned; the device may be offline.")
        hops.append(f"{name} port {port}")
        if name == "dlink1" and str(port) == "23":
            return CheckResult(7, f"Trace {mac}", Status.PASS,
                               detail=f"{name} port 23 (ISP/upstream side)")
        key = str(port)
        if name == "dlink1" and key in CASCADE:
            name = CASCADE[key]
            continue
        return CheckResult(7, f"Trace {mac}", Status.PASS,
                           detail=f"{name}, port {port}",
                           suggested_fix=f"Unplug the device on {name} port {port}.")
    return CheckResult(7, f"Trace {mac}", Status.WARN, detail="; ".join(hops) + " (loop?)")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_trace -v`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_trace.py
git commit -m "feat: add check 7 MAC-to-port tracing with SNMP and Telnet fallback"
```

---

### Task 15: Check 8 (loop / storm hints)

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_storm_hints.py`

**Interfaces:**
- Consumes: `Config`, `CheckResult`, `Status`, `SnmpClient`, `decode_port_list`.
- Produces: `check_storm_hints(cfg, gateway_result, loop_ports, client_factory=SnmpClient) -> CheckResult`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_storm_hints.py
import unittest

from netcheck import Config, PingResult, Status, check_storm_hints


class TestStormHints(unittest.TestCase):
    def test_loop_ports_flag_fail(self):
        gateway = PingResult(host="192.168.1.1", transmitted=10, received=10,
                             loss_pct=0.0, min_ms=1.0, avg_ms=5.0, max_ms=40.0)
        result = check_storm_hints(Config(), gateway, loop_ports={"dlink1": [7]},
                                   client_factory=lambda *a, **k: None)
        self.assertIs(result.status, Status.FAIL)
        self.assertIn("dlink1", result.detail)

    def test_clean_passes(self):
        gateway = PingResult(host="192.168.1.1", transmitted=10, received=10,
                             loss_pct=0.0, min_ms=1.0, avg_ms=1.0, max_ms=2.0)
        result = check_storm_hints(Config(), gateway, loop_ports={},
                                   client_factory=lambda *a, **k: None)
        self.assertIs(result.status, Status.PASS)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_storm_hints -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
def check_storm_hints(cfg: Config, gateway_result: PingResult,
                      loop_ports: dict[str, list[int]], client_factory=SnmpClient
                      ) -> CheckResult:
    if loop_ports:
        listing = "; ".join(f"{name} port {p}" for name, ports in loop_ports.items()
                            for p in ports)
        return CheckResult(8, "Loop/storm hints", Status.FAIL, detail=f"loop on {listing}",
                           likely_cause="Loopback Detection reports a port in loop state.",
                           suggested_fix="Unplug the looped port; see the trace/hardening checks.")
    jitter = None
    if gateway_result.max_ms is not None and gateway_result.min_ms is not None:
        jitter = gateway_result.max_ms - gateway_result.min_ms
    if gateway_result.loss_pct > 5 or (jitter is not None and jitter > 30):
        return CheckResult(8, "Loop/storm hints", Status.WARN,
                           detail=f"gateway loss {gateway_result.loss_pct:.0f}% jitter {jitter}",
                           likely_cause="Possible broadcast storm or flapping link.",
                           suggested_fix="Check LBD loop status and error counters on ports 23-27.")
    return CheckResult(8, "Loop/storm hints", Status.PASS, detail="no storm indicators")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_storm_hints -v`
Expected: PASS (2 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_storm_hints.py
git commit -m "feat: add check 8 loop and storm hints"
```

---

### Task 16: Check 9 (hardening audit + evaluator)

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_hardening.py`

**Interfaces:**
- Consumes: `Config`, `CheckResult`, `Status`, `SnmpClient`, `decode_port_list`.
- Produces: `HardeningState` dataclass; `read_hardening_state(client) -> HardeningState`; `evaluate_hardening(state, measured=None) -> list[str]`; `check_hardening(cfg, measured=None, client_factory=SnmpClient) -> tuple[CheckResult, dict[str, list[int]]]` where the dict is loop ports per switch.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_hardening.py
import unittest

from netcheck import HardeningState, Status, evaluate_hardening

BASELINE_GOOD = HardeningState(
    lbd_enabled=True, lbd_recover_time=0, storm_enabled=True, storm_type=3,
    storm_threshold=20000, rstp_enabled=True, rstp_priority=4096,
    safeguard_enabled=True, dhcp_screen_ports=[1, 2], dos_enabled=True)

BASELINE_BAD = HardeningState(
    lbd_enabled=False, lbd_recover_time=60, storm_enabled=False, storm_type=1,
    storm_threshold=0, rstp_enabled=False, rstp_priority=32768,
    safeguard_enabled=False, dhcp_screen_ports=[], dos_enabled=False)


class TestHardening(unittest.TestCase):
    def test_all_good_no_findings(self):
        self.assertEqual(evaluate_hardening(BASELINE_GOOD), [])

    def test_bad_reports_features(self):
        findings = "\n".join(evaluate_hardening(BASELINE_BAD))
        for feature in ("Loopback Detection", "Storm Control", "RSTP", "Safeguard"):
            self.assertIn(feature, findings)

    def test_measured_threshold_overrides(self):
        from dataclasses import replace
        state = replace(BASELINE_GOOD, storm_threshold=30000)
        self.assertEqual(evaluate_hardening(state, measured={"threshold": 30000}), [])
        self.assertTrue(evaluate_hardening(state))  # default 20000 would flag it


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_hardening -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
@dataclass
class HardeningState:
    lbd_enabled: bool = False
    lbd_recover_time: int = 60
    storm_enabled: bool = False
    storm_type: int = 1
    storm_threshold: int = 0
    rstp_enabled: bool = False
    rstp_priority: int = 32768
    safeguard_enabled: bool = True
    dhcp_screen_ports: list[int] = field(default_factory=list)
    dos_enabled: bool = False


def evaluate_hardening(state: HardeningState,
                       measured: dict | None = None) -> list[str]:
    findings: list[str] = []
    if not state.lbd_enabled:
        findings.append("Loopback Detection: disabled (recommended: enabled, recover time 0)")
    elif state.lbd_recover_time != 0:
        findings.append(f"Loopback Detection: recover time {state.lbd_recover_time} "
                        "(recommended: 0)")
    recommended_threshold = (measured or {}).get("threshold", 20000)
    if not state.storm_enabled:
        findings.append("Storm Control: disabled (recommended: enabled, type 3)")
    elif state.storm_type != 3:
        findings.append(f"Storm Control: type {state.storm_type} (recommended: 3)")
    elif state.storm_threshold != recommended_threshold:
        findings.append(f"Storm Control: threshold {state.storm_threshold} "
                        f"(recommended: {recommended_threshold})")
    if not state.rstp_enabled:
        findings.append("RSTP: disabled (recommended: enabled)")
    if not state.safeguard_enabled:
        findings.append("Safeguard Engine: disabled (recommended: enabled)")
    if not state.dhcp_screen_ports:
        findings.append("DHCP Server Screening: not enabled on access ports")
    if not state.dos_enabled:
        findings.append("DoS Prevention: disabled (optional, recommended: enabled)")
    return findings


def read_hardening_state(client) -> HardeningState:
    state = HardeningState()
    values = client.get([
        "1.3.6.1.4.1.171.10.76.20.1.17.1",
        "1.3.6.1.4.1.171.10.76.20.1.17.4",
        "1.3.6.1.4.1.171.10.76.20.1.13.3.1",
        "1.3.6.1.4.1.171.10.76.20.1.13.3.2",
        "1.3.6.1.4.1.171.10.76.20.1.13.3.3",
        "1.3.6.1.4.1.171.10.76.20.1.6.1.1",
        "1.3.6.1.4.1.171.10.76.20.1.6.1.3",
        "1.3.6.1.4.1.171.10.76.20.1.1.8",
        "1.3.6.1.4.1.171.10.76.20.1.14.7.1",
        "1.3.6.1.4.1.171.10.76.20.1.99.1",
    ])
    state.lbd_enabled = values.get("1.3.6.1.4.1.171.10.76.20.1.17.1") == 1
    state.lbd_recover_time = int(values.get("1.3.6.1.4.1.171.10.76.20.1.17.4") or 0)
    state.storm_enabled = values.get("1.3.6.1.4.1.171.10.76.20.1.13.3.1") == 1
    state.storm_type = int(values.get("1.3.6.1.4.1.171.10.76.20.1.13.3.2") or 1)
    state.storm_threshold = int(values.get("1.3.6.1.4.1.171.10.76.20.1.13.3.3") or 0)
    state.rstp_enabled = values.get("1.3.6.1.4.1.171.10.76.20.1.6.1.1") == 1
    state.rstp_priority = int(values.get("1.3.6.1.4.1.171.10.76.20.1.6.1.3") or 32768)
    state.safeguard_enabled = values.get("1.3.6.1.4.1.171.10.76.20.1.1.8") == 1
    ports = values.get("1.3.6.1.4.1.171.10.76.20.1.14.7.1")
    state.dhcp_screen_ports = decode_port_list(ports) if isinstance(ports, bytes) else []
    state.dos_enabled = values.get("1.3.6.1.4.1.171.10.76.20.1.99.1") == 1
    return state


def read_loop_ports(client) -> list[int]:
    loop: list[int] = []
    for oid, value in client.walk("1.3.6.1.4.1.171.10.76.20.1.17.5.1.3"):
        if value == 2:
            loop.append(int(oid.rsplit(".", 1)[1]))
    return loop


def check_hardening(cfg: Config, measured: dict | None = None,
                    client_factory=SnmpClient
                    ) -> tuple[CheckResult, dict[str, list[int]]]:
    if not cfg.snmp_community:
        return (CheckResult(9, "Hardening audit", Status.WARN,
                            detail="SNMP community not set; cannot audit switches"),
                {})
    findings: list[str] = []
    loop_ports: dict[str, list[int]] = {}
    for name, host in cfg.switches.items():
        try:
            client = client_factory(host, cfg.snmp_community, timeout=cfg.timeout)
            state = read_hardening_state(client)
            for finding in evaluate_hardening(state, measured):
                findings.append(f"{name}: {finding}")
            ports = read_loop_ports(client)
            if ports:
                loop_ports[name] = ports
        except SnmpError as exc:
            findings.append(f"{name}: SNMP unavailable ({exc})")
    if not findings:
        return CheckResult(9, "Hardening audit", Status.PASS,
                           detail="all switches meet the baseline"), loop_ports
    status = Status.FAIL if loop_ports else Status.WARN
    return CheckResult(9, "Hardening audit", status, detail="; ".join(findings[:6]),
                       suggested_fix="Apply the baseline in USAGE.md (LBD, Storm Control, "
                                     "RSTP, DHCP Server Screening)."), loop_ports
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_hardening -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_hardening.py
git commit -m "feat: add check 9 hardening audit and evaluator"
```

---

### Task 17: §7.1 storm-threshold auto-measurement

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_storm_measure.py`

**Interfaces:**
- Consumes: `SnmpClient`.
- Produces: `ceil_to_64(n) -> int`; `compute_threshold(peak_kbps, link_kbps, factor=4, floor=10000) -> int`; `measure_storm_threshold(cfg, sample_seconds=30, client_factory=SnmpClient) -> dict[str, dict]` returning per-switch `{"threshold": int}` (empty when SNMP unavailable).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_storm_measure.py
import unittest

from netcheck import ceil_to_64, compute_threshold, measure_storm_threshold


class FakeCounterClient:
    reads = 0

    def __init__(self, host, community, **kw):
        self.host = host

    def walk(self, base_oid):
        FakeCounterClient.reads += 1
        delta = 0 if FakeCounterClient.reads == 1 else 10_000
        if base_oid == "1.3.6.1.2.1.31.1.1.1.9":
            return [("1.3.6.1.2.1.31.1.1.1.9.1", delta)]
        if base_oid == "1.3.6.1.2.1.31.1.1.1.8":
            return [("1.3.6.1.2.1.31.1.1.1.8.1", 0)]
        return []


class TestStormMeasure(unittest.TestCase):
    def test_ceil_to_64(self):
        self.assertEqual(ceil_to_64(1), 64)
        self.assertEqual(ceil_to_64(64), 64)
        self.assertEqual(ceil_to_64(65), 128)

    def test_compute_threshold_floor_and_cap(self):
        self.assertEqual(compute_threshold(100, 1_000_000), 10000)   # floor
        self.assertEqual(compute_threshold(100_000, 1_000_000), 400000)  # 4x
        self.assertEqual(compute_threshold(900_000, 1_000_000), 800000)  # cap 0.8x

    def test_measure_empty_without_community(self):
        cfg = type("C", (), {"switches": {"dlink1": "10.90.90.90"},
                             "snmp_community": "", "timeout": 1.0,
                             "storm_safety_factor": 4, "storm_floor_kbps": 10000})()
        self.assertEqual(measure_storm_threshold(cfg, sample_seconds=0), {})


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_storm_measure -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
def ceil_to_64(n: float) -> int:
    return int(-(-n // 64) * 64)


def compute_threshold(peak_kbps: float, link_kbps: int, factor: int = 4,
                      floor: int = 10000) -> int:
    target = max(ceil_to_64(peak_kbps * factor), floor)
    return min(target, int(0.8 * link_kbps))


def _counter_snapshot(client) -> dict[str, int]:
    snapshot: dict[str, int] = {}
    for oid, value in client.walk("1.3.6.1.2.1.31.1.1.1.9"):
        snapshot["b" + oid.rsplit(".", 1)[1]] = int(value)
    for oid, value in client.walk("1.3.6.1.2.1.31.1.1.1.8"):
        snapshot["m" + oid.rsplit(".", 1)[1]] = int(value)
    return snapshot


def measure_storm_threshold(cfg: Config, sample_seconds: float = 30,
                            client_factory=SnmpClient) -> dict[str, dict]:
    if not cfg.snmp_community or sample_seconds <= 0:
        return {}
    import concurrent.futures

    def per_switch(item: tuple[str, str]) -> tuple[str, dict]:
        name, host = item
        try:
            client = client_factory(host, cfg.snmp_community, timeout=cfg.timeout)
            before = _counter_snapshot(client)
            time.sleep(sample_seconds)
            after = _counter_snapshot(client)
        except SnmpError:
            return name, {}
        link_kbps = 1_000_000  # GbE
        peak = 0.0
        for key, start in before.items():
            end = after.get(key, start)
            rate = max(0, end - start) / sample_seconds
            kbps = rate * 512 / 1000  # 64-byte min frame
            peak = max(peak, kbps)
        return name, {"threshold": compute_threshold(
            peak, link_kbps, cfg.storm_safety_factor, cfg.storm_floor_kbps)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(cfg.switches)) as pool:
        return {name: data for name, data in pool.map(per_switch, cfg.switches.items())
                if data}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_storm_measure -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_storm_measure.py
git commit -m "feat: add storm threshold auto-measurement"
```

---

### Task 18: Optional fixes with TTY-safe prompts

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_fixes.py`

**Interfaces:**
- Consumes: `Config`, `run_command`.
- Produces: `open_tty() -> TextIO | None`; `prompt_yes_no(question, tty=None) -> bool`; `apply_fixes(cfg, allow_fix=True, tty=None, runner=run_command) -> list[str]`; `dns_servers(cfg) -> tuple[str, str]` returning `("1.1.1.1", "8.8.8.8")`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_fixes.py
import io
import unittest

from netcheck import Config, apply_fixes, prompt_yes_no


class TestFixes(unittest.TestCase):
    def test_prompt_yes(self):
        tty = io.StringIO("y\n")
        self.assertTrue(prompt_yes_no("Do it?", tty=tty))

    def test_prompt_no(self):
        self.assertFalse(prompt_yes_no("Do it?", tty=io.StringIO("n\n")))

    def test_no_fix_skips(self):
        self.assertEqual(apply_fixes(Config(), allow_fix=False, tty=io.StringIO("y\n")), [])


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_fixes -v`
Expected: FAIL with `ImportError`.

- [ ] **Step 3: Write minimal implementation**

```python
# append to netcheck.py
def open_tty():
    if not sys.stdin.isatty():
        return None
    try:
        return open("/dev/tty", "r+") if sys.platform != "win32" else open("CONIN$", "r+")
    except OSError:
        return None


def prompt_yes_no(question: str, tty=None) -> bool:
    stream = tty
    if stream is None:
        stream = open_tty()
    if stream is None:
        return False
    stream.write(question + " [y/N] ")
    stream.flush()
    answer = stream.readline()
    return answer.strip().lower() in ("y", "yes")


def dns_servers(cfg: Config) -> tuple[str, str]:
    return "1.1.1.1", "8.8.8.8"


def apply_fixes(cfg: Config, allow_fix: bool = True, tty=None,
                runner=run_command) -> list[str]:
    applied: list[str] = []
    if not allow_fix:
        return applied
    if prompt_yes_no("Flush the DNS cache?", tty=tty):
        if sys.platform.startswith("win"):
            runner(["ipconfig", "/flushdns"])
        elif sys.platform == "darwin":
            runner(["dscacheutil", "-flushcache"])
            runner(["killall", "-HUP", "mDNSResponder"])
        else:
            runner(["resolvectl", "flush-caches"])
        applied.append("flushed DNS cache")
    if prompt_yes_no("Renew the DHCP lease?", tty=tty):
        if sys.platform.startswith("win"):
            runner(["ipconfig", "/renew"])
        elif sys.platform == "darwin":
            runner(["ipconfig", "set", "en0", "DHCP"])
        else:
            runner(["dhclient", "-r"])
            runner(["dhclient"])
        applied.append("renewed DHCP lease")
    primary, secondary = dns_servers(cfg)
    if prompt_yes_no(f"Set this PC's DNS to {primary}/{secondary}?", tty=tty):
        applied.append(f"requested DNS change to {primary}/{secondary}")
    return applied
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_fixes -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add netcheck.py tests/test_fixes.py
git commit -m "feat: add TTY-safe optional fixes"
```

---

### Task 19: CLI wiring and orchestration

**Files:**
- Modify: `netcheck.py`
- Test: `tests/test_orchestration.py`

**Interfaces:**
- Consumes: everything above.
- Produces: `run_all(cfg, reporter, quick=False, no_measure=False, sample=30.0,
  allow_fix=True, tty=None, runner=run_command) -> None`; updated `build_parser()`
  with `--quick`, `--log`, `--config`, `--no-fix`, `--sample`, `--no-measure`,
  `--timeout`, `--verbose`, `--no-color`, `--version`; updated `main()`.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_orchestration.py
import io
import unittest

import netcheck


class TestOrchestration(unittest.TestCase):
    def test_quick_runs_only_layer_checks(self):
        reporter = netcheck.Reporter(color=False)
        netcheck.run_all(netcheck.Config(), reporter, quick=True,
                         runner=lambda *a, **k: (0, "", ""))
        self.assertTrue(all(r.id <= 4 for r in reporter.results))
        self.assertGreaterEqual(len(reporter.results), 1)

    def test_parser_has_flags(self):
        parser = netcheck.build_parser()
        args = parser.parse_args(["--quick", "--no-measure", "--no-fix"])
        self.assertTrue(args.quick)
        self.assertTrue(args.no_measure)
        self.assertTrue(args.no_fix)

    def test_main_version(self):
        self.assertEqual(netcheck.main(["--version"]), 0)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_orchestration -v`
Expected: FAIL (`run_all` not defined / parser missing flags).

- [ ] **Step 3: Replace `build_parser` and `main`, add `run_all`**

```python
# replace the Task 1 build_parser/main with:
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netcheck", description=__doc__)
    parser.add_argument("--version", action="version", version=f"netcheck {__version__}")
    parser.add_argument("--quick", action="store_true", help="checks 1-4 only")
    parser.add_argument("--log", action="store_true", help="save a timestamped report")
    parser.add_argument("--config", help="path to an INI config file")
    parser.add_argument("--no-fix", action="store_true", help="never prompt for fixes")
    parser.add_argument("--sample", type=float, default=30.0,
                        help="counter-sampling window for storm thresholds (seconds)")
    parser.add_argument("--no-measure", action="store_true",
                        help="skip rate sampling; use the static storm baseline")
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="per-operation network timeout (seconds)")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    return parser


def run_all(cfg: Config, reporter: Reporter, quick: bool = False,
            no_measure: bool = False, sample: float = 30.0, allow_fix: bool = True,
            tty=None, runner=run_command) -> None:
    layer_ping = lambda host, **kw: ping(host, runner=runner, **kw)  # noqa: E731
    layer_query = lambda server, name, **kw: dns_query(  # noqa: E731
        server, name, timeout=kw.get("timeout", cfg.timeout))
    run_layer_checks(cfg, reporter,
                     local_fn=lambda: detect_local_config(runner),
                     ping_fn=layer_ping, query_fn=layer_query)
    if quick:
        return

    reporter.add(check_switches(cfg, ping_fn=layer_ping))
    rogue_result, rogue_macs = check_rogue_dhcp(cfg, runner=runner)
    reporter.add(rogue_result)

    measured = {} if no_measure else measure_storm_threshold(cfg, sample_seconds=sample)
    per_switch_measured = next(iter(measured.values()), None)
    hardening_result, loop_ports = check_hardening(cfg, measured=per_switch_measured)
    reporter.add(hardening_result)

    gateway_ping = ping(cfg.gateway, count=4, timeout=cfg.timeout, runner=runner)
    reporter.add(check_storm_hints(cfg, gateway_ping, loop_ports))

    for mac in rogue_macs:
        reporter.add(trace_mac(cfg, mac))

    fixed = apply_fixes(cfg, allow_fix=allow_fix, tty=tty, runner=runner)
    if fixed:
        reporter.add(CheckResult(99, "Fixes applied", Status.PASS, detail="; ".join(fixed)))


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    cfg = load_config(path=args.config)
    cfg.timeout = args.timeout
    reporter = Reporter(color=not args.no_color and sys.stdout.isatty())
    try:
        run_all(cfg, reporter, quick=args.quick, no_measure=args.no_measure,
                sample=args.sample, allow_fix=not args.no_fix)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    text = reporter.render()
    print(text)
    if args.log:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        with open(f"netcheck-{stamp}.log", "w") as fh:
            fh.write(text + "\n")
    return reporter.exit_code()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m unittest tests.test_orchestration -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Run the whole suite**

Run: `python -m unittest discover -s tests -v`
Expected: all tests PASS.

- [ ] **Step 6: Commit**

```bash
git add netcheck.py tests/test_orchestration.py
git commit -m "feat: wire CLI flags, orchestration, and phased checks"
```

---

### Task 20: `netcheck.ini.example` and `USAGE.md`

**Files:**
- Create: `netcheck.ini.example`
- Create: `USAGE.md`
- Test: `tests/test_docs.py`

**Interfaces:**
- Consumes: `load_config`, `__version__`.
- Produces: documentation artifacts; a test guaranteeing the example config parses.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_docs.py
import unittest

from netcheck import Config, load_config


class TestDocs(unittest.TestCase):
    def test_example_config_parses(self):
        cfg = load_config(path="netcheck.ini.example", env={})
        self.assertEqual(cfg.gateway, "192.168.1.1")
        self.assertEqual(len(cfg.switches), 5)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_docs -v`
Expected: FAIL (`netcheck.ini.example` not found).

- [ ] **Step 3: Create `netcheck.ini.example`**

```ini
[netcheck]
# Secrets: prefer environment variables (NETCHECK_SNMP_COMMUNITY, NETCHECK_SWITCH_PASS).
# This file is gitignored when named netcheck.ini; do not commit real secrets.
gateway = 192.168.1.1
dns = 58.71.2.8,45.63.30.117
domain = example.com
snmp_community = public
snmp_version = 2c
switch_user = admin
switch_pass =
storm_safety_factor = 4
storm_floor_kbps = 10000
switches = dlink1=10.90.90.90,dlink2=10.90.90.91,dlink3=10.90.90.92,dlink4=10.90.90.93,dlink5=10.90.90.94
```

- [ ] **Step 4: Create `USAGE.md`**

````markdown
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

## 6. Interpreting output

One `[PASS]/[WARN]/[FAIL]` line per check, then "Likely cause" and "Suggested fix".
Exit codes: `0` clean, `1` warnings, `2` failures. Scenarios:

- **No internet, gateway fails**: fix the local/uplink path; the router is out of scope.
- **Internet by IP fails, gateway passes**: upstream/ISP problem; you cannot fix it.
- **DNS fails while IP works**: ISP DNS problem - switch the PC to 1.1.1.1/8.8.8.8.
- **Rogue DHCP FAIL**: trace the reported MAC, unplug that device, enable screening.
- **Loop/storm FAIL**: a port is in loop state; unplug it, then re-check hardening.

## 7. Troubleshooting the tool

- SNMP errors: confirm SNMP is enabled and the community/management subnet is right.
- scapy without rights: the probe degrades to `nmap`, then to WARN.
- Telnet format drift: `--verbose` captures a sample; do not trust an unverified parse.

## 8. Security

Credentials/community never leave env/INI and are never logged; the tool is read-only.
````

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m unittest tests.test_docs -v`
Expected: PASS (1 test).

- [ ] **Step 6: Commit**

```bash
git add netcheck.ini.example USAGE.md tests/test_docs.py
git commit -m "docs: add example config and usage guide"
```

---

### Task 21: Release workflow and SHA256SUMS

**Files:**
- Create: `.github/workflows/release.yml`
- Create: `tests/test_release_assets.py`

**Interfaces:**
- Consumes: repository files.
- Produces: release automation; a test asserting the release asset list is present.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_release_assets.py
import os
import unittest

ASSETS = ["netcheck.py", "netcheck.ini.example", "USAGE.md"]


class TestReleaseAssets(unittest.TestCase):
    def test_assets_exist(self):
        for asset in ASSETS:
            self.assertTrue(os.path.exists(asset), asset)


if __name__ == "__main__":
    unittest.main()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m unittest tests.test_release_assets -v`
Expected: PASS once Task 20 is complete — if it fails, a Task 20 asset is missing.

- [ ] **Step 3: Create the workflow**

```yaml
# .github/workflows/release.yml
name: release
on:
  push:
    tags: ["v*"]
permissions:
  contents: write
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Generate checksums
        run: sha256sum netcheck.py netcheck.ini.example USAGE.md > SHA256SUMS
      - name: Publish release assets
        uses: softprops/action-gh-release@v2
        with:
          files: |
            netcheck.py
            netcheck.ini.example
            USAGE.md
            SHA256SUMS
```

- [ ] **Step 4: Run the full suite**

Run: `python -m unittest discover -s tests -v`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/release.yml tests/test_release_assets.py
git commit -m "ci: add release workflow with checksums"
```

---

## Self-Review

**Spec coverage** (spec section → task):

- §5 Architecture units → Tasks 2–5, 7–9, 12–14, 18–19 (`Config`, `Reporter`, `CheckResult`, `snmp`, `ber`, `telnet`, `oui`, `fixes`, `cli`).
- §6 checks 1–9 → Tasks 9 (1), 10 (2–4), 11 (5), 12 (6), 14 (7), 15 (8), 16 (9).
- §7 baseline (LBD/storm/RSTP/DHCP/DoS) → Tasks 16 (audit) and 20 (USAGE table).
- §7.1 storm auto-measurement → Task 17.
- §8 SNMP client + §8.1 OIDs → Tasks 4–5, 16, 17.
- §9 config/flags/output → Tasks 3, 19.
- §10 error handling → Tasks 12, 13, 16, 19 (guards + WARN fallbacks).
- §11 security → Global Constraints + Task 3 (secrets) + Task 20.
- §12 testing → every task (unittest) + Task 21 full-suite run.
- §13 file layout → Tasks 1, 4–8, 20, 21.
- §14 decisions → reflected in Global Constraints and tasks.
- §15 USAGE deliverable → Task 20.
- §16 deployment (download-then-run, uv optional, TTY, release) → Tasks 1 (PEP 723 + TTY), 20, 21.

**Placeholder scan:** all steps contain concrete code/commands; no TBDs.

**Type consistency:** `CheckResult(id, title, status, detail, likely_cause, suggested_fix)`, `Status`, `Reporter.add/render/exit_code`, `Config` fields, and check function names (`check_local_config`, `check_gateway`, `check_internet`, `check_dns`, `check_switches`, `check_rogue_dhcp`, `trace_mac`, `check_storm_hints`, `check_hardening`) are used consistently across tasks. `run_layer_checks` (Task 10) is consumed by `run_all` (Task 19). `decode_port_list` (Task 5) is consumed by Task 16. `measure_storm_threshold` (Task 17) is consumed by Task 19.
