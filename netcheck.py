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
            if r.likely_cause:
                lines.append("    Likely cause: " + r.likely_cause)
            if r.suggested_fix:
                lines.append("    Suggested fix: " + r.suggested_fix)
        return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netcheck", description=__doc__)
    parser.add_argument("--version", action="version", version=f"netcheck {__version__}")
    parser.add_argument("--quick", action="store_true", help="checks 1-4 only")
    parser.add_argument("--log", action="store_true", help="save a timestamped report")
    parser.add_argument("--config", default="netcheck.ini", help="path to an INI config file")
    parser.add_argument("--no-fix", action="store_true", help="never prompt for fixes")
    parser.add_argument("--sample", type=float, default=30.0,
                        help="counter-sampling window for storm thresholds (seconds)")
    parser.add_argument("--no-measure", action="store_true",
                        help="skip rate sampling; use the static storm baseline")
    parser.add_argument("--timeout", type=float, default=3.0,
                        help="per-operation network timeout (seconds)")
    parser.add_argument("--verbose", action="store_true",
                        help="Show full tracebacks on internal errors")
    parser.add_argument("--no-color", action="store_true")
    return parser


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
                sample=args.sample, allow_fix=not args.no_fix, verbose=args.verbose)
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
    snmp_community: str = field(default="", repr=False)
    snmp_version: str = "2c"
    switch_user: str = "admin"
    switch_pass: str = field(default="", repr=False)
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


def _to_int(value, default):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_switches(text):
    result = {}
    for token in text.replace(" ", "").split(","):
        if "=" in token:
            name, _, ip = token.partition("=")
            if name:
                result[name] = ip
    return result


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
            cfg.storm_safety_factor = _to_int(section.get("storm_safety_factor",
                                                           cfg.storm_safety_factor),
                                              cfg.storm_safety_factor)
            cfg.storm_floor_kbps = _to_int(section.get("storm_floor_kbps",
                                                       cfg.storm_floor_kbps),
                                           cfg.storm_floor_kbps)
            if section.get("switches"):
                cfg.switches = _parse_switches(section["switches"])
            if section.get("dns"):
                cfg.dns_servers = section["dns"].replace(" ", "").split(",")

    for env_key, attr in _ENV_MAP.items():
        if env_key in env:
            value: object = env[env_key]
            if attr in ("storm_safety_factor", "storm_floor_kbps"):
                value = _to_int(value, getattr(cfg, attr))
            setattr(cfg, attr, value)
    if "NETCHECK_SWITCHES" in env:
        cfg.switches = _parse_switches(env["NETCHECK_SWITCHES"])
    if "NETCHECK_DNS" in env:
        cfg.dns_servers = env["NETCHECK_DNS"].replace(" ", "").split(",")
    return cfg


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
TAG_COUNTER64 = 0x46
_INTEGER_TAGS = {TAG_INTEGER, TAG_COUNTER, TAG_GAUGE, TAG_TIMETICKS, TAG_COUNTER64,
                 TAG_IPADDRESS}

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
    if tag in (TAG_NULL, 0x80, 0x81, 0x82):
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


def _apply_pdu(pdu_tag: int, request_id: int, oids: list[str],
               max_repetitions: int | None) -> bytes:
    varbinds = b"".join(
        ber_encode_sequence([ber_encode_oid(oid), ber_encode_null()]) for oid in oids
    )
    if pdu_tag == PDU_GET_BULK:
        fields = [
            ber_encode_integer(request_id),
            ber_encode_integer(0),
            ber_encode_integer(25 if max_repetitions is None else max_repetitions),
            ber_encode_sequence([varbinds]),
        ]
    else:
        fields = [
            ber_encode_integer(request_id),
            ber_encode_integer(0),
            ber_encode_integer(0),
            ber_encode_sequence([varbinds]),
        ]
    body = b"".join(fields)
    return bytes([pdu_tag]) + ber_encode_length(len(body)) + body


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
    pdu_tag, pdu, _ = ber_decode_tlv(message, offset)
    pdu_offset = 0
    _, request_bytes, pdu_offset = ber_decode_tlv(pdu, pdu_offset)
    _, first_field, pdu_offset = ber_decode_tlv(pdu, pdu_offset)
    if pdu_tag != PDU_GET_BULK:
        error_status = ber_decode_integer(first_field)
        if error_status:
            raise SnmpError(f"SNMP error-status {error_status}")
    _, _, pdu_offset = ber_decode_tlv(pdu, pdu_offset)
    _, varbind_list_bytes, _ = ber_decode_tlv(pdu, pdu_offset)
    return (ber_decode_integer(version_bytes), ber_decode_integer(request_bytes),
            _parse_varbinds(varbind_list_bytes))


def _oid_key(oid: str) -> tuple[int, ...]:
    return tuple(int(part) for part in oid.split("."))


def _oid_in_subtree(oid: str, base: str) -> bool:
    oid_parts = _oid_key(oid)
    base_parts = _oid_key(base)
    return oid_parts[:len(base_parts)] == base_parts


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
        _version, req_id, varbinds = _parse_response(self._exchange(packet))
        if req_id != self.request_id:
            raise SnmpError(f"request id mismatch: sent {self.request_id}, got {req_id}")
        return varbinds

    def get(self, oids: list[str]) -> dict[str, object]:
        return dict(self._request(PDU_GET, oids))

    def get_next(self, oid: str) -> tuple[str, object] | None:
        varbinds = self._request(PDU_GET_NEXT, [oid])
        if not varbinds:
            return None
        next_oid, value = varbinds[0]
        if value is None or _oid_key(next_oid) <= _oid_key(oid):
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
    return ["ping", "-c", str(count), host]


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


import struct
import time


def build_dns_query(name: str, txid: int) -> bytes:
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    question = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    return header + question + struct.pack(">HH", 1, 1)


def _skip_dns_name(data: bytes, offset: int) -> int:
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0:
            return offset + 2
        offset += 1 + length
    return len(data)


def parse_dns_a(data: bytes) -> list[str]:
    if len(data) < 12:
        return []
    _txid, flags, qdcount, ancount, _ns, _ar = struct.unpack(">HHHHHH", data[:12])
    if flags & 0x000F:
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
        if rtype == 1 and rdlen == 4 and len(rdata) == 4:
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
    try:
        answers = parse_dns_a(data)
    except (IndexError, struct.error, OSError):
        answers = []
    return bool(answers), elapsed, answers


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
    gw = re.search(r"default via ([\d.]+)(?: dev (\S+))?", route_text)
    if gw:
        lc.gateway = gw.group(1)
        lc.interface = gw.group(2)
    addr = re.search(r"inet ([\d.]+)/(\d+) .*scope global", addr_text)
    if not addr:
        addr = re.search(r"inet (?!127\.|169\.254\.)([\d.]+)/(\d+)", addr_text)
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
                           suggested_fix=f"Set the default gateway to {cfg.gateway}.")
    if not lc.dns:
        return CheckResult(1, "Local config", Status.WARN, detail=detail,
                           likely_cause="No DNS servers configured.",
                           suggested_fix="Set DNS to 1.1.1.1/8.8.8.8 or the ISP DNS.")
    return CheckResult(1, "Local config", Status.PASS, detail=detail)


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
        from scapy.all import DHCP, BOOTP, Ether, IP, UDP, srp
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
        discover_fn = lambda cfg=None: scapy_dhcp_discover()
    responders = discover_fn(cfg)
    if responders is None:
        _, out, _ = runner(["nmap", "--script", "broadcast-dhcp-discover",
                            "-e", "any"], timeout=15)
        responders = parse_nmap_dhcp(out)
    if not responders:
        return (CheckResult(6, "Rogue DHCP", Status.WARN,
                            detail="no DHCP server answered or could not determine "
                                   "(needs root/scapy/nmap)"),
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
        self._read_until_idle()
        self.run_command(user, wait=0.5)
        return self.run_command(password, wait=1.0).decode(errors="replace")

    def run_command(self, cmd: str, wait: float = 1.0) -> bytes:
        if self.sock is None:
            raise TelnetError("not connected")
        self.sock.sendall(cmd.encode() + b"\r\n")
        time.sleep(wait)
        return self._read_until_idle()

    def close(self) -> None:
        if self.sock is not None:
            self.sock.close()
            self.sock = None


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
    for base in (QB_FDB_OID, BRIDGE_FDB_OID):
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


def debug_info_lookup(cfg: Config, host: str, mac: str,
                      telnet_factory=TelnetConnection) -> int | None:
    factory = telnet_factory or TelnetConnection
    conn = factory(host, timeout=cfg.timeout)
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
              telnet_factory=TelnetConnection) -> CheckResult:
    telnet_factory = telnet_factory or TelnetConnection
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
            port = debug_info_lookup(cfg, host, mac, telnet_factory)
        if port is None:
            trail = "; ".join(hops)
            detail = f"{trail + '; ' if trail else ''}not found on {name}"
            return CheckResult(7, f"Trace {mac}", Status.WARN, detail=detail,
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
    trail = "; ".join(hops)
    return CheckResult(7, f"Trace {mac}", Status.WARN,
                       detail=f"{trail + ' ' if trail else ''}(loop?)")


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
        except (SnmpError, ValueError) as exc:
            findings.append(f"{name}: SNMP unavailable ({exc})")
    if not findings and not loop_ports:
        return CheckResult(9, "Hardening audit", Status.PASS,
                           detail="all switches meet the baseline"), loop_ports
    loop_detail = "; ".join(f"{name} loop port {p}"
                            for name, ports in loop_ports.items() for p in ports)
    detail = "; ".join(part for part in (loop_detail, "; ".join(findings[:6])) if part)
    if loop_ports:
        return CheckResult(9, "Hardening audit", Status.FAIL, detail=detail,
                           likely_cause="A switch port is in loop state.",
                           suggested_fix="Unplug the looped port, then re-run."), loop_ports
    return CheckResult(9, "Hardening audit", Status.WARN, detail=detail,
                       suggested_fix="Apply the baseline in USAGE.md (LBD, Storm Control, "
                                     "RSTP, DHCP Server Screening)."), loop_ports


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
        link_kbps = 1_000_000
        peak = 0.0
        for key, start in before.items():
            end = after.get(key, start)
            rate = max(0, end - start) / sample_seconds
            kbps = rate * 512 / 1000
            peak = max(peak, kbps)
        return name, {"threshold": compute_threshold(
            peak, link_kbps, cfg.storm_safety_factor, cfg.storm_floor_kbps)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(cfg.switches)) as pool:
        return {name: data for name, data in pool.map(per_switch, cfg.switches.items())
                if data}


from typing import TextIO


def open_tty() -> TextIO | None:
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
    if getattr(stream, "isatty", None) is not None and stream.isatty():
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


def run_all(cfg: Config, reporter: Reporter, quick: bool = False,
            no_measure: bool = False, sample: float = 30.0, allow_fix: bool = True,
            tty=None, runner=run_command, verbose: bool = False) -> None:
    try:
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
            reporter.add(CheckResult(99, "Fixes applied", Status.PASS,
                                     detail="; ".join(fixed)))
    except Exception as exc:
        if verbose:
            import traceback
            traceback.print_exc()
        reporter.add(CheckResult(98, "Internal error", Status.WARN, detail=str(exc),
                                 likely_cause="An unexpected error interrupted the checks.",
                                 suggested_fix="Re-run with --verbose for details."))


if __name__ == "__main__":
    raise SystemExit(main())
