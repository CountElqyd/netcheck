#!/usr/bin/env python3
# /// script
# requires-python = ">=3.10"
# dependencies = []
# ///
"""netcheck - diagnose office internet problems and audit the switch fabric."""

from __future__ import annotations

import argparse
import ipaddress
import json
import shutil
import sys
import textwrap

__version__ = "0.5.0"


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

    def counts(self) -> dict:
        return {s: sum(1 for r in self.results if r.status is s) for s in Status}

    def to_dict(self) -> dict:
        counts = self.counts()
        return {
            "version": __version__,
            "exit_code": self.exit_code(),
            "summary": {s.value: counts[s] for s in Status},
            "checks": [
                {
                    "id": r.id,
                    "title": r.title,
                    "status": r.status.value,
                    "detail": r.detail,
                    "likely_cause": r.likely_cause,
                    "suggested_fix": r.suggested_fix,
                }
                for r in self.results
            ],
        }

    def _render_check(self, r: CheckResult, head: str, title_width: int,
                      width: int, use_color: bool) -> list[str]:
        plain_tag = f"[{r.status.value}]"
        tag = f"{_COLORS[r.status]}{plain_tag}{_RESET}" if use_color else plain_tag
        lines = [f"{tag} {head:<{title_width}}".rstrip()]
        if r.detail:
            lines.extend(textwrap.wrap(r.detail, width=width,
                                       initial_indent="      ",
                                       subsequent_indent="      ") or [""])
        for label, value in (("Likely cause", r.likely_cause),
                             ("Suggested fix", r.suggested_fix)):
            if value:
                indent = " " * (5 + len(label) + 2)
                lines.extend(textwrap.wrap(
                    value, width=width,
                    initial_indent=f"    {label}: ",
                    subsequent_indent=indent))
        return lines

    def render(self, color: bool | None = None, quiet: bool = False) -> str:
        use_color = self.color if color is None else color
        try:
            width = shutil.get_terminal_size((88, 24)).columns
        except OSError:
            width = 88
        width = max(width, 40)
        heads = [f"{r.id:>2}. {r.title}" for r in self.results]
        title_width = max((len(h) for h in heads), default=0)
        lines: list[str] = []
        if not quiet:
            for head, r in zip(heads, self.results):
                lines.extend(self._render_check(r, head, title_width, width, use_color))
        if self.results:
            counts = self.counts()
            if lines:
                lines.append("")
            lines.append(f"Summary: {counts[Status.PASS]} PASS · {counts[Status.WARN]} WARN · "
                         f"{counts[Status.FAIL]} FAIL  (exit code {self.exit_code()})")
            if not quiet:
                lines.append("Legend:  PASS healthy  ·  WARN needs attention  ·  "
                             "FAIL broken — fix FAILs first")
        return "\n".join(lines)


def _positive_float(text: str) -> float:
    try:
        value = float(text)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number: {text!r}")
    if value <= 0:
        raise argparse.ArgumentTypeError("must be > 0")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netcheck", description=__doc__)
    parser.add_argument("--version", action="version", version=f"netcheck {__version__}")
    parser.add_argument("--quick", action="store_true", help="checks 1-4 only")
    parser.add_argument("--log", action="store_true", help="save a timestamped report")
    parser.add_argument("--config", default="netcheck.ini", help="path to an INI config file")
    parser.add_argument("--no-fix", action="store_true", help="never prompt for fixes")
    parser.add_argument("--sample", type=_positive_float, default=None, metavar="SECONDS",
                        help="sample storm counters and print per-switch threshold "
                             "recommendations (also feeds --hardening)")
    parser.add_argument("--hardening", action="store_true",
                        help="run the opt-in hardening audit (check 9)")
    parser.add_argument("--timeout", type=_positive_float, default=3.0,
                        help="per-operation network timeout (seconds)")
    parser.add_argument("--verbose", action="store_true",
                        help="print diagnostics (config summary, error tracebacks)")
    parser.add_argument("--no-color", action="store_true",
                        help="disable ANSI color output")
    parser.add_argument("--quiet", action="store_true",
                        help="print only the summary line")
    parser.add_argument("--json", action="store_true",
                        help="emit machine-readable JSON instead of the report")
    return parser


def _log_path(stamp: str) -> str:
    path = f"netcheck-{stamp}.log"
    counter = 1
    while os.path.exists(path):
        path = f"netcheck-{stamp}-{counter}.log"
        counter += 1
    return path


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    cfg = load_config(path=args.config)
    cfg.timeout = args.timeout
    cfg.verbose = args.verbose
    reporter = Reporter(color=not args.no_color and sys.stdout.isatty())
    try:
        run_all(cfg, reporter, quick=args.quick, sample=args.sample,
                hardening=args.hardening, allow_fix=not args.no_fix,
                verbose=args.verbose)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 130
    if args.json:
        print(json.dumps(reporter.to_dict(), indent=2, sort_keys=False))
    else:
        print(reporter.render(quiet=args.quiet))
    if args.log:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        with open(_log_path(stamp), "w") as fh:
            fh.write(reporter.render(color=False) + "\n")
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
    uplink_ports: set[int] = field(default_factory=lambda: set(range(23, 28)))
    uplink_ports_by_switch: dict[str, set[int]] = field(default_factory=dict)
    timeout: float = 3.0
    verbose: bool = False
    mgmt_address: str = "10.90.90.100"
    lan_interface: str | None = None


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


def _diag(cfg, message: str) -> None:
    if getattr(cfg, "verbose", False):
        print(f"[verbose] {message}", file=sys.stderr)


def _diag_exc(cfg) -> None:
    if getattr(cfg, "verbose", False):
        import traceback
        traceback.print_exc()


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


def parse_port_spec(text: str) -> set[int]:
    ports: set[int] = set()
    for part in text.replace(" ", "").split("+"):
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            try:
                ports.update(range(int(lo), int(hi) + 1))
            except ValueError:
                continue
        else:
            try:
                ports.add(int(part))
            except ValueError:
                continue
    return ports


def parse_uplink_ports(text: str) -> tuple[set[int], dict[str, set[int]]]:
    global_ports: set[int] = set()
    per_switch: dict[str, set[int]] = {}
    for token in text.replace(" ", "").split(","):
        if not token:
            continue
        name, sep, spec = token.partition(":")
        if sep:
            if name:
                per_switch[name] = parse_port_spec(spec)
        else:
            global_ports |= parse_port_spec(token)
    return global_ports, per_switch


def uplink_ports_for(cfg, switch: str) -> set[int]:
    return cfg.uplink_ports_by_switch.get(switch, cfg.uplink_ports)



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
            cfg.mgmt_address = section.get("mgmt_address", cfg.mgmt_address)
            cfg.lan_interface = section.get("lan_interface", cfg.lan_interface)
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
            if section.get("uplink_ports"):
                cfg.uplink_ports, cfg.uplink_ports_by_switch = \
                    parse_uplink_ports(section["uplink_ports"])

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
    if "NETCHECK_UPLINK_PORTS" in env:
        cfg.uplink_ports, cfg.uplink_ports_by_switch = \
            parse_uplink_ports(env["NETCHECK_UPLINK_PORTS"])
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

    def _exchange(self, packet: bytes) -> bytes:
        last_error = "timeout"
        for _ in range(self.retries + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            try:
                if self.source:
                    sock.bind((self.source, 0))
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
         runner=run_command, source: str | None = None) -> PingResult:
    _, out, _ = runner(ping_argv(host, count, source=source),
                       timeout=count * timeout + 5)
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


def dns_query(server: str, name: str, timeout: float = 3.0, source: str | None = None) -> tuple[bool, float, list[str]]:
    txid = random.randint(0, 0xFFFF)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    started = time.monotonic()
    try:
        if source:
            sock.bind((source, 0))
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
    default_route_interface: str | None = None


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


def run_layer_checks(cfg: Config, reporter: Reporter, local_fn=None,
                     ping_fn=ping, query_fn=dns_query) -> None:
    if local_fn is None:
        local_fn = lambda: detect_local_config(cfg)
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


@dataclass
class DhcpProbe:
    responders: list[RogueResponder] | None
    reason: str = ""


def scapy_dhcp_discover(timeout: float = 5.0, cfg=None,
                        iface: str | None = None) -> DhcpProbe:
    try:
        from scapy.all import DHCP, BOOTP, Ether, IP, UDP, srp
    except ImportError:
        return DhcpProbe(None, "scapy not installed")
    if iface is None:
        try:
            from scapy.all import conf
            iface = conf.route.route("10.90.90.90")[0]
        except Exception:  # noqa: BLE001 - scapy routing is best-effort
            iface = None
    try:
        packet = (Ether(dst="ff:ff:ff:ff:ff:ff") / IP(src="0.0.0.0", dst="255.255.255.255")
                  / UDP(sport=68, dport=67) / BOOTP(op=1, chaddr=b"\x00" * 16)
                  / DHCP(options=[("message-type", "discover"), "end"]))
        answered, _ = srp(packet, timeout=timeout, verbose=False, iface=iface)
    except PermissionError:
        return DhcpProbe(None, "raw sockets denied (needs root or CAP_NET_RAW)")
    except OSError as exc:
        _diag_exc(cfg)
        return DhcpProbe(None, f"raw sockets unavailable ({exc})")
    except Exception as exc:  # noqa: BLE001 - scapy raises assorted types
        _diag_exc(cfg)
        return DhcpProbe(None, f"scapy probe failed: {exc}")
    found: dict[str, RogueResponder] = {}
    for _sent, received in answered:
        if received.haslayer(DHCP):
            server_ip = received[IP].src
            mac = received[Ether].src
            found[server_ip] = RogueResponder(server_ip, mac, lookup_vendor(mac))
    return DhcpProbe(list(found.values()))


def check_rogue_dhcp(cfg: Config, discover_fn=None,
                     iface: str | None = None) -> tuple[CheckResult, list[str]]:
    if discover_fn is None:
        discover_fn = lambda cfg=None, iface=iface: scapy_dhcp_discover(
            cfg=cfg, iface=iface)
    probe = discover_fn(cfg, iface)
    if probe.responders is None:
        return (CheckResult(6, "Rogue DHCP", Status.WARN,
                            detail=f"not tested: {probe.reason}",
                            likely_cause="The rogue-DHCP probe could not run.",
                            suggested_fix="Install scapy (uv run --with scapy netcheck.py) and "
                                          "grant raw-socket rights: sudo -E uv run --with scapy "
                                          "netcheck.py, or sudo setcap cap_net_raw+ep "
                                          "\"$(readlink -f \"$(command -v python3)\")\"."),
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
                        suggested_fix="Find the responder in the device inventory "
                                      "(check 7) and unplug it; enable DHCP Server "
                                      "Screening on access ports."),
            [r.mac for r in rogues if r.mac])


class TelnetError(Exception):
    pass


_MAC_LINE = re.compile(
    r"([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})\s+(?:eth\S+\s+)?(\d+)\b"
)


# Retained: read-only `debug info` parser; no longer wired into check 7; still unit-tested.
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


def mac_to_oid_suffix(mac: str) -> str:
    return ".".join(str(int(byte, 16)) for byte in mac.replace("-", ":").split(":"))


def mac_from_oid_suffix(oid: str, base: str) -> str | None:
    if not oid.startswith(base + "."):
        return None
    parts = oid[len(base) + 1:].split(".")
    if len(parts) < 6:
        return None
    parts = parts[-6:]
    try:
        octets = [int(p) for p in parts]
    except ValueError:
        return None
    if any(o < 0 or o > 255 for o in octets):
        return None
    return ":".join(f"{o:02X}" for o in octets)


def resolve_ifindex_ports(client) -> dict[int, int]:
    mapping: dict[int, int] = {}
    for oid, value in client.walk(BASE_PORT_IFINDEX_OID):
        if isinstance(value, int):
            mapping[int(oid.rsplit(".", 1)[1])] = value
    return mapping


@dataclass
class Devicelist:
    devices: dict[str, dict[str, int]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)


def _walk_fdb(client) -> list[tuple[str, object, str]]:
    error: SnmpError | None = None
    for base in (QB_FDB_OID, BRIDGE_FDB_OID):
        try:
            rows = client.walk(base)
        except SnmpError as exc:
            error = exc
            rows = []
        if rows:
            return [(oid, value, base) for oid, value in rows]
    if error is not None:
        raise error
    return []


def collect_devices(cfg: Config, client_factory=SnmpClient,
                    source: str | None = None) -> Devicelist:
    result = Devicelist()
    if not cfg.snmp_community:
        return result
    for name, host in cfg.switches.items():
        result.devices[name] = {}
        try:
            client = client_factory(host, cfg.snmp_community,
                                    timeout=cfg.timeout, source=source)
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
            _diag_exc(cfg)
            result.errors.append(f"{name}: SNMP unavailable ({exc})")
    return result


def access_devices(devs: Devicelist, uplink_of) -> Devicelist:
    """Drop uplink/trunk rows and duplicates so only end devices remain.

    A MAC learned on a trunk port is infrastructure traffic (another switch or
    the router). After removing configured uplink ports, a MAC still seen more
    than once is kept on the least-populated port (the most access-like),
    breaking ties by switch order then port number.
    """
    counts = {switch: {} for switch in devs.devices}
    for switch, macs in devs.devices.items():
        for port in macs.values():
            counts[switch][port] = counts[switch].get(port, 0) + 1
    best: dict[str, tuple[tuple[int, int, int], str, int]] = {}
    for order, (switch, macs) in enumerate(devs.devices.items()):
        uplinks = uplink_of(switch)
        for mac, port in macs.items():
            if port in uplinks:
                continue
            rank = (counts[switch][port], order, port)
            current = best.get(mac)
            if current is None or rank < current[0]:
                best[mac] = (rank, switch, port)
    devices: dict[str, dict[str, int]] = {switch: {} for switch in devs.devices}
    for mac, (_rank, switch, port) in best.items():
        devices[switch][mac] = port
    return Devicelist(devices=devices, errors=list(devs.errors))


def format_inventory(devs: Devicelist, rogue_macs: list[str]) -> str:
    rogue = {m.replace("-", ":").upper() for m in rogue_macs}
    rows: list[tuple[str, int, str]] = []
    for switch, macs in devs.devices.items():
        for mac, port in macs.items():
            rows.append((switch, port, mac))
    order = {name: i for i, name in enumerate(devs.devices)}
    rows.sort(key=lambda r: (order[r[0]], r[1], r[2]))
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
                           client_factory=SnmpClient,
                           source: str | None = None) -> CheckResult:
    title = "Device inventory"
    if not cfg.snmp_community:
        return CheckResult(7, title, Status.WARN,
                           detail="SNMP community not set; cannot list devices",
                           likely_cause="The inventory needs read-only SNMP on each switch.",
                           suggested_fix="Set the SNMP community (NETCHECK_SNMP_COMMUNITY "
                                         "or netcheck.ini).")
    devs = collect_devices(cfg, client_factory=client_factory, source=source)
    raw_total = sum(len(m) for m in devs.devices.values())
    filtered = access_devices(devs, lambda switch: uplink_ports_for(cfg, switch))
    total = sum(len(m) for m in filtered.devices.values())
    table = format_inventory(filtered, rogue_macs)
    rogue = {m.replace("-", ":").upper() for m in rogue_macs}
    hits = [(switch, port, mac) for switch, macs in filtered.devices.items()
            for mac, port in macs.items() if mac.upper() in rogue]
    if not hits:
        hits = [(switch, port, mac) for switch, macs in devs.devices.items()
                for mac, port in macs.items() if mac.upper() in rogue]
    hidden = raw_total - total
    summary = f"{total} end devices on {len(devs.devices)} switches"
    if hidden > 0:
        summary += f" ({hidden} on uplink ports hidden)"
    if hits:
        where = ", ".join(f"{switch} port {port}" for switch, port, _ in hits)
        return CheckResult(7, title, Status.FAIL,
                           detail=f"{summary}; rogue on {where}\n{table}",
                           likely_cause="A non-gateway DHCP server is attached to the fabric.",
                           suggested_fix=f"Unplug the flagged device ({where}); enable DHCP "
                                         "Server Screening with 192.168.1.1 trusted.")
    if total == 0 and devs.errors:
        return CheckResult(7, title, Status.WARN,
                           detail="inventory unavailable\n" + table,
                           likely_cause="No switch returned an FDB.",
                           suggested_fix="Confirm SNMP is enabled and reachable on each switch.")
    return CheckResult(7, title, Status.PASS, detail=summary + ("\n" + table if table else ""))


def check_storm_hints(cfg: Config, gateway_result: PingResult,
                      client_factory=SnmpClient) -> CheckResult:
    jitter = None
    if gateway_result.max_ms is not None and gateway_result.min_ms is not None:
        jitter = gateway_result.max_ms - gateway_result.min_ms
    if gateway_result.loss_pct > 5 or (jitter is not None and jitter > 30):
        return CheckResult(8, "Loop/storm hints", Status.WARN,
                           detail=f"gateway loss {gateway_result.loss_pct:.0f}% jitter {jitter}",
                           likely_cause="Possible broadcast storm or flapping link.",
                           suggested_fix="Check LBD loop status and error counters on ports 23-27.")
    return CheckResult(8, "Loop/storm hints", Status.PASS, detail="no storm indicators")


PRIVATE_ROOT = "1.3.6.1.4.1.171.10.76.20.1"

# Scalar hardening objects on the DGS-1210 are single-instance, addressed with a
# trailing ".0". Requesting the bare OID returns noSuchInstance (None), which is
# how the audit used to silently fall back to "disabled" for every feature.
_HARDENING_OIDS = {
    "lbd_enabled":      PRIVATE_ROOT + ".17.1.0",
    "lbd_recover_time": PRIVATE_ROOT + ".17.4.0",
    "storm_enabled":    PRIVATE_ROOT + ".13.3.1.0",
    "storm_type":       PRIVATE_ROOT + ".13.3.2.0",
    "storm_threshold":  PRIVATE_ROOT + ".13.3.3.0",
    "rstp_enabled":     PRIVATE_ROOT + ".6.1.1.0",
    "rstp_priority":    PRIVATE_ROOT + ".6.1.3.0",
    "safeguard_enabled": PRIVATE_ROOT + ".1.8.0",
    "dhcp_enabled":     PRIVATE_ROOT + ".14.1.1.0",
    "dos_enabled":      PRIVATE_ROOT + ".99.1.0",
}
_DHCP_TRUSTED_SERVER_BASE = PRIVATE_ROOT + ".14.7.3.1.2"


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
    dhcp_enabled: bool = False
    dhcp_trusted_servers: list[str] = field(default_factory=list)
    dos_enabled: bool = False
    readable: bool = True
    unknown: frozenset = frozenset()


def _ipv4_from_snmp(value) -> str | None:
    if isinstance(value, bytes) and len(value) == 4:
        return ".".join(str(b) for b in value)
    return None


def evaluate_hardening(state: HardeningState,
                       measured: dict | None = None) -> list[str]:
    if not state.readable:
        return ["hardening MIB not exposed by this firmware "
                "(cannot audit LBD/STP/storm/DHCP/DoS)"]
    findings: list[str] = []
    unknown = state.unknown
    if "lbd_enabled" in unknown:
        findings.append("Loopback Detection: not readable (SNMP timeout)")
    elif not state.lbd_enabled:
        findings.append("Loopback Detection: disabled (recommended: enabled, recover time 0)")
    elif state.lbd_recover_time != 0:
        findings.append(f"Loopback Detection: recover time {state.lbd_recover_time} "
                        "(recommended: 0)")
    recommended_threshold = (measured or {}).get("threshold", STORM_FALLBACK_KBPS)
    if "storm_enabled" in unknown:
        findings.append("Storm Control: not readable (SNMP timeout)")
    elif not state.storm_enabled:
        findings.append("Storm Control: disabled (recommended: enabled, type 3)")
    elif state.storm_type != 3:
        findings.append(f"Storm Control: type {state.storm_type} (recommended: 3)")
    elif state.storm_threshold != recommended_threshold:
        findings.append(
            f"Storm Control: threshold {state.storm_threshold} Kbit/s "
            f"(N={kbps_to_n(state.storm_threshold)}) (recommended: "
            f"{recommended_threshold} Kbit/s, N={kbps_to_n(recommended_threshold)})")
    if "rstp_enabled" in unknown:
        findings.append("RSTP: not readable (SNMP timeout)")
    elif not state.rstp_enabled:
        findings.append("RSTP: disabled (recommended: enabled)")
    if "safeguard_enabled" in unknown:
        findings.append("Safeguard Engine: not readable (SNMP timeout)")
    elif not state.safeguard_enabled:
        findings.append("Safeguard Engine: disabled (recommended: enabled)")
    if "dhcp_enabled" in unknown:
        findings.append("DHCP Server Screening: not readable (SNMP timeout)")
    elif not state.dhcp_enabled:
        findings.append("DHCP Server Screening: disabled (recommended: enabled). "
                        "Per-port trust is not exposed over SNMP on this firmware; "
                        "verify trusted ports in the web UI and use check 6 for rogues")
    if not state.dhcp_trusted_servers:
        findings.append("DHCP Server Screening: no trusted DHCP server IP configured")
    if not state.dos_enabled:
        findings.append("DoS Prevention: disabled (optional, recommended: enabled)")
    return findings


def read_hardening_state(client) -> HardeningState:
    state = HardeningState()
    values: dict[str, object] = {}
    unknown: set[str] = set()
    for key, oid in _HARDENING_OIDS.items():
        try:
            values[key] = client.get([oid]).get(oid)
        except SnmpError:
            values[key] = None
            unknown.add(key)
    returned = sum(1 for value in values.values() if value is not None)
    if returned == 0:
        # Nothing came back: the switch either did not answer (every probe
        # raised) or the objects are not implemented (every probe returned
        # noSuchObject). Either way the features are unauditable.
        state.readable = False
        state.unknown = frozenset(unknown)
        return state
    state.unknown = frozenset(unknown)
    state.lbd_enabled = values.get("lbd_enabled") == 1
    state.lbd_recover_time = int(values.get("lbd_recover_time") or 0)
    state.storm_enabled = values.get("storm_enabled") == 1
    state.storm_type = int(values.get("storm_type") or 1)
    state.storm_threshold = int(values.get("storm_threshold") or 0)
    state.rstp_enabled = values.get("rstp_enabled") == 1
    state.rstp_priority = int(values.get("rstp_priority") or 32768)
    state.safeguard_enabled = values.get("safeguard_enabled") == 1
    state.dos_enabled = values.get("dos_enabled") == 1
    state.dhcp_enabled = values.get("dhcp_enabled") not in (None, 0)
    try:
        for _oid, value in client.walk(_DHCP_TRUSTED_SERVER_BASE):
            ip = _ipv4_from_snmp(value)
            if ip:
                state.dhcp_trusted_servers.append(ip)
    except SnmpError:
        pass
    return state


def check_hardening(cfg: Config, measured: dict[str, dict] | None = None,
                    client_factory=SnmpClient,
                    source: str | None = None) -> CheckResult:
    if not cfg.snmp_community:
        return CheckResult(9, "Hardening audit", Status.WARN,
                           detail="SNMP community not set; cannot audit switches")
    measured = measured or {}
    findings: list[str] = []
    for name, host in cfg.switches.items():
        try:
            client = client_factory(host, cfg.snmp_community,
                                    timeout=cfg.timeout, source=source)
            state = read_hardening_state(client)
            if not state.readable:
                findings.append(f"{name}: hardening MIB not exposed by this firmware "
                                "(cannot audit LBD/STP/storm/DHCP/DoS)")
                continue
            for finding in evaluate_hardening(state, measured.get(name)):
                findings.append(f"{name}: {finding}")
            _diag(cfg, f"{name}: DHCP screening enabled={state.dhcp_enabled}; "
                       f"trusted servers {state.dhcp_trusted_servers or 'none'}")
        except (SnmpError, ValueError) as exc:
            _diag_exc(cfg)
            findings.append(f"{name}: SNMP unavailable ({exc})")
    if not findings:
        return CheckResult(9, "Hardening audit", Status.PASS,
                           detail="all switches meet the baseline")
    return CheckResult(9, "Hardening audit", Status.WARN, detail="; ".join(findings),
                       suggested_fix="Apply the baseline in USAGE.md (LBD, Storm Control, "
                                     "RSTP, DHCP Server Screening). LBD and RSTP are "
                                     "mutually exclusive per port on DGS-1210: keep RSTP on "
                                     "the cascade ports, LBD on the access ports.")


def ceil_to_64(n: float) -> int:
    return int(-(-n // 64) * 64)


def kbps_to_n(kbps: float) -> int:
    """Convert a Kbit/s threshold to the switch's web-UI step count N.

    The DGS-1210 storm-control field is ``Threshold (64Kbps * N)`` with
    ``N = 1..16000`` (DGS-1210-28 manual, Security > Storm Control); the real
    threshold is ``64 * N`` Kbit/s and must be a multiple of 64.
    """
    n = int(round(kbps / 64.0))
    return max(1, min(16000, n))


def format_port_list(ports: list[int]) -> str:
    if not ports:
        return "none"
    ordered = sorted(set(ports))
    ranges: list[str] = []
    start = prev = ordered[0]
    for port in ordered[1:]:
        if port == prev + 1:
            prev = port
            continue
        ranges.append(f"{start}" if start == prev else f"{start}-{prev}")
        start = prev = port
    ranges.append(f"{start}" if start == prev else f"{start}-{prev}")
    return ",".join(ranges)


STORM_FALLBACK_KBPS = 313 * 64


def compute_threshold(peak_kbps: float, link_kbps: int, factor: int = 4,
                      floor: int = 10000) -> int:
    target = max(ceil_to_64(peak_kbps * factor), ceil_to_64(floor))
    return min(target, int(0.8 * link_kbps))


def _counter_snapshot(client) -> dict[str, int]:
    snapshot: dict[str, int] = {}
    for oid, value in client.walk("1.3.6.1.2.1.31.1.1.1.9"):
        snapshot["b" + oid.rsplit(".", 1)[1]] = int(value)
    for oid, value in client.walk("1.3.6.1.2.1.31.1.1.1.8"):
        snapshot["m" + oid.rsplit(".", 1)[1]] = int(value)
    return snapshot


def measure_storm_threshold(cfg: Config, sample_seconds: float = 30,
                            client_factory=SnmpClient,
                            source: str | None = None) -> dict[str, dict]:
    if not cfg.snmp_community or sample_seconds <= 0:
        return {}
    import concurrent.futures

    def per_switch(item: tuple[str, str]) -> tuple[str, dict]:
        name, host = item
        try:
            client = client_factory(host, cfg.snmp_community,
                                    timeout=cfg.timeout, source=source)
            before = _counter_snapshot(client)
            time.sleep(sample_seconds)
            after = _counter_snapshot(client)
        except SnmpError:
            _diag_exc(cfg)
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


def format_threshold_samples(measured: dict[str, dict]) -> CheckResult:
    """Render per-switch storm-threshold recommendations as a check result."""
    if not measured:
        return CheckResult(10, "Storm thresholds", Status.WARN,
                           detail="no samples collected (SNMP unavailable or sampling skipped)",
                           likely_cause="SNMP did not answer, or no switches configured.",
                           suggested_fix="Check SNMP reachability, then re-run with --sample.")
    lines = []
    for name in sorted(measured):
        kbps = measured[name].get("threshold", 0)
        lines.append(f"{name}: {kbps} Kbit/s (N={kbps_to_n(kbps)})")
    return CheckResult(10, "Storm thresholds", Status.PASS,
                       detail="set Threshold (64Kbps x N): " + "; ".join(lines))


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
            sample: float | None = None, hardening: bool = False,
            allow_fix: bool = True, tty=None, runner=run_command,
            verbose: bool = False) -> None:
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

    try:
        layer_ping = lambda host, **kw: ping(host, runner=runner, **kw)  # noqa: E731
        layer_query = lambda server, name, **kw: dns_query(  # noqa: E731
            server, name, timeout=kw.get("timeout", cfg.timeout))
        _diag(cfg, "checks 1-4: local config, gateway, internet, DNS")
        run_layer_checks(cfg, reporter,
                         local_fn=lambda: detect_local_config(cfg, runner=runner),
                         ping_fn=layer_ping, query_fn=layer_query)
        if quick:
            return

        _run_check(5, "Switches",
                   lambda: reporter.add(check_switches(cfg, ping_fn=layer_ping)))

        rogue_macs: list[str] = []

        def _rogue() -> None:
            result, macs = check_rogue_dhcp(cfg)
            reporter.add(result)
            rogue_macs.extend(macs)

        _run_check(6, "Rogue DHCP", _rogue)

        if sample is not None:
            def _sample_only() -> None:
                measured = measure_storm_threshold(cfg, sample_seconds=sample)
                reporter.add(format_threshold_samples(measured))
            _run_check(10, "Storm thresholds", _sample_only)

        if hardening:
            def _hardening() -> None:
                measured = (measure_storm_threshold(cfg, sample_seconds=sample)
                            if sample is not None else {})
                reporter.add(check_hardening(cfg, measured=measured))

            _run_check(9, "Hardening audit", _hardening)

        def _storm() -> None:
            gateway_ping = ping(cfg.gateway, count=4, timeout=cfg.timeout, runner=runner)
            reporter.add(check_storm_hints(cfg, gateway_ping))

        _run_check(8, "Loop/storm hints", _storm)

        def _inventory() -> None:
            reporter.add(check_device_inventory(cfg, rogue_macs))

        _run_check(7, "Device inventory", _inventory)

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


if __name__ == "__main__":
    raise SystemExit(main())
