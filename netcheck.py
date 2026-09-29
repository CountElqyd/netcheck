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
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


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


if __name__ == "__main__":
    raise SystemExit(main())
