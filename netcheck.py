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


if __name__ == "__main__":
    raise SystemExit(main())
