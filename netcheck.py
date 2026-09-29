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
