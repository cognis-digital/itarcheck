"""Command-line interface for ITARCHECK.

Usage:
    itarcheck scan PATH [--format table|json] [--fail-on high|medium|low]
    itarcheck categories [--format table|json]
    itarcheck --version

Exit codes:
    0  scan completed, no findings at/above --fail-on threshold
    1  findings at/above --fail-on threshold (CI gate failure)
    2  usage / runtime error
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Sequence

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    USML_CATEGORIES,
    Severity,
    exceeds_threshold,
    scan_path,
    summarize,
)


def _print_findings_table(result, fail_on: Severity) -> None:
    if not result.findings:
        print("No export-control indicators detected.")
    else:
        header = f"{'SEV':<6} {'REGIME':<8} {'RULE':<22} {'LOCATION':<32} MATCH"
        print(header)
        print("-" * len(header))
        for f in result.findings:
            loc = f"{f.path}:{f.line}:{f.column}"
            if len(loc) > 32:
                loc = "..." + loc[-29:]
            print(
                f"{f.severity.value:<6} {f.regime:<8} {f.rule_id:<22} "
                f"{loc:<32} {f.match}"
            )
            detail = f.description
            if f.usml_category:
                detail += f"  [USML {f.usml_category}: {f.usml_title}]"
            if f.ear_reason:
                detail += f"  [EAR: {f.ear_reason}]"
            print(f"       ↳ {detail}")
    print()
    print(summarize(result))
    print(f"fail-on threshold: {fail_on.value}")
    print(
        "NOTE: screening aid only — not a legal export-control determination. "
        "Review with an empowered official."
    )


def _cmd_scan(args: argparse.Namespace) -> int:
    fail_on = Severity(args.fail_on)

    # Validate --ext values: each must start with '.' or be empty string ""
    for ext in args.ext:
        if ext and not ext.startswith("."):
            print(
                f"error: extension must start with '.' (got {ext!r}). "
                "Example: --ext .vhd",
                file=sys.stderr,
            )
            return 2

    try:
        result = scan_path(args.path, extensions=args.ext or None)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"error: could not access path: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        payload = result.to_dict()
        payload["fail_on"] = fail_on.value
        payload["gate_failed"] = exceeds_threshold(result, fail_on)
        print(json.dumps(payload, indent=2))
    else:
        _print_findings_table(result, fail_on)

    return 1 if exceeds_threshold(result, fail_on) else 0


def _cmd_categories(args: argparse.Namespace) -> int:
    if args.format == "json":
        print(json.dumps(USML_CATEGORIES, indent=2))
    else:
        print("USML categories (22 CFR 121.1):")
        for key, title in USML_CATEGORIES.items():
            print(f"  Cat {key:<6} {title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description=(
            "Flag potential ITAR/EAR export-controlled terms and USML "
            "categories in code, datasheets, and docs (compliance screening)."
        ),
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser(
        "scan", help="scan a file or directory for control indicators"
    )
    p_scan.add_argument("path", help="file or directory to scan")
    p_scan.add_argument(
        "--format", choices=("table", "json"), default="table",
        help="output format (default: table)",
    )
    p_scan.add_argument(
        "--fail-on", choices=("high", "medium", "low"), default="high",
        help="minimum severity that fails the gate (default: high)",
    )
    p_scan.add_argument(
        "--ext", action="append", default=[],
        help="additional/override file extension to scan (repeatable, e.g. --ext .vhd)",
    )
    p_scan.set_defaults(func=_cmd_scan)

    p_cat = sub.add_parser(
        "categories", help="list USML categories used for classification"
    )
    p_cat.add_argument(
        "--format", choices=("table", "json"), default="table",
        help="output format (default: table)",
    )
    p_cat.set_defaults(func=_cmd_categories)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        raise  # let argparse handle --help / bad flags normally
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        print(f"error: unexpected failure: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
