#!/usr/bin/env python3
"""Minimal, dependency-free webhook forwarder for Cognis findings.

Reads JSON findings on stdin and POSTs them to a URL (SIEM/Slack/Jira bridge).
Usage:  <tool> scan . --format json | python integrations/webhook.py --url URL
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request


def _validate_url(url: str) -> str:
    """Return *url* if it looks safe to POST to, else raise ValueError."""
    if not url.startswith(("http://", "https://")):
        raise ValueError(
            f"URL must begin with http:// or https://, got: {url!r}"
        )
    return url


def main() -> int:
    ap = argparse.ArgumentParser(
        description="POST ITARCHECK JSON findings to a webhook endpoint."
    )
    ap.add_argument("--url", required=True, help="Destination URL (http/https)")
    ap.add_argument(
        "--header",
        action="append",
        default=[],
        help="Extra request header in 'Key: Value' form (repeatable)",
    )
    args = ap.parse_args()

    try:
        url = _validate_url(args.url)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    raw = sys.stdin.read()
    if not raw.strip():
        print("error: stdin is empty — nothing to POST", file=sys.stderr)
        return 2

    # Validate that stdin contains parseable JSON before sending.
    try:
        json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"error: stdin is not valid JSON: {exc}", file=sys.stderr)
        return 2

    payload = raw.encode("utf-8")
    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    for h in args.header:
        if ":" not in h:
            print(
                f"error: header {h!r} is not in 'Key: Value' form",
                file=sys.stderr,
            )
            return 2
        k, _, v = h.partition(":")
        req.add_header(k.strip(), v.strip())

    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"posted {len(payload)} bytes -> {r.status}")
        return 0
    except Exception as exc:  # noqa: BLE001
        print(f"webhook error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
