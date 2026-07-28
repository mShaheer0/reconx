#!/usr/bin/env python3
"""CLI entrypoint for Recon Orchestrator (phase 1 skeleton).

Implements argument parsing and the `--active` confirmation flow.
"""
from __future__ import annotations

import argparse
import re
import sys

from config import settings


DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Recon Orchestrator CLI")
    p.add_argument("domain", help="Target domain, e.g. example.com")
    p.add_argument("--active", action="store_true", help="Enable active scanning (Nuclei). Off by default.")
    p.add_argument("--output-dir", default=settings.DEFAULT_OUTPUT_DIR, help=f"Output directory (default: {settings.DEFAULT_OUTPUT_DIR})")
    p.add_argument("--timeout", type=int, default=settings.DEFAULT_TIMEOUT, help=f"Per-tool timeout in seconds (default: {settings.DEFAULT_TIMEOUT})")
    return p.parse_args()


def validate_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain))


def confirm_active_scan(domain: str) -> bool:
    prompt = (
        f"WARNING: Active scanning will be performed against '{domain}'.\n"
        "Only proceed if you have explicit authorization. Type 'y' to confirm: "
    )
    try:
        resp = input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("No confirmation received; aborting active scan.")
        return False
    return resp == "y"


def main() -> int:
    args = parse_args()

    if not validate_domain(args.domain):
        print("Invalid domain format. Provide a domain like 'example.com'.")
        return 2

    if args.active:
        if not confirm_active_scan(args.domain):
            print("Active scan aborted by user.")
            return 0

    # Phase 1: skeleton only. Actual orchestration implemented in later phases.
    print(f"Domain: {args.domain}")
    print(f"Active: {args.active}")
    print(f"Output dir: {args.output_dir}")
    print(f"Timeout: {args.timeout}s")

    print("Phase-1 CLI validated. Next: implement passive pipeline wrappers.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
