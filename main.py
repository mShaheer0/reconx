#!/usr/bin/env python3
"""CLI entrypoint for Recon Orchestrator (phase 1 skeleton).

Implements argument parsing and the `--active` confirmation flow.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

from config import settings
from recon import passive, active, aggregator, ai_summary

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None


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
    if load_dotenv is not None:
        load_dotenv()

    args = parse_args()

    if not validate_domain(args.domain):
        print("Invalid domain format. Provide a domain like 'example.com'.")
        return 2

    if args.active:
        if not confirm_active_scan(args.domain):
            print("Active scan aborted by user.")
            return 0

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    print(f"Starting passive reconnaissance for {args.domain}...")
    subdomains = passive.run_subfinder(args.domain, output_dir, args.timeout)
    print(f"Subdomains found: {len(subdomains)}")

    print("Running httpx against discovered subdomains (passive)...")
    httpx_results = passive.run_httpx(subdomains, output_dir, args.timeout)
    print(f"HTTP probes: {len(httpx_results)}")

    nuclei_results = []
    if args.active:
        print("Running active scanner (nuclei)...")
        nuclei_targets = [r.get("url") or r.get("host") for r in httpx_results if r.get("url") or r.get("host")]
        nuclei_results = active.run_nuclei(nuclei_targets, output_dir, args.timeout)
        print(f"Nuclei findings: {len(nuclei_results)}")

    print("Aggregating and masking results...")
    aggregated = aggregator.clean_and_mask(args.domain, subdomains, httpx_results, nuclei_results, settings.MAX_DESCRIPTION_LENGTH)

    payload = ai_summary.build_payload(aggregated)

    print("Generating summary (LLM)...")
    try:
        markdown = ai_summary.generate_summary(payload)
    except Exception as e:
        print(f"LLM call failed: {e}. Writing fallback summary from payload.")
        # Build a fallback markdown from the payload
        md_lines = ["# Recon Summary (fallback)", ""]
        md_lines.append("## Attack Surface Summary")
        md_lines.append(f"Target: {payload.get('target')}")
        md_lines.append(f"Subdomains found: {payload.get('subdomains_found')}")
        md_lines.append(f"Live hosts: {payload.get('live_hosts')}")
        md_lines.append("")
        md_lines.append("## Technologies Identified")
        techs = payload.get('technologies') or []
        md_lines.append("\n".join(f"- {t}" for t in techs))
        md_lines.append("")
        md_lines.append("## Findings")
        if not payload.get('active_scan_run'):
            md_lines.append("Active scanning was not performed; no vulnerability data available.")
        else:
            for f in payload.get('findings') or []:
                md_lines.append(f"- {f.get('severity')}: {f.get('name')} ({f.get('matched_at')})")
        md_lines.append("")
        md_lines.append("## Risk Assessment")
        md_lines.append("See findings. No further inference is made in fallback mode.")
        markdown = "\n".join(md_lines)

    ai_summary.write_summary(markdown, output_dir)

    print(f"Summary written to {os.path.join(output_dir, 'summary.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
