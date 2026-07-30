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
from pathlib import Path

from config import settings
from recon import passive, active, aggregator, ai_summary
from recon.tools import resolve_projectdiscovery_binary

try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None


DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Recon Orchestrator CLI", prog="recon-orchestrator")
    p.add_argument("domain", help="Target domain, e.g. example.com")
    p.add_argument("--active", action="store_true", help="Enable active scanning (Nuclei). Off by default.")
    p.add_argument("--output-dir", default=settings.DEFAULT_OUTPUT_DIR, help=f"Output directory (default: {settings.DEFAULT_OUTPUT_DIR})")
    p.add_argument("--timeout", type=int, default=settings.DEFAULT_TIMEOUT, help=f"Per-tool timeout in seconds (default: {settings.DEFAULT_TIMEOUT})")
    p.add_argument("--json", action="store_true", help="Write aggregated payload as JSON alongside summary.md")
    p.add_argument("--version", action="version", version=f"%(prog)s {settings.VERSION}")
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
    env_path = Path(__file__).resolve().parent / ".env"
    if load_dotenv is not None:
        load_dotenv(dotenv_path=env_path)
    else:
        if env_path.exists():
            print("Warning: python-dotenv is not installed; .env file will not be loaded. Install dependencies with: pip install -r requirements.txt")

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

    try:
        subfinder_bin = resolve_projectdiscovery_binary("subfinder", "PD_SUBFINDER_BIN")
        httpx_bin = resolve_projectdiscovery_binary("httpx", "PD_HTTPX_BIN")
        nuclei_bin = resolve_projectdiscovery_binary("nuclei", "PD_NUCLEI_BIN")
        print("Using scanner binaries:")
        print(f"- subfinder: {subfinder_bin}")
        print(f"- httpx: {httpx_bin}")
        print(f"- nuclei: {nuclei_bin}")
    except Exception as e:
        print(f"Scanner binary resolution warning: {e}")

    print(f"Starting passive reconnaissance for {args.domain}...")
    subdomains = passive.run_subfinder(args.domain, output_dir, args.timeout)
    print(f"Subdomains found: {len(subdomains)}")
    if subdomains:
        preview = ", ".join(subdomains[:10])
        print(f"Subdomain preview: {preview}")

    probe_targets = list(dict.fromkeys([args.domain] + subdomains))
    if args.domain not in subdomains:
        print(f"Also probing apex domain: {args.domain}")

    print("Running dnsx against discovered subdomains (passive)...")
    dns_results = passive.run_dnsx(probe_targets, output_dir, args.timeout)
    print(f"DNS records found: {len(dns_results)}")
    if dns_results:
        preview = ", ".join(f"{r.get('host')} [{r.get('record_type')}]" for r in dns_results[:10])
        print(f"DNS preview: {preview}")

    print("Running httpx against discovered subdomains (passive)...")
    httpx_results = passive.run_httpx(probe_targets, output_dir, args.timeout)
    print(f"HTTP probes: {len(httpx_results)}")
    if httpx_results:
        print("HTTPX highlights:")
        for row in httpx_results[:5]:
            print(f"- {row.get('url')} [{row.get('status_code')}] {row.get('title') or ''}".strip())

    nuclei_results = []
    if args.active:
        print("Running active scanner (nuclei)...")
        nuclei_targets = [r.get("url") or r.get("host") for r in httpx_results if r.get("url") or r.get("host")]
        nuclei_results = active.run_nuclei(nuclei_targets, output_dir, args.timeout)
        print(f"Nuclei findings: {len(nuclei_results)}")
        if nuclei_results:
            print("Nuclei highlights:")
            for finding in nuclei_results[:10]:
                print(f"- {finding.get('severity')}: {finding.get('name')} @ {finding.get('matched_at')}")

    print("Aggregating and masking results...")
    aggregated = aggregator.clean_and_mask(
        args.domain,
        subdomains,
        httpx_results,
        nuclei_results,
        dns_results,
        settings.MAX_DESCRIPTION_LENGTH,
        active_scan_run=args.active,
    )

    if args.json:
        json_path = os.path.join(output_dir, "aggregated.json")
        try:
            with open(json_path, "w", encoding="utf-8") as jf:
                json.dump(aggregated, jf, indent=2)
            print(f"Aggregated JSON written to {json_path}")
        except Exception as e:
            print(f"Failed to write JSON output: {e}")

    print("Scan highlights:")
    for note in aggregated.get("key_observations", [])[:6]:
        print(f"- {note}")

    payload = ai_summary.build_payload(aggregated)

    print("Generating summary (LLM)...")
    try:
        markdown = ai_summary.generate_summary(payload)
    except Exception as e:
        print(f"LLM call failed: {e}. Writing fallback summary from payload.")
        markdown = ai_summary.build_fallback_summary(payload)

    ai_summary.write_summary(markdown, output_dir)

    print(f"Summary written to {os.path.join(output_dir, 'summary.md')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
