"""Passive reconnaissance wrappers.

Runs subfinder -> dnsx -> httpx in sequence.
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import List, Dict

from config import settings
from recon.tools import resolve_projectdiscovery_binary


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _chunked(items: List[str], size: int) -> List[List[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _normalize_probe_targets(targets: List[str]) -> List[str]:
    """Expand bare hostnames into https/http URLs for httpx.

    ProjectDiscovery httpx is much more reliable when given full URLs. We try
    https first, then http, while leaving already-qualified inputs untouched.
    """
    normalized: List[str] = []
    seen = set()
    for target in targets:
        if not target:
            continue
        candidate_urls = [target]
        if not target.startswith(("http://", "https://")):
            candidate_urls = [f"https://{target}", f"http://{target}"]
        for candidate in candidate_urls:
            if candidate not in seen:
                seen.add(candidate)
                normalized.append(candidate)
    return normalized


def run_subfinder(domain: str, output_dir: str, timeout: int) -> List[str]:
    """Run `subfinder` for `domain` and return discovered subdomains.

    - Writes a `subfinder.json` file into `output_dir` when possible.
    - Returns a list of hostnames (strings). Swallows missing-binary errors
      and returns an empty list in that case.
    """
    _ensure_dir(output_dir)
    out_file = os.path.join(output_dir, "subfinder.json")
    try:
        subfinder_bin = resolve_projectdiscovery_binary("subfinder", "PD_SUBFINDER_BIN")
    except RuntimeError as e:
        print(f"subfinder: {e}")
        return []
    cmd = [
        subfinder_bin,
        "-d",
        domain,
        "-silent",
        "-json",
        "-all",
    ]

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(timeout, settings.SUBFINDER_TIMEOUT))
    except FileNotFoundError:
        print("subfinder: tool not found. Is it installed and on PATH?")
        return []
    except subprocess.TimeoutExpired:
        print("subfinder: timed out")
        return []

    stdout = proc.stdout.decode(errors="ignore").strip()
    if stdout:
        try:
            with open(out_file, "w", encoding="utf-8") as fh:
                fh.write(stdout + "\n")
        except Exception:
            pass

    subdomains: List[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        # common key is 'host'
        host = obj.get("host") or obj.get("domain") or obj.get("subdomain")
        if host:
            subdomains.append(host)

    # dedupe, sort, and cap to keep downstream tools responsive
    unique = sorted(set(subdomains))
    if len(unique) > settings.SUBFINDER_WORD_LIMIT:
        print(f"subfinder: capping subdomains to first {settings.SUBFINDER_WORD_LIMIT} results for responsiveness")
        unique = unique[: settings.SUBFINDER_WORD_LIMIT]
    return unique


def run_dnsx(domains: List[str], output_dir: str, timeout: int) -> List[Dict]:
    """Run `dnsx` against the provided domains and return parsed DNS records.

    - Writes `dnsx.json` to `output_dir` when possible.
    - Returns a list of dicts with keys: host, record_type, record_value.
    - Missing tool -> empty list.
    """
    _ensure_dir(output_dir)
    if not domains:
        return []

    out_file = os.path.join(output_dir, "dnsx.json")
    try:
        dnsx_bin = resolve_projectdiscovery_binary("dnsx", "PD_DNSX_BIN")
    except RuntimeError as e:
        print(f"dnsx: {e}")
        return []

    unique_domains = sorted(set(d for d in domains if d))
    cmd = [
        dnsx_bin,
        "-silent",
        "-json",
        "-a",
        "-aaaa",
        "-cname",
        "-mx",
        "-ns",
        "-txt",
    ]

    results: List[Dict] = []
    try:
        with open(out_file, "w", encoding="utf-8") as raw_fh:
            inp = "\n".join(unique_domains).encode()
            try:
                proc = subprocess.run(cmd, input=inp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            except subprocess.TimeoutExpired:
                print(f"dnsx: timed out on batch of {len(unique_domains)} domains; continuing")
                return results
            except FileNotFoundError:
                print("dnsx: tool not found. Is it installed and on PATH?")
                return []

            stdout = proc.stdout.decode(errors="ignore").strip()
            if stdout:
                raw_fh.write(stdout + "\n")

            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue

                host = str(obj.get("host") or obj.get("input") or "")
                if not host:
                    continue

                for record_type, values in [
                    ("A", obj.get("a") or []),
                    ("AAAA", obj.get("aaaa") or []),
                    ("CNAME", obj.get("cname") or []),
                    ("MX", obj.get("mx") or []),
                    ("NS", obj.get("ns") or []),
                    ("TXT", obj.get("txt") or []),
                ]:
                    if not isinstance(values, list):
                        continue
                    for value in values:
                        if not value:
                            continue
                        results.append({
                            "host": host,
                            "record_type": record_type,
                            "record_value": str(value).strip('"'),
                        })
    except Exception:
        pass

    return results


def run_httpx(subdomains: List[str], output_dir: str, timeout: int) -> List[Dict]:
    """Run `httpx` against the provided `subdomains` list and return parsed results.

    Expects `httpx` to be on PATH. Returns a list of dicts with at least
    `url` and `status_code` when available. Missing tool -> empty list.
    """
    _ensure_dir(output_dir)
    if not subdomains:
        return []

    probe_targets = _normalize_probe_targets(subdomains)

    results: List[Dict] = []
    raw_out = os.path.join(output_dir, "httpx.json")
    try:
        httpx_bin = resolve_projectdiscovery_binary("httpx", "PD_HTTPX_BIN")
    except RuntimeError as e:
        print(f"httpx: {e}")
        return []

    try:
        with open(raw_out, "w", encoding="utf-8") as raw_fh:
            if not probe_targets:
                return []

            cmd = [
                httpx_bin,
                "-silent",
                "-json",
                "-title",
                "-tech-detect",
                "-status-code",
                "-follow-redirects",
            ]
            inp = "\n".join(probe_targets).encode()
            try:
                proc = subprocess.run(cmd, input=inp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            except subprocess.TimeoutExpired:
                print(f"httpx: timed out on batch of {len(probe_targets)} targets; continuing")
                return results
            except FileNotFoundError:
                print("httpx: tool not found. Is it installed and on PATH?")
                return []

            stdout = proc.stdout.decode(errors="ignore").strip()
            if stdout:
                raw_fh.write(stdout + "\n")

            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                entry: Dict = {
                    "url": obj.get("url") or obj.get("host") or obj.get("input") or probe_targets[0],
                    "status_code": obj.get("status_code") or obj.get("status"),
                    "title": obj.get("title"),
                    "tech": obj.get("tech") or obj.get("technologies") or obj.get("technology"),
                }
                if entry["url"]:
                    results.append(entry)
    except Exception:
        pass

    # Deduplicate by URL/title/status so the report reflects unique live hosts.
    deduped: List[Dict] = []
    seen = set()
    for row in results:
        key = (
            str(row.get("url") or ""),
            str(row.get("status_code") or ""),
            str(row.get("title") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(row)

    return deduped
