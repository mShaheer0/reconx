"""Passive reconnaissance wrappers (stubs).

Functions are placeholders and will be implemented in Phase 2.
"""
from __future__ import annotations

import json
import os
import subprocess
from typing import List, Dict


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def run_subfinder(domain: str, output_dir: str, timeout: int) -> List[str]:
    """Run `subfinder` for `domain` and return discovered subdomains.

    - Writes a `subfinder.json` file into `output_dir` when possible.
    - Returns a list of hostnames (strings). Swallows missing-binary errors
      and returns an empty list in that case.
    """
    _ensure_dir(output_dir)
    out_file = os.path.join(output_dir, "subfinder.json")
    cmd = [
        "subfinder",
        "-d",
        domain,
        "-silent",
        "-json",
    ]

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
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

    # dedupe and sort
    return sorted(set(subdomains))


def run_httpx(subdomains: List[str], output_dir: str, timeout: int) -> List[Dict]:
    """Run `httpx` against the provided `subdomains` list and return parsed results.

    Expects `httpx` to be on PATH. Returns a list of dicts with at least
    `url` and `status_code` when available. Missing tool -> empty list.
    """
    _ensure_dir(output_dir)
    if not subdomains:
        return []

    cmd = [
        "httpx",
        "-silent",
        "-json",
        "-title",
        "-tech-detect",
        "-status-code",
    ]

    inp = "\n".join(subdomains).encode()

    try:
        proc = subprocess.run(cmd, input=inp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except FileNotFoundError:
        print("httpx: tool not found. Is it installed and on PATH?")
        return []
    except subprocess.TimeoutExpired:
        print("httpx: timed out")
        return []

    stdout = proc.stdout.decode(errors="ignore").strip()
    results: List[Dict] = []

    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        # Normalize common fields
        entry: Dict = {
            "url": obj.get("url") or obj.get("host") or obj.get("input"),
            "status_code": obj.get("status_code") or obj.get("status"),
            "title": obj.get("title"),
            "tech": obj.get("tech") or obj.get("technologies") or obj.get("technology"),
        }
        results.append(entry)

    # write raw output for debugging
    raw_out = os.path.join(output_dir, "httpx.json")
    try:
        with open(raw_out, "w", encoding="utf-8") as fh:
            fh.write(stdout + "\n")
    except Exception:
        pass

    return results
