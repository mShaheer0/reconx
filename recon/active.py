"""Active scanning wrappers (stubs).

Only invoked when --active is confirmed by the user.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from typing import List, Dict

from config import settings
from recon.tools import resolve_projectdiscovery_binary


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _chunked(items: List[str], size: int) -> List[List[str]]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def run_nuclei(live_hosts: List[str], output_dir: str, timeout: int) -> List[Dict]:
    """Run `nuclei` against the provided hosts and return findings.

    - Writes `nuclei.json` to `output_dir` when possible.
    - Returns list of findings dicts with keys: template_id, name, severity, matched_at, description.
    - Swallows missing-binary errors and returns empty list in that case.
    """
    _ensure_dir(output_dir)
    if not live_hosts:
        return []

    out_file = os.path.join(output_dir, "nuclei.json")
    findings: List[Dict] = []

    try:
        nuclei_bin = resolve_projectdiscovery_binary("nuclei", "PD_NUCLEI_BIN")
    except RuntimeError as e:
        print(f"nuclei: {e}")
        return []

    cmd = [
        nuclei_bin,
        "-jsonl",
        "-silent",
        "-severity",
        "info,low,medium,high,critical",
    ]

    try:
        with open(out_file, "w", encoding="utf-8") as raw_fh:
            for batch in _chunked(live_hosts, settings.NUCLEI_BATCH_SIZE):
                inp = "\n".join(batch).encode()
                try:
                    proc = subprocess.run(cmd, input=inp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
                except subprocess.TimeoutExpired:
                    print(f"nuclei: timed out on batch of {len(batch)} hosts; continuing")
                    continue
                except FileNotFoundError:
                    print("nuclei: tool not found. Is it installed and on PATH?")
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

                    # nuclei JSON can vary; attempt to extract the common fields
                    template_id = obj.get("templateID") or obj.get("template_id") or obj.get("template")
                    info = obj.get("info") or {}
                    name = info.get("name") or obj.get("name")
                    severity = info.get("severity") or obj.get("severity") or obj.get("severityLevel")
                    matched_at = obj.get("matched-at") or obj.get("matched_at") or obj.get("timestamp") or obj.get("matched_at_time")
                    description = info.get("description") or obj.get("matched") or obj.get("description") or ""

                    findings.append({
                        "template_id": template_id,
                        "name": name,
                        "severity": severity,
                        "matched_at": matched_at,
                        "description": description,
                    })
    except Exception:
        pass

    return findings
