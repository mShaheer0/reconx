"""Active scanning wrappers (stubs).

Only invoked when --active is confirmed by the user.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from typing import List, Dict


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def run_nuclei(live_hosts: List[str], output_dir: str, timeout: int) -> List[Dict]:
    """Run `nuclei` against the provided hosts and return findings.

    - Writes `nuclei.json` to `output_dir` when possible.
    - Returns list of findings dicts with keys: template_id, name, severity, matched_at, description.
    - Swallows missing-binary errors and returns empty list in that case.
    """
    _ensure_dir(output_dir)
    if not live_hosts:
        return []

    cmd = [
        "nuclei",
        "-json",
        "-silent",
        "-severity",
        "low,medium,high,critical",
    ]

    # feed hosts via stdin
    inp = "\n".join(live_hosts).encode()

    try:
        proc = subprocess.run(cmd, input=inp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except FileNotFoundError:
        print("nuclei: tool not found. Is it installed and on PATH?")
        return []
    except subprocess.TimeoutExpired:
        print("nuclei: timed out")
        return []

    stdout = proc.stdout.decode(errors="ignore").strip()
    out_file = os.path.join(output_dir, "nuclei.json")
    try:
        with open(out_file, "w", encoding="utf-8") as fh:
            fh.write(stdout + "\n")
    except Exception:
        pass

    findings: List[Dict] = []
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

    return findings
