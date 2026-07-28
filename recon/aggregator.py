"""Aggregation, cleaning, and masking utilities."""
from __future__ import annotations

import re
from typing import Dict, List


_IP_RE = re.compile(r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+)\b")
_TOKEN_RE = re.compile(r"(?i)(?:bearer\s+[A-Za-z0-9\-\._~\+\/]+=*|api[_-]?key[:=]\s*\S+|token[:=]\s*\S+|ghp_[A-Za-z0-9_]{20,})")


def _mask_text(s: str) -> str:
    if not s:
        return s
    s = _IP_RE.sub("<REDACTED_IP>", s)
    s = _TOKEN_RE.sub("<REDACTED_TOKEN>", s)
    # mask long base64-like strings
    s = re.sub(r"[A-Za-z0-9-_]{40,}", "<REDACTED_TOKEN>", s)
    return s


def clean_and_mask(domain: str, subdomains: List[str], httpx_results: List[Dict], nuclei_results: List[Dict], max_desc_len: int) -> Dict:
    """Clean and mask raw scan outputs and return structured payload.

    Implements the rules from the spec:
    - Strip raw/large fields (not present here), mask internal IPs and tokens,
    - Truncate nuclei descriptions/matched_at to `max_desc_len`.
    - Produce a structured dict with deduped technologies.
    """
    subdomains_found = len(subdomains or [])
    live_hosts = len(httpx_results or [])

    techs = set()
    for r in (httpx_results or []):
        t = r.get("tech") or r.get("technologies") or r.get("techs")
        if not t:
            continue
        if isinstance(t, str):
            # some httpx outputs may present comma-separated techs
            for part in re.split(r"[,;]\s*", t):
                if part:
                    techs.add(part.strip())
        elif isinstance(t, (list, tuple, set)):
            for part in t:
                if part:
                    techs.add(str(part).strip())

    technologies = sorted(x for x in techs if x)

    active_scan_run = bool(nuclei_results)

    findings = []
    for f in (nuclei_results or []):
        name = f.get("name") or f.get("template_id") or "unnamed"
        severity = f.get("severity") or "unknown"
        matched_at = f.get("matched_at") or f.get("matched-at") or ""
        desc = f.get("description") or ""

        matched_at = _mask_text(str(matched_at))
        desc = _mask_text(str(desc))
        if len(desc) > max_desc_len:
            desc = desc[:max_desc_len] + "..."

        findings.append({
            "severity": severity,
            "name": name,
            "matched_at": matched_at,
            "description": desc,
        })

    payload = {
        "target": domain,
        "subdomains_found": subdomains_found,
        "live_hosts": live_hosts,
        "technologies": technologies,
        "active_scan_run": active_scan_run,
        "findings": findings,
    }

    return payload
