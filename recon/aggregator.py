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


def clean_and_mask(domain: str, subdomains: List[str], httpx_results: List[Dict], nuclei_results: List[Dict], dns_results: List[Dict], max_desc_len: int, active_scan_run: bool) -> Dict:
    """Clean and mask raw scan outputs and return structured payload.

    Implements the rules from the spec:
    - Strip raw/large fields (not present here), mask internal IPs and tokens,
    - Truncate nuclei descriptions/matched_at to `max_desc_len`.
    - Produce a structured dict with deduped technologies.
    """
    subdomains_found = len(subdomains or [])

    unique_httpx: List[Dict] = []
    seen_httpx = set()
    for row in (httpx_results or []):
        url = str(row.get("url") or "")
        status = str(row.get("status_code") or "")
        title = str(row.get("title") or "")
        key = (url, status, title)
        if key in seen_httpx:
            continue
        seen_httpx.add(key)
        unique_httpx.append(row)

    live_hosts = len(unique_httpx)

    techs = set()
    for r in unique_httpx:
        t = r.get("tech") or r.get("technologies") or r.get("techs")
        if not t:
            continue
        if isinstance(t, str):
            for part in re.split(r"[,;]\s*", t):
                if part:
                    techs.add(part.strip())
        elif isinstance(t, (list, tuple, set)):
            for part in t:
                if part:
                    techs.add(str(part).strip())

    technologies = sorted(x for x in techs if x)

    status_codes = sorted({str(r.get("status_code")) for r in unique_httpx if r.get("status_code") is not None})
    live_urls = sorted({str(r.get("url")) for r in unique_httpx if r.get("url")})

    dns_records = []
    dns_record_types = {}
    for r in (dns_results or []):
        record_type = str(r.get("record_type") or "").upper()
        record_value = str(r.get("record_value") or "")
        host = str(r.get("host") or "")
        if not record_type or not record_value:
            continue
        masked_value = _mask_text(record_value)
        dns_records.append({
            "host": host,
            "record_type": record_type,
            "record_value": masked_value,
        })
        dns_record_types[record_type] = dns_record_types.get(record_type, 0) + 1

    findings = []
    severity_counts = {}
    for f in (nuclei_results or []):
        name = f.get("name") or f.get("template_id") or "unnamed"
        severity = f.get("severity") or "unknown"
        matched_at = f.get("matched_at") or f.get("matched-at") or ""
        desc = f.get("description") or ""

        matched_at = _mask_text(str(matched_at))
        desc = _mask_text(str(desc))
        if len(desc) > max_desc_len:
            desc = desc[:max_desc_len] + "..."

        severity_key = str(severity).lower()
        severity_counts[severity_key] = severity_counts.get(severity_key, 0) + 1

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
        "live_urls": live_urls,
        "status_codes": status_codes,
        "technologies": technologies,
        "dns_records": dns_records,
        "dns_record_types": dns_record_types,
        "active_scan_run": active_scan_run,
        "severity_counts": severity_counts,
        "key_observations": _build_key_observations(subdomains_found, live_hosts, technologies, dns_record_types, active_scan_run, findings, severity_counts),
        "findings": findings,
    }

    return payload


def _build_key_observations(subdomains_found: int, live_hosts: int, technologies: List[str], dns_record_types: Dict[str, int], active_scan_run: bool, findings: List[Dict], severity_counts: Dict[str, int]) -> List[str]:
    observations = [f"Subdomains discovered: {subdomains_found}", f"Live hosts detected: {live_hosts}"]
    if live_hosts == 0:
        observations.append("No live hosts were confirmed, so the attack surface could not be fully exercised.")
    if technologies:
        observations.append(f"Technologies identified: {', '.join(technologies[:8])}")
    else:
        observations.append("No technologies were identified by httpx.")
    if dns_record_types:
        dns_bits = ", ".join(f"{rtype}:{count}" for rtype, count in sorted(dns_record_types.items()))
        observations.append(f"DNS records resolved: {dns_bits}")
    else:
        observations.append("No DNS records were resolved by dnsx.")
    if active_scan_run:
        if findings:
            sev_bits = []
            for sev in ("critical", "high", "medium", "low", "info", "unknown"):
                if severity_counts.get(sev):
                    sev_bits.append(f"{sev}:{severity_counts[sev]}")
            if sev_bits:
                observations.append("Nuclei findings by severity: " + ", ".join(sev_bits))
            observations.append(f"Nuclei findings returned: {len(findings)}")
        else:
            observations.append("Active scanning ran, but no nuclei findings were returned.")
    else:
        observations.append("Active scanning was not performed.")
    return observations
