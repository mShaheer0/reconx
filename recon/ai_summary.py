"""AI summarization module.

Supports Groq only.
"""
from __future__ import annotations

import json
import os
from typing import Dict


def build_payload(aggregated: Dict) -> Dict:
    """Validate/prepare payload for LLM.

    Currently a thin passthrough.
    """
    return dict(aggregated)


def build_fallback_summary(payload: Dict) -> str:
    """Build a markdown fallback summary from the aggregated payload."""
    md_lines = ["# Recon Summary (fallback)", ""]
    md_lines.append("## Attack Surface Summary")
    md_lines.append(f"Target: {payload.get('target')}")
    md_lines.append(f"Subdomains found: {payload.get('subdomains_found')}")
    md_lines.append(f"Live hosts: {payload.get('live_hosts')}")
    live_urls = payload.get('live_urls') or []
    if live_urls:
        md_lines.append(f"Live URLs: {', '.join(live_urls[:5])}")
    md_lines.append("")
    md_lines.append("## Technologies Identified")
    techs = payload.get('technologies') or []
    if techs:
        md_lines.extend(f"- {t}" for t in techs)
    else:
        md_lines.append("- No technologies were identified.")
    md_lines.append("")
    md_lines.append("## Findings")
    for obs in payload.get('key_observations') or []:
        md_lines.append(f"- {obs}")
    findings = payload.get('findings') or []
    if findings:
        md_lines.append("- Notable nuclei results:")
        for f in findings[:10]:
            md_lines.append(f"  - {f.get('severity')}: {f.get('name')} ({f.get('matched_at')})")
    md_lines.append("")
    md_lines.append("## Risk Assessment")
    if findings:
        md_lines.append("The main risk comes from the nuclei findings listed above; prioritize high and critical severity items first.")
    elif payload.get('active_scan_run'):
        md_lines.append("Active scanning ran, but no nuclei findings were returned. Re-run active scanning with a broader template set if deeper validation is needed.")
    elif payload.get('live_hosts'):
        md_lines.append("Live hosts were found, but active scanning was not performed, so risk remains unvalidated rather than disproven.")
    else:
        md_lines.append("No live hosts or nuclei findings were confirmed, so risk remains unvalidated rather than disproven.")
    return "\n".join(md_lines)


def generate_summary(payload: Dict) -> str:
    """Call Groq and return a markdown summary.

    Uses environment-only configuration. Secret values are never written to
    the repository and are expected to live in local environment variables or
    a local .env file.
    """
    try:
        import requests
    except Exception:
        raise RuntimeError("requests package not installed; required for Groq support")

    system_prompt = (
        "You are a concise technical assistant. Produce a markdown report with exactly these four headers in this order:\n"
        "## Attack Surface Summary\n"
        "## Technologies Identified\n"
        "## Findings\n"
        "## Risk Assessment\n"
        "\n"
        "Grounding rule: Only summarize data present in the JSON payload. Do not infer, speculate about, or invent vulnerabilities, exploitability, or risk beyond what is explicitly stated.\n"
        "The Findings section is the most important part of the report. Make it findings-first, concise, and action-oriented. Use bullet points.\n"
        "Prefer the payload's key observations, severity counts, live-host counts, technologies, nuclei findings, and dns record types over generic restatements.\n"
        "If `active_scan_run` is false: in the Findings section explicitly state that active scanning was not performed and no vulnerability data is available. Do not guess at risk in this case.\n"
        "Stay under ~400 words. Audience: technical security stakeholder, plain language. Use only severity language present in the data. Avoid generic filler prose.\n"
        "\n"
        "Additional constraints:\n"
        "- Never state that a severity tier (e.g. high-severity) is absent unless the payload explicitly shows zero findings at that tier. Report only what is present.\n"
        "- In the Findings section, group findings by category (e.g. Headers, TLS/SSL, DNS, WAF, SSH) rather than listing each individually.\n"
        "- Do not include remediation recommendations or prescriptive advice. The Risk Assessment section must characterize severity distribution only, based strictly on what is present in the data.\n"
        "- Tie findings back to scope: mention counts relative to subdomains_found and live_hosts for grounding (e.g. across N live hosts)."
    )

    user_content = "```json\n" + (json.dumps(payload, indent=2)) + "\n```"

    groq_key = os.environ.get("GROQ_API_KEY")
    if not groq_key:
        raise RuntimeError("No Groq API key configured: set GROQ_API_KEY in environment")

    groq_url = os.environ.get("GROQ_API_URL") or "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {groq_key}", "Content-Type": "application/json"}
    body = {
        "model": os.environ.get("GROQ_MODEL", "llama-3.3-70b-versatile"),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
        "temperature": 0.3,
        "max_tokens": 800,
    }
    resp = requests.post(groq_url, headers=headers, json=body, timeout=30)
    if resp.status_code >= 400:
        raise RuntimeError(f"Groq request failed ({resp.status_code}): {resp.text}")
    data = resp.json()
    text = _extract_chat_text(data)
    if not text:
        text = json.dumps(data)
    return str(text).strip()


def _extract_chat_text(data: Dict) -> str:
    """Extract assistant text from OpenAI-compatible chat/completions responses."""
    choices = data.get("choices") or []
    if not choices or not isinstance(choices, list):
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    message = first.get("message") or {}
    if isinstance(message, dict):
        content = message.get("content")
        if isinstance(content, str) and content.strip():
            return content.strip()
        if isinstance(content, list):
            for part in content:
                if isinstance(part, dict):
                    text = part.get("text")
                    if isinstance(text, str) and text.strip():
                        return text.strip()
    text = first.get("text")
    if isinstance(text, str) and text.strip():
        return text.strip()
    return ""


def write_summary(markdown: str, output_dir: str) -> None:
    """Write `summary.md` to the given output directory."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "summary.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(markdown)
