"""AI summarization module.

Supports x.ai Responses API primarily, with OpenAI as a fallback.
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


def generate_summary(payload: Dict) -> str:
    """Call x.ai or OpenAI and return a markdown summary.

    Uses environment-only configuration. Secret values are never written to
    the repository and are expected to live in local environment variables or
    a local .env file.
    """
    try:
        import openai
    except Exception:
        openai = None

    try:
        import requests
    except Exception:
        requests = None

    system_prompt = (
        "You are a concise technical assistant. Produce a markdown report with exactly these four headers in this order:\n"
        "## Attack Surface Summary\n"
        "## Technologies Identified\n"
        "## Findings\n"
        "## Risk Assessment\n"
        "\n"
        "Grounding rule: Only summarize data present in the JSON payload. Do not infer, speculate about, or invent vulnerabilities, exploitability, or risk beyond what is explicitly stated.\n"
        "If `active_scan_run` is false: in the Findings section explicitly state that active scanning was not performed and no vulnerability data is available. Do not guess at risk in this case.\n"
        "Stay under ~400 words. Audience: technical security stakeholder, plain language. Use only severity language present in the data."
    )

    # Build user content from payload -> include the payload as JSON
    user_content = "```json\n" + (json.dumps(payload, indent=2)) + "\n```"

    # Prefer x.ai if configured
    xai_key = os.environ.get("XAI_API_KEY") or os.environ.get("GROK_API_KEY")
    xai_url = os.environ.get("XAI_API_URL") or os.environ.get("GROK_API_URL") or "https://api.x.ai/v1/responses"
    if xai_key:
        if requests is None:
            raise RuntimeError("requests package not installed; required for x.ai support")
        headers = {"Authorization": f"Bearer {xai_key}", "Content-Type": "application/json"}
        body = {
            "model": os.environ.get("XAI_MODEL", "grok-4.5"),
            "input": system_prompt + "\n\n" + user_content,
            "temperature": 0.3,
            "max_tokens": 800,
        }
        resp = requests.post(xai_url, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        text = _extract_xai_text(data)
        if not text:
            # fallback to raw body so we never lose data
            text = json.dumps(data)
        return str(text).strip()

    # Otherwise fall back to OpenAI if available
    api_key = os.environ.get("OPENAI_API_KEY")
    if openai and api_key:
        openai.api_key = api_key
        # Build ChatCompletion request
        resp = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            temperature=0.3,
            max_tokens=800,
        )
        choices = resp.get("choices") or []
        if not choices:
            raise RuntimeError("No choices returned from OpenAI")
        text = choices[0]["message"]["content"]
        return text.strip()

    raise RuntimeError("No LLM configured: set XAI_API_KEY (optionally XAI_API_URL) or OPENAI_API_KEY in environment")


def _extract_xai_text(data: Dict) -> str:
    """Extract text from x.ai Responses API variants.

    Tries common shapes first, then recursively searches for obvious text
    payloads inside nested output structures.
    """
    candidates = [
        data.get("output_text"),
        data.get("text"),
        data.get("output"),
        data.get("response"),
    ]
    for c in candidates:
        if isinstance(c, str) and c.strip():
            return c.strip()

    # Responses API commonly returns a nested output list.
    output = data.get("output")
    if isinstance(output, list):
        for item in output:
            if not isinstance(item, dict):
                continue
            # Common patterns: {content:[{type:'output_text', text:'...'}]}
            content = item.get("content") or []
            if isinstance(content, list):
                for part in content:
                    if isinstance(part, dict):
                        text = part.get("text") or part.get("output_text")
                        if isinstance(text, str) and text.strip():
                            return text.strip()
            # Sometimes a direct 'text' or nested 'message'
            direct = item.get("text")
            if isinstance(direct, str) and direct.strip():
                return direct.strip()
            message = item.get("message") or {}
            if isinstance(message, dict):
                msg_text = message.get("content")
                if isinstance(msg_text, str) and msg_text.strip():
                    return msg_text.strip()
                if isinstance(msg_text, list):
                    for part in msg_text:
                        if isinstance(part, dict):
                            t = part.get("text")
                            if isinstance(t, str) and t.strip():
                                return t.strip()
    return ""


def write_summary(markdown: str, output_dir: str) -> None:
    """Write `summary.md` to the given output directory.

    Simple helper used by fallback logic.
    """
    import os

    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "summary.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(markdown)
