"""AI summarization module (stubs).

Implements prompt building, API call, and fallback write.
"""
from __future__ import annotations

from typing import Dict


def build_payload(aggregated: Dict) -> Dict:
    """Validate/prepare payload for LLM.

    Currently a thin passthrough.
    """
    return dict(aggregated)


def generate_summary(payload: Dict) -> str:
    """Call OpenAI API and return markdown summary.

    Implements the system prompt rules from the spec exactly and returns
    the markdown string. On API failure an exception is raised by the caller.
    """
    import os
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

    # Prefer GROK if configured
    grok_key = os.environ.get("GROK_API_KEY")
    grok_url = os.environ.get("GROK_API_URL")
    if grok_key and grok_url:
        if requests is None:
            raise RuntimeError("requests package not installed; required for GROK support")
        headers = {"Authorization": f"Bearer {grok_key}", "Content-Type": "application/json"}
        body = {
            "prompt": system_prompt + "\n\n" + user_content,
            "temperature": 0.3,
            "max_tokens": 800,
        }
        resp = requests.post(grok_url, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        # Try common response fields for text
        text = data.get("text") or data.get("output") or None
        if not text:
            choices = data.get("choices") or []
            if choices and isinstance(choices, list) and isinstance(choices[0], dict):
                text = choices[0].get("text") or choices[0].get("message", {}).get("content")
        if not text:
            # fallback to raw body
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

    raise RuntimeError("No LLM configured: set GROK_API_KEY+GROK_API_URL or OPENAI_API_KEY in environment")


def write_summary(markdown: str, output_dir: str) -> None:
    """Write `summary.md` to the given output directory.

    Simple helper used by fallback logic.
    """
    import os

    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "summary.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(markdown)
