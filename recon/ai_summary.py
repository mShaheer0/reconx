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

    Not implemented in Phase 1.
    """
    raise NotImplementedError("generate_summary not implemented yet")


def write_summary(markdown: str, output_dir: str) -> None:
    """Write `summary.md` to the given output directory.

    Simple helper used by fallback logic.
    """
    import os

    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, "summary.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(markdown)
