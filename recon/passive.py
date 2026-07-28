"""Passive reconnaissance wrappers (stubs).

Functions are placeholders and will be implemented in Phase 2.
"""
from __future__ import annotations

from typing import List, Dict


def run_subfinder(domain: str, output_dir: str, timeout: int) -> List[str]:
    """Run subfinder and return list of discovered subdomains.

    Placeholder for subprocess invocation.
    """
    raise NotImplementedError("run_subfinder not implemented yet")


def run_httpx(subdomains: List[str], output_dir: str, timeout: int) -> List[Dict]:
    """Run httpx against subdomains and return parsed results.

    Placeholder for subprocess invocation.
    """
    raise NotImplementedError("run_httpx not implemented yet")
