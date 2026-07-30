"""Helpers for resolving ProjectDiscovery binaries.

The repo may live inside a Python virtual environment that also provides a
`httpx` module entrypoint. This helper makes sure we use the real ProjectDiscovery
scanner binaries instead of the Python package shims.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Optional


def _looks_like_projectdiscovery(binary_path: str) -> bool:
    try:
        out = subprocess.check_output([binary_path, "-version"], stderr=subprocess.STDOUT, text=True, timeout=5)
    except Exception:
        return False
    text = (out or "").lower()
    return "projectdiscovery.io" in text or "projectdiscovery" in text or "version: v" in text


def resolve_projectdiscovery_binary(tool_name: str, env_var: Optional[str] = None) -> str:
    """Return the absolute path to a ProjectDiscovery binary.

    Search order:
    1. Explicit env var override (if provided)
    2. `shutil.which()` on PATH
    3. Common Go install locations

    Raises RuntimeError if no suitable binary is found.
    """
    candidates = []

    if env_var:
        explicit = os.environ.get(env_var)
        if explicit:
            candidates.append(explicit)

    found = shutil.which(tool_name)
    if found:
        candidates.append(found)

    gopath = os.environ.get("GOPATH") or os.path.join(os.path.expanduser("~"), "go")
    candidates.extend([
        os.path.join(gopath, "bin", tool_name),
        f"/usr/local/bin/{tool_name}",
        f"/usr/bin/{tool_name}",
    ])

    seen = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        if not os.path.exists(candidate):
            continue
        if _looks_like_projectdiscovery(candidate):
            return candidate

    raise RuntimeError(
        f"Could not find a ProjectDiscovery {tool_name} binary. Set {env_var or tool_name.upper() + '_BIN'} to the correct path (for example, $(go env GOPATH)/bin/{tool_name})."
    )