"""Active scanning wrappers (stubs).

Only invoked when --active is confirmed by the user.
"""
from __future__ import annotations

from typing import List, Dict


def run_nuclei(live_hosts: List[str], output_dir: str, timeout: int) -> List[Dict]:
    """Run Nuclei and return list of findings.

    Placeholder for subprocess invocation.
    """
    raise NotImplementedError("run_nuclei not implemented yet")
