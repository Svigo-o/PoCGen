"""Session state management for PoCGen MCP server."""

from __future__ import annotations

import atexit
from typing import Any, Dict, Optional


class SessionCache:
    """Simple in-memory cache for MCP tool results and long-lived resources."""

    def __init__(self) -> None:
        self._monitor: Any = None
        self._cve_results: Dict[str, Any] = {}
        self._target_samples: Dict[str, Any] = {}

    # -- Monitor -----------------------------------------------------------

    @property
    def monitor(self) -> Any:
        return self._monitor

    @monitor.setter
    def monitor(self, value: Any) -> None:
        self._monitor = value

    # -- CVE results -------------------------------------------------------

    def get_cve(self, ref_key: str) -> Optional[Any]:
        return self._cve_results.get(ref_key)

    def set_cve(self, ref_key: str, value: Any) -> None:
        self._cve_results[ref_key] = value

    # -- Target samples ----------------------------------------------------

    def get_sample(self, ref_key: str) -> Optional[Any]:
        return self._target_samples.get(ref_key)

    def set_sample(self, ref_key: str, value: Any) -> None:
        self._target_samples[ref_key] = value

    # -- Cleanup -----------------------------------------------------------

    def cleanup(self) -> None:
        if self._monitor:
            try:
                self._monitor.stop()
            except Exception:
                pass
            self._monitor = None


session_cache = SessionCache()


@atexit.register
def _atexit_cleanup() -> None:
    session_cache.cleanup()


def _truncate(text: str, limit: int = 50000) -> str:
    if len(text) > limit:
        return text[:limit] + f"\n... <truncated, {len(text)} total chars>"
    return text
