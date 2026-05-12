"""Utility MCP tools: file reading and PoC saving."""

from __future__ import annotations

import glob
import json
from typing import List

from mcp.server.fastmcp import FastMCP

from PoCGen.mcp_tools.state import _truncate


def register_utility_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    async def pocgen_read_code(paths: List[str]) -> str:
        """Read source code files by path or glob pattern.

        Expands glob patterns (e.g. "./src/*.c", "**/vuln_func/*.c") and
        returns the content of each matched file. Useful for reading
        vulnerability-related source code before analysis.

        Args:
            paths: List of file paths or glob patterns to read
        """
        import anyio

        def _sync() -> list:
            results = []
            seen = set()
            for pattern in paths:
                matched = glob.glob(pattern, recursive=True)
                if not matched:
                    matched = [pattern]
                for fp in matched:
                    if fp in seen:
                        continue
                    seen.add(fp)
                    try:
                        with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        results.append({"path": fp, "content": content})
                    except Exception as e:
                        results.append({"path": fp, "error": str(e)})
            return results

        results = await anyio.to_thread.run_sync(_sync)
        return _truncate(json.dumps(results, ensure_ascii=False, indent=2))

    @mcp.tool()
    async def pocgen_save_poc(raw_text: str, format: str = "http") -> str:
        """Save a PoC request to disk with automatic normalization.

        For format="http": saves raw HTTP request text to output/poc/ with
        automatic Content-Length adjustment and timestamp naming.

        For format="socket": saves Socket.IO event JSON to output/socket/
        with path/cookie normalization and timestamp naming.

        Args:
            raw_text: Raw HTTP request text or Socket.IO event JSON string
            format: "http" or "socket" (default "http")
        """
        import anyio
        from PoCGen.config.config import SETTINGS

        def _sync() -> dict:
            if format == "socket":
                from PoCGen.core.command_injection.socket.postprocess import (
                    save_socket_messages,
                )
                saved = save_socket_messages([raw_text], SETTINGS.socket_save_dir)
            else:
                from PoCGen.core.command_injection.http.postprocess import (
                    save_messages,
                )
                saved = save_messages([raw_text], SETTINGS.save_dir)

            path = saved[0] if saved else None
            return {
                "saved_path": path,
                "format": format,
            }

        result = await anyio.to_thread.run_sync(_sync)
        return json.dumps(result, ensure_ascii=False, indent=2)
