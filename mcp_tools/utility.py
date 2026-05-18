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
                from PoCGen.core.shared.socket_postprocess import (
                    save_socket_messages,
                )
                saved = save_socket_messages([raw_text], SETTINGS.socket_save_dir)
            else:
                from PoCGen.core.shared.http_postprocess import (
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


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="PoC 工具：源码读取与 PoC 保存")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # read-code
    p = sub.add_parser("read-code", help="读取源码文件（支持 glob）")
    p.add_argument("paths", nargs="+", help="文件路径或 glob 模式")
    p.add_argument("--max-chars", type=int, default=50000, help="最大输出字符数")

    # save-poc
    p = sub.add_parser("save-poc", help="保存 PoC 到磁盘")
    p.add_argument("--raw", help="原始 HTTP 请求文本或 Socket.IO JSON")
    p.add_argument("--file", help="从文件读取")
    p.add_argument("--format", default="http", choices=["http", "socket"], help="格式")

    args = parser.parse_args()

    if args.cmd == "read-code":
        import glob as glob_mod
        results = []
        seen = set()
        for pattern in args.paths:
            matched = glob_mod.glob(pattern, recursive=True)
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

        total_chars = sum(len(r.get("content", "")) for r in results)
        for r in results:
            if "error" in r:
                print(f"[ERROR] {r['path']}: {r['error']}")
            else:
                print(f"--- {r['path']} ({len(r['content'])} chars) ---")
                print(r["content"])
        print(f"\nTotal: {len(results)} files, {total_chars} chars")

    elif args.cmd == "save-poc":
        raw = args.raw
        if not raw and args.file:
            with open(args.file, "r", encoding="utf-8") as f:
                raw = f.read()
        if not raw:
            print("Error: --raw or --file required", file=sys.stderr)
            exit(1)

        from PoCGen.config.config import SETTINGS
        if args.format == "socket":
            from PoCGen.core.shared.socket_postprocess import save_socket_messages
            saved = save_socket_messages([raw], SETTINGS.socket_save_dir)
        else:
            from PoCGen.core.shared.http_postprocess import save_messages
            saved = save_messages([raw], SETTINGS.save_dir)

        if saved:
            print(f"Saved: {saved[0]}")
        else:
            print("Failed to save", file=sys.stderr)
            exit(1)
