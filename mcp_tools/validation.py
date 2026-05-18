"""Parsing and validation tools for HTTP and Socket.IO PoCs."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP

from PoCGen.mcp_tools.state import _truncate


def register_validation_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    async def pocgen_parse_http(
        raw: str,
    ) -> str:
        """Parse a raw HTTP request string into a structured object.

        Args:
            raw: Raw HTTP request text (e.g. "POST /cgi-bin/ping.cgi HTTP/1.1\\nHost: ...")
        """
        import anyio
        from PoCGen.core.shared.http_validators import parse_and_validate, fix_content_length

        def _sync() -> dict:
            try:
                msg, errs = parse_and_validate(raw)
                fix_content_length(msg)
                return {
                    "parsed": {
                        "method": msg.method,
                        "path": msg.path,
                        "version": msg.version,
                        "headers": msg.headers,
                        "body": msg.body,
                    },
                    "errors": errs,
                }
            except Exception as exc:
                return {"parsed": None, "errors": [str(exc)]}

        result = await anyio.to_thread.run_sync(_sync)
        return _truncate(json.dumps(result, ensure_ascii=False, indent=2))

    @mcp.tool()
    async def pocgen_parse_socket(
        raw: str,
    ) -> str:
        """Parse a raw Socket.IO event JSON string into a structured object.

        Args:
            raw: Raw JSON socket event text (e.g. '{"url":"ws://...", "event":"message", ...}')
        """
        import anyio
        from PoCGen.core.shared.socket_validators import parse_and_validate

        def _sync() -> dict:
            try:
                msg, errs = parse_and_validate(raw)
                return {
                    "parsed": {
                        "url": msg.url,
                        "path": msg.path,
                        "event": msg.event,
                        "payload": msg.payload,
                        "namespace": msg.namespace,
                        "headers": msg.headers,
                        "cookies": msg.cookies,
                    },
                    "errors": errs,
                }
            except Exception as exc:
                return {"parsed": None, "errors": [str(exc)]}

        result = await anyio.to_thread.run_sync(_sync)
        return _truncate(json.dumps(result, ensure_ascii=False, indent=2))

    @mcp.tool()
    async def pocgen_validate_http(
        requests: List[Dict[str, Any]],
        target: str,
    ) -> str:
        """Validate parsed HTTP requests by replaying them against the target.

        Args:
            requests: List of parsed HTTP request objects, each with keys: method, path, version, headers, body
            target: Target base URL for resolving relative paths
        """
        import anyio
        from PoCGen.core.models import HTTPMessage
        from PoCGen.core.shared.http_remote_validator import validate_http_requests

        def _sync() -> dict:
            http_msgs = []
            for r in requests:
                http_msgs.append(HTTPMessage(
                    method=r.get("method", ""),
                    path=r.get("path", ""),
                    version=r.get("version", "HTTP/1.1"),
                    headers=r.get("headers", {}),
                    body=r.get("body", ""),
                ))
            try:
                results = validate_http_requests(http_msgs, target)
                return {
                    "results": [
                        {
                            "request_index": v.request_index,
                            "url": v.url,
                            "status_code": v.status_code,
                            "success": v.success,
                            "response_preview": _truncate(v.response_preview, 500) if v.response_preview else None,
                            "error": v.error,
                        }
                        for v in results
                    ]
                }
            except Exception as exc:
                return {"results": [], "error": str(exc)}

        result = await anyio.to_thread.run_sync(_sync)
        return _truncate(json.dumps(result, ensure_ascii=False, indent=2))

    @mcp.tool()
    async def pocgen_validate_socket(
        events: List[Dict[str, Any]],
        target: Optional[str] = None,
    ) -> str:
        """Validate parsed Socket.IO events by dispatching them to the target.

        Args:
            events: List of parsed socket event objects, each with keys: url, path, event, payload, namespace, headers, cookies
            target: Optional target URL for resolving relative ws/wss URLs
        """
        import anyio
        from PoCGen.core.models import SocketEventMessage
        from PoCGen.core.shared.socket_remote_validator import validate_socket_events

        def _sync() -> dict:
            socket_msgs = []
            for e in events:
                socket_msgs.append(SocketEventMessage(
                    url=e.get("url", ""),
                    path=e.get("path"),
                    event=e.get("event"),
                    payload=e.get("payload"),
                    namespace=e.get("namespace"),
                    headers=e.get("headers", {}),
                    cookies=e.get("cookies"),
                    raw_frame=e.get("raw_frame"),
                    wait_for_response=e.get("wait_for_response", True),
                    max_response_frames=e.get("max_response_frames", 1),
                ))
            try:
                results = validate_socket_events(socket_msgs, target)
                return {
                    "results": [
                        {
                            "request_index": v.request_index,
                            "url": v.url,
                            "status_code": v.status_code,
                            "success": v.success,
                            "response_preview": _truncate(v.response_preview, 500) if v.response_preview else None,
                            "error": v.error,
                        }
                        for v in results
                    ]
                }
            except Exception as exc:
                return {"results": [], "error": str(exc)}

        result = await anyio.to_thread.run_sync(_sync)
        return _truncate(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="HTTP/Socket.IO PoC 解析与验证工具")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # parse-http
    p = sub.add_parser("parse-http", help="解析原始 HTTP 请求")
    p.add_argument("--raw", help="原始 HTTP 请求文本")
    p.add_argument("--file", help="从文件读取原始 HTTP 请求")

    # parse-socket
    p = sub.add_parser("parse-socket", help="解析 Socket.IO 事件 JSON")
    p.add_argument("--raw", help="原始 Socket.IO JSON 文本")
    p.add_argument("--file", help="从文件读取")

    # validate-http
    p = sub.add_parser("validate-http", help="重放 HTTP 请求到目标验证")
    p.add_argument("--file", required=True, help="包含原始 HTTP 请求的文件")
    p.add_argument("--target", required=True, help="目标 base URL")

    # validate-socket
    p = sub.add_parser("validate-socket", help="分发 Socket.IO 事件到目标验证")
    p.add_argument("--file", required=True, help="包含 Socket.IO JSON 的文件")
    p.add_argument("--target", help="目标 URL（用于解析相对 ws/wss 地址）")

    args = parser.parse_args()

    if args.cmd == "parse-http":
        raw = args.raw
        if not raw and args.file:
            with open(args.file, "r", encoding="utf-8") as f:
                raw = f.read()
        if not raw:
            print("Error: --raw or --file required", file=sys.stderr)
            exit(1)
        from PoCGen.core.shared.http_validators import parse_and_validate, fix_content_length
        msg, errs = parse_and_validate(raw)
        fix_content_length(msg)
        result = {"parsed": {"method": msg.method, "path": msg.path, "version": msg.version, "headers": msg.headers, "body": msg.body}, "errors": errs}
        print(json.dumps(result, ensure_ascii=False, indent=2))

    elif args.cmd == "parse-socket":
        raw = args.raw
        if not raw and args.file:
            with open(args.file, "r", encoding="utf-8") as f:
                raw = f.read()
        if not raw:
            print("Error: --raw or --file required", file=sys.stderr)
            exit(1)
        from PoCGen.core.shared.socket_validators import parse_and_validate as socket_parse
        msg, errs = socket_parse(raw)
        result = {"parsed": {"url": msg.url, "path": msg.path, "event": msg.event, "payload": msg.payload, "namespace": msg.namespace, "headers": msg.headers, "cookies": msg.cookies}, "errors": errs}
        print(json.dumps(result, ensure_ascii=False, indent=2))

    elif args.cmd == "validate-http":
        with open(args.file, "r", encoding="utf-8") as f:
            raw = f.read()
        from PoCGen.core.shared.http_validators import parse_and_validate, fix_content_length
        from PoCGen.core.shared.http_remote_validator import validate_http_requests
        msg, errs = parse_and_validate(raw)
        fix_content_length(msg)
        if errs:
            print(f"Parse warnings: {errs}", file=sys.stderr)
        results = validate_http_requests([msg], args.target)
        for r in results:
            status = f"HTTP {r.status_code}" if r.status_code else "no status"
            print(f"#{r.request_index}: {'OK' if r.success else 'FAIL'} {status} {r.url}")
            if r.response_preview:
                print(f"  Preview: {r.response_preview[:200]}")
            if r.error:
                print(f"  Error: {r.error}")

    elif args.cmd == "validate-socket":
        with open(args.file, "r", encoding="utf-8") as f:
            raw = f.read()
        from PoCGen.core.shared.socket_validators import parse_and_validate as socket_parse
        from PoCGen.core.shared.socket_remote_validator import validate_socket_events
        msg, errs = socket_parse(raw)
        if errs:
            print(f"Parse warnings: {errs}", file=sys.stderr)
        results = validate_socket_events([msg], args.target)
        for r in results:
            print(f"#{r.request_index}: {'OK' if r.success else 'FAIL'} {r.url}")
            if r.response_preview:
                print(f"  Preview: {r.response_preview[:200]}")
            if r.error:
                print(f"  Error: {r.error}")
