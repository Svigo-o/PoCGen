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
        from PoCGen.core.command_injection.http.validators import parse_and_validate, fix_content_length

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
        from PoCGen.core.command_injection.socket.validators import parse_and_validate

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
        from PoCGen.core.command_injection.http.remote_validator import validate_http_requests

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
        from PoCGen.core.command_injection.socket.remote_validator import validate_socket_events

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
