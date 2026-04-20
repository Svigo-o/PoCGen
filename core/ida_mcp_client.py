"""
IDA MCP Client - communicates with idalib-mcp server via Streamable HTTP.

Provides a thin wrapper that sends JSON-RPC tool_call requests to the
IDA MCP endpoint (default http://127.0.0.1:8745/mcp) and returns
parsed results.  All interactions are logged to logs/idamcp/.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

_LOG_DIR = Path(__file__).resolve().parent.parent / "logs" / "idamcp"
_LOG_DIR.mkdir(parents=True, exist_ok=True)

_current_log_file: Optional[Path] = None


def _get_log_file() -> Path:
    global _current_log_file
    if _current_log_file is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        _current_log_file = _LOG_DIR / f"idamcp_{ts}.log"
    return _current_log_file


def _log(message: str) -> None:
    try:
        tz = timezone(timedelta(hours=8))
        ts = datetime.now(tz).strftime("%Y-%m-%d %H:%M:%S")
        with open(_get_log_file(), "a", encoding="utf-8") as fh:
            fh.write(f"[{ts}] {message}\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# MCP JSON-RPC helpers
# ---------------------------------------------------------------------------

_MCP_PROTOCOL_VERSION = "2025-06-18"


class IDAMCPClient:
    """Synchronous client for the IDA MCP Streamable HTTP endpoint."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8745/mcp",
        timeout: float = 120.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._session_id: Optional[str] = None
        self._client = httpx.Client(timeout=timeout)
        _log(f"IDA MCP client initialised, endpoint={self.base_url}")

    # -- low-level ----------------------------------------------------------

    def _call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Send a JSON-RPC request and return the parsed *result* field."""
        request_id = uuid.uuid4().hex[:8]
        payload: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params is not None:
            payload["params"] = params

        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        _log(f"--> {method} params={json.dumps(params, ensure_ascii=False)[:500]}")

        try:
            resp = self._client.post(self.base_url, json=payload, headers=headers)
        except httpx.ConnectError as exc:
            _log(f"<-- CONNECT ERROR: {exc}")
            raise RuntimeError(f"Cannot connect to IDA MCP at {self.base_url}: {exc}") from exc

        # Capture session id from response headers
        sid = resp.headers.get("mcp-session-id")
        if sid:
            self._session_id = sid

        # The MCP spec allows the server to return either a direct JSON
        # response or an SSE stream that eventually delivers the result.
        content_type = resp.headers.get("content-type", "")

        if "text/event-stream" in content_type:
            result = self._parse_sse_response(resp.text)
        else:
            body = resp.json()
            if "error" in body:
                err = body["error"]
                _log(f"<-- ERROR: {err}")
                raise RuntimeError(f"MCP error: {err}")
            result = body.get("result")

        _log(f"<-- result preview: {json.dumps(result, ensure_ascii=False)[:500] if result else 'None'}")
        return result

    def _parse_sse_response(self, text: str) -> Any:
        """Parse an SSE text stream and extract the JSON-RPC result."""
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            data_str = line[len("data:"):].strip()
            if not data_str:
                continue
            try:
                msg = json.loads(data_str)
            except json.JSONDecodeError:
                continue
            if "error" in msg:
                _log(f"<-- SSE ERROR: {msg['error']}")
                raise RuntimeError(f"MCP error: {msg['error']}")
            if "result" in msg:
                return msg["result"]
        return None

    # -- initialise ---------------------------------------------------------

    def initialize(self) -> Dict[str, Any]:
        """Send MCP initialise handshake."""
        result = self._call("initialize", {
            "protocolVersion": _MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "PoCGen", "version": "1.0.0"},
        })
        # Send initialised notification (no id, fire-and-forget)
        try:
            headers: Dict[str, str] = {"Content-Type": "application/json"}
            if self._session_id:
                headers["Mcp-Session-Id"] = self._session_id
            self._client.post(
                self.base_url,
                json={"jsonrpc": "2.0", "method": "notifications/initialized"},
                headers=headers,
            )
        except Exception:
            pass
        _log("MCP session initialised")
        return result

    # -- tool calls ---------------------------------------------------------

    def call_tool(self, name: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        """Call an MCP tool by name and return the structured content."""
        params: Dict[str, Any] = {"name": name}
        if arguments:
            params["arguments"] = arguments
        result = self._call("tools/call", params)
        # result.content is a list of content items; extract text
        if isinstance(result, dict):
            content = result.get("content") or []
            structured = result.get("structuredContent")
            if structured:
                return structured
            # Fall back to text content
            texts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    texts.append(item.get("text", ""))
            if texts:
                joined = "\n".join(texts)
                try:
                    return json.loads(joined)
                except json.JSONDecodeError:
                    return joined
        return result

    # -- convenience wrappers for common IDA MCP operations -----------------

    def idalib_open(self, binary_path: str, run_auto_analysis: bool = True) -> Any:
        """Open a binary file in idalib headless mode."""
        _log(f"Opening binary: {binary_path}")
        return self.call_tool("idalib_open", {
            "input_path": binary_path,
            "run_auto_analysis": run_auto_analysis,
        })

    def idalib_health(self) -> Any:
        return self.call_tool("idalib_health")

    def idalib_warmup(self, wait_auto_analysis: bool = True) -> Any:
        return self.call_tool("idalib_warmup", {
            "wait_auto_analysis": wait_auto_analysis,
            "build_caches": True,
            "init_hexrays": True,
        })

    def survey_binary(self, detail_level: str = "standard") -> Any:
        return self.call_tool("survey_binary", {"detail_level": detail_level})

    def decompile(self, addr: str) -> Any:
        return self.call_tool("decompile", {"addr": addr})

    def lookup_funcs(self, queries: List[str]) -> Any:
        return self.call_tool("lookup_funcs", {"queries": queries})

    def list_funcs(self, queries: Optional[List[str]] = None) -> Any:
        params: Dict[str, Any] = {}
        if queries:
            params["queries"] = queries
        return self.call_tool("list_funcs", params)

    def xrefs_to(self, addrs: List[str], limit: int = 50) -> Any:
        return self.call_tool("xrefs_to", {"addrs": addrs, "limit": limit})

    def callees(self, addrs: List[str], limit: int = 50) -> Any:
        return self.call_tool("callees", {"addrs": addrs, "limit": limit})

    def analyze_function(self, addr: str) -> Any:
        return self.call_tool("analyze_function", {"addr": addr})

    def analyze_batch(self, queries: List[str]) -> Any:
        return self.call_tool("analyze_batch", {"queries": queries})

    def find_regex(self, pattern: str, limit: int = 20) -> Any:
        return self.call_tool("find_regex", {"pattern": pattern, "limit": limit})

    def imports_query(self, queries: Optional[List[str]] = None) -> Any:
        params: Dict[str, Any] = {}
        if queries:
            params["queries"] = queries
        return self.call_tool("imports_query", params)

    def trace_data_flow(self, addr: str, direction: str = "forward", max_depth: int = 3) -> Any:
        return self.call_tool("trace_data_flow", {
            "addr": addr,
            "direction": direction,
            "max_depth": max_depth,
        })

    def callgraph(self, roots: List[str], max_depth: int = 2) -> Any:
        return self.call_tool("callgraph", {
            "roots": roots,
            "max_depth": max_depth,
            "max_nodes": 200,
            "max_edges": 500,
        })

    def idalib_close(self) -> Any:
        return self.call_tool("idalib_close")

    # -- lifecycle ----------------------------------------------------------

    def close(self) -> None:
        try:
            self._client.close()
        except Exception:
            pass
        _log("IDA MCP client closed")
