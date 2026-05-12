"""PoCGen MCP Tools — register all tools onto a FastMCP instance."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from PoCGen.mcp_tools.state import session_cache
from PoCGen.mcp_tools.intelligence import register_intelligence_tools
from PoCGen.mcp_tools.validation import register_validation_tools
from PoCGen.mcp_tools.monitor import register_monitor_tools
from PoCGen.mcp_tools.utility import register_utility_tools
from PoCGen.mcp_tools.device_profile import register_device_profile_tools


def register_all(mcp: FastMCP) -> None:
    register_intelligence_tools(mcp)
    register_validation_tools(mcp)
    register_monitor_tools(mcp)
    register_utility_tools(mcp)
    register_device_profile_tools(mcp)
