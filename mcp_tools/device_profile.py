"""Device profile MCP tools."""

from __future__ import annotations

import json
from typing import List, Optional

from mcp.server.fastmcp import FastMCP

from PoCGen.mcp_tools.state import _truncate


def register_device_profile_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    async def pocgen_save_device_profile(
        device_name: str,
        ip: str,
        web_server: str = "",
        request_format: str = "",
        cgi_paths: List[str] = [],
        injection_method: str = "",
        injection_delimiter: str = "`",
        requires_referer: bool = False,
        requires_cookie: bool = False,
        cookie_header: str = "",
        notes: str = "",
    ) -> str:
        """Save a device profile for future reuse.

        Stores device-specific knowledge (CGI paths, request format, injection method)
        so that validated patterns can be reused across same-model devices.

        Args:
            device_name: Device model name (e.g. "TotolinkA3300R")
            ip: Device IP address
            web_server: Web server software (e.g. "shttpd", "lighttpd")
            request_format: "json" or "form-urlencoded"
            cgi_paths: List of CGI endpoint paths
            injection_method: How injection reaches shell (e.g. "Uci_Set_Str", "sprintf+system")
            injection_delimiter: Preferred delimiter ("`", "$()", ";", "&&")
            requires_referer: Whether Referer header is required
            requires_cookie: Whether Cookie header is required
            cookie_header: Cookie header value if needed
            notes: Additional notes about the device
        """
        import anyio
        from PoCGen.core.device_profile import DeviceProfile, save_profile

        def _sync() -> dict:
            profile = DeviceProfile(
                device_name=device_name,
                ip=ip,
                web_server=web_server,
                request_format=request_format,
                cgi_paths=cgi_paths,
                injection_method=injection_method,
                injection_delimiter=injection_delimiter,
                requires_referer=requires_referer,
                requires_cookie=requires_cookie,
                cookie_header=cookie_header,
                notes=notes,
            )
            path = save_profile(profile)
            return {"saved_path": path, "device_name": device_name}

        result = await anyio.to_thread.run_sync(_sync)
        return json.dumps(result, ensure_ascii=False, indent=2)

    @mcp.tool()
    async def pocgen_load_device_profile(
        device_name: str,
    ) -> str:
        """Load a saved device profile by name.

        Args:
            device_name: Device model name (e.g. "TotolinkA3300R")
        """
        import anyio
        from PoCGen.core.device_profile import load_profile

        def _sync() -> dict:
            profile = load_profile(device_name)
            if profile is None:
                return {"found": False, "device_name": device_name}
            return {"found": True, "profile": profile.as_prompt_block()}

        result = await anyio.to_thread.run_sync(_sync)
        return _truncate(json.dumps(result, ensure_ascii=False, indent=2))

    @mcp.tool()
    async def pocgen_list_device_profiles() -> str:
        """List all saved device profiles."""
        import anyio
        from PoCGen.core.device_profile import list_profiles

        def _sync() -> dict:
            return {"profiles": list_profiles()}

        result = await anyio.to_thread.run_sync(_sync)
        return json.dumps(result, ensure_ascii=False, indent=2)
