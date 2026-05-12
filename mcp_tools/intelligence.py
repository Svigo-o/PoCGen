"""Intelligence collection tools: CVE, code reading, target sampling."""

from __future__ import annotations

import json
from typing import Optional

from mcp.server.fastmcp import FastMCP

from PoCGen.mcp_tools.state import session_cache, _truncate


def register_intelligence_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    async def pocgen_cve_intelligence(
        cve_id: str,
        force: bool = False,
    ) -> str:
        """Collect CVE vulnerability intelligence from NVD mirror and reference links.

        Crawls fkie-cad NVD mirror, follows reference links (prioritising Exploit-tagged),
        and consolidates results via LLM into structured {info, reason, webpoc}.

        Args:
            cve_id: CVE identifier, e.g. "CVE-2025-9149"
            force: Force re-crawl even if cached result exists
        """
        import anyio
        from PoCGen.tools.getWeb import get_web_infomation

        def _sync() -> dict:
            result = get_web_infomation(cve_id, force=force)
            if result is None:
                return {"error": f"Failed to fetch CVE data for {cve_id}"}
            ref_key = f"cve:{cve_id.upper()}"
            session_cache.set_cve(ref_key, result)
            return {
                "cve_id": cve_id.upper(),
                "info": result.get("info", ""),
                "reason": result.get("reason", ""),
                "webpoc": result.get("webpoc", ""),
                "ref_key": ref_key,
            }

        result = await anyio.to_thread.run_sync(_sync)
        return _truncate(json.dumps(result, ensure_ascii=False, indent=2))

    @mcp.tool()
    async def pocgen_sample_target(
        target: str,
        login_url: Optional[str] = None,
        login_username: Optional[str] = None,
        login_password: Optional[str] = None,
        login_user_field: str = "username",
        login_pass_field: str = "password",
        headless: bool = True,
        capture_posts: bool = True,
        capture_cookies: bool = True,
        capture_socket_messages: bool = True,
    ) -> str:
        """Sample a target using Playwright browser — optionally log in and capture POST/Cookie/Socket.IO frames.

        Args:
            target: Target base URL (e.g. "http://192.168.6.2")
            login_url: Login page URL (defaults to target + /login)
            login_username: Username for browser login
            login_password: Password for browser login
            login_user_field: Form field name for username
            login_pass_field: Form field name for password
            headless: Run browser in headless mode
            capture_posts: Capture POST request samples
            capture_cookies: Capture cookies after login
            capture_socket_messages: Capture Socket.IO frames
        """
        import anyio
        from PoCGen.core.sampler import sample_target_with_playwright

        def _sync() -> dict:
            sample = sample_target_with_playwright(
                target=target,
                login_url=login_url,
                login_username=login_username,
                login_password=login_password,
                login_user_field=login_user_field,
                login_pass_field=login_pass_field,
                headless=headless,
                capture_posts=capture_posts,
                capture_cookies=capture_cookies,
                capture_socket_messages=capture_socket_messages,
            )
            ref_key = f"sample:{target}"
            session_cache.set_sample(ref_key, sample)
            return {
                "url": sample.url,
                "status_code": sample.status_code,
                "content_type": sample.content_type,
                "body_preview": _truncate(sample.body_preview, 5000),
                "response_headers": sample.response_headers,
                "post_samples_count": len(sample.post_samples) if sample.post_samples else 0,
                "cookies_header": sample.cookies_header,
                "socket_samples_count": len(sample.socket_samples) if sample.socket_samples else 0,
                "ref_key": ref_key,
                "prompt_block": sample.as_prompt_block() if hasattr(sample, "as_prompt_block") else "",
            }

        result = await anyio.to_thread.run_sync(_sync)
        return _truncate(json.dumps(result, ensure_ascii=False, indent=2))
