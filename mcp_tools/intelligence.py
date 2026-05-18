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
        from PoCGen.core.cve_crawler import get_web_infomation

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
        """Sample a target using CDP browser — optionally log in and capture POST/Cookie/Socket.IO frames.

        Args:
            target: Target base URL (e.g. "http://192.168.6.2")
            login_url: Login page URL (defaults to target + /login)
            login_username: Username for browser login
            login_password: Password for browser login
            login_user_field: Form field name for username
            login_pass_field: Form field name for password
            headless: Run Chrome in headless mode
            capture_posts: Capture POST request samples
            capture_cookies: Capture cookies after login
            capture_socket_messages: Capture Socket.IO frames
        """
        import anyio
        from PoCGen.core.cdp_sampler import sample_target

        def _sync() -> dict:
            sample = sample_target(
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


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="情报收集工具：CVE 爬取 + 目标探测")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # cve
    p = sub.add_parser("cve", help="爬取 CVE 情报")
    p.add_argument("cve_id", help="CVE 编号")
    p.add_argument("--force", action="store_true", help="强制重新爬取")

    # sample
    p = sub.add_parser("sample", help="CDP 浏览器探测目标")
    p.add_argument("target", help="目标 URL")
    p.add_argument("--login-url", default=None)
    p.add_argument("--login-username", default=None)
    p.add_argument("--login-password", default=None)
    p.add_argument("--no-headless", action="store_true", help="显示浏览器窗口")
    p.add_argument("--socket", action="store_true", help="采集 Socket.IO")

    args = parser.parse_args()

    if args.cmd == "cve":
        from PoCGen.core.cve_crawler import get_web_infomation
        result = get_web_infomation(args.cve_id, force=args.force)
        if result:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print("Failed")
            exit(1)

    elif args.cmd == "sample":
        from PoCGen.core.cdp_sampler import sample_target
        sample = sample_target(
            target=args.target,
            login_url=args.login_url,
            login_username=args.login_username,
            login_password=args.login_password,
            headless=not args.no_headless,
            capture_socket_messages=args.socket,
        )
        print(f"URL: {sample.url}")
        print(f"Status: {sample.status_code}")
        print(f"Posts: {len(sample.post_samples)}")
        print(f"Cookie: {'yes' if sample.cookies_header else 'no'}")
        print(f"Body: {sample.body_preview[:300]}")
