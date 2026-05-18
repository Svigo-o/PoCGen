from __future__ import annotations

from typing import List, Optional

from rich.console import Console

from PoCGen.llm.client import ChatMessage
from PoCGen.prompts.templates import build_prompt_cross_site_scripting_http
from PoCGen.core.xss_detector import XSSDetector
from PoCGen.core.models import HTTPMessage, ValidationResult
from PoCGen.core.shared.http_handler import HTTPHandlerBase, GenerationContext

console = Console()


class CrossSiteScriptingHTTPHandler(HTTPHandlerBase):
    name = "cross_site_scripting_http"

    @property
    def file_prefix(self) -> str:
        return "xss_poc"

    def build_prompt(self, description, code_texts, target,
                     target_profile=None, validation_feedback=None, **kwargs):
        return build_prompt_cross_site_scripting_http(
            description=description,
            code_files=code_texts,
            target=target,
            attacker_url=kwargs.get("attacker_url", ""),
            target_profile=target_profile,
            validation_feedback=validation_feedback,
        )

    def detect_success(self, validation_results, requests, ctx):
        xss_detector: Optional[XSSDetector] = getattr(ctx, "_xss_detector", None)
        if not validation_results or not xss_detector:
            return False, None
        for res in validation_results:
            if res.success and res.status_code in [200, 201, 202, 302]:
                console.print(f"[cyan]Checking for XSS in response of request #{res.request_index}...[/cyan]")
                xss_found, summary = xss_detector.detect_xss(
                    res.url or ctx.target or "", res.response_body or ""
                )
                if xss_found:
                    return True, summary
        return False, None

    def build_feedback(self, parse_issues, validation_results, validation_error=None, **kwargs):
        messages: List[str] = []
        if parse_issues:
            bullet = "\n".join(f"- {issue}" for issue in parse_issues)
            messages.append("Local HTTP parsing/validation issues detected:\n" + bullet)

        validation_summaries: List[str] = []
        if validation_results is not None:
            for res in validation_results:
                status = f"HTTP {res.status_code}" if res.status_code is not None else "no status"
                url = res.url or "<no url>"
                preview = (res.response_preview or "").strip()
                if preview:
                    preview = preview[:200] + ("..." if len(preview) > 200 else "")
                detail_parts: List[str] = []
                if res.error:
                    detail_parts.append(res.error)
                if preview:
                    detail_parts.append(f"body: {preview}")
                detail = "; ".join(detail_parts)
                if res.success:
                    line = f"Request #{res.request_index}: success -> {status} ({url})"
                else:
                    line = f"Request #{res.request_index}: failure -> {status} ({url})"
                    if not detail:
                        detail = "no response"
                if detail:
                    line += f"; {detail}"
                validation_summaries.append(line)

            if validation_summaries:
                messages.append("Target validation summary:\n" + "\n".join(f"- {item}" for item in validation_summaries))
        elif validation_error:
            messages.append(f"Target validation did not run due to error: {validation_error}")
        else:
            messages.append("Target validation did not run or returned no results.")

        messages.append(
            "No XSS alert detected. Adjust along the following tracks before the next attempt:\n"
            "1) Payload Construction: Use classic XSS payloads like `<svg/onload=alert()>`, `<img src=x onerror=alert()>`, or `<script>alert()</script>`.\n"
            "2) Context Awareness: If payload appears in response but doesn't execute, check if it's properly placed in HTML context (not inside attributes or JavaScript strings).\n"
            "3) Encoding: Try different encodings (HTML entities, URL encoding) to bypass filters.\n"
            "4) Event Handlers: Try different event handlers: onload, onerror, onmouseover, onclick.\n"
            "5) Tag Variation: Use different HTML tags: svg, img, div, a, iframe.\n"
            "6) Sanitization Bypass: If payload is filtered, try techniques like `<scr<script>ipt>alert()</scr<script>ipt>`."
        )
        return "\n\n".join(messages) if messages else None

    def on_before_loop(self, ctx):
        if ctx.auto_validate and ctx.target:
            detector = XSSDetector()
            ctx._xss_detector = detector
            console.print("[cyan]XSS detection mode: will look for alert dialogs in browser[/cyan]")
            return detector
        ctx._xss_detector = None
        return None

    def on_cleanup(self, resource):
        if resource:
            resource.close()


# Legacy wrapper
def generate_cross_site_scripting_http(**kwargs) -> "GenerationResult":
    handler = CrossSiteScriptingHTTPHandler()
    return handler.generate(**kwargs)
