from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import time
from typing import List, Optional

from rich.console import Console

from PoCGen.config.config import SETTINGS
from PoCGen.llm.client import ChatMessage, LLMClient
from PoCGen.core.cdp_sampler import sample_target
from PoCGen.core.target_profile import TargetSample
from PoCGen.core.cve_crawler import get_web_infomation
from PoCGen.core.models import (
    AttemptResult,
    GenerationResult,
    HTTPMessage,
    ValidationResult,
    VulnHandler,
)
from .http_postprocess import save_messages, split_messages
from .http_validators import parse_and_validate
from .http_remote_validator import validate_http_requests

console = Console()


@dataclass
class GenerationContext:
    description: str
    code_texts: List[str]
    target: Optional[str]
    payload: Optional[str]
    cvenumber: Optional[str]
    auto_validate: bool
    max_iters: int
    stop_after_success: bool
    out_dir: str
    temperature: float
    max_tokens: int
    generation_start_ts: float
    chat_log_path: Path
    target_profile_block: Optional[str] = None
    sample_cookies_header: Optional[str] = None
    web_info_block: Optional[str] = None
    conversation_messages: List[ChatMessage] = field(default_factory=list)


class HTTPHandlerBase(VulnHandler):
    """HTTP 漏洞 PoC 生成的模板方法基类。

    子类必须覆盖:
        - file_prefix: PoC 文件名前缀
        - build_prompt(): 构建 prompt 消息
        - detect_success(): 判断验证结果是否成功
        - build_feedback(): 构建失败时的反馈

    子类可选覆盖:
        - on_before_loop(): 循环前的初始化
        - on_after_attempt(): 每次尝试后的清理
        - inject_cookies(): 自定义 cookie 注入逻辑
        - build_retry_messages(): 自定义重试消息构建
    """

    name = "base_http"

    # ── 子类必须覆盖 ──────────────────────────────────────────────

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
        raise NotImplementedError

    def detect_success(
        self,
        validation_results: Optional[List[ValidationResult]],
        requests: List[HTTPMessage],
        ctx: GenerationContext,
    ) -> tuple[bool, Optional[str]]:
        """返回 (success, summary)。"""
        raise NotImplementedError

    def build_feedback(
        self,
        parse_issues: List[str],
        validation_results: Optional[List[ValidationResult]],
        validation_error: Optional[str] = None,
        **kwargs,
    ) -> Optional[str]:
        raise NotImplementedError

    # ── 子类可选覆盖 ──────────────────────────────────────────────

    def on_before_loop(self, ctx: GenerationContext) -> Optional[object]:
        """循环前初始化，返回的资源会在 finally 中调用 on_cleanup()。"""
        return None

    def on_cleanup(self, resource: Optional[object]) -> None:
        """清理 on_before_loop 返回的资源。"""
        pass

    def on_after_attempt(
        self, ctx: GenerationContext, attempt_index: int, success: bool
    ) -> None:
        pass

    def inject_cookies(
        self, requests: List[HTTPMessage], cookies_header: str
    ) -> None:
        for req in requests:
            if "Cookie" not in req.headers:
                req.headers["Cookie"] = cookies_header

    def build_retry_messages(
        self,
        initial_messages: List[ChatMessage],
        last_raw_output: str,
        feedback_text: Optional[str],
        attempt_index: int,
    ) -> List[ChatMessage]:
        """默认实现：在对话历史中追加 feedback。"""
        messages = list(initial_messages)
        if feedback_text:
            messages.append(
                ChatMessage(role="user", content=f"Feedback from previous attempt:\n{feedback_text}")
            )
        return messages

    def build_messages(
        self,
        description: str,
        code_texts: List[str],
        target: Optional[str],
        payload: Optional[str] = None,
        target_profile: Optional[str] = None,
        validation_feedback: Optional[str] = None,
        vuln_analysis: Optional[str] = None,
        web_info: Optional[str] = None,
    ) -> List[dict]:
        msgs = self.build_prompt(
            description=description,
            code_texts=code_texts,
            target=target,
            target_profile=target_profile,
            validation_feedback=validation_feedback,
        )
        return [m.model_dump() for m in msgs]

    # ── 模板方法 ──────────────────────────────────────────────────

    def generate(
        self,
        description: str,
        code_texts: List[str],
        target: Optional[str] = None,
        vuln_type: Optional[str] = None,
        temperature: float = 0.2,
        max_tokens: int = 4000,
        payload: Optional[str] = None,
        attacker_url: Optional[str] = None,
        probe_target: bool = False,
        auto_validate: bool = False,
        max_iterations: Optional[int] = None,
        stop_on_success: Optional[bool] = None,
        monitor_timeout: Optional[float] = None,
        cvenumber: Optional[str] = None,
        login_url: Optional[str] = None,
        login_username: Optional[str] = None,
        login_password: Optional[str] = None,
        login_user_field: str = "username",
        login_pass_field: str = "password",
        use_browser_login: bool = False,
        browser_headless: Optional[bool] = None,
        **kwargs,
    ) -> GenerationResult:
        handler_key = vuln_type or self.name

        if cvenumber:
            get_web_infomation(cvenumber)

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
        )

        max_iters = max(1, max_iterations or SETTINGS.max_iterations)
        if not auto_validate:
            max_iters = 1
        stop_after_success = SETTINGS.stop_on_success if stop_on_success is None else stop_on_success
        out_dir = SETTINGS.save_dir

        ctx = GenerationContext(
            description=description,
            code_texts=code_texts,
            target=target,
            payload=payload,
            cvenumber=cvenumber,
            auto_validate=auto_validate,
            max_iters=max_iters,
            stop_after_success=stop_after_success,
            out_dir=out_dir,
            temperature=temperature or SETTINGS.temperature,
            max_tokens=max_tokens or SETTINGS.max_tokens,
            generation_start_ts=time.time(),
            chat_log_path=chat_log_path,
        )

        attempts: List[AttemptResult] = []
        feedback_text: Optional[str] = None
        overall_success = False
        last_raw_output = ""
        last_requests: List[HTTPMessage] = []
        last_saved_paths: List[str] = []
        last_validation_results: Optional[List[ValidationResult]] = None

        loop_resource = self.on_before_loop(ctx)

        try:
            # ── 目标探测 ──
            if probe_target and target:
                if use_browser_login:
                    try:
                        sample: TargetSample = sample_target(
                            target,
                            login_url=login_url,
                            login_username=login_username,
                            login_password=login_password,
                            login_user_field=login_user_field,
                            login_pass_field=login_pass_field,
                            headless=browser_headless or SETTINGS.browser_headless,
                            capture_posts=True,
                            capture_cookies=True,
                            capture_socket_messages=False,
                        )
                        ctx.target_profile_block = sample.as_prompt_block()
                        ctx.sample_cookies_header = sample.cookies_header
                    except Exception as exc:
                        console.print(f"[yellow]Warning: failed to probe target {target}: {exc}")
                else:
                    console.print("[yellow]probe_target currently requires --browser-login; skipping target sampling")

            # ── 构建初始消息 ──
            initial_messages: List[ChatMessage] = [ChatMessage(**m) for m in self.build_messages(
                description, code_texts, target, payload,
                ctx.target_profile_block, None,
            )]
            ctx.conversation_messages = list(initial_messages)

            # ── 迭代循环 ──
            for attempt_index in range(max_iters):
                console.print(f"\n[bold]Attempt {attempt_index + 1}/{max_iters}[/bold]")
                log_chat(f"Attempt {attempt_index + 1} starting")
                if feedback_text:
                    log_chat(f"Feedback provided to model:\n{feedback_text}")

                messages = self.build_retry_messages(
                    initial_messages, last_raw_output, feedback_text, attempt_index
                )

                log_chat(
                    "Model input messages:\n" +
                    "\n".join(f"- {m.role}: {m.content}" for m in messages)
                )

                client = LLMClient()
                try:
                    raw_output = client.chat(messages, temperature=ctx.temperature, max_tokens=ctx.max_tokens)
                finally:
                    client.close()

                ctx.conversation_messages.append(ChatMessage(role="assistant", content=raw_output))
                log_chat("Model output:\n" + raw_output)

                # ── 分割 + 保存 ──
                raw_messages = split_messages(raw_output)
                if not raw_messages and raw_output.strip():
                    raw_messages = [raw_output.strip()]

                if raw_messages:
                    saved_paths = save_messages(raw_messages, out_dir, prefix=self.file_prefix)
                    console.print(f"Saved {len(saved_paths)} PoC request(s) to: {out_dir}")
                else:
                    saved_paths = []
                    console.print(f"[yellow]Attempt {attempt_index + 1} produced no parseable HTTP request")

                # ── 解析 ──
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

                # ── Cookie 注入 ──
                if ctx.sample_cookies_header:
                    self.inject_cookies(requests, ctx.sample_cookies_header)

                # ── 远程验证 ──
                validation_results: Optional[List[ValidationResult]] = None
                validation_error: Optional[str] = None
                if auto_validate and target and requests:
                    try:
                        validation_results = validate_http_requests(requests, target)
                        for res in validation_results:
                            if res.success:
                                console.print(f"[green]Request #{res.request_index} -> HTTP {res.status_code} ({res.url})")
                            else:
                                detail = res.error or (f"HTTP {res.status_code}" if res.status_code else "no response")
                                console.print(f"[yellow]Request #{res.request_index} validation failed ({detail})")
                    except Exception as exc:
                        console.print(f"[yellow]Warning: validation failed: {exc}")
                        validation_results = None
                        validation_error = str(exc)

                # ── 成功检测 ──
                success, success_summary = self.detect_success(validation_results, requests, ctx)

                if success:
                    if success_summary:
                        console.print(f"[bold green]{success_summary}[/bold green]")
                elif validation_results:
                    console.print("[yellow]Success criteria not met.[/yellow]")

                # ── 反馈 ──
                feedback_for_next = None
                if not success:
                    feedback_for_next = self.build_feedback(
                        parse_issues, validation_results, validation_error,
                    )

                attempts.append(
                    AttemptResult(
                        attempt_index=attempt_index,
                        raw_output=raw_output,
                        requests=requests,
                        saved_paths=saved_paths,
                        validation_results=validation_results,
                        monitor_hit=success,
                        monitor_summary=success_summary,
                        feedback=feedback_for_next,
                    )
                )

                self.on_after_attempt(ctx, attempt_index, success)

                last_raw_output = raw_output
                last_requests = requests
                last_saved_paths = saved_paths
                last_validation_results = validation_results
                overall_success = overall_success or success
                feedback_text = feedback_for_next

                if success and stop_after_success:
                    console.print("[bold green]Success criteria met; stopping further attempts[/bold green]")
                    break

                if attempt_index + 1 < max_iters:
                    if feedback_text:
                        console.print("[cyan]Prepared feedback for next attempt (feedback logged, not printed to console)")
                    elif not success:
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
            self.on_cleanup(loop_resource)
