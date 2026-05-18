from __future__ import annotations

from typing import List, Optional

from rich.console import Console

from PoCGen.llm.client import ChatMessage
from PoCGen.prompts.templates import build_prompt_stack_overflow_http
from PoCGen.core.models import HTTPMessage, ValidationResult
from PoCGen.core.shared.http_handler import HTTPHandlerBase, GenerationContext

console = Console()


class StackOverflowHTTPHandler(HTTPHandlerBase):
    name = "stack_overflow_http"

    @property
    def file_prefix(self) -> str:
        return "poc"

    def build_prompt(self, description, code_texts, target,
                     target_profile=None, validation_feedback=None, **kwargs):
        return build_prompt_stack_overflow_http(
            description=description,
            code_files=code_texts,
            target=target,
            attacker_url=kwargs.get("attacker_url", ""),
            target_profile=target_profile,
            validation_feedback=validation_feedback,
        )

    def detect_success(self, validation_results, requests, ctx):
        if not validation_results:
            return False, None
        for res in validation_results:
            if res.success and res.status_code and 500 <= res.status_code < 600:
                return True, f"Request #{res.request_index} -> HTTP {res.status_code} - Server error detected!"
            if res.error and any(kw in res.error.lower() for kw in [
                "connection", "timeout", "reset", "refused", "unreachable", "aborted"
            ]):
                return True, f"Request #{res.request_index} connection error ({res.error}) - Service may have crashed!"
        return False, None

    def build_feedback(self, parse_issues, validation_results, validation_error=None, **kwargs):
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

                if res.success and res.status_code and 500 <= res.status_code < 600:
                    line = f"Request #{res.request_index}: success -> {status} ({url}) - Good! This indicates a server error."
                elif res.success:
                    line = f"Request #{res.request_index}: success -> {status} ({url})"
                else:
                    if res.error and any(kw in res.error.lower() for kw in [
                        "connection", "timeout", "reset", "refused", "unreachable", "aborted"
                    ]):
                        line = f"Request #{res.request_index}: connection error -> {res.error} - This may indicate service crash!"
                    else:
                        failed_validation.append(res)
                        line = f"Request #{res.request_index}: failure -> {status} ({url})"
                        if not detail:
                            detail = "no response"
                    if detail and "This may indicate" not in line:
                        line += f"; {detail}"
                if detail:
                    line += f"; {detail}"
                validation_summaries.append(line)

            if validation_summaries:
                messages.append("Target validation summary:\n" + "\n".join(f"- {item}" for item in validation_summaries))
        elif validation_error:
            messages.append(f"Target validation did not run due to error: {validation_error}")
        else:
            messages.append("Target validation did not run or returned no results.")

        if parse_issues or failed_validation:
            messages.append(
                "Adjust along the following tracks before the next attempt:\n"
                "1) Payload Construction: Focus on the vulnerable parameter(s) that accept user input. Construct payloads that cause buffer overflow. "
                "   This may include sending extremely long strings, format strings, or specifically crafted binary data via multipart/form-data or raw body.\n"
                "2) Error Analysis: We are looking for either:\n"
                "   a) HTTP 5xx status codes (500, 503, etc.) - indicating server internal error\n"
                "   b) Connection errors (connection refused, timeout, reset) - indicating the service may have crashed\n"
                "3) Request Structure: Ensure the Content-Type header matches the payload.\n"
                "4) Crash Indicators: If you get a normal response (2xx/3xx/4xx), the payload likely didn't trigger the overflow. Try:\n"
                "   - Increase payload length gradually\n"
                "   - Try different memory corruption techniques\n"
                "   - Try different parameter injection points"
            )
        else:
            messages.append(
                "No stack overflow detected. The payload needs adjustment:\n"
                "1) Increase the size of buffer overflow payloads\n"
                "2) Try different memory corruption techniques\n"
                "3) Target different parameters or endpoints\n"
                "4) Adjust the payload to bypass potential mitigations\n"
                "5) Consider using format string vulnerabilities"
            )

        return "\n\n".join(messages) if messages else None


# Legacy wrapper
def generate_stack_overflow_http(**kwargs) -> "GenerationResult":
    handler = StackOverflowHTTPHandler()
    return handler.generate(**kwargs)
