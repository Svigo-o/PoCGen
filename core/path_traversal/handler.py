from __future__ import annotations

from typing import List, Optional

from rich.console import Console

from PoCGen.llm.client import ChatMessage
from PoCGen.prompts.templates import build_prompt_path_traversal_http
from PoCGen.core.models import HTTPMessage, ValidationResult
from PoCGen.core.shared.http_handler import HTTPHandlerBase, GenerationContext

console = Console()


class PathTraversalHTTPHandler(HTTPHandlerBase):
    name = "path_traversal_http"

    @property
    def file_prefix(self) -> str:
        return "pathtra_poc"

    def build_prompt(self, description, code_texts, target,
                     target_profile=None, validation_feedback=None, **kwargs):
        return build_prompt_path_traversal_http(
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
            if res.status_code == 200:
                preview = (res.response_preview or "").strip()[:200]
                summary = f"Request #{res.request_index} returned HTTP 200"
                if preview:
                    summary += f" | Preview: {preview}"
                return True, summary
        return False, None

    def build_feedback(self, parse_issues, validation_results, validation_error=None, **kwargs):
        messages: List[str] = []
        if parse_issues:
            bullet = "\n".join(f"- {issue}" for issue in parse_issues)
            messages.append("HTTP解析/验证问题:\n" + bullet)

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
                    detail_parts.append(f"preview: {preview}")
                detail = "; ".join(detail_parts)

                if res.status_code == 200:
                    line = f"Request #{res.request_index}: 成功获得200响应 -> {status} ({url})"
                    if "system_upgrade" in preview.lower():
                        line += " - 响应可能包含目标文件内容！"
                    else:
                        line += " - 但未检测到明显的目标文件内容，请确认payload是否正确。"
                elif res.status_code == 302:
                    line = f"Request #{res.request_index}: 收到302重定向 -> {status} ({url})"
                    line += "\n  建议：尝试增加 `../` 的层数，或对路径进行URL编码。"
                elif res.status_code in (401, 403):
                    line = f"Request #{res.request_index}: 认证/授权失败 -> {status} ({url})"
                    line += "\n  建议：添加或更新认证头（如Cookie、Authorization）。"
                elif res.status_code == 404:
                    line = f"Request #{res.request_index}: 文件未找到 -> {status} ({url})"
                    line += "\n  建议：尝试不同的路径遍历payload，或确认参数名是否正确。"
                elif res.status_code and 500 <= res.status_code < 600:
                    line = f"Request #{res.request_index}: 服务器错误 -> {status} ({url})"
                    line += "\n  注意：服务器可能已崩溃或遇到内部错误。"
                else:
                    line = f"Request #{res.request_index}: {status} ({url})"
                if detail:
                    line += f"\n  {detail}"
                validation_summaries.append(line)

            if validation_summaries:
                messages.append("目标验证总结:\n" + "\n".join(f"- {item}" for item in validation_summaries))
        elif validation_error:
            messages.append(f"目标验证因错误未运行: {validation_error}")
        else:
            messages.append("目标验证未运行或无结果返回。")

        if validation_results:
            has_302 = any(res.status_code == 302 for res in validation_results)
            has_40x = any(res.status_code and 400 <= res.status_code < 500 for res in validation_results)
            has_200 = any(res.status_code == 200 for res in validation_results)

            if has_302:
                messages.append(
                    "调整建议（针对302重定向）：\n"
                    "1. 增加路径遍历深度：在路径中添加更多 `../` 序列\n"
                    "2. URL编码：对斜杠进行编码（`/` -> `%2f`）\n"
                    "3. 双重编码：尝试对已编码的字符再次编码\n"
                    "4. 尝试绝对路径\n"
                    "5. 空字节截断：在ASP环境中尝试 `%00` 风格"
                )
            elif has_40x:
                messages.append(
                    "调整建议（针对40x错误）：\n"
                    "1. 认证问题（401/403）：添加必要的Cookie、Session ID或Authorization头部\n"
                    "2. 文件未找到（404）：尝试不同的路径组合\n"
                    "3. 检查请求方法和请求头"
                )
            elif not has_200:
                messages.append(
                    "通用调整建议：\n"
                    "1. 检查参数名：从代码中确认正确的参数名称\n"
                    "2. 尝试不同的payload格式（基本、URL编码、Windows风格）\n"
                    "3. 检查目标路径\n"
                    "4. 简化请求：移除不必要的头部"
                )

        return "\n\n".join(messages) if messages else None


# Legacy wrapper
def generate_path_traversal_http(**kwargs) -> "GenerationResult":
    handler = PathTraversalHTTPHandler()
    return handler.generate(**kwargs)
