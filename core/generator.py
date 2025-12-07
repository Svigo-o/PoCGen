from __future__ import annotations

from typing import Dict, List, Optional, Type

from rich.console import Console

from PoCGen.config.config import SETTINGS
from PoCGen.llm.client import ChatMessage, LLMClient
from PoCGen.prompts.templates import build_prompt_command_injection_http
from .models import GenerationResult, VulnHandler
from .postprocess import save_messages, split_messages

console = Console()


class CommandInjectionHTTPHandler(VulnHandler):
    name = "command_injection_http"

    def build_messages(self, description: str, code_texts: List[str], target: Optional[str], attacker_url: str) -> List[dict]:
        msgs = build_prompt_command_injection_http(description=description, code_files=code_texts, target=target, attacker_url=attacker_url)
        # return as dict for client
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
    max_tokens: int = 2048,
    output_dir: Optional[str] = None,
    attacker_url: Optional[str] = None,
) -> GenerationResult:
    handler = get_handler(vuln_type)
    atk_url = attacker_url or SETTINGS.attacker_url
    messages = handler.build_messages(description, code_texts, target, atk_url)

    client = LLMClient()
    try:
        # Convert to ChatMessage for type, though client accepts dicts
        cm = [ChatMessage(**m) for m in messages]
        raw_output = client.chat(cm, temperature=temperature, max_tokens=max_tokens)
    finally:
        client.close()

    # Postprocess and save
    raw_messages = split_messages(raw_output)
    out_dir = output_dir or SETTINGS.save_dir
    saved_paths = save_messages(raw_messages, out_dir)
    requests = []
    from .models import HTTPMessage

    for raw in raw_messages:
        try:
            requests.append(HTTPMessage.parse(raw))
        except Exception:
            # Keep minimal placeholder
            requests.append(HTTPMessage(method="", path="", version="", headers={}, body=raw))

    console.print(f"Saved {len(saved_paths)} PoC request(s) to: {out_dir}")
    return GenerationResult(raw_output=raw_output, requests=requests, saved_paths=saved_paths)
