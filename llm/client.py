from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import httpx
from pydantic import BaseModel

from PoCGen.config.config import SETTINGS


class ChatMessage(BaseModel):
    role: str
    content: str


class LLMClient:
    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        timeout_seconds: Optional[int] = None,
        extra_body: Optional[Dict[str, Any]] = None,
    ) -> None:
        s = SETTINGS.llm
        self.base_url = (base_url or s.base_url).rstrip("/")
        self.api_key = api_key or s.api_key
        self.model = model or s.model
        self.timeout = timeout_seconds or s.timeout_seconds
        self.extra_body = extra_body or s.extra_body

        self._client = httpx.Client(timeout=self.timeout)

    def chat(self, messages: List[ChatMessage], temperature: float = 0.2, max_tokens: int = 2048) -> str:
        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": [m.model_dump() for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        # Attach extra body under a dedicated key (common pattern for OpenAI-compatible proxies)
        if self.extra_body:
            payload["extra_body"] = self.extra_body

        resp = self._client.post(url, headers=headers, json=payload)
        try:
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            # Surface server error detail to help troubleshooting
            detail: str
            try:
                detail = json.dumps(resp.json(), ensure_ascii=False)
            except Exception:
                detail = resp.text
            raise RuntimeError(f"LLM API error {resp.status_code}: {detail}") from e
        data = resp.json()
        try:
            return data["choices"][0]["message"]["content"]
        except Exception:
            # Fallback to raw json
            return json.dumps(data, ensure_ascii=False)

    def close(self) -> None:
        self._client.close()


__all__ = ["LLMClient", "ChatMessage"]
