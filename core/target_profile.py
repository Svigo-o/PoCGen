from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

import httpx
from urllib.parse import urlparse

from PoCGen.config.config import SETTINGS


def _normalize_target(target: str) -> str:
    target = target.strip()
    if not target:
        raise ValueError("target URL required for sampling")
    if target.startswith("http://") or target.startswith("https://"):
        return target
    return f"http://{target.strip('/')}"


@dataclass
class TargetSample:
    url: str
    status_code: int
    content_type: Optional[str]
    encoding: Optional[str]
    body_preview: str
    request_template: str
    response_headers: str

    def as_prompt_block(self) -> str:
        ct = self.content_type or "unknown"
        enc = self.encoding or "unknown"
        return (
            "Sample Target HTTP Interaction:\n"
            f"Request template used to reach target:\n{self.request_template}\n"
            f"Response status: HTTP {self.status_code}\n"
            f"Response headers (truncated):\n{self.response_headers}\n"
            f"Body preview (truncated):\n{self.body_preview}\n"
        )


def fetch_target_sample(
    target: str,
    timeout: Optional[float] = None,
    preview_chars: Optional[int] = None,
    client: Optional[httpx.Client] = None,
) -> TargetSample:
    normalized = _normalize_target(target)
    parsed = urlparse(normalized)
    path = parsed.path or "/"
    request_template = (
        f"GET {path} HTTP/1.1\n"
        f"Host: {parsed.hostname}\n"
        "User-Agent: PoCGen-Sampler/1.0\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n"
        "Accept-Language: en-US,en;q=0.9\n"
        "Connection: close\n"
        "\n"
    )
    client_args = {
        "timeout": timeout or SETTINGS.validation_timeout,
        "verify": False,
    }
    proxy = SETTINGS.http_proxy
    if proxy:
        client_args["proxies"] = proxy

    owns_client = client is None
    http_client = client or httpx.Client(**client_args)
    try:
        resp = http_client.get(normalized, headers={"User-Agent": "PoCGen-Sampler/1.0"})
        encoding = resp.encoding or resp.apparent_encoding
        preview_len = preview_chars or SETTINGS.sample_preview_chars
        if encoding:
            text_body = resp.text
        else:
            encoding = "bytes"
            text_body = resp.content.decode("latin-1", errors="ignore")
        if len(text_body) > preview_len:
            preview = text_body[:preview_len] + "\n... <truncated>"
        else:
            preview = text_body

        header_lines = []
        for name, value in resp.headers.items():
            header_lines.append(f"{name}: {value}")
            if len("\n".join(header_lines)) > SETTINGS.sample_preview_chars:
                break
        headers_str = "\n".join(header_lines)

        return TargetSample(
            url=normalized,
            status_code=resp.status_code,
            content_type=resp.headers.get("Content-Type"),
            encoding=encoding,
            body_preview=preview,
            request_template=request_template,
            response_headers=headers_str,
        )
    finally:
        if owns_client:
            http_client.close()


def sample_to_prompt_block(sample: TargetSample) -> str:
    try:
        parsed = json.loads(sample.body_preview)
        formatted = json.dumps(parsed, indent=2, ensure_ascii=False)
        preview = formatted[: SETTINGS.sample_preview_chars]
        if len(formatted) > len(preview):
            preview += "\n... <truncated>"
        return sample.as_prompt_block().replace(sample.body_preview, preview)
    except Exception:
        return sample.as_prompt_block()
