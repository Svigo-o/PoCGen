from __future__ import annotations

from typing import List, Tuple

from PoCGen.core.models import HTTPMessage


def validate_http_message(msg: HTTPMessage) -> List[str]:
    errors: List[str] = []
    if msg.version.upper() not in {"HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/2.0"}:
        errors.append(f"Unsupported HTTP version: {msg.version}")
    if not msg.method or not msg.path:
        errors.append("Missing method or path")
    if "Host" not in msg.headers:
        errors.append("Missing Host header")
    # Content-Length is auto-corrected by fix_content_length(); no mismatch error needed.
    return errors


def fix_content_length(msg: HTTPMessage) -> None:
    """Auto-correct Content-Length to match actual body byte size."""
    if msg.body is not None:
        msg.headers["Content-Length"] = str(len(msg.body.encode("utf-8")))


def parse_and_validate(raw: str) -> Tuple[HTTPMessage, List[str]]:
    msg = HTTPMessage.parse(raw)
    return msg, validate_http_message(msg)
