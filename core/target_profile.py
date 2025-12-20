from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


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
