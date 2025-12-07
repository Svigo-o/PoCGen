from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class HTTPMessage:
    method: str
    path: str
    version: str
    headers: Dict[str, str]
    body: str

    @staticmethod
    def parse(raw: str) -> "HTTPMessage":
        lines = raw.splitlines()
        if not lines:
            raise ValueError("Empty HTTP message")
        start = lines[0].strip()
        parts = start.split()
        if len(parts) < 3:
            raise ValueError(f"Invalid request line: {start}")
        method, path, version = parts[0], parts[1], parts[2]

        headers: Dict[str, str] = {}
        i = 1
        while i < len(lines):
            line = lines[i]
            i += 1
            if line.strip() == "":
                break
            if ":" not in line:
                # skip malformed header
                continue
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
        body = "\n".join(lines[i:]) if i < len(lines) else ""
        return HTTPMessage(method=method, path=path, version=version, headers=headers, body=body)


@dataclass
class GenerationResult:
    raw_output: str
    requests: List[HTTPMessage]
    saved_paths: List[str]


class VulnHandler:
    name: str = "base"

    def build_messages(self, description: str, code_texts: List[str], target: Optional[str]) -> List[dict]:
        raise NotImplementedError

    def post_process(self, raw_output: str) -> List[str]:
        """Split raw output into individual HTTP messages (as strings)."""
        # naive split on two consecutive newlines separating requests
        chunks: List[str] = []
        buf: List[str] = []
        for line in raw_output.splitlines():
            if line.strip() == "" and buf and buf[-1].strip() == "":
                # double blank -> boundary
                chunk = "\n".join([l for l in buf if l is not None])
                if chunk.strip():
                    chunks.append(chunk.strip())
                buf = []
            else:
                buf.append(line)
        if buf:
            chunk = "\n".join(buf).strip()
            if chunk:
                chunks.append(chunk)
        # If still a single block, try to split by two newlines
        if len(chunks) <= 1:
            parts = [p.strip() for p in raw_output.strip().split("\n\n") if p.strip()]
            if len(parts) > 1:
                return parts
        return chunks if chunks else ([raw_output.strip()] if raw_output.strip() else [])
