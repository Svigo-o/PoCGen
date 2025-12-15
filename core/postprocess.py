from __future__ import annotations

import os
import time
from typing import List, Tuple
import re

from .models import HTTPMessage
from .validators import parse_and_validate


def split_messages(raw_output: str) -> List[str]:
    """
    Split raw model output into HTTP request blocks.

    Previous implementation split on blank lines, which incorrectly separated headers and body
    of a single HTTP request. Here we detect request-line boundaries and split only when we see
    a new request-line (e.g., 'POST /path HTTP/1.1'). If only one request-line is found, return
    the entire output as a single message.
    """
    text = raw_output.strip("\n\r ")
    if not text:
        return []

    # Normalize line endings to \n for matching
    # Keep original text segments when slicing to preserve CRLF if present
    norm = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = norm.split("\n")

    method_re = re.compile(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+[^\r\n]+\s+HTTP/\d\.\d\s*$")
    request_line_idxs: List[int] = [i for i, ln in enumerate(lines) if method_re.match(ln or "")] 

    if len(request_line_idxs) <= 1:
        # Single request (or none detected) -> keep whole as one block
        return [text]

    # Multiple request-lines: split by these indices
    blocks: List[str] = []
    for idx, start in enumerate(request_line_idxs):
        end = request_line_idxs[idx + 1] if idx + 1 < len(request_line_idxs) else len(lines)
        block = "\n".join(lines[start:end]).strip("\n")
        if block:
            blocks.append(block)
    return blocks


def parse_and_filter(raw_messages: List[str]) -> List[Tuple[HTTPMessage, List[str]]]:
    results: List[Tuple[HTTPMessage, List[str]]] = []
    for m in raw_messages:
        try:
            msg, errs = parse_and_validate(m)
            results.append((msg, errs))
        except Exception as e:
            results.append((HTTPMessage(method="", path="", version="", headers={}, body=m), [f"Parse error: {e}"]))
    return results


def save_messages(raw_messages: List[str], output_dir: str) -> List[str]:
    os.makedirs(output_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    paths: List[str] = []
    for i, raw in enumerate(raw_messages, start=1):
        fname = f"poc_{ts}_{i:02d}.http"
        fpath = os.path.join(output_dir, fname)
        counter = 1
        while os.path.exists(fpath):
            fname = f"poc_{ts}_{i:02d}_{counter}.http"
            fpath = os.path.join(output_dir, fname)
            counter += 1
        # Normalize Content-Length before saving; do not append extra newline to avoid skewing length
        normalized = _adjust_content_length(raw)
        with open(fpath, "w", encoding="utf-8") as f:
            f.write(normalized)
        paths.append(fpath)
    return paths


def _adjust_content_length(raw: str) -> str:
    """
    Ensure Content-Length reflects the actual UTF-8 byte length of the body.
    If Content-Length exists, replace it; if missing and body is non-empty, insert it before the blank line.
    """
    # Preserve original line endings if possible; treat \r\n, \r, or \n uniformly for parsing
    original = raw
    text = raw.replace("\r\n", "\n").replace("\r", "\n")
    # Split headers and body
    if "\n\n" in text:
        head, body = text.split("\n\n", 1)
        sep = "\n\n"
    else:
        # No explicit blank line -> treat entire as headers (no body)
        head, body = text, ""
        sep = "\n\n"

    # Compute body byte length in UTF-8
    body_len = len(body.encode("utf-8"))

    # Update or insert Content-Length header
    lines = head.split("\n") if head else []
    found = False
    for idx, ln in enumerate(lines):
        if ln.lower().startswith("content-length:"):
            lines[idx] = f"Content-Length: {body_len}"
            found = True
            break
    if not found and body:
        # Insert Content-Length at the end of headers
        lines.append(f"Content-Length: {body_len}")

    new_head = "\n".join(lines)
    rebuilt = new_head + sep + body if body or (sep in original) else new_head
    # If original used CRLF, convert back to CRLF
    if "\r\n" in original:
        rebuilt = rebuilt.replace("\n", "\r\n")
    return rebuilt
