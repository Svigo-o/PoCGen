from __future__ import annotations

import json
import os
import time
from typing import List

from PoCGen.core.models import SocketEventMessage
from .validators import parse_and_validate


def split_socket_messages(raw_output: str) -> List[str]:
    text = raw_output.strip()
    if not text:
        return []

    decoder = json.JSONDecoder()
    idx = 0
    blocks: List[str] = []
    while idx < len(text):
        while idx < len(text) and text[idx].isspace():
            idx += 1
        if idx >= len(text):
            break
        try:
            obj, end = decoder.raw_decode(text, idx)
        except json.JSONDecodeError:
            # fallback: treat remainder as a single block for downstream error reporting
            if not blocks:
                blocks.append(text[idx:].strip())
            break
        normalized = json.dumps(obj, ensure_ascii=False, indent=2)
        blocks.append(normalized)
        idx = end
    if not blocks:
        blocks.append(text)
    return blocks


def save_socket_messages(raw_messages: List[str], output_dir: str) -> List[str]:
    os.makedirs(output_dir, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    paths: List[str] = []
    for idx, raw in enumerate(raw_messages, start=1):
        fname = f"socket_poc_{ts}_{idx:02d}.json"
        fpath = os.path.join(output_dir, fname)
        counter = 1
        while os.path.exists(fpath):
            fname = f"socket_poc_{ts}_{idx:02d}_{counter}.json"
            fpath = os.path.join(output_dir, fname)
            counter += 1
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = raw
        with open(fpath, "w", encoding="utf-8") as fh:
            if isinstance(parsed, (dict, list)):
                json.dump(parsed, fh, ensure_ascii=False, indent=2)
            else:
                fh.write(str(parsed))
        paths.append(fpath)
    return paths


def parse_socket_payloads(raw_messages: List[str]) -> List[SocketEventMessage]:
    messages: List[SocketEventMessage] = []
    for payload in raw_messages:
        msg, _ = parse_and_validate(payload)
        messages.append(msg)
    return messages