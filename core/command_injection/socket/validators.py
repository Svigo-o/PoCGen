from __future__ import annotations

from typing import List, Tuple
from urllib.parse import urlparse

from PoCGen.core.models import SocketEventMessage


def validate_socket_event(message: SocketEventMessage) -> List[str]:
    errors: List[str] = []
    parsed = urlparse(message.url)
    if parsed.scheme not in {"ws", "wss"}:
        errors.append("Socket URL should start with ws:// or wss://")
    if not message.event:
        errors.append("Missing event name")
    if message.payload is None:
        errors.append("Missing payload field")
    if message.max_response_frames < 1:
        errors.append("max_response_frames must be >= 1")
    return errors


def parse_and_validate(raw: str) -> Tuple[SocketEventMessage, List[str]]:
    message = SocketEventMessage.parse(raw)
    return message, validate_socket_event(message)