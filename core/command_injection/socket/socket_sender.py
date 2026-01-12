from __future__ import annotations

import json
import ssl
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import websocket

PayloadType = Union[str, Dict[str, Any], List[Any]]


@dataclass
class SocketSendResult:
    """Structured response for a Socket.IO dispatch."""

    handshake: Optional[str]
    ready: Optional[str]
    responses: List[str]


class SocketIOSender:
    """Minimal Socket.IO client for dispatching crafted events."""

    def __init__(
        self,
        url: str,
        namespace: Optional[str] = None,
        timeout: float = 10.0,
        headers: Optional[Dict[str, str]] = None,
        verify_ssl: bool = False,
    ) -> None:
        self.url = url
        self.namespace = namespace or ""
        self.timeout = timeout
        self.headers = headers or {}
        self.verify_ssl = verify_ssl

    def _build_header_list(self, cookies: Optional[str]) -> List[str]:
        header_list = [f"{k}: {v}" for k, v in self.headers.items()]
        if cookies:
            header_list.append(f"Cookie: {cookies}")
        return header_list

    def _ssl_options(self) -> Optional[Dict[str, Any]]:
        scheme = urlparse(self.url).scheme.lower()
        if scheme != "wss":
            return None
        if self.verify_ssl:
            return {}
        return {"cert_reqs": ssl.CERT_NONE}

    def _build_handshake_frame(self) -> str:
        if self.namespace:
            return f"40/{self.namespace.lstrip('/') }"
        return "40"

    def _build_event_frame(self, event: str, payload: str) -> str:
        if self.namespace:
            return f"42/{self.namespace.lstrip('/') },[\"{event}\",{payload}]"
        return f"42[\"{event}\",{payload}]"

    @staticmethod
    def _serialize_payload(payload: PayloadType) -> str:
        if isinstance(payload, str):
            return payload
        return json.dumps(payload, separators=(",", ":"))

    def send_event(
        self,
        event: str,
        payload: PayloadType,
        cookies: Optional[str] = None,
        wait_for_response: bool = True,
        max_response_frames: int = 1,
    ) -> SocketSendResult:
        """Send a single Socket.IO event and optional response collection."""

        header_list = self._build_header_list(cookies)
        sslopt = self._ssl_options()
        ws = websocket.create_connection(
            self.url,
            timeout=self.timeout,
            header=header_list if header_list else None,
            sslopt=sslopt,
        )
        result = SocketSendResult(handshake=None, ready=None, responses=[])
        try:
            try:
                result.handshake = ws.recv()
            except websocket.WebSocketTimeoutException:
                result.handshake = None
            ws.send(self._build_handshake_frame())
            try:
                result.ready = ws.recv()
            except websocket.WebSocketTimeoutException:
                result.ready = None
            ws.send(self._build_event_frame(event, self._serialize_payload(payload)))
            if wait_for_response:
                frames = 0
                while frames < max_response_frames:
                    try:
                        message = ws.recv()
                    except websocket.WebSocketTimeoutException:
                        break
                    except websocket.WebSocketConnectionClosedException:
                        break
                    if message is None:
                        break
                    result.responses.append(message)
                    frames += 1
        finally:
            try:
                ws.close()
            except Exception:
                pass
        return result


def send_socketio_event(
    url: str,
    event: str,
    payload: PayloadType,
    namespace: Optional[str] = None,
    cookies: Optional[str] = None,
    timeout: float = 10.0,
    headers: Optional[Dict[str, str]] = None,
    verify_ssl: bool = False,
    wait_for_response: bool = True,
    max_response_frames: int = 1,
) -> SocketSendResult:
    """Helper wrapper to send a Socket.IO event in one call."""

    sender = SocketIOSender(
        url=url,
        namespace=namespace,
        timeout=timeout,
        headers=headers,
        verify_ssl=verify_ssl,
    )
    return sender.send_event(
        event=event,
        payload=payload,
        cookies=cookies,
        wait_for_response=wait_for_response,
        max_response_frames=max_response_frames,
    )
