from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import urlparse

from rich.console import Console

console = Console()


class _MonitorHandler(BaseHTTPRequestHandler):
    server_version = "PoCGenAttackerMonitor/1.0"

    def do_GET(self):
        self.server.parent.record_hit(self)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        body = b"OK"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length) if length > 0 else b""
        self.do_GET()

    def log_message(self, format: str, *args):
        # Suppress default logging to stderr; handled by monitor
        return


class AttackerMonitor:
    def __init__(self, url: str, timeout: float) -> None:
        parsed = urlparse(url)
        self.listen_host = parsed.hostname or "0.0.0.0"
        self.listen_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.timeout = timeout
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._event = threading.Event()
        self.last_request_summary: Optional[str] = None

    def start(self) -> None:
        try:
            self._server = ThreadingHTTPServer((self.listen_host, self.listen_port), _MonitorHandler)
        except OSError as exc:
            console.print(f"[yellow]Warning: failed to start attacker monitor on {self.listen_host}:{self.listen_port}: {exc}")
            self._server = None
            return
        self._server.parent = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        console.print(f"[green]Attacker monitor listening on http://{self.listen_host}:{self.listen_port}")

    def is_running(self) -> bool:
        return self._server is not None

    def record_hit(self, handler: _MonitorHandler) -> None:
        summary = f"{handler.command} {handler.path}\n" + "\n".join(f"{k}: {v}" for k, v in handler.headers.items())
        self.last_request_summary = summary
        self._event.set()
        console.print(f"[bold green]Attacker monitor received request:[/bold green]\n{summary}")

    def wait_for_hit(self, timeout: Optional[float] = None) -> bool:
        if not self._server:
            return False
        wait_timeout = self.timeout if timeout is None else timeout
        hit = self._event.wait(wait_timeout)
        if hit:
            # Allow waiting again for subsequent attempts
            self._event.clear()
        return hit

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1)
        self._thread = None
        self._event.clear()


__all__ = ["AttackerMonitor"]
