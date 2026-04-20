"""
IDA MCP Service Manager.

Automatically starts the idalib-mcp subprocess, waits for it to become
ready, and shuts it down when the analysis is complete.  All operations
are logged to logs/idamcp/.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time
from typing import Optional

import httpx
from rich.console import Console

from PoCGen.core.ida_mcp_client import _log

console = Console()

# Default paths
_PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
_IDALIB_MCP_BIN = os.path.join(_PROJECT_ROOT, "ida-mcp-env", ".venv", "bin", "idalib-mcp")


class IDAMCPService:
    """Manages the lifecycle of an idalib-mcp subprocess."""

    def __init__(
        self,
        binary_path: str,
        mcp_url: str = "http://127.0.0.1:8745/mcp",
        idalib_mcp_bin: Optional[str] = None,
        startup_timeout: float = 120.0,
    ) -> None:
        self.binary_path = binary_path
        self.mcp_url = mcp_url.rstrip("/")
        self.idalib_mcp_bin = idalib_mcp_bin or _IDALIB_MCP_BIN
        self.startup_timeout = startup_timeout
        self._process: Optional[subprocess.Popen] = None
        self._was_already_running = False

        # Parse host/port from mcp_url for the subprocess
        # e.g. "http://127.0.0.1:8745/mcp" -> host=127.0.0.1, port=8745
        try:
            without_scheme = mcp_url.replace("http://", "").replace("https://", "")
            host_port = without_scheme.split("/")[0]
            self._host, self._port = host_port.rsplit(":", 1)
        except Exception:
            self._host = "127.0.0.1"
            self._port = "8745"

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> bool:
        """Start the idalib-mcp subprocess and wait until it is ready.

        If the MCP server is already running at the target URL, reuse it
        and do NOT shut it down when stop() is called.

        Returns True if the service is ready (either started or already running).
        """
        # Check if already running
        if self._is_responsive():
            _log(f"IDA MCP already running at {self.mcp_url}, reusing existing service")
            console.print(f"[cyan]  IDA MCP: reusing existing service at {self.mcp_url}")
            self._was_already_running = True
            return True

        # Start the subprocess
        cmd = [
            self.idalib_mcp_bin,
            self.binary_path,
            "--host", self._host,
            "--port", self._port,
        ]

        _log(f"Starting idalib-mcp: {' '.join(cmd)}")
        console.print(f"[cyan]  IDA MCP: starting subprocess on {self._host}:{self._port}...")

        log_dir = os.path.join(_PROJECT_ROOT, "logs", "idamcp")
        os.makedirs(log_dir, exist_ok=True)
        stdout_log = open(
            os.path.join(log_dir, "idalib_mcp_stdout.log"),
            "a", encoding="utf-8",
        )
        stderr_log = open(
            os.path.join(log_dir, "idalib_mcp_stderr.log"),
            "a", encoding="utf-8",
        )

        try:
            self._process = subprocess.Popen(
                cmd,
                stdout=stdout_log,
                stderr=stderr_log,
                preexec_fn=os.setsid,
            )
        except Exception as exc:
            _log(f"Failed to start idalib-mcp: {exc}")
            console.print(f"[red]  IDA MCP: failed to start subprocess: {exc}")
            stdout_log.close()
            stderr_log.close()
            return False

        # Wait for the service to become responsive
        console.print(f"[cyan]  IDA MCP: waiting for service to become ready (timeout {self.startup_timeout}s)...")
        start_ts = time.time()
        while time.time() - start_ts < self.startup_timeout:
            if self._process.poll() is not None:
                _log(f"idalib-mcp exited prematurely with code {self._process.returncode}")
                console.print(f"[red]  IDA MCP: subprocess exited prematurely (code {self._process.returncode})")
                self._process = None
                stdout_log.close()
                stderr_log.close()
                return False
            if self._is_responsive():
                elapsed = time.time() - start_ts
                _log(f"idalib-mcp ready after {elapsed:.1f}s (pid={self._process.pid})")
                console.print(f"[green]  IDA MCP: service ready after {elapsed:.1f}s (pid={self._process.pid})")
                return True
            time.sleep(2)

        _log("idalib-mcp startup timed out")
        console.print(f"[red]  IDA MCP: startup timed out after {self.startup_timeout}s")
        self.stop()
        stdout_log.close()
        stderr_log.close()
        return False

    def stop(self) -> None:
        """Stop the idalib-mcp subprocess.

        If the service was already running before we started, do nothing.
        """
        if self._was_already_running:
            _log("Not stopping IDA MCP: it was already running before this session")
            console.print("[dim]  IDA MCP: not stopping (was already running before this session)")
            return

        if self._process is None:
            return

        pid = self._process.pid
        _log(f"Stopping idalib-mcp (pid={pid})")
        console.print(f"[cyan]  IDA MCP: stopping subprocess (pid={pid})...")

        try:
            # Send SIGTERM to the process group (to kill child processes too)
            os.killpg(os.getpgid(pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        except Exception as exc:
            _log(f"SIGTERM failed: {exc}, trying SIGKILL")
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except Exception:
                pass

        try:
            self._process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _log("idalib-mcp did not exit after SIGTERM, sending SIGKILL")
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except Exception:
                pass
            try:
                self._process.wait(timeout=5)
            except Exception:
                pass

        _log(f"idalib-mcp stopped (pid={pid})")
        console.print(f"[green]  IDA MCP: subprocess stopped")
        self._process = None

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def _is_responsive(self) -> bool:
        """Check if the MCP server is responding at the target URL."""
        # Try a simple HTTP GET/POST to the MCP endpoint
        try:
            # Send a minimal JSON-RPC initialize request
            base = self.mcp_url
            with httpx.Client(timeout=5.0) as client:
                resp = client.post(
                    base,
                    json={
                        "jsonrpc": "2.0",
                        "id": "health",
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2025-06-18",
                            "capabilities": {},
                            "clientInfo": {"name": "PoCGen-health", "version": "1.0"},
                        },
                    },
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code == 200:
                    return True
        except (httpx.ConnectError, httpx.TimeoutException):
            pass
        except Exception:
            pass
        return False

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "IDAMCPService":
        if not self.start():
            raise RuntimeError(f"Failed to start IDA MCP service for {self.binary_path}")
        return self

    def __exit__(self, *args) -> None:
        self.stop()


__all__ = ["IDAMCPService"]
