"""Attacker monitor management tools."""

from __future__ import annotations

import glob
import json
from typing import List, Optional

from mcp.server.fastmcp import FastMCP

from PoCGen.mcp_tools.state import session_cache, _truncate


def register_monitor_tools(mcp: FastMCP) -> None:

    @mcp.tool()
    async def pocgen_monitor_start(
        url: str = "http://0.0.0.0:6666",
        timeout: float = 60,
    ) -> str:
        """Start the attacker monitor HTTP server to listen for wget callbacks.

        The monitor listens for GET/POST requests that indicate the PoC payload
        executed successfully on the target. If a monitor is already running,
        it will be reused.

        Args:
            url: Listen URL (default "http://0.0.0.0:6666")
            timeout: Default wait timeout in seconds for callbacks
        """
        import anyio
        from PoCGen.core.attacker_monitor import AttackerMonitor

        def _sync() -> dict:
            existing = session_cache.monitor
            if existing and existing.is_running():
                return {
                    "running": True,
                    "url": url,
                    "reused_existing": True,
                }

            monitor = AttackerMonitor(url, timeout=timeout)
            monitor.start()
            session_cache.monitor = monitor
            return {
                "running": monitor.is_running(),
                "url": url,
                "reused_existing": False,
            }

        result = await anyio.to_thread.run_sync(_sync)
        return _truncate(json.dumps(result, ensure_ascii=False, indent=2))

    @mcp.tool()
    async def pocgen_monitor_wait(
        timeout: float = 10,
    ) -> str:
        """Wait for a wget callback on the attacker monitor.

        Blocks until a callback is received or the timeout expires.

        Args:
            timeout: Seconds to wait for a callback
        """
        import anyio

        def _sync() -> dict:
            monitor = session_cache.monitor
            if not monitor or not monitor.is_running():
                return {"hit": False, "error": "No active monitor. Call pocgen_monitor_start first."}

            hit = monitor.wait_for_hit(timeout)
            summary = None
            if hit and hasattr(monitor, "last_request_summary"):
                summary = monitor.last_request_summary
            return {"hit": hit, "summary": summary}

        result = await anyio.to_thread.run_sync(_sync)
        return _truncate(json.dumps(result, ensure_ascii=False, indent=2))

    @mcp.tool()
    async def pocgen_monitor_stop() -> str:
        """Stop the attacker monitor HTTP server."""
        import anyio

        def _sync() -> dict:
            monitor = session_cache.monitor
            if not monitor:
                return {"stopped": True}
            try:
                monitor.stop()
                session_cache.monitor = None
                return {"stopped": True}
            except Exception as exc:
                return {"stopped": False, "error": str(exc)}

        result = await anyio.to_thread.run_sync(_sync)
        return _truncate(json.dumps(result, ensure_ascii=False, indent=2))

    @mcp.tool()
    async def pocgen_batch_validate(
        poc_dir: str,
        target: str,
        monitor_url: str = "http://0.0.0.0:6666",
        wait_seconds: float = 3,
    ) -> str:
        """Batch-validate all PoC files in a directory against a target device.

        Reads all .http files from poc_dir, sends each request to the target,
        and waits for the attacker monitor callback to confirm command execution.
        Returns a summary table of results.

        Args:
            poc_dir: Directory containing .http PoC files
            target: Target device base URL (e.g. "http://192.168.6.2")
            monitor_url: Attacker monitor URL for callback detection
            wait_seconds: Seconds to wait for monitor callback after each request
        """
        import anyio

        def _sync() -> dict:
            from PoCGen.core.shared.http_validators import parse_and_validate, fix_content_length
            from PoCGen.core.shared.http_remote_validator import validate_http_requests
            from PoCGen.core.attacker_monitor import reset_external_monitor, wait_for_external_monitor

            # Collect .http files
            patterns = [
                poc_dir.rstrip("/") + "/*.http",
                poc_dir.rstrip("/") + "/**/*.http",
            ]
            files = []
            seen = set()
            for pat in patterns:
                for fp in glob.glob(pat, recursive=True):
                    if fp not in seen:
                        seen.add(fp)
                        files.append(fp)
            files.sort()

            if not files:
                return {"error": f"No .http files found in {poc_dir}", "total": 0}

            results = []
            for fp in files:
                fname = fp.rsplit("/", 1)[-1]
                try:
                    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                        raw = f.read()
                except Exception as e:
                    results.append({"file": fname, "status": "READ_ERROR", "error": str(e)})
                    continue

                # Parse
                msg, errs = parse_and_validate(raw)
                if errs:
                    results.append({"file": fname, "status": "PARSE_ERROR", "error": "; ".join(errs)})
                    continue
                fix_content_length(msg)

                # Reset monitor before sending
                reset_external_monitor(monitor_url, timeout=1.0)

                # Send request
                try:
                    validate_results = validate_http_requests([msg], target)
                    vr = validate_results[0] if validate_results else None
                except Exception as e:
                    results.append({"file": fname, "status": "SEND_ERROR", "error": str(e)})
                    continue

                if vr and not vr.success and vr.error:
                    results.append({
                        "file": fname,
                        "status": "HTTP_ERROR",
                        "status_code": vr.status_code,
                        "error": vr.error,
                    })
                    continue

                # Wait for callback
                hit, summary = wait_for_external_monitor(monitor_url, timeout=wait_seconds, poll_interval=0.5)

                results.append({
                    "file": fname,
                    "status": "CONFIRMED" if hit else "NO_CALLBACK",
                    "status_code": vr.status_code if vr else None,
                    "callback": hit,
                })

            confirmed = sum(1 for r in results if r.get("callback"))
            return {
                "total": len(results),
                "confirmed": confirmed,
                "failed": len(results) - confirmed,
                "results": results,
            }

        result = await anyio.to_thread.run_sync(_sync)
        return _truncate(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    import argparse
    import sys
    import time

    parser = argparse.ArgumentParser(description="Attacker monitor 管理工具")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # start
    p = sub.add_parser("start", help="启动 attacker monitor HTTP 服务器")
    p.add_argument("--url", default="http://0.0.0.0:6666", help="监听地址")
    p.add_argument("--timeout", type=float, default=60, help="默认超时秒数")

    # wait
    p = sub.add_parser("wait", help="等待 wget 回调")
    p.add_argument("--timeout", type=float, default=10, help="等待超时秒数")
    p.add_argument("--url", default="http://0.0.0.0:6666", help="Monitor 地址")

    # stop
    sub.add_parser("stop", help="停止 attacker monitor")

    # batch-validate
    p = sub.add_parser("batch-validate", help="批量验证目录下所有 .http PoC 文件")
    p.add_argument("poc_dir", help="包含 .http 文件的目录")
    p.add_argument("--target", required=True, help="目标 base URL")
    p.add_argument("--monitor-url", default="http://0.0.0.0:6666", help="Attacker monitor 地址")
    p.add_argument("--wait", type=float, default=3, help="每个 PoC 等待回调秒数")

    args = parser.parse_args()

    if args.cmd == "start":
        from PoCGen.core.attacker_monitor import AttackerMonitor
        monitor = AttackerMonitor(args.url, timeout=args.timeout)
        monitor.start()
        if monitor.is_running():
            print(f"Monitor started on {args.url}")
            print("Press Ctrl+C to stop...")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                monitor.stop()
                print("Monitor stopped")
        else:
            print("Failed to start monitor", file=sys.stderr)
            exit(1)

    elif args.cmd == "wait":
        from PoCGen.core.attacker_monitor import wait_for_external_monitor
        hit, summary = wait_for_external_monitor(args.url, timeout=args.timeout)
        print(f"Hit: {hit}")
        if summary:
            print(f"Summary: {summary}")

    elif args.cmd == "stop":
        from PoCGen.core.attacker_monitor import reset_external_monitor
        print("Use Ctrl+C in the start terminal to stop, or:")
        print("kill $(lsof -ti:6666) 2>/dev/null")

    elif args.cmd == "batch-validate":
        from PoCGen.core.shared.http_validators import parse_and_validate, fix_content_length
        from PoCGen.core.shared.http_remote_validator import validate_http_requests
        from PoCGen.core.attacker_monitor import reset_external_monitor, wait_for_external_monitor
        import glob as glob_mod

        patterns = [args.poc_dir.rstrip("/") + "/*.http", args.poc_dir.rstrip("/") + "/**/*.http"]
        files = []
        seen = set()
        for pat in patterns:
            for fp in glob_mod.glob(pat, recursive=True):
                if fp not in seen:
                    seen.add(fp)
                    files.append(fp)
        files.sort()

        if not files:
            print(f"No .http files found in {args.poc_dir}", file=sys.stderr)
            exit(1)

        confirmed = 0
        for fp in files:
            fname = fp.rsplit("/", 1)[-1]
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as f:
                    raw = f.read()
            except Exception as e:
                print(f"{fname}: READ_ERROR ({e})")
                continue

            msg, errs = parse_and_validate(raw)
            if errs:
                print(f"{fname}: PARSE_ERROR ({'; '.join(errs)})")
                continue
            fix_content_length(msg)

            reset_external_monitor(args.monitor_url, timeout=1.0)

            try:
                vr_list = validate_http_requests([msg], args.target)
                vr = vr_list[0] if vr_list else None
            except Exception as e:
                print(f"{fname}: SEND_ERROR ({e})")
                continue

            if vr and not vr.success and vr.error:
                print(f"{fname}: HTTP_ERROR {vr.status_code} ({vr.error})")
                continue

            hit, _ = wait_for_external_monitor(args.monitor_url, timeout=args.wait, poll_interval=0.5)
            if hit:
                confirmed += 1
                print(f"{fname}: CONFIRMED")
            else:
                print(f"{fname}: NO_CALLBACK")

        print(f"\nTotal: {len(files)}, Confirmed: {confirmed}, Failed: {len(files) - confirmed}")
