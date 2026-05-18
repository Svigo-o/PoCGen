"""Chrome DevTools Protocol (CDP) based browser sampler.

Uses direct CDP JSON-RPC over WebSocket for browser automation —
lightweight and transparent for LLM-driven workflows.

Requires: websocket-client (pip install websocket-client)
Chrome: google-chrome --remote-debugging-port=9222 [--headless]
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
import websocket

from PoCGen.config.config import SETTINGS
from PoCGen.core.logger import _log
from PoCGen.core.target_profile import TargetSample

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _request_log_dir() -> str:
    return getattr(SETTINGS, "collect_dir", None) or str(PROJECT_ROOT / "output" / "http_post_sample")


def _cookie_dir() -> str:
    return getattr(SETTINGS, "cookie_dir", None) or str(PROJECT_ROOT / "output" / "cookie")


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


# ─── Chrome Process Management ─────────────────────────────────────────────


def _cdp_port() -> int:
    return int(getattr(SETTINGS, "cdp_port", 9222))


def _chrome_path() -> str:
    return str(getattr(SETTINGS, "cdp_chrome_path", "google-chrome"))


def is_chrome_running(port: Optional[int] = None) -> bool:
    """Check if a Chrome instance with remote debugging is accessible."""
    p = port or _cdp_port()
    try:
        resp = requests.get(f"http://127.0.0.1:{p}/json/version", timeout=2)
        return resp.status_code == 200
    except Exception:
        return False


def ensure_chrome(headless: bool = True, port: Optional[int] = None) -> int:
    """Launch Chrome with remote debugging if not already running. Returns port."""
    p = port or _cdp_port()
    if is_chrome_running(p):
        _log(f"Chrome already running on port {p}")
        return p

    chrome = _chrome_path()
    args = [
        chrome,
        f"--remote-debugging-port={p}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-gpu",
        "--disable-software-rasterizer",
        "--disable-dev-shm-usage",
        "--remote-allow-origins=*",
    ]
    if headless:
        args.append("--headless=new")

    _log(f"Launching Chrome: {' '.join(args)}")
    subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Wait for Chrome to be ready
    deadline = time.time() + 10
    while time.time() < deadline:
        if is_chrome_running(p):
            _log(f"Chrome ready on port {p}")
            return p
        time.sleep(0.3)

    raise RuntimeError(f"Chrome did not start on port {p} within 10s")


# ─── CDP Connection ────────────────────────────────────────────────────────


class CDPConnection:
    """Low-level CDP JSON-RPC connection over WebSocket."""

    def __init__(self, ws_url: str) -> None:
        self._ws = websocket.create_connection(ws_url, timeout=30)
        self._msg_id = 0
        self._events: List[Dict[str, Any]] = []

    def send(self, method: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """Send CDP command and wait for response."""
        self._msg_id += 1
        msg = {"id": self._msg_id, "method": method}
        if params:
            msg["params"] = params
        self._ws.send(json.dumps(msg))

        # Read responses until we get the matching result
        deadline = time.time() + 30
        while time.time() < deadline:
            raw = self._ws.recv()
            data = json.loads(raw)
            if "id" in data and data["id"] == self._msg_id:
                if "error" in data:
                    raise RuntimeError(f"CDP error: {data['error']}")
                return data.get("result", {})
            # It's an event — store it
            self._events.append(data)

        raise TimeoutError(f"CDP timeout waiting for response to {method}")

    def get_events(self, event_method: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get accumulated events, optionally filtered by method name."""
        if event_method:
            return [e for e in self._events if e.get("method") == event_method]
        return list(self._events)

    def clear_events(self) -> None:
        self._events.clear()

    def poll_events(self, timeout: float = 5.0) -> List[Dict[str, Any]]:
        """Poll for new events for up to timeout seconds."""
        self._ws.settimeout(timeout)
        new_events = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                raw = self._ws.recv()
                data = json.loads(raw)
                if "method" in data:
                    self._events.append(data)
                    new_events.append(data)
            except websocket.WebSocketTimeoutException:
                break
            except Exception:
                break
        self._ws.settimeout(30)
        return new_events

    def close(self) -> None:
        try:
            self._ws.close()
        except Exception:
            pass


def get_page_ws_url(port: Optional[int] = None, target_url: Optional[str] = None) -> str:
    """Get WebSocket URL for a page. Creates new tab or finds existing one."""
    p = port or _cdp_port()
    resp = requests.get(f"http://127.0.0.1:{p}/json", timeout=5)
    pages = resp.json()

    # Find existing page matching target URL
    if target_url:
        for page in pages:
            if page.get("type") == "page" and target_url in page.get("url", ""):
                return page["webSocketDebuggerUrl"]

    # Use first available page
    for page in pages:
        if page.get("type") == "page":
            return page["webSocketDebuggerUrl"]

    # Create new tab
    resp = requests.get(f"http://127.0.0.1:{p}/json/new?about:blank", timeout=5)
    return resp.json()["webSocketDebuggerUrl"]


# ─── CDP Page Operations ───────────────────────────────────────────────────


def cdp_navigate(cdp: CDPConnection, url: str, wait_load: bool = True, timeout: float = 30) -> Dict:
    """Navigate to URL and optionally wait for load event."""
    cdp.clear_events()
    result = cdp.send("Page.navigate", {"url": url})
    if wait_load:
        deadline = time.time() + timeout
        while time.time() < deadline:
            events = cdp.poll_events(min(2.0, deadline - time.time()))
            for ev in events:
                if ev.get("method") == "Page.loadEventFired":
                    return result
            # Also check if frameStoppedLoading
            for ev in events:
                if ev.get("method") == "Page.frameStoppedLoading":
                    return result
        _log(f"CDP navigate load timeout for {url}")
    return result


def cdp_evaluate(cdp: CDPConnection, expression: str, return_by_value: bool = True) -> Any:
    """Evaluate JavaScript expression and return result."""
    result = cdp.send("Runtime.evaluate", {
        "expression": expression,
        "returnByValue": return_by_value,
        "awaitPromise": True,
    })
    remote = result.get("result", {})
    if remote.get("type") == "undefined":
        return None
    if "value" in remote:
        return remote["value"]
    return remote.get("description", str(remote))


def cdp_get_cookies(cdp: CDPConnection, urls: Optional[List[str]] = None) -> List[Dict]:
    """Get cookies for given URLs (or all)."""
    params = {}
    if urls:
        params["urls"] = urls
    result = cdp.send("Network.getCookies", params)
    return result.get("cookies", [])


def cdp_get_page_html(cdp: CDPConnection) -> str:
    """Get current page HTML."""
    result = cdp_evaluate(cdp, "document.documentElement.outerHTML")
    return result or ""


# ─── Login Flow (LLM-based field analysis) ─────────────────────────────────


def _scan_inputs_cdp(cdp: CDPConnection) -> List[Dict[str, Any]]:
    """Scan page input fields via CDP, returning metadata compatible with login_flow._collect_inputs().

    Returns list of dicts with keys matching _collect_inputs() output:
    field_index, tag, type, name, placeholder, aria, class, visible, disabled,
    role, tabindex, contenteditable, text, value
    """
    js = """
    (function() {
        var selector = 'input, textarea, select, [contenteditable], [role="textbox"], [role="combobox"], [role="searchbox"], [role="spinbutton"]';
        var nodes = document.querySelectorAll(selector);
        var result = [];
        for (var i = 0; i < nodes.length; i++) {
            var el = nodes[i];
            var tag = el.tagName.toLowerCase();
            if (tag === 'svg' || tag === 'img' || tag === 'path' || tag === 'canvas' || tag === 'script' || tag === 'style') continue;
            var ce = el.getAttribute('contenteditable') || '';
            var role = el.getAttribute('role') || '';
            var fillable = (tag === 'input' || tag === 'textarea') ||
                           (ce && ce.toLowerCase() !== 'false') ||
                           role === 'textbox' || role === 'searchbox';
            result.push({
                field_index: i,
                tag: tag,
                type: (el.type || '').toLowerCase(),
                name: el.name || '',
                placeholder: el.placeholder || '',
                aria: el.getAttribute('aria-label') || '',
                class: el.className || '',
                visible: el.offsetParent !== null,
                disabled: el.disabled || false,
                role: role,
                tabindex: el.getAttribute('tabindex') || '',
                contenteditable: ce,
                text: (el.textContent || '').trim().substring(0, 100),
                value: el.value || '',
                fillable: fillable,
                id: el.id || ''
            });
        }
        return JSON.stringify(result);
    })()
    """
    raw = cdp_evaluate(cdp, js)
    if not raw:
        return []
    try:
        return json.loads(raw) if isinstance(raw, str) else (raw or [])
    except (json.JSONDecodeError, TypeError):
        return []


def _build_selector(meta: Dict[str, Any]) -> str:
    """Build a CSS selector from field metadata."""
    tag = meta.get("tag", "input")
    field_id = meta.get("id", "")
    name = meta.get("name", "")
    ftype = meta.get("type", "")

    if field_id:
        return f"#{field_id}"
    if name:
        return f'{tag}[name="{name}"]'
    if ftype:
        return f'{tag}[type="{ftype}"]'
    return tag


def _fill_field_cdp(cdp: CDPConnection, selector: str, value: str) -> bool:
    """Fill a field identified by CSS selector via CDP."""
    escaped = value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n")
    js = f"""
    (function() {{
        var el = document.querySelector('{selector}');
        if (!el) return 'not_found';
        el.focus();
        el.value = '{escaped}';
        el.dispatchEvent(new Event('input', {{bubbles: true}}));
        el.dispatchEvent(new Event('change', {{bubbles: true}}));
        return 'ok';
    }})()
    """
    result = cdp_evaluate(cdp, js)
    return result == "ok"


def _collect_buttons_cdp(cdp: CDPConnection) -> List[Dict[str, Any]]:
    """Collect visible buttons for LLM-based login button selection."""
    js = """
    (function() {
        var btns = document.querySelectorAll('button, input[type="submit"], input[type="button"], a[role="button"]');
        var result = [];
        for (var i = 0; i < btns.length; i++) {
            var el = btns[i];
            if (el.offsetParent === null) continue;
            result.push({
                button_index: i,
                tag: el.tagName.toLowerCase(),
                type: el.type || '',
                id: el.id || '',
                class: el.className || '',
                text: (el.textContent || el.value || '').trim().substring(0, 80),
                name: el.name || ''
            });
        }
        return JSON.stringify(result);
    })()
    """
    raw = cdp_evaluate(cdp, js)
    if not raw:
        return []
    try:
        return json.loads(raw) if isinstance(raw, str) else (raw or [])
    except (json.JSONDecodeError, TypeError):
        return []


def _click_button_by_index(cdp: CDPConnection, index: int) -> str:
    """Click a button by its DOM index."""
    js = f"""
    (function() {{
        var btns = document.querySelectorAll('button, input[type="submit"], input[type="button"], a[role="button"]');
        var visible = [];
        for (var i = 0; i < btns.length; i++) {{
            if (btns[i].offsetParent !== null) visible.push(btns[i]);
        }}
        if ({index} < visible.length) {{
            visible[{index}].click();
            return 'clicked: ' + (visible[{index}].id || visible[{index}].textContent || '').trim();
        }}
        return 'not_found';
    }})()
    """
    return cdp_evaluate(cdp, js) or "not_found"


def perform_login_cdp(
    cdp: CDPConnection,
    login_url: str,
    username: Optional[str],
    password: Optional[str],
    user_field: str = "username",
    pass_field: str = "password",
    chat_log_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """Perform login using CDP with LLM-based field analysis.

    Uses the same _llm_choose_fields() / _llm_pick_login_button() logic
    from login_flow.py for complex page analysis.
    """
    from PoCGen.core.login_flow import _llm_choose_fields, _llm_pick_login_button

    result = {"scenario": "no-login", "user_field": None, "pass_field": None, "clicked": False}

    if username is None and password is None:
        return result

    _log(f"CDP: navigating to login page {login_url}")
    cdp_navigate(cdp, login_url, wait_load=True, timeout=15)
    time.sleep(1)  # Let JS render

    # Scan input fields with full metadata (same format as login_flow._collect_inputs)
    inputs_info = _scan_inputs_cdp(cdp)
    _log(f"CDP: scanned {len(inputs_info)} input fields")

    # Use LLM to choose username/password fields
    llm_fields = _llm_choose_fields(inputs_info, chat_log_path=chat_log_path)

    user_selector = None
    pass_selector = None

    if llm_fields:
        user_idx = llm_fields.get("username_field_index")
        pass_idx = llm_fields.get("password_field_index")
        _log(f"CDP: LLM selected user_index={user_idx} pass_index={pass_idx}")

        if isinstance(user_idx, int) and 0 <= user_idx < len(inputs_info):
            meta = inputs_info[user_idx]
            if meta.get("fillable") and meta.get("visible"):
                user_selector = _build_selector(meta)
                _log(f"CDP: user field selector={user_selector}")
            else:
                _log(f"CDP: LLM user field not fillable/visible, fallback")
        if isinstance(pass_idx, int) and 0 <= pass_idx < len(inputs_info):
            meta = inputs_info[pass_idx]
            if meta.get("fillable") and meta.get("visible"):
                pass_selector = _build_selector(meta)
                _log(f"CDP: pass field selector={pass_selector}")
            else:
                _log(f"CDP: LLM pass field not fillable/visible, fallback")

    # Fallback: heuristic matching if LLM didn't select
    if user_selector is None:
        for meta in inputs_info:
            if not meta.get("fillable") or not meta.get("visible"):
                continue
            if meta.get("type") in ("password", "hidden"):
                continue
            if meta.get("type") in ("text", "email", "tel", ""):
                user_selector = _build_selector(meta)
                _log(f"CDP: fallback user selector={user_selector}")
                break

    if pass_selector is None:
        for meta in inputs_info:
            if not meta.get("fillable") or not meta.get("visible"):
                continue
            if meta.get("type") == "password":
                pass_selector = _build_selector(meta)
                _log(f"CDP: fallback pass selector={pass_selector}")
                break

    # Fill username
    if username and user_selector:
        _log(f"CDP: filling username via {user_selector}")
        if _fill_field_cdp(cdp, user_selector, username):
            result["user_field"] = user_selector
            result["scenario"] = "both_visible"

    # Fill password
    if password and pass_selector:
        _log(f"CDP: filling password via {pass_selector}")
        if _fill_field_cdp(cdp, pass_selector, password):
            result["pass_field"] = pass_selector

    # Click login button (LLM-assisted)
    time.sleep(0.5)
    buttons = _collect_buttons_cdp(cdp)
    clicked = False

    if buttons:
        llm_btn = _llm_pick_login_button(buttons, purpose="login", chat_log_path=chat_log_path)
        if llm_btn and isinstance(llm_btn.get("button_index"), int):
            btn_idx = llm_btn["button_index"]
            _log(f"CDP: LLM selected button index={btn_idx}")
            click_result = _click_button_by_index(cdp, btn_idx)
            _log(f"CDP: button click result: {click_result}")
            clicked = "not_found" not in str(click_result)
        else:
            # Fallback: click first visible button with login-like text
            for btn in buttons:
                text = (btn.get("text") or "").lower()
                if any(kw in text for kw in ("login", "log in", "sign in", "submit", "登录", "确定")):
                    click_result = _click_button_by_index(cdp, btn["button_index"])
                    _log(f"CDP: fallback button click: {click_result}")
                    clicked = "not_found" not in str(click_result)
                    break

    result["clicked"] = clicked

    # Wait for post-login navigation
    if clicked:
        time.sleep(2)
        cdp.poll_events(timeout=5)

    return result


# ─── POST Request Capture ──────────────────────────────────────────────────


def _format_raw_http(request: Dict, body: Optional[str] = None) -> str:
    """Format a CDP Network.requestWillBeSent event as raw HTTP."""
    req = request.get("request", {})
    url = req.get("url", "")
    parsed = urlparse(url)
    method = req.get("method", "GET")
    path_q = parsed.path or "/"
    if parsed.query:
        path_q += f"?{parsed.query}"

    lines = [f"{method} {path_q} HTTP/1.1"]
    headers = req.get("headers", {})
    # Add Host if missing
    if "Host" not in headers and "host" not in headers and parsed.netloc:
        lines.append(f"Host: {parsed.netloc}")
    for name, value in headers.items():
        lines.append(f"{name}: {value}")
    lines.append("")

    post_data = body or req.get("postData", "")
    if post_data:
        lines.append(post_data)

    return "\n".join(lines)


# ─── Main Entry Point ──────────────────────────────────────────────────────


def sample_target_with_cdp(
    target: str,
    login_url: Optional[str] = None,
    login_username: Optional[str] = None,
    login_password: Optional[str] = None,
    login_user_field: str = "username",
    login_pass_field: str = "password",
    headless: Optional[bool] = None,
    preview_chars: Optional[int] = None,
    capture_posts: bool = True,
    capture_cookies: bool = True,
    capture_socket_messages: bool = False,
) -> TargetSample:
    """Use CDP to optionally log in and capture the target page.

    Returns TargetSample with page HTML, cookies, POST samples, etc.
    """

    if headless is None:
        headless_flag = str(getattr(SETTINGS, "browser_headless", "true")).lower() not in {"0", "false", "no", "off"}
    else:
        headless_flag = headless
    login_page = login_url or urljoin(target.rstrip("/") + "/", "login")
    preview_len = preview_chars or SETTINGS.sample_preview_chars

    captured_posts: List[str] = []
    captured_cookie_header: Optional[str] = None

    # Ensure Chrome is running
    port = ensure_chrome(headless=headless_flag)

    # Get or create page
    ws_url = get_page_ws_url(port, target_url=None)
    _log(f"CDP: connecting to {ws_url}")
    cdp = CDPConnection(ws_url)

    try:
        # Enable required domains
        cdp.send("Page.enable")
        cdp.send("Network.enable")
        cdp.send("Runtime.enable")

        # Track POST requests
        post_events: List[Dict] = []

        def on_request(event: Dict) -> None:
            req = event.get("params", {}).get("request", {})
            if req.get("method", "").upper() == "POST":
                post_events.append(event.get("params", {}))

        # We'll collect events via polling instead of callbacks
        cdp.clear_events()

        # Create chat log path for LLM field analysis
        from PoCGen.core.logger import _create_login_chat_file
        chat_log_path = _create_login_chat_file()
        if chat_log_path:
            from PoCGen.core.logger import _append_login_chat
            password_state = "<provided>" if login_password else "<none>"
            username_state = login_username if login_username is not None else "<none>"
            _append_login_chat(
                chat_log_path,
                "system",
                f"Target: {target}\nLogin URL: {login_page}\nCredentials: username={username_state} password={password_state}",
            )

        # Login
        login_result = perform_login_cdp(
            cdp, login_page, login_username, login_password,
            login_user_field, login_pass_field,
            chat_log_path=chat_log_path,
        )

        # Collect POST requests from login
        for ev in cdp.get_events("Network.requestWillBeSent"):
            req = ev.get("params", {}).get("request", {})
            if req.get("method", "").upper() == "POST":
                raw = _format_raw_http(ev.get("params", {}))
                if capture_posts and raw not in captured_posts:
                    captured_posts.append(raw)
                    # Save to disk
                    log_dir = _request_log_dir()
                    _ensure_dir(log_dir)
                    ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
                    fname = os.path.join(log_dir, f"cdp_login_{ts}_{len(captured_posts):04d}.http")
                    with open(fname, "w", encoding="utf-8") as fh:
                        fh.write(raw)
                    _log(f"CDP: saved POST sample {fname}")

        # Navigate to target if different from current URL
        current_url = cdp_evaluate(cdp, "window.location.href") or ""
        if not current_url.startswith(target.rstrip("/")):
            _log(f"CDP: navigating to target {target}")
            cdp.clear_events()
            cdp_navigate(cdp, target, wait_load=True, timeout=20)
            time.sleep(1)

            # Collect any POST requests from target page
            for ev in cdp.get_events("Network.requestWillBeSent"):
                req = ev.get("params", {}).get("request", {})
                if req.get("method", "").upper() == "POST":
                    raw = _format_raw_http(ev.get("params", {}))
                    if capture_posts and raw not in captured_posts:
                        captured_posts.append(raw)

        # Capture cookies
        if capture_cookies:
            cookies = cdp_get_cookies(cdp)
            pairs = []
            for ck in cookies:
                name = ck.get("name")
                value = ck.get("value")
                if name and value:
                    pairs.append(f"{name}={value}")
            if pairs:
                captured_cookie_header = "; ".join(pairs)
                # Save to disk
                cookie_dir = _cookie_dir()
                _ensure_dir(cookie_dir)
                ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
                fname = os.path.join(cookie_dir, f"cookies_cdp_{ts}.json")
                with open(fname, "w", encoding="utf-8") as fh:
                    json.dump({"tag": "cdp_login", "cookies": cookies}, fh, indent=2)
                _log(f"CDP: saved cookies to {fname}")

        # Get page HTML
        html = cdp_get_page_html(cdp) or ""
        status_code = 200  # CDP doesn't directly expose status for navigation
        content_type = "text/html"

        # Build result
        strategy = login_result.get("scenario", "no-login")
        if login_username or login_password:
            strategy = login_result.get("scenario", "unknown")

        artifacts = (
            f"Captured artifacts -> POST:{len(captured_posts)} "
            f"Cookie:{'yes' if captured_cookie_header else 'no'} Socket:0"
        )
        request_template = (
            "CDP GET (rendered page)\n"
            f"Target: {target}\n"
            f"Login URL: {login_page}\n"
            f"Headless: {headless_flag}\n"
            f"Login strategy: {strategy}\n"
            f"Detected fields: user={login_result.get('user_field', '<none>')} "
            f"pass={login_result.get('pass_field', '<none>')}\n"
            f"{artifacts}"
        )

        body = html
        if len(body) > preview_len:
            preview = body[:preview_len] + "\n... <truncated>"
        else:
            preview = body

        return TargetSample(
            url=target,
            status_code=status_code,
            content_type=content_type,
            encoding="utf-8",
            body_preview=preview,
            request_template=request_template,
            response_headers="",
            post_samples=captured_posts,
            cookies_header=captured_cookie_header if capture_cookies else None,
            socket_samples=[],
        )

    finally:
        cdp.close()


# Public alias — callers can do `from PoCGen.core.cdp_sampler import sample_target`
sample_target = sample_target_with_cdp


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CDP 浏览器探测目标（登录、采集 Cookie/POST/Socket）")
    parser.add_argument("target", help="目标 URL，如 http://192.168.6.2")
    parser.add_argument("--login-url", default=None, help="登录页面 URL")
    parser.add_argument("--login-username", default=None, help="登录用户名")
    parser.add_argument("--login-password", default=None, help="登录密码")
    parser.add_argument("--login-user-field", default="username", help="用户名字段名")
    parser.add_argument("--login-pass-field", default="password", help="密码字段名")
    parser.add_argument("--no-headless", action="store_true", help="显示浏览器窗口")
    parser.add_argument("--no-posts", action="store_true", help="不采集 POST 请求")
    parser.add_argument("--no-cookies", action="store_true", help="不采集 Cookie")
    parser.add_argument("--socket", action="store_true", help="采集 Socket.IO 消息")
    args = parser.parse_args()

    sample = sample_target(
        target=args.target,
        login_url=args.login_url,
        login_username=args.login_username,
        login_password=args.login_password,
        login_user_field=args.login_user_field,
        login_pass_field=args.login_pass_field,
        headless=not args.no_headless,
        capture_posts=not args.no_posts,
        capture_cookies=not args.no_cookies,
        capture_socket_messages=args.socket,
    )

    print(f"URL: {sample.url}")
    print(f"Status: {sample.status_code}")
    print(f"Content-Type: {sample.content_type}")
    print(f"POST samples: {len(sample.post_samples)}")
    print(f"Cookie: {'yes' if sample.cookies_header else 'no'}")
    print(f"Socket samples: {len(sample.socket_samples)}")
    print(f"Body preview ({len(sample.body_preview)} chars):")
    print(sample.body_preview[:500])
    if sample.post_samples:
        print(f"\n--- POST samples ---")
        for i, p in enumerate(sample.post_samples):
            print(f"\n#{i+1}:\n{p[:500]}")
    if sample.cookies_header:
        print(f"\nCookie: {sample.cookies_header[:200]}")
