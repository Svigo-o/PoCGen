# Playwright-based browser driver with REST API, proxied through Burp (optional)
# - Exposes /navigate, /click, /fill for basic DOM automation
# - Adds /network_log (GET) and /clear_log (POST) to取回最近的 request/response 概要
# - Adds /har (GET) to导出当前内存中的日志为 HAR-like 结构
# - 默认可选代理：BURP_PROXY_ENABLE=true 时才走代理
# - Requires: pip install playwright aiohttp; then python -m playwright install

import asyncio
import os
from aiohttp import web
from playwright.async_api import async_playwright

PW = None
BROWSER = None
CTX = None
PAGE = None

BURP_PROXY = os.environ.get("BURP_PROXY", "http://127.0.0.1:8080")
BURP_PROXY_ENABLE = os.environ.get("BURP_PROXY_ENABLE", "false").lower() not in {"0", "false", "no", "off"}
LISTEN_HOST = os.environ.get("BROWSER_DRV_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("BROWSER_DRV_PORT", "7000"))

# 简单的内存日志（避免过大），最多保留 N 条
NETWORK_LOG = []
MAX_LOG_ENTRIES = int(os.environ.get("BROWSER_MAX_LOG", "200"))

def _get_headless_flag() -> bool:
    raw = os.environ.get("BROWSER_HEADLESS", "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}

HEADLESS = _get_headless_flag()

async def init_browser():
    global PW, BROWSER, CTX, PAGE
    PW = await async_playwright().start()
    BROWSER = await PW.chromium.launch(headless=HEADLESS)
    proxy_cfg = {"server": BURP_PROXY} if BURP_PROXY_ENABLE else None
    CTX = await BROWSER.new_context(proxy=proxy_cfg)
    PAGE = await CTX.new_page()
    PAGE.on("request", _on_request)
    PAGE.on("response", _on_response)

async def close_browser():
    global PW, BROWSER
    try:
        if BROWSER:
            await BROWSER.close()
    finally:
        if PW:
            await PW.stop()

async def navigate(req: web.Request):
    data = await req.json()
    url = data.get("url")
    assert url, "url is required"
    await PAGE.goto(url)
    return web.json_response({"status": "ok"})

async def click(req: web.Request):
    data = await req.json()
    selector = data.get("selector")
    assert selector, "selector is required"
    await PAGE.click(selector)
    return web.json_response({"status": "ok"})

async def fill(req: web.Request):
    data = await req.json()
    selector = data.get("selector")
    text = data.get("text", "")
    assert selector is not None, "selector is required"
    await PAGE.fill(selector, text)
    return web.json_response({"status": "ok"})


async def network_log(_: web.Request):
    return web.json_response({"entries": NETWORK_LOG})


async def clear_log(_: web.Request):
    NETWORK_LOG.clear()
    return web.json_response({"status": "cleared"})


async def har(_: web.Request):
    # 生成一个简单 HAR-like 结构，方便后端解析
    har_like = {
        "log": {
            "version": "1.2",
            "creator": {"name": "browser_driver", "version": "0.1"},
            "entries": NETWORK_LOG,
        }
    }
    return web.json_response(har_like)

async def run_app():
    await init_browser()
    app = web.Application()
    app.router.add_post("/navigate", navigate)
    app.router.add_post("/click", click)
    app.router.add_post("/fill", fill)
    app.router.add_get("/network_log", network_log)
    app.router.add_post("/clear_log", clear_log)
    app.router.add_get("/har", har)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, LISTEN_HOST, LISTEN_PORT)
    await site.start()
    proxy_msg = BURP_PROXY if BURP_PROXY_ENABLE else "(direct)"
    print(f"Browser driver listening on http://{LISTEN_HOST}:{LISTEN_PORT}, proxy {proxy_msg}")
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        await close_browser()


# --- helpers ---

async def _on_request(request):
    entry = {
        "type": "request",
        "method": request.method,
        "url": request.url,
        "headers": await _safe_headers(request.headers),
    }
    _push_log(entry)


async def _on_response(response):
    try:
        body_bytes = await response.body()
        body_preview = body_bytes[:2048].decode(errors="ignore") if body_bytes else ""
    except Exception:
        body_preview = ""

    entry = {
        "type": "response",
        "url": response.url,
        "status": response.status,
        "headers": await _safe_headers(response.headers),
        "body_preview": body_preview,
    }
    _push_log(entry)


async def _safe_headers(headers):
    try:
        return dict(headers)
    except Exception:
        return {}


def _push_log(entry):
    NETWORK_LOG.append(entry)
    if len(NETWORK_LOG) > MAX_LOG_ENTRIES:
        del NETWORK_LOG[: len(NETWORK_LOG) - MAX_LOG_ENTRIES]

if __name__ == "__main__":
    asyncio.run(run_app())
