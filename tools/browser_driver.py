# Playwright-based browser driver with REST API, proxied through Burp
# - Exposes /navigate, /click, /fill endpoints for model-driven automation
# - All traffic is routed via Burp proxy (127.0.0.1:8080 by default)
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
LISTEN_HOST = os.environ.get("BROWSER_DRV_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("BROWSER_DRV_PORT", "7000"))

async def init_browser():
    global PW, BROWSER, CTX, PAGE
    PW = await async_playwright().start()
    BROWSER = await PW.chromium.launch(headless=False)
    CTX = await BROWSER.new_context(proxy={"server": BURP_PROXY})
    PAGE = await CTX.new_page()

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

async def run_app():
    await init_browser()
    app = web.Application()
    app.router.add_post("/navigate", navigate)
    app.router.add_post("/click", click)
    app.router.add_post("/fill", fill)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, LISTEN_HOST, LISTEN_PORT)
    await site.start()
    print(f"Browser driver listening on http://{LISTEN_HOST}:{LISTEN_PORT}, proxy {BURP_PROXY}")
    try:
        while True:
            await asyncio.sleep(3600)
    finally:
        await close_browser()

if __name__ == "__main__":
    asyncio.run(run_app())
