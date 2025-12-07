"""
Unified bridge service for model tools:
- Proxies simple REST endpoints to Browser Driver (Playwright) and Burp Extender API.
- Provide consistent, minimal API for LLM to call.

Endpoints:
  POST /browser/navigate {url}
  POST /browser/click {selector}
  POST /browser/fill {selector,text}

  GET  /burp/list
  GET  /burp/get_raw?id=N           -> returns octet-stream
  POST /burp/replay_raw?host=...&port=...&https=true|false   (body: octet-stream)

Environment:
  BRIDGE_HOST=127.0.0.1
  BRIDGE_PORT=7002
  BROWSER_API=http://127.0.0.1:7000
  BURP_API=http://127.0.0.1:7001

Run:
  pip install aiohttp requests
  python PoCGen/tools/bridge.py
"""
import os
import asyncio
from aiohttp import web
import requests

BRIDGE_HOST = os.environ.get("BRIDGE_HOST", "127.0.0.1")
BRIDGE_PORT = int(os.environ.get("BRIDGE_PORT", "7002"))
BROWSER_API = os.environ.get("BROWSER_API", "http://127.0.0.1:7000")
BURP_API = os.environ.get("BURP_API", "http://127.0.0.1:7001")

# --- Browser endpoints ---
async def browser_navigate(req: web.Request):
    data = await req.json()
    r = requests.post(f"{BROWSER_API}/navigate", json={"url": data["url"]})
    return web.json_response(r.json(), status=r.status_code)

async def browser_click(req: web.Request):
    data = await req.json()
    r = requests.post(f"{BROWSER_API}/click", json={"selector": data["selector"]})
    return web.json_response(r.json(), status=r.status_code)

async def browser_fill(req: web.Request):
    data = await req.json()
    r = requests.post(f"{BROWSER_API}/fill", json={"selector": data["selector"], "text": data.get("text", "")})
    return web.json_response(r.json(), status=r.status_code)

# --- Burp endpoints ---
async def burp_list(req: web.Request):
    r = requests.get(f"{BURP_API}/list")
    return web.json_response(r.json(), status=r.status_code)

async def burp_get_raw(req: web.Request):
    id_ = req.query.get("id")
    r = requests.get(f"{BURP_API}/get_raw", params={"id": id_})
    return web.Response(body=r.content, status=r.status_code, content_type="application/octet-stream")

async def burp_replay_raw(req: web.Request):
    host = req.query.get("host")
    port = req.query.get("port")
    https = req.query.get("https", "false")
    body = await req.read()
    r = requests.post(f"{BURP_API}/replay_raw", params={"host": host, "port": port, "https": https}, data=body,
                      headers={"Content-Type": "application/octet-stream"})
    return web.Response(body=r.content, status=r.status_code, content_type="application/octet-stream")

async def run_app():
    app = web.Application()
    app.router.add_post("/browser/navigate", browser_navigate)
    app.router.add_post("/browser/click", browser_click)
    app.router.add_post("/browser/fill", browser_fill)

    app.router.add_get("/burp/list", burp_list)
    app.router.add_get("/burp/get_raw", burp_get_raw)
    app.router.add_post("/burp/replay_raw", burp_replay_raw)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, BRIDGE_HOST, BRIDGE_PORT)
    await site.start()
    print(f"Bridge listening on http://{BRIDGE_HOST}:{BRIDGE_PORT}")
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    asyncio.run(run_app())
