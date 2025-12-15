from __future__ import annotations

import os
from datetime import datetime
from typing import Optional

import httpx
from playwright.sync_api import sync_playwright
from urllib.parse import urljoin

from PoCGen.config.config import SETTINGS

LOG_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "logs"))
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "playwright_login.log")


def login_http(
    target: str,
    login_url: Optional[str],
    login_username: Optional[str],
    login_password: Optional[str],
    login_user_field: str,
    login_pass_field: str,
    login_method: str,
) -> Optional[httpx.Client]:
    url = login_url or urljoin(target.rstrip("/") + "/", "login")
    data = {}
    if login_username is not None:
        data[login_user_field] = login_username
    if login_password is not None:
        data[login_pass_field] = login_password
    if not data:
        return None

    client_kwargs = {
        "timeout": SETTINGS.validation_timeout,
        "verify": False,
        "follow_redirects": True,
    }
    if SETTINGS.http_proxy:
        client_kwargs["proxies"] = SETTINGS.http_proxy

    session = httpx.Client(**client_kwargs)
    resp = session.request(login_method.upper(), url, data=data)
    _log_login(f"http_login status={resp.status_code} url={url}")
    return session


def login_playwright(
    target: str,
    login_url: Optional[str],
    login_username: Optional[str],
    login_password: Optional[str],
    login_user_field: str,
    login_pass_field: str,
    browser_headless: Optional[bool],
) -> Optional[httpx.Client]:
    url = login_url or urljoin(target.rstrip("/") + "/", "login")
    user_val = "" if login_username is None else login_username
    pass_val = login_password
    if pass_val is None and not user_val:
        return None

    client_kwargs = {
        "timeout": SETTINGS.validation_timeout,
        "verify": False,
    }
    if SETTINGS.http_proxy:
        client_kwargs["proxies"] = SETTINGS.http_proxy

    headless_flag = browser_headless
    if headless_flag is None:
        headless_flag = os.getenv("BROWSER_HEADLESS", "true").lower() not in {"0", "false", "no", "off"}

    cookies = []
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless_flag)
        context = browser.new_context()
        page = context.new_page()
        page.goto(url, wait_until="networkidle")

        try:
            if user_val is not None:
                page.fill(f"input[name='{login_user_field}']", user_val)
            if pass_val is not None:
                page.fill(f"input[name='{login_pass_field}']", pass_val)
        except Exception:
            pass

        submitted = False
        for sel in ["input[type='submit']", "button[type='submit']"]:
            try:
                page.click(sel)
                submitted = True
                break
            except Exception:
                continue
        if not submitted:
            try:
                page.press(f"input[name='{login_pass_field}']", "Enter")
            except Exception:
                pass

        page.wait_for_timeout(1000)
        try:
            page.goto(target, wait_until="networkidle")
            page.wait_for_timeout(500)
        except Exception:
            pass

        cookies = context.cookies()
        browser.close()

    session = httpx.Client(**client_kwargs)
    for ck in cookies:
        session.cookies.set(ck.get("name"), ck.get("value"), domain=ck.get("domain"), path=ck.get("path", "/"))
    _log_login(f"browser_login cookies={len(cookies)} url={url} headless={headless_flag}")
    return session


def _log_login(message: str) -> None:
    try:
        timestamp = datetime.utcnow().isoformat()
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(f"[{timestamp} UTC] {message}\n")
    except Exception:
        pass
