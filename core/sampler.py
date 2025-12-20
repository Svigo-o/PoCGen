from __future__ import annotations

from typing import Optional, Tuple, List, Dict, Any

import json
import re

from playwright.sync_api import sync_playwright

from PoCGen.llm.client import LLMClient, ChatMessage

from PoCGen.config.config import SETTINGS
from PoCGen.core.target_profile import TargetSample


LOG_DIR = None
LOG_FILE = None
REQUEST_LOG_DIR = "/home/li/LLM_POC/PoCGen/output/request"


def _ensure_log():
    global LOG_DIR, LOG_FILE
    if LOG_DIR:
        return
    import os

    LOG_DIR = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "logs"))
    os.makedirs(LOG_DIR, exist_ok=True)
    LOG_FILE = os.path.join(LOG_DIR, "playwright_probe.log")


def _log(message: str) -> None:
    try:
        _ensure_log()
        from datetime import datetime, timezone, timedelta

        tz = timezone(timedelta(hours=8))
        ts = datetime.now(tz).strftime("%Y-%m-%dT%H:%M:%S")
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(f"[{ts}] {message}\n")
    except Exception:
        pass


def _ensure_request_dir():
    try:
        import os

        os.makedirs(REQUEST_LOG_DIR, exist_ok=True)
    except Exception:
        pass


def _setup_network_logging(context, tag: str = "login"):
    """Attach Playwright listeners to dump POST request raw payloads.

    Only outgoing POST requests are captured,并以标准 HTTP 报文格式写入：
    请求行 + 头部 + 空行 + body。
    """

    import os
    import time
    from urllib.parse import urlsplit

    _ensure_request_dir()

    seq = {"n": 0}

    def _safe_str_body(body: Any, limit: int = 8000) -> str:
        try:
            if body is None:
                return ""
            if isinstance(body, (bytes, bytearray)):
                return body.decode("utf-8", errors="replace")[:limit]
            text = str(body)
            return text[:limit]
        except Exception:
            return "<body decode failed>"

    def _on_request(request):
        try:
            method = (request.method or "").upper()
            if method != "POST":
                return
            seq["n"] += 1
            req_id = seq["n"]
            ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
            headers = dict(getattr(request, "headers", {}) or {})
            body = _safe_str_body(getattr(request, "post_data", None))
            parsed = urlsplit(request.url or "")
            path_q = parsed.path or "/"
            if parsed.query:
                path_q += f"?{parsed.query}"

            request_line = f"{method} {path_q} HTTP/1.1"

            # ensure Host header存在
            has_host = any(k.lower() == "host" for k in headers.keys())
            if not has_host and parsed.netloc:
                headers = {"Host": parsed.netloc, **headers}

            fname = os.path.join(
                REQUEST_LOG_DIR,
                f"{tag}_{ts}_{req_id:04d}.http",
            )

            lines = []
            lines.append(request_line)
            for k, v in headers.items():
                lines.append(f"{k}: {v}")
            lines.append("")
            if body:
                lines.append(body)
            content = "\n".join(lines)

            with open(fname, "w", encoding="utf-8", errors="replace") as fh:
                fh.write(content)
            _log(f"network log saved {fname} method=POST url={request.url}")
        except Exception as exc:
            _log(f"network log request hook failed: {exc}")

    try:
        context.on("request", _on_request)
        _log(f"network logging attached tag={tag} dir={REQUEST_LOG_DIR} mode=POST")
    except Exception as exc:
        _log(f"attach network logging failed: {exc}")


def sample_target_with_playwright(
    target: str,
    login_url: Optional[str] = None,
    login_username: Optional[str] = None,
    login_password: Optional[str] = None,
    login_user_field: str = "username",
    login_pass_field: str = "password",
    headless: Optional[bool] = None,
    preview_chars: Optional[int] = None,
) -> TargetSample:
    """Use Playwright to perform (optional) login and fetch the target page content.

    This captures the rendered page after authentication (if creds provided),
    then converts it into TargetSample for downstream prompt usage.
    """
    from urllib.parse import urljoin

    headless_flag = headless
    if headless_flag is None:
        headless_flag = str(getattr(SETTINGS, "browser_headless", "true")).lower() not in {"0", "false", "no", "off"}

    login_page = login_url or urljoin(target.rstrip("/") + "/", "login")
    preview_len = preview_chars or SETTINGS.sample_preview_chars

    def _detect_form_fields(page) -> Tuple[str, str, List[str]]:
        user_field = login_user_field
        pass_field = login_pass_field
        candidates: List[str] = []
        try:
            # prefer visible inputs; ignore hidden fields
            pwd_el = page.query_selector("input[type='password']")
            if pwd_el and pwd_el.is_visible():
                pass_field = pwd_el.get_attribute("name") or pass_field
                candidates.append(f"password:{pass_field}")

            for selector in [
                "input[name*='user']",
                "input[name*='login']",
                "input[name*='email']",
                "input[type='text']",
            ]:
                el = page.query_selector(selector)
                if el and el.is_visible():
                    user_field = el.get_attribute("name") or user_field
                    candidates.append(f"user:{user_field}")
                    break
        except Exception as exc:
            _log(f"detect form fields failed: {exc}")
        return user_field, pass_field, candidates

    def _extract_forms(page) -> List[Dict[str, Any]]:
        forms: List[Dict[str, Any]] = []
        try:
            form_nodes = page.query_selector_all("form")
            for idx, form in enumerate(form_nodes):
                method = (form.get_attribute("method") or "get").lower()
                action = form.get_attribute("action") or ""
                inputs = []
                fields = form.query_selector_all("input, textarea, select")
                for inp in fields:
                    try:
                        itype = (inp.get_attribute("type") or "text").lower()
                        name = inp.get_attribute("name") or ""
                        placeholder = inp.get_attribute("placeholder") or ""
                        label = inp.get_attribute("aria-label") or ""
                        try:
                            value = inp.get_attribute("value") or inp.inner_text() or ""
                        except Exception:
                            value = ""
                        try:
                            visible = inp.is_visible()
                        except Exception:
                            visible = False
                        try:
                            disabled = inp.is_disabled()
                        except Exception:
                            disabled = False
                        try:
                            readonly = inp.get_attribute("readonly") is not None
                        except Exception:
                            readonly = False
                        inputs.append(
                            {
                                "name": name,
                                "type": itype,
                                "placeholder": placeholder,
                                "label": label,
                                "value": value,
                                "visible": visible,
                                "disabled": disabled,
                                "readonly": readonly,
                            }
                        )
                    except Exception:
                        continue
                forms.append({"index": idx, "method": method, "action": action, "inputs": inputs})
        except Exception as exc:
            _log(f"extract forms failed: {exc}")
        return forms

    def _extract_buttons(page) -> List[Dict[str, Any]]:
        buttons: List[Dict[str, Any]] = []
        try:
            nodes = page.query_selector_all("button, input[type='button'], input[type='submit'], a[role='button']")
            for idx, btn in enumerate(nodes):
                try:
                    if not btn.is_visible():
                        continue
                    text = (btn.inner_text() or "").strip()
                    value = (btn.get_attribute("value") or "").strip()
                    btn_type = (btn.get_attribute("type") or "").strip()
                    btn_id = btn.get_attribute("id") or ""
                    btn_class = btn.get_attribute("class") or ""
                    aria = btn.get_attribute("aria-label") or ""
                    href = btn.get_attribute("href") or ""
                    form_meta = None
                    try:
                        form_meta = btn.evaluate(
                            """
                            (el) => {
                                let p = el;
                                while (p) {
                                    if (p.tagName && p.tagName.toLowerCase() === 'form') {
                                        return {
                                            method: (p.getAttribute('method') || '').toLowerCase(),
                                            action: p.getAttribute('action') || ''
                                        };
                                    }
                                    p = p.parentElement;
                                }
                                return null;
                            }
                            """
                        )
                    except Exception:
                        form_meta = None
                    buttons.append(
                        {
                            "index": idx,
                            "text": text,
                            "value": value,
                            "type": btn_type,
                            "id": btn_id,
                            "class": btn_class,
                            "aria": aria,
                            "href": href,
                            "form_method": (form_meta or {}).get("method") or "",
                            "form_action": (form_meta or {}).get("action") or "",
                        }
                    )
                except Exception:
                    continue
        except Exception as exc:
            _log(f"extract buttons failed: {exc}")
        return buttons

    def _parse_llm_json(resp: str, expected_keys: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        if not resp:
            return None

        def _try_load(text: str) -> Optional[Dict[str, Any]]:
            try:
                obj = json.loads(text)
                if isinstance(obj, dict):
                    if expected_keys:
                        # keep only expected keys when present
                        return {k: obj.get(k) for k in expected_keys}
                    return obj
            except Exception:
                return None
            return None
        obj = _try_load(resp)
        if obj is not None:
            return obj
        # fallback: extract first JSON object substring
        m = re.search(r"\{.*\}", resp, flags=re.S)
        if m:
            obj = _try_load(m.group(0))
            if obj is not None:
                return obj
        return None

    def _ask_llm(prompt: str, expected_keys: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        try:
            client = LLMClient()
            resp = client.chat([ChatMessage(role="user", content=prompt)], temperature=0, max_tokens=800)
            client.close()
            _log(f"llm raw reply: {resp[:500]}")
            parsed = _parse_llm_json(resp, expected_keys=expected_keys)
            if parsed is None:
                raise ValueError(f"invalid json from llm: {resp[:200]}")
            return parsed
        except Exception as exc:
            _log(f"llm call failed: {exc}")
            return None

    def _llm_pick_login_form(forms: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not forms:
            return None
        prompt = (
            "你是安全测试助手。给出网页表单列表，请选出最可能的登录表单并指出用户名/密码字段名。"
            "严格输出 JSON，不能包含除 JSON 外的任何内容，不要加反引号、说明或前缀。"
            "格式: {\"form_index\": int, \"username_field\": str, \"password_field\": str}."
            "若无法确定，返回空对象 {}。\n"
            f"表单: {forms}"
        )
        return _ask_llm(prompt, expected_keys=["form_index", "username_field", "password_field"])

    def _llm_pick_login_button(buttons: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not buttons:
            return None
        prompt = (
            "你是安全测试助手。下面是登录页上可见的按钮列表，请选择最可能用于登录的按钮。"
            "严格输出 JSON，不能包含除 JSON 外的任何内容，不要加反引号、说明或前缀。"
            "格式: {\"button_index\": int}，若无法判断返回 {}。\n"
            f"按钮列表: {buttons}"
        )
        return _ask_llm(prompt, expected_keys=["button_index"])

    def _save_cookies(context, tag: str):
        try:
            _ensure_log()
            import os
            import time

            cookies_dir = getattr(SETTINGS, "cookie_dir", None) or os.path.normpath(
                os.path.join(os.path.dirname(__file__), "..", "cookie")
            )
            os.makedirs(cookies_dir, exist_ok=True)

            ck = context.cookies()
            payload = {"tag": tag, "cookies": ck}
            ts = time.strftime("%Y%m%d_%H%M%S", time.localtime())
            fname = os.path.join(cookies_dir, f"cookies_{tag}_{ts}.json")
            with open(fname, "w", encoding="utf-8") as fh:
                json.dump(payload, fh, ensure_ascii=False, indent=2)
            _log(f"saved cookies to {fname}")
        except Exception as exc:
            _log(f"save cookies failed: {exc}")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless_flag)
        context = browser.new_context()
        _setup_network_logging(context, tag="login_flow")
        page = context.new_page()

        def _sample_value(name: str, input_type: str) -> str:
            lname = (name or "").lower()
            if "pass" in lname:
                return login_password or "admin"
            if "user" in lname or "login" in lname:
                return login_username or "admin"

        _log(f"open {login_page}")
        page.goto(login_page, wait_until="networkidle", timeout=5000)

        user_field, pass_field, candidates = _detect_form_fields(page)
        _log(f"静态规则初匹配： user='{user_field}' pass='{pass_field}' candidates={candidates}")

        orig_user_field, orig_pass_field = user_field, pass_field

        # LLM-assisted login field selection
        forms_info = _extract_forms(page)
        llm_login = _llm_pick_login_form(forms_info)
        if llm_login:
            try:
                suggested_user = llm_login.get("username_field") or orig_user_field
                suggested_pass = llm_login.get("password_field") or orig_pass_field

                def _visible_input(name: str) -> bool:
                    try:
                        loc = page.locator(f"input[name='{name}']")
                        return loc.is_visible()
                    except Exception:
                        return False

                if suggested_user and _visible_input(suggested_user):
                    user_field = suggested_user
                else:
                    _log(f"LLM user field '{suggested_user}' not visible, keep '{orig_user_field}'")

                if suggested_pass and _visible_input(suggested_pass):
                    pass_field = suggested_pass
                else:
                    _log(f"LLM pass field '{suggested_pass}' not visible, keep '{orig_pass_field}'")

                _log(f"LLM login selection form_index={llm_login.get('form_index')} user_field={user_field} pass_field={pass_field}")
            except Exception as exc:
                _log(f"apply llm login selection failed: {exc}")

        # optional login
        if login_username is not None:
            try:
                user_locator = page.locator(f"input[name='{user_field}']")
                if user_locator.is_visible():
                    user_locator.fill(login_username, timeout=5000)
                    _log(f"filled user into {user_field}")
                else:
                    _log(f"skip user field {user_field} (not visible)")
            except Exception as exc:
                _log(f"fill user failed: {exc}")
        if login_password is not None:
            try:
                pass_locator = page.locator(f"input[name='{pass_field}']")
                if pass_locator.is_visible():
                    pass_locator.fill(login_password, timeout=5000)
                    _log(f"filled password into {pass_field}")
                else:
                    _log(f"skip password field {pass_field} (not visible)")
            except Exception as exc:
                _log(f"fill password failed: {exc}")

        if login_password is not None or login_username is not None:
            try:
                buttons = page.query_selector_all("button, input[type='button'], input[type='submit'], a[role='button']")
                labels = []
                visible_buttons = []

                def _describe(btn):
                    try:
                        tag = (btn.evaluate("e => e.tagName") or "").lower()
                        btn_type = (btn.get_attribute("type") or "").lower()
                        btn_id = btn.get_attribute("id") or ""
                        btn_cls = btn.get_attribute("class") or ""
                        return f"{tag}[type={btn_type}] id={btn_id} class={btn_cls}"
                    except Exception:
                        return "<unknown>"

                for idx, btn in enumerate(buttons):
                    try:
                        if not btn.is_visible():
                            continue
                        text = (btn.inner_text() or "").strip()
                        value = (btn.get_attribute("value") or "").strip()
                        label = text or value or (btn.get_attribute("href") or "").strip() or "<no-text>"
                        labels.append(f"[{idx}] {label} ({_describe(btn)})")
                        visible_buttons.append((idx, btn, label))
                    except Exception:
                        continue

                _log(f"visible buttons: {labels}")

                # LLM choose login button among visible ones
                llm_buttons_info = _extract_buttons(page)
                chosen = None
                chosen_idx = None
                chosen_label = None
                llm_btn = _llm_pick_login_button(llm_buttons_info)
                if llm_btn:
                    try:
                        idx_sel = llm_btn.get("button_index")
                        if idx_sel is not None and 0 <= idx_sel < len(buttons):
                            btn = buttons[idx_sel]
                            if btn.is_visible():
                                chosen = btn
                                chosen_idx = idx_sel
                                chosen_label = (btn.inner_text() or btn.get_attribute("value") or "").strip() or "<no-text>"
                                _log(f"LLM picked login button idx={chosen_idx} label='{chosen_label}'")
                    except Exception as exc:
                        _log(f"apply LLM login button failed: {exc}")

                # fallback: pick first visible containing 'log'
                if chosen is None:
                    for idx, btn, label in visible_buttons:
                        if "log" in label.lower():
                            chosen = btn
                            chosen_idx = idx
                            chosen_label = label
                            break

                if chosen is None and visible_buttons:
                    # last resort: first visible
                    chosen_idx, chosen, chosen_label = visible_buttons[0]

                if chosen is not None:
                    chosen.click(timeout=5000)
                    _log(f"clicked login button idx={chosen_idx} label='{chosen_label}'")
                else:
                    _log("no visible buttons to click")
            except Exception as exc:
                _log(f"button scan/click failed: {exc}")
            # wait for possible navigation after login
            try:
                page.wait_for_load_state("networkidle", timeout=25000)
            except Exception:
                pass
            try:
                page.wait_for_timeout(2000)
            except Exception:
                pass

        # if target differs from current page, navigate; otherwise stay on post-login page
        from urllib.parse import urlparse

        resp = None
        cur_url = page.url
        _log(f"post-login current url: {cur_url}")
        try:
            # ensure some DOM is ready before deciding navigation
            page.wait_for_selector("form, button, input, body", timeout=8000)
        except Exception:
            _log("post-login wait_for_selector timeout; continuing")

        try:
            cur = urlparse(cur_url)
            tgt = urlparse(target)
            same_host = cur.netloc == tgt.netloc
            same_prefix = cur.geturl().rstrip('/').startswith(tgt.geturl().rstrip('/'))
        except Exception:
            same_host = False
            same_prefix = False

        if same_host and same_prefix:
            _log("already on target host/path after login; reuse current page")
            try:
                page.wait_for_load_state("networkidle", timeout=25000)
            except Exception:
                pass
            try:
                page.wait_for_selector("form, button, input, body", timeout=8000)
            except Exception:
                _log("post-login reuse wait_for_selector timeout; continuing")
            try:
                page.wait_for_timeout(2000)
            except Exception:
                pass
        else:
            _log(f"goto target {target}")
            resp = page.goto(target, wait_until="networkidle", timeout=25000)
            page.wait_for_timeout(1500)

        try:
            _save_cookies(context, "post_login")
        except Exception:
            pass
        html = page.content()
        status_code = resp.status if resp else 0
        headers = resp.headers if resp else {}
        _log(f"target status={status_code} headers={list(headers.keys()) if headers else []}")

        browser.close()

    # build TargetSample from rendered page
    body = html
    if len(body) > preview_len:
        preview = body[:preview_len] + "\n... <truncated>"
    else:
        preview = body

    header_lines = []
    for name, value in headers.items():
        header_lines.append(f"{name}: {value}")
        if len("\n".join(header_lines)) > preview_len:
            break
    headers_str = "\n".join(header_lines)

    request_template = (
        "PLAYWRIGHT GET (rendered page)\n"
        f"Target: {target}\n"
        f"Login URL: {login_page}\n"
        f"Headless: {headless_flag}\n"
        f"Detected fields: user='{user_field}' pass='{pass_field}'"
    )

    return TargetSample(
        url=target,
        status_code=status_code or 0,
        content_type=headers.get("content-type") if headers else None,
        encoding="utf-8",
        body_preview=preview,
        request_template=request_template,
        response_headers=headers_str,
    )
