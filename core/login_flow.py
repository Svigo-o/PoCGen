"""LLM-assisted login field analysis.

Provides two functions used by cdp_sampler.py:
- _llm_choose_fields: identify username/password fields from DOM metadata
- _llm_pick_login_button: identify the login button from DOM metadata

Browser automation is handled by cdp_sampler.py (Chrome DevTools Protocol).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional, List, Dict, Any

from PoCGen.llm.client import ChatMessage, LLMClient
from PoCGen.core.logger import _log, _append_login_chat


def _parse_llm_json(resp: str, expected_keys: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    if not resp:
        return None

    def _try_load(text: str) -> Optional[Dict[str, Any]]:
        try:
            obj = json.loads(text)
            if isinstance(obj, dict):
                if expected_keys:
                    return {k: obj.get(k) for k in expected_keys}
                return obj
        except Exception:
            return None
        return None

    obj = _try_load(resp)
    if obj is not None:
        return obj
    match = re.search(r"\{.*\}", resp, flags=re.S)
    if match:
        obj = _try_load(match.group(0))
        if obj is not None:
            return obj
    return None


def _ask_llm(
    prompt: str,
    expected_keys: Optional[List[str]] = None,
    chat_log_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    try:
        client = LLMClient()
        if chat_log_path:
            _append_login_chat(chat_log_path, "user", prompt)
        resp = client.chat([ChatMessage(role="user", content=prompt)], temperature=0, max_tokens=800)
        client.close()
        _log(f"llm raw reply: {resp[:500]}")
        if chat_log_path:
            _append_login_chat(chat_log_path, "assistant", resp)
        parsed = _parse_llm_json(resp, expected_keys=expected_keys)
        if parsed is None:
            raise ValueError(f"invalid json from llm: {resp[:200]}")
        return parsed
    except Exception as exc:
        if chat_log_path:
            _append_login_chat(chat_log_path, "assistant", f"<error: {exc}>")
        _log(f"llm call failed: {exc}")
        return None


def _llm_pick_login_button(
    buttons: List[Dict[str, Any]],
    purpose: str = "login",
    chat_log_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    if not buttons:
        return None
    purpose_desc = "登录" if purpose == "login" else "进入下一步"
    prompt = (
        "你是安全测试助手。下面是登录页上可见的按钮列表，请选择最可能用于"
        f"{purpose_desc}的按钮。"
        "严格输出 JSON，不能包含除 JSON 外的任何内容，不要加反引号、说明或前缀。"
        "格式: {\"button_index\": int}，若无法判断返回 {}。\n"
        f"按钮列表: {buttons}"
    )
    return _ask_llm(prompt, expected_keys=["button_index"], chat_log_path=chat_log_path)


def _llm_choose_fields(
    inputs: List[Dict[str, Any]],
    chat_log_path: Optional[Path] = None,
) -> Optional[Dict[str, Any]]:
    if not inputs:
        return None
    prompt = (
        "你是安全测试助手。下面是页面上的输入字段列表，请选出最可能用于填写用户名和密码的字段。"
        "严格输出 JSON，不能包含除 JSON 外的任何内容，不要加反引号、说明或前缀。"
        "格式: {\"username_field_index\": int | null, \"password_field_index\": int | null}。"
        "若无法判断返回 {}。\n"
        f"字段列表: {inputs}"
    )
    return _ask_llm(
        prompt,
        expected_keys=["username_field_index", "password_field_index"],
        chat_log_path=chat_log_path,
    )
