"""XSS vulnerability detector using Chrome DevTools Protocol."""

from __future__ import annotations
import re
import time
from typing import Tuple, Optional

from PoCGen.core.cdp_sampler import (
    CDPConnection,
    ensure_chrome,
    get_page_ws_url,
    cdp_navigate,
    cdp_evaluate,
    cdp_get_page_html,
)
from PoCGen.core.logger import _log


class XSSDetector:
    def __init__(self, headless: bool = True, timeout: int = 10):
        self.headless = headless
        self.timeout = timeout
        self._cdp: Optional[CDPConnection] = None
        self._port: Optional[int] = None

    def __enter__(self):
        self._port = ensure_chrome(headless=self.headless)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _get_cdp(self) -> CDPConnection:
        if self._cdp is None:
            ws_url = get_page_ws_url(self._port)
            self._cdp = CDPConnection(ws_url)
            self._cdp.send("Page.enable")
            self._cdp.send("Runtime.enable")
        return self._cdp

    def detect_xss(self, url: str, response_body: str = "") -> Tuple[bool, str]:
        """检测给定URL或响应体中是否存在XSS漏洞"""
        cdp = self._get_cdp()

        try:
            # 设置 alert 监听
            cdp_evaluate(cdp, """
                window.__xss_alert_triggered = false;
                window.__xss_alert_message = '';
                window.alert = function(msg) {
                    window.__xss_alert_triggered = true;
                    window.__xss_alert_message = msg || '';
                };
            """)

            if response_body:
                cdp_evaluate(cdp, f"document.open(); document.write({repr(response_body)}); document.close()")
            else:
                cdp_navigate(cdp, url, wait_load=True, timeout=self.timeout)

            time.sleep(1)

            html_content = cdp_get_page_html(cdp)

            # 检查 alert
            alert_check = cdp_evaluate(cdp, "JSON.stringify({triggered: window.__xss_alert_triggered, msg: window.__xss_alert_message})")
            if alert_check:
                import json
                try:
                    alert_data = json.loads(alert_check) if isinstance(alert_check, str) else alert_check
                    if alert_data.get("triggered"):
                        return True, f"Alert triggered with message: '{alert_data.get('msg')}'"
                except (json.JSONDecodeError, TypeError):
                    pass

            # 检查 XSS pattern
            xss_patterns = [
                r'<svg[^>]*onload\s*=',
                r'<img[^>]*onerror\s*=',
                r'<script[^>]*>.*alert.*</script>',
                r'onload\s*=\s*["\']?alert',
                r'onerror\s*=\s*["\']?alert',
                r'onclick\s*=\s*["\']?alert',
                r'onmouseover\s*=\s*["\']?alert',
            ]

            for pattern in xss_patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    return True, f"XSS pattern found in response: {pattern}"

            # 检查事件处理程序
            event_handlers = cdp_evaluate(cdp, """
                (() => {
                    const result = [];
                    ['onload', 'onerror', 'onclick', 'onmouseover'].forEach(event => {
                        document.querySelectorAll(`[${event}]`).forEach(el => {
                            result.push({tag: el.tagName, event: event, handler: el.getAttribute(event)});
                        });
                    });
                    return JSON.stringify(result);
                })()
            """)

            if event_handlers:
                import json
                try:
                    handlers = json.loads(event_handlers) if isinstance(event_handlers, str) else event_handlers
                    for element in handlers:
                        if 'alert' in element.get('handler', ''):
                            return True, f"Alert found in {element['tag']} {element['event']} handler"
                except (json.JSONDecodeError, TypeError):
                    pass

            return False, "No XSS detected"

        except Exception as e:
            return False, f"Error during XSS detection: {str(e)}"

    def close(self):
        if self._cdp:
            self._cdp.close()
            self._cdp = None
