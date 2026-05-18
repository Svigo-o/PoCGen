from __future__ import annotations
from typing import Dict, List, Optional, Type

from PoCGen.config.config import SETTINGS
from .command_injection.handler import CommandInjectionHTTPHandler
from .socket.handler import CommandInjectionSocketHandler
from .stackoverflow.handler import StackOverflowHTTPHandler
from .cross_site_scripting.handler import CrossSiteScriptingHTTPHandler
from .stackoverflow_python.handler import StackOverflowPythonHandler
from .path_traversal.handler import PathTraversalHTTPHandler
from .models import GenerationResult, VulnHandler


HANDLERS: Dict[str, Type[VulnHandler]] = {
    CommandInjectionHTTPHandler.name: CommandInjectionHTTPHandler,
    CommandInjectionSocketHandler.name: CommandInjectionSocketHandler,
    StackOverflowHTTPHandler.name: StackOverflowHTTPHandler,
    CrossSiteScriptingHTTPHandler.name: CrossSiteScriptingHTTPHandler,
    StackOverflowPythonHandler.name: StackOverflowPythonHandler,
    PathTraversalHTTPHandler.name: PathTraversalHTTPHandler,
}


def get_handler(vuln_type: Optional[str] = None) -> VulnHandler:
    key = vuln_type or SETTINGS.default_vuln_type
    cls = HANDLERS.get(key)
    if not cls:
        raise ValueError(f"Unsupported vuln type: {key}")
    return cls()


def generate_poc(
    description: str,
    code_texts: List[str],
    target: Optional[str] = None,
    vuln_type: Optional[str] = None,
    payload: Optional[str] = None,
    probe_target: bool = False,
    auto_validate: bool = False,
    max_iterations: Optional[int] = None,
    stop_on_success: Optional[bool] = None,
    cvenumber: Optional[str] = None,
    login_url: Optional[str] = None,
    login_username: Optional[str] = None,
    login_password: Optional[str] = None,
    login_user_field: str = "username",
    login_pass_field: str = "password",
    use_browser_login: bool = False,
    binary_path: Optional[str] = None,
) -> GenerationResult:
    selected_vuln_type = vuln_type or SETTINGS.default_vuln_type
    handler = get_handler(selected_vuln_type)

    return handler.generate(
        description=description,
        code_texts=code_texts,
        target=target,
        vuln_type=selected_vuln_type,
        payload=payload,
        probe_target=probe_target,
        auto_validate=auto_validate,
        max_iterations=max_iterations,
        stop_on_success=stop_on_success,
        cvenumber=cvenumber,
        login_url=login_url,
        login_username=login_username,
        login_password=login_password,
        login_user_field=login_user_field,
        login_pass_field=login_pass_field,
        use_browser_login=use_browser_login,
        binary_path=binary_path,
    )
