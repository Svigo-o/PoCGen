from __future__ import annotations

import argparse
import os
from typing import List

from PoCGen.config.config import SETTINGS
from PoCGen.core.generator import generate_poc
from PoCGen.core.ingest import read_code_files


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate HTTP PoCs for command injection using an LLM")
    parser.add_argument("--desc", required=False, default=None, help="漏洞描述文件路径（可选）")
    parser.add_argument("--code", nargs="+", required=False, default=[], help="相关源代码文件路径或 glob（可选）")
    parser.add_argument("--target", help="Optional target base URL")
    parser.add_argument("--vuln-type", default="command_injection_http", help="Vulnerability type handler key")
    parser.add_argument("--payload", default=None, help="想要执行的shell指令，例如 wget xxx或反弹shell等")
    parser.add_argument("--probe-target", action="store_true", help="在生成前主动访问 target，采集响应样本并提供给 LLM")
    parser.add_argument("--auto-validate", action="store_true", help="生成后自动向 target 发送 PoC 进行验证（需 target 可访问）")
    parser.add_argument("--max-iters", type=int, default=None, help="最大尝试次数（默认读取配置 POCGEN_MAX_ITERS）")
    parser.add_argument("--stop-on-success", dest="stop_on_success", action="store_true", help="监测到 wget 回调后立即停止后续尝试")
    parser.add_argument("--no-stop-on-success", dest="stop_on_success", action="store_false", help="即便检测到 wget 回调也继续剩余尝试")
    parser.set_defaults(stop_on_success=None)
    parser.add_argument("--login-url", default=None, help="可选，登录请求的完整 URL，缺省时使用 target")
    parser.add_argument("--login-username", default=None, help="可选，登录用户名，缺省不传；若仅给密码，则用户名为空字符串")
    parser.add_argument("--login-password", default=None, help="可选，登录密码")
    parser.add_argument("--login-user-field", default="username", help="登录表单用户名字段名，默认 username")
    parser.add_argument("--login-pass-field", default="password", help="登录表单密码字段名，默认 password")
    parser.add_argument("--browser-login", action="store_true", help="使用 Playwright 浏览器登录以获取 cookie 后再验证")
    parser.add_argument("--CVENumber",  default=None, help="CVE 编号，用于自动爬取漏洞情报")
    parser.add_argument("--binary", default=None, help="漏洞二进制文件路径，启用 Step1+Step2 自动分析（IDA MCP）")
    args = parser.parse_args()

    if args.desc:
        with open(args.desc, "r", encoding="utf-8", errors="ignore") as f:
            description = f.read()
    else:
        description = ""

    code_texts: List[str] = read_code_files(args.code)

    result = generate_poc(
        description=description,
        code_texts=code_texts,
        target=args.target,
        vuln_type=args.vuln_type,
        payload=args.payload,
        probe_target=args.probe_target,
        auto_validate=args.auto_validate,
        max_iterations=args.max_iters,
        stop_on_success=args.stop_on_success,
        cvenumber=args.CVENumber,
        login_url=args.login_url,
        login_username=args.login_username,
        login_password=args.login_password,
        login_user_field=args.login_user_field,
        login_pass_field=args.login_pass_field,
        use_browser_login=args.browser_login,
        binary_path=args.binary,
    )

    print("\nGenerated and saved the following PoC files:")
    for p in result.saved_paths:
        print(p)


if __name__ == "__main__":
    main()
