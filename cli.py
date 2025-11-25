from __future__ import annotations

import argparse
import os
from typing import List

from PoCGen.core.generator import generate_poc
from PoCGen.core.ingest import read_code_files


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate HTTP PoCs for command injection using an LLM")
    parser.add_argument("--desc", required=False, default=None, help="Path to vulnerability description text file (optional)")
    parser.add_argument("--code", nargs="+", required=True, help="One or more code file paths or globs")
    parser.add_argument("--target", help="Optional target base URL")
    parser.add_argument("--vuln-type", default="command_injection_http", help="Vulnerability type handler key")
    parser.add_argument("--temperature", type=float, default=0.2)
    parser.add_argument("--max-tokens", type=int, default=65535)
    parser.add_argument("--out", default=None, help="输出目录，默认使用配置中的 outputs 目录")
    parser.add_argument("--attacker", default=None, help="攻击机 URL（用于 wget 取回 net.sh），默认从配置 POCGEN_ATTACKER_URL 读取")
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
        temperature=args.temperature,
        max_tokens=args.max_tokens,
        output_dir=args.out,
        attacker_url=args.attacker,
    )

    print("\nGenerated and saved the following PoC files:")
    for p in result.saved_paths:
        print(p)


if __name__ == "__main__":
    main()
