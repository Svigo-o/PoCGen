"""PoCGen MCP Server — exposes PoCGen capabilities as MCP tools for Claude Code.

Run with: python -m PoCGen.mcp_server
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from PoCGen.mcp_tools import register_all

mcp = FastMCP(
    "pocgen",
    instructions=(
        "PoCGen: Infrastructure tools for command injection PoC development.\n"
        "You (Claude) are the analyst and PoC author. Use these tools for capabilities you lack:\n\n"
        "INTELLIGENCE GATHERING:\n"
        "- pocgen_cve_intelligence: crawl NVD mirror + reference links for CVE data\n"
        "- pocgen_sample_target: CDP browser probe (login, capture POST/cookies)\n\n"
        "SOURCE CODE:\n"
        "- pocgen_read_code: read source files by path or glob pattern\n\n"
        "VALIDATION & MONITORING:\n"
        "- pocgen_parse_http / pocgen_parse_socket: parse raw PoC into structured format\n"
        "- pocgen_validate_http / pocgen_validate_socket: replay PoC against target\n"
        "- pocgen_monitor_start / pocgen_monitor_wait / pocgen_monitor_stop: wget callback listener\n"
        "- pocgen_batch_validate: batch-validate all .http files in a directory with callback detection\n\n"
        "DEVICE PROFILES:\n"
        "- pocgen_save_device_profile: cache device-specific knowledge (CGI paths, injection method)\n"
        "- pocgen_load_device_profile: load a saved device profile for reuse\n"
        "- pocgen_list_device_profiles: list all saved device profiles\n\n"
        "OUTPUT:\n"
        "- pocgen_save_poc: save your generated PoC to disk with auto-normalization\n\n"
        "For IDA binary analysis, use the ida MCP server directly (idalib_open, "
        "decompile, analyze_funcs, find_bytes, disasm, xrefs_to, callees, "
        "find_regex, callgraph, py_eval, etc.).\n\n"
        "TYPICAL WORKFLOW: read desc+code → gather CVE intel → probe target → "
        "analyze vulnerability yourself → write PoC → validate → monitor for callback."
    ),
)

register_all(mcp)


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
