"""
Unified Vulnerability Analyzer – Source Code + IDA MCP Binary Analysis.

When a binary path is provided:
  1. Auto-starts IDA MCP service and collects binary data
     (survey, decompile, xrefs, callgraph, dangerous imports)
  2. Feeds source code + vulnerability description + IDA binary data
     to the LLM in a single call
  3. Produces a structured VulnAnalysisResult with PoC recommendations

When no binary path is provided:
  Falls back to source-code-only analysis.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console

from PoCGen.config.config import SETTINGS
from PoCGen.core.ida_mcp_client import IDAMCPClient
from PoCGen.core.ida_mcp_service import IDAMCPService
from PoCGen.llm.client import ChatMessage, LLMClient
from PoCGen.prompts.vuln_analysis_templates import build_vuln_analysis_messages

console = Console()

# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------


@dataclass
class VulnAnalysisResult:
    """Structured output of vulnerability analysis (source + optional binary)."""

    raw_output: str
    parsed: Optional[Dict[str, Any]] = None
    ida_data_summary: str = ""
    error: Optional[str] = None

    # Convenience accessors
    @property
    def source_points(self) -> List[Dict[str, Any]]:
        return (self.parsed or {}).get("source_points", [])

    @property
    def sink_points(self) -> List[Dict[str, Any]]:
        return (self.parsed or {}).get("sink_points", [])

    @property
    def propagation_paths(self) -> List[Dict[str, Any]]:
        return (self.parsed or {}).get("propagation_paths", [])

    @property
    def exploitation_context(self) -> Dict[str, Any]:
        return (self.parsed or {}).get("exploitation_context", {})

    @property
    def function_addresses_hint(self) -> Dict[str, Any]:
        return (self.parsed or {}).get("function_addresses_hint", {})

    @property
    def poc_recommendations(self) -> Dict[str, Any]:
        return (self.parsed or {}).get("poc_generation_recommendations", {})

    @property
    def summary(self) -> str:
        return (self.parsed or {}).get("summary", "")

    @property
    def is_valid(self) -> bool:
        return self.parsed is not None and self.error is None

    @property
    def as_prompt_block(self) -> str:
        """Format as a block suitable for inclusion in PoC generation prompts."""
        if not self.parsed:
            return f"Vulnerability Analysis (raw):\n{self.raw_output[:3000]}"

        parts: List[str] = ["## Vulnerability Analysis Results"]

        parts.append(f"Summary: {self.summary}")
        confidence = self.parsed.get("analysis_confidence")
        if confidence:
            parts.append(f"Confidence: {confidence}")
        if self.parsed.get("vulnerability_confirmed"):
            parts.append("Vulnerability CONFIRMED.")

        # Source analysis
        if self.parsed.get("source_analysis"):
            sa = self.parsed["source_analysis"]
            parts.append(f"Source: {sa.get('input_entry_function', '?')} at {sa.get('binary_address', '?')}")
            parts.append(f"  Input: {sa.get('input_parameter_name', '?')} via {sa.get('input_extraction_method', '?')}")

        # Sink analysis
        if self.parsed.get("sink_analysis"):
            sk = self.parsed["sink_analysis"]
            parts.append(f"Sink: {sk.get('dangerous_function', '?')} at {sk.get('binary_address', '?')}")
            parts.append(f"  Caller: {sk.get('caller_function', '?')} at {sk.get('caller_address', '?')}")
            parts.append(f"  Command construction: {sk.get('command_construction_method', '?')}")

        # Exploitation context
        ctx = self.exploitation_context
        if ctx:
            parts.append(f"HTTP Method: {ctx.get('http_method', '?')}")
            parts.append(f"URL Path: {ctx.get('url_path', '?')}")
            parts.append(f"Vulnerable Parameter: {ctx.get('vulnerable_parameter', '?')}")
            parts.append(f"Parameter Location: {ctx.get('parameter_location', '?')}")
            if ctx.get("injection_delimiter_hint"):
                parts.append(f"Injection Delimiter: {ctx['injection_delimiter_hint']}")
            if ctx.get("content_type"):
                parts.append(f"Content-Type: {ctx['content_type']}")
            if ctx.get("requires_auth"):
                parts.append(f"Auth Required: {ctx.get('auth_mechanism', 'yes')}")

        # PoC recommendations
        rec = self.poc_recommendations
        if rec:
            parts.append("PoC Generation Recommendations:")
            for k, v in rec.items():
                if v is not None:
                    parts.append(f"  {k}: {v}")

        # Key addresses
        if self.parsed.get("key_addresses"):
            parts.append(f"Key addresses: {json.dumps(self.parsed['key_addresses'])}")

        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Chat log helper
# ---------------------------------------------------------------------------

_VULN_LOG_DIR = Path(__file__).resolve().parent.parent / "logs" / "vuln_analysis"
_VULN_LOG_DIR.mkdir(parents=True, exist_ok=True)


def _log_vuln(text: str, log_path: Optional[Path] = None) -> None:
    if log_path is None:
        return
    try:
        ts = datetime.now().isoformat(timespec="seconds")
        with open(log_path, "a", encoding="utf-8") as fh:
            fh.write(f"[{ts}] {text}\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# IDA MCP data collection
# ---------------------------------------------------------------------------


def _collect_ida_data(
    mcp: IDAMCPClient,
) -> str:
    """Query IDA MCP for binary data relevant to the vulnerability analysis.

    Uses a general strategy: survey the binary, then decompile all
    interesting functions (complex / high-xref-count), and search for
    dangerous imports.
    """
    sections: List[str] = []

    # 1. Binary survey
    console.print("[cyan]  IDA: surveying binary...")
    try:
        survey = mcp.survey_binary(detail_level="standard")
        sections.append(f"### Binary Survey\n{json.dumps(survey, ensure_ascii=False, indent=2)[:8000]}")
    except Exception as exc:
        sections.append(f"### Binary Survey\nERROR: {exc}")
        return "\n\n".join(sections)

    # 2. Collect interesting functions from survey for decompilation
    interesting_funcs: List[Dict[str, Any]] = []
    survey_data = survey if isinstance(survey, dict) else {}

    int_funcs = survey_data.get("interesting_functions", [])
    if isinstance(int_funcs, list):
        for fn in int_funcs:
            if isinstance(fn, dict):
                fn_type = fn.get("type", "")
                addr = fn.get("addr", "")
                # Skip thunks (library wrappers) – focus on complex/dispatcher
                if fn_type in ("complex", "dispatcher") and addr:
                    interesting_funcs.append(fn)

    # Also look for entrypoints that look like real functions
    entrypoints = survey_data.get("entrypoints", [])
    if isinstance(entrypoints, list):
        for ep in entrypoints:
            if isinstance(ep, dict):
                name = ep.get("name", "")
                addr = ep.get("addr", "")
                if name.startswith(".") or name in ("stdout", "stderr", "stdin", "__RLD_MAP", "_edata", "_fdata"):
                    continue
                if addr and not any(f.get("addr") == addr for f in interesting_funcs):
                    interesting_funcs.append({"addr": addr, "name": name})

    # 3. Decompile interesting functions (limit 15)
    addrs_to_decompile: List[Dict[str, str]] = []
    for fn in interesting_funcs[:15]:
        addr = fn.get("addr", "")
        name = fn.get("name", "")
        if addr:
            addrs_to_decompile.append({"addr": addr, "name": name})

    for fn_info in addrs_to_decompile:
        addr = fn_info["addr"]
        name = fn_info.get("name", addr)
        console.print(f"[cyan]  IDA: decompiling {name} @ {addr}...")
        try:
            decomp = mcp.decompile(addr)
            sections.append(
                f"### Decompile {name} @ {addr}\n{json.dumps(decomp, ensure_ascii=False, indent=2)[:6000]}"
            )
        except Exception as exc:
            sections.append(f"### Decompile {name} @ {addr}\nERROR: {exc}")

    # 4. Search for dangerous import strings
    console.print("[cyan]  IDA: searching for dangerous imports...")
    for pattern in ["system", "popen", "exec", "doSystem"]:
        try:
            result = mcp.find_regex(pattern, limit=10)
            if result:
                text = json.dumps(result, ensure_ascii=False, indent=2)[:2000]
                if pattern.lower() in text.lower():
                    sections.append(f"### String Search: {pattern}\n{text}")
        except Exception:
            pass

    return "\n\n".join(sections)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def analyze_vulnerability(
    description: str,
    code_texts: List[str],
    cvenumber: Optional[str] = None,
    binary_path: Optional[str] = None,
    mcp_url: Optional[str] = None,
    temperature: float = 0.2,
    max_tokens: int = 8000,
) -> VulnAnalysisResult:
    """Run vulnerability analysis: source code + optional IDA MCP binary analysis.

    When binary_path is provided, auto-starts IDA MCP, collects binary data,
    and feeds everything to the LLM in a single call.
    """
    log_path = _VULN_LOG_DIR / f"vuln_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    _log_vuln(
        f"Vulnerability analysis starting: cve={cvenumber}, "
        f"code_files={len(code_texts)}, desc_len={len(description)}, "
        f"binary={binary_path or '<none>'}, mcp_url={mcp_url}",
        log_path,
    )

    # ------------------------------------------------------------------
    # Phase A: Collect IDA MCP binary data (if binary_path provided)
    # ------------------------------------------------------------------
    ida_data = ""
    if binary_path:
        console.print("[bold]Vulnerability analysis: collecting IDA MCP binary data")

        endpoint = mcp_url or SETTINGS.ida_mcp_url
        mcp = IDAMCPClient(base_url=endpoint, timeout=300.0)

        service = IDAMCPService(
            binary_path=binary_path,
            mcp_url=endpoint,
            idalib_mcp_bin=SETTINGS.ida_mcp_bin,
            startup_timeout=SETTINGS.ida_mcp_startup_timeout,
        )
        service_started = False

        try:
            if service.start():
                service_started = True
            else:
                raise RuntimeError("Failed to start IDA MCP service")

            console.print("[cyan]  IDA: initialising MCP session...")
            mcp.initialize()

            need_open = True
            try:
                health = mcp.idalib_health()
                if isinstance(health, dict) and health.get("success"):
                    _log_vuln("Binary already loaded in idalib session, skipping idalib_open", log_path)
                    console.print("[cyan]  IDA: binary already loaded in session")
                    need_open = False
            except Exception:
                pass

            if need_open:
                console.print(f"[cyan]  IDA: opening binary {binary_path}...")
                mcp.idalib_open(binary_path)

            console.print("[cyan]  IDA: warming up (auto-analysis + caches)...")
            try:
                mcp.idalib_warmup(wait_auto_analysis=True)
            except Exception:
                console.print("[yellow]  IDA: warmup timed out or partially failed, continuing...")

            ida_data = _collect_ida_data(mcp)

        except Exception as exc:
            console.print(f"[red]  IDA MCP error: {exc}")
            _log_vuln(f"IDA MCP error: {exc}", log_path)
        finally:
            if not service_started:
                try:
                    mcp.idalib_close()
                except Exception:
                    pass
            mcp.close()
            if service_started:
                service.stop()

        _log_vuln(f"IDA data collected ({len(ida_data)} chars)", log_path)
    else:
        console.print("[dim]No binary path provided; running source-code-only analysis")

    # ------------------------------------------------------------------
    # Phase B: Single LLM call (source code + IDA data)
    # ------------------------------------------------------------------
    console.print("[cyan]  LLM: analyzing vulnerability...")

    messages = build_vuln_analysis_messages(
        description=description,
        code_files=code_texts,
        cvenumber=cvenumber,
        ida_analysis_data=ida_data or None,
        binary_path=binary_path,
    )

    for m in messages:
        _log_vuln(f"MODEL INPUT [{m.role.upper()}]:\n{m.content}", log_path)

    client = LLMClient(timeout_seconds=300)
    try:
        raw_output = client.chat(messages, temperature=temperature, max_tokens=max_tokens)
    except Exception as exc:
        console.print(f"[red]LLM call failed: {exc}")
        return VulnAnalysisResult(
            raw_output="",
            ida_data_summary=ida_data[:2000],
            error=str(exc),
        )
    finally:
        client.close()

    _log_vuln(f"MODEL OUTPUT:\n{raw_output}", log_path)

    parsed, error = _parse_vuln_json(raw_output)

    if parsed:
        console.print("[green]Vulnerability analysis completed successfully")
        console.print(f"  Summary: {parsed.get('summary', 'N/A')}")
        console.print(f"  Source points: {len(parsed.get('source_points', []))}")
        console.print(f"  Sink points: {len(parsed.get('sink_points', []))}")
        console.print(f"  Propagation paths: {len(parsed.get('propagation_paths', []))}")
        if parsed.get("vulnerability_confirmed"):
            console.print(f"  Confirmed: {parsed.get('vulnerability_confirmed')}")
            console.print(f"  Confidence: {parsed.get('analysis_confidence', '?')}")
        rec = parsed.get("poc_generation_recommendations", {})
        if rec:
            console.print(f"  Vuln param: {rec.get('vulnerable_parameter', '?')}")
            console.print(f"  URL path: {rec.get('url_path', '?')}")
    else:
        console.print(f"[yellow]Failed to parse structured JSON ({error})")
        console.print("[yellow]  Falling back to raw output for downstream steps")

    return VulnAnalysisResult(
        raw_output=raw_output,
        parsed=parsed,
        ida_data_summary=ida_data[:3000],
        error=error,
    )


# ---------------------------------------------------------------------------
# JSON parser
# ---------------------------------------------------------------------------


def _parse_vuln_json(raw: str) -> tuple:
    """Try to extract and parse the JSON object from the LLM output."""
    try:
        data = json.loads(raw.strip())
        if isinstance(data, dict):
            return data, None
    except json.JSONDecodeError:
        pass

    text = raw.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        try:
            data = json.loads("\n".join(lines))
            if isinstance(data, dict):
                return data, None
        except json.JSONDecodeError:
            pass

    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end > start:
        try:
            data = json.loads(raw[start : end + 1])
            if isinstance(data, dict):
                return data, None
        except json.JSONDecodeError:
            pass

    return None, "Could not extract valid JSON from LLM output"


__all__ = ["analyze_vulnerability", "VulnAnalysisResult"]
