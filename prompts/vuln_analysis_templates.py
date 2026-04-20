"""
Prompt templates for Vulnerability Analysis (source code + optional IDA MCP binary data).

The LLM analyses the vulnerability description, source code, and optionally
binary analysis data from IDA Pro to produce a single structured JSON report
with source/sink points, propagation paths, exploitation context, and PoC
generation recommendations.
"""

from __future__ import annotations

from typing import List, Optional

from PoCGen.llm.client import ChatMessage

# ---------------------------------------------------------------------------
# System prompt (source-code only)
# ---------------------------------------------------------------------------

_VULN_ANALYSIS_SYSTEM_PROMPT = """\
You are a senior vulnerability researcher specialising in firmware / embedded \
binary security.  Your task is to analyse a given vulnerability description \
and the associated source code, and produce a structured JSON report.

## What you must identify

1. **Source points** – where untrusted user input first enters the program \
(e.g. CGI query-string parameters, HTTP POST fields, environment variables, \
socket recv buffers, cookie values).

2. **Sink points** – where the tainted data reaches a dangerous operation \
(e.g. system(), popen(), execve(), doSystemCmd(), sprintf→system chain).

3. **Propagation path** – the call-chain / data-flow from source to sink, \
including every intermediate function and how data is passed (argument index, \
global variable, struct field, etc.).

4. **Vulnerable parameter** – the exact parameter name / field that carries \
the injection payload.

5. **Exploitation context** – the HTTP method, URL path, required \
authentication / cookies, Content-Type, and any encoding constraints that \
the PoC must satisfy.

## Output format

Produce EXACTLY ONE JSON object matching the schema below.  No extra text, \
no markdown fences, no commentary.

```json
{
  "vulnerability_type": "command_injection",
  "summary": "one-line summary of the vulnerability",
  "source_points": [
    {
      "function": "function_name",
      "location": "file:line or address hint",
      "parameter": "parameter_name",
      "input_channel": "http_query | http_post | http_cookie | http_header | socket | environment",
      "details": "how the input is read"
    }
  ],
  "sink_points": [
    {
      "function": "function_name",
      "location": "file:line or address hint",
      "dangerous_call": "system | popen | execve | doSystemCmd | ...",
      "tainted_argument_index": 0,
      "details": "how the dangerous call is reached"
    }
  ],
  "propagation_paths": [
    {
      "source_index": 0,
      "sink_index": 0,
      "call_chain": ["func_a", "func_b", "func_c"],
      "data_flow": [
        {
          "from": "func_a:param_name",
          "to": "func_b:param_name",
          "via": "function_call_argument | global_variable | struct_field",
          "details": "brief description"
        }
      ]
    }
  ],
  "exploitation_context": {
    "http_method": "POST",
    "url_path": "/cgi-bin/endpoint.cgi",
    "content_type": "application/x-www-form-urlencoded",
    "requires_auth": true,
    "auth_mechanism": "cookie | basic | digest",
    "required_cookies": ["sessionid"],
    "required_headers": ["X-Requested-With"],
    "vulnerable_parameter": "param_name",
    "parameter_location": "body | query | header | cookie",
    "encoding_constraints": "e.g. must not URL-encode semicolons",
    "injection_delimiter_hint": "e.g. ; or $() or backticks"
  },
  "function_addresses_hint": {
    "sink_function": "symbol_name_or_partial",
    "source_function": "symbol_name_or_partial",
    "intermediate_functions": ["symbol1", "symbol2"]
  }
}
```

## Rules

- Be precise with function names – use the exact names appearing in the code.
- If a piece of information cannot be determined from the source, use `null`.
- Keep the JSON valid and UTF-8 clean.
- Do NOT fabricate information that is not supported by the code.
"""

# ---------------------------------------------------------------------------
# System prompt (source-code + IDA binary data)
# ---------------------------------------------------------------------------

_VULN_ANALYSIS_WITH_IDA_SYSTEM_PROMPT = """\
You are a senior vulnerability researcher specialising in firmware / embedded \
binary security.  You will receive:

1. A vulnerability description and the associated source code (decompiled or \
original).

2. Binary analysis results from IDA Pro (decompilation, cross-references, \
call graphs, imports, function lists, etc.) for the vulnerable binary.

Your task is to **analyse** the vulnerability using both the source-level \
information and the binary-level evidence, and produce a **structured JSON \
report** with concrete **PoC generation recommendations**.

## What you must identify

1. **Source points** – where untrusted user input first enters the program.

2. **Sink points** – where the tainted data reaches a dangerous operation.

3. **Propagation path** – the call-chain / data-flow from source to sink.

4. **Vulnerable parameter** – the exact parameter name / field that carries \
the injection payload.

5. **Exploitation context** – the HTTP method, URL path, required \
authentication / cookies, Content-Type, and any encoding constraints.

6. **Binary-level correlation** – confirm the vulnerability in the binary, \
map source functions to binary addresses, and provide concrete PoC \
generation recommendations based on binary evidence.

## Output format

Produce EXACTLY ONE JSON object matching the schema below.  No extra text, \
no markdown fences, no commentary.

```json
{
  "vulnerability_type": "command_injection",
  "summary": "one-line summary of the vulnerability",
  "analysis_confidence": "high | medium | low",
  "vulnerability_confirmed": true,
  "source_points": [
    {
      "function": "function_name",
      "location": "file:line or address hint",
      "binary_address": "0xADDR",
      "binary_symbol": "symbol_in_binary",
      "parameter": "parameter_name",
      "input_channel": "http_query | http_post | http_cookie | http_header | socket | environment",
      "details": "how the input is read"
    }
  ],
  "sink_points": [
    {
      "function": "function_name",
      "location": "file:line or address hint",
      "binary_address": "0xADDR",
      "binary_symbol": "symbol_in_binary",
      "dangerous_call": "system | popen | execve | doSystemCmd | ...",
      "tainted_argument_index": 0,
      "details": "how the dangerous call is reached"
    }
  ],
  "propagation_paths": [
    {
      "source_index": 0,
      "sink_index": 0,
      "call_chain": ["func_a", "func_b", "func_c"],
      "call_chain_addresses": ["0xADDR1", "0xADDR2", "0xADDR3"],
      "data_flow": [
        {
          "from": "func_a:param_name",
          "to": "func_b:param_name",
          "via": "function_call_argument | global_variable | struct_field",
          "details": "brief description"
        }
      ]
    }
  ],
  "sink_analysis": {
    "dangerous_function": "system | popen | doSystemCmd | ...",
    "binary_address": "0xADDR",
    "caller_function": "caller_name",
    "caller_address": "0xADDR",
    "tainted_parameter_register_or_offset": "description",
    "command_construction_method": "how the command string is built"
  },
  "source_analysis": {
    "input_entry_function": "function_name",
    "binary_address": "0xADDR",
    "input_parameter_name": "param_name",
    "input_extraction_method": "getenv | cgi_input | nvram_get | ...",
    "input_buffer_or_variable": "variable/offset where input is stored"
  },
  "exploitation_context": {
    "http_method": "POST",
    "url_path": "/cgi-bin/endpoint.cgi",
    "content_type": "application/x-www-form-urlencoded",
    "requires_auth": true,
    "auth_mechanism": "cookie | basic | digest",
    "required_cookies": ["sessionid"],
    "required_headers": ["X-Requested-With"],
    "vulnerable_parameter": "param_name",
    "parameter_location": "body | query | header | cookie",
    "encoding_constraints": "e.g. must not URL-encode semicolons",
    "injection_delimiter_hint": "e.g. ; or $() or backticks"
  },
  "poc_generation_recommendations": {
    "http_method": "GET | POST",
    "url_path": "/exact/path/from/binary",
    "content_type": "application/x-www-form-urlencoded | application/json | ...",
    "vulnerable_parameter": "exact_param_name",
    "parameter_location": "body | query | cookie | header",
    "payload_encoding": "plaintext | url_encoded | json",
    "injection_delimiter": "; | $() | backticks | &&",
    "required_cookies": ["cookie1", "cookie2"],
    "required_headers": {"Header-Name": "value"},
    "auth_required": true,
    "auth_type": "cookie | basic | digest",
    "special_notes": "any binary-specific quirks, constraints, or observations",
    "decompiled_sink_code": "the decompiled code at the sink point for reference",
    "decompiled_source_code": "the decompiled code at the source point for reference"
  },
  "key_addresses": {
    "sink_addr": "0xADDR",
    "source_addr": "0xADDR",
    "intermediate_addrs": ["0xADDR1", "0xADDR2"]
  },
  "function_addresses_hint": {
    "sink_function": "symbol_name_or_partial",
    "source_function": "symbol_name_or_partial",
    "intermediate_functions": ["symbol1", "symbol2"]
  }
}
```

## Rules

- Be precise with function names – use the exact names appearing in the code.
- Use the binary evidence (decompiled code, xrefs, addresses) to confirm or \
adjust the source-level analysis.
- If a source-level function name does not exactly match a binary symbol, \
try heuristics (prefix/suffix, substring match) and note it.
- Provide concrete hex addresses from the IDA analysis wherever possible.
- The `poc_generation_recommendations` section is the most important output – \
it will be directly consumed by the PoC generator.  Be specific and precise.
- If something cannot be determined, use `null` rather than guessing.
- Keep the JSON valid and UTF-8 clean.
- Do NOT fabricate information that is not supported by the code or binary evidence.
"""

# ---------------------------------------------------------------------------
# User prompt builder
# ---------------------------------------------------------------------------


def build_vuln_analysis_messages(
    *,
    description: str,
    code_files: List[str],
    cvenumber: Optional[str] = None,
    ida_analysis_data: Optional[str] = None,
    binary_path: Optional[str] = None,
) -> List[ChatMessage]:
    """Build the messages for vulnerability analysis.

    When ida_analysis_data is provided, uses the extended system prompt
    that includes binary-level analysis fields.
    """
    has_ida_data = bool(ida_analysis_data and ida_analysis_data.strip())
    system_prompt = (
        _VULN_ANALYSIS_WITH_IDA_SYSTEM_PROMPT
        if has_ida_data
        else _VULN_ANALYSIS_SYSTEM_PROMPT
    )

    user_parts: List[str] = []

    if cvenumber:
        user_parts.append(f"CVE: {cvenumber}")

    user_parts.append("Vulnerability Description:\n" + description.strip())

    for idx, content in enumerate(code_files, start=1):
        user_parts.append(f"--- Source Code File #{idx} ---\n{content}")

    if has_ida_data:
        ida_section = (
            "## IDA Pro Binary Analysis Data\n\n"
            f"Binary file: {binary_path or 'N/A'}\n\n"
            "The following data was collected by querying IDA Pro MCP "
            "(decompilation, cross-references, imports, call graphs, etc.):\n\n"
            f"{ida_analysis_data}"
        )
        user_parts.append(ida_section)

    return [
        ChatMessage(role="system", content=system_prompt),
        ChatMessage(role="user", content="\n\n".join(user_parts)),
    ]


__all__ = ["build_vuln_analysis_messages"]
