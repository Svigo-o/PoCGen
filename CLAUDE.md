# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

PoCGen provides infrastructure tools for command injection PoC development. Claude (you) is the analyst and PoC author — you read source code, understand vulnerabilities, and generate PoC requests yourself. The MCP tools provide capabilities Claude lacks: CVE web crawling, CDP browser automation, HTTP/Socket.IO replay validation, and wget callback monitoring.

## Commands

```bash
# Activate virtual environment
source .venv/bin/activate

# Run PoC generation (minimal)
python -m PoCGen.cli --desc desc.txt --code src/*.c

# With CVE crawl + auto-validate + target sampling
python -m PoCGen.cli --desc desc.txt --code src/*.c \
  --target http://192.168.6.2 --CVENumber CVE-2025-9149 \
  --probe-target --browser-login --auto-validate --max-iters 5

# Socket.IO PoC
python -m PoCGen.cli --desc desc.txt --code src/*.c \
  --target ws://192.168.6.2:3000/socket.io/?EIO=4&transport=websocket \
  --vuln-type command_injection_socket --auto-validate

# With IDA binary analysis
python -m PoCGen.cli --desc desc.txt --code src/*.c \
  --binary /path/to/firmware.cgi --ida-mcp-url http://127.0.0.1:8745/mcp

# Standalone attacker monitor
python -m PoCGen.core.attacker_monitor --url http://0.0.0.0:6666

# Setup environment (with optional IDA)
./setup_env.sh
./setup_env.sh --with-ida --ida-home /home/li/ida9.1
```

## Architecture

### MCP Workflow (Claude-主导)

```
1. pocgen_read_code("./desc.txt", "./src/*.c")     → 读取漏洞描述和源码
2. pocgen_cve_intelligence("CVE-2025-9149")         → 爬取 CVE 情报
3. pocgen_sample_target("http://192.168.6.2")       → CDP 浏览器探测目标
4. pocgen_load_device_profile("TotolinkA3300R")     → 加载已知设备模式（可选）
5. (Claude 自己分析漏洞，理解注入点)                   → Claude 的核心价值
6. (Claude 自己生成 PoC HTTP 请求)                    → 基于理解，不是猜
7. pocgen_parse_http(raw_request)                   → 验证格式
8. pocgen_validate_http(requests, target)           → 重放到目标验证
9. pocgen_monitor_start() + pocgen_monitor_wait()   → 监听 wget 回调
10. pocgen_save_poc(raw_request)                    → 保存到磁盘
11. pocgen_save_device_profile(...)                  → 缓存设备模式（首次验证后）
12. pocgen_batch_validate("./pocs_saved/", target)  → 批量验证所有 PoC
13. 失败? Claude 分析原因，调整策略，重试              → 比弱LLM反馈循环更强
```

### MCP Tools (15 个)

| 工具 | 用途 | Claude 能否自己做 |
|---|---|---|
| `pocgen_cve_intelligence` | 爬取 NVD + 参考链接 | 否（需要 HTTP 请求） |
| `pocgen_sample_target` | CDP 浏览器探测 | 否（需要浏览器） |
| `pocgen_read_code` | 读取源码文件 | 是（但封装更方便） |
| `pocgen_parse_http` | 解析 HTTP 请求格式 | 是（但封装更准确） |
| `pocgen_parse_socket` | 解析 Socket.IO 事件 | 同上 |
| `pocgen_validate_http` | 重放 HTTP 请求 | 否（需要 HTTP 请求） |
| `pocgen_validate_socket` | 分发 Socket.IO 事件 | 否（需要 WebSocket） |
| `pocgen_monitor_start` | 启动回调监听 | 否（需要 HTTP 服务器） |
| `pocgen_monitor_wait` | 等待回调 | 否 |
| `pocgen_monitor_stop` | 停止回调 | 否 |
| `pocgen_save_poc` | 保存 PoC 到磁盘 | 是（但封装更规范） |
| `pocgen_batch_validate` | 批量验证目录下所有 .http PoC 文件 | 否（需要 HTTP 请求 + monitor） |
| `pocgen_save_device_profile` | 保存设备 profile（CGI 路径、注入方式） | 是（但封装更规范） |
| `pocgen_load_device_profile` | 加载已保存的设备 profile | 是（但封装更规范） |
| `pocgen_list_device_profiles` | 列出所有设备 profiles | 是（但封装更规范） |

### CLI (完整流水线)

CLI 模式仍保留完整的自动化流水线，供非 Claude 用户使用：

```bash
python -m PoCGen.cli --desc desc.txt --code src/*.c \
  --target http://192.168.6.2 --CVENumber CVE-2025-9149 \
  --probe-target --browser-login --auto-validate --max-iters 5
```

CLI 内部使用弱 LLM（DeepSeek/GLM）完成漏洞分析和 PoC 生成，通过 `core/generator.py` 调度。

### Key Module Responsibilities

- `mcp_tools/`: MCP 工具注册（intelligence, validation, monitor, utility）
- `mcp_tools/state.py`: SessionCache 缓存 CVE 情报和目标采样结果
- `core/shared/`: 公共基础设施（HTTP/Socket.IO 的 postprocess、validators、remote_validator、handler 基类）
- `core/attacker_monitor.py`: HTTP 服务器监听 wget 回调（0.0.0.0:6666）
- `core/cdp_sampler.py`: CDP 浏览器自动化（Chrome DevTools Protocol，LLM 辅助字段分析）
- `core/ida_mcp_service.py` / `core/ida_mcp_client.py`: IDA Pro 二进制分析
- `core/cve_crawler.py`: CVE 情报爬取（NVD 镜像 + 参考链接爬虫）
- `core/command_injection/`: 命令注入 PoC handler（HTTP/Socket.IO）
- `core/cross_site_scripting/`: XSS PoC handler
- `core/path_traversal/`: 路径遍历 PoC handler
- `core/stackoverflow/`: 栈溢出 PoC handler（HTTP/Python）
- `core/generator.py`: CLI 流水线调度器（handler 注册、分发）

### Configuration

All config via `.env` or environment variables with `POCGEN_` prefix. See `config/config.py` for full list. Key providers: `POCGEN_DS_*` (DeepSeek), `POCGEN_GLM_*` (GLM), `POCGEN_QWEN_*` (Qwen). Default provider set by `POCGEN_DEFAULT_PROVIDER`.

### Output Locations

- HTTP PoC: `output/poc/poc_<timestamp>_nn.http`
- Socket PoC: `output/socket/socket_poc_<timestamp>_nn.json`
- CVE cache: `output/cve_cache/<CVE-ID>.json`
- Browser samples: `output/cookie/`, `output/http_post_sample/`, `output/socket_sample/`
- Device profiles: `output/device_profiles/<device_name>.json`
- Logs: `logs/` (chat, vuln_analysis, idamcp, login_chat)

## Firmware Injection Decision Guide

When analyzing firmware command injection vulnerabilities, follow these rules to avoid common pitfalls.

### Device-Specific Injection Patterns

**Totolink (shttpd, JSON API):**
```
POST /cgi-bin/cstecgi.cgi
Content-Type: application/json
Referer: http://<target>/
{"topicurl":"<endpoint>","<param>":"<value>`<payload>`"}
```
- Parameters go through `Uci_Set_Str` → `snprintf` → `CsteSystem` (shell execution)
- Use backtick `` ` `` as injection delimiter — most reliable across firmware shells
- Always include `Referer` header or the request is rejected

**Wavlink (lighttpd, form-urlencoded):**
```
POST /cgi-bin/<login|wireless|firewall>.cgi
Content-Type: application/x-www-form-urlencoded
page=<type>&<param>=<value>`<payload>`
```
- Parameters go through `sprintf` → `system()`
- Same backtick delimiter works

### Critical Rules

1. **`addEffect` controls code flow**: Many Totolink handlers use `addEffect` to decide execution path. `addEffect="0"` usually only toggles enable/disable state and does NOT read other parameters. `addEffect="1"` enters the add-rule branch that reads all parameters. Always use `addEffect="1"` when injecting via rule-adding endpoints (setMacFilterRules, setPortForwardRules, setStaticDhcpRules, setParentalRules, setStaticRoute).

2. **`atoi()` breaks injection**: If a parameter passes through `atoi()` before reaching the shell command, backtick injection will fail — `atoi()` stops at the first non-digit character. Check the source code for `atoi()` calls on your target parameter. Choose parameters that go directly to `snprintf`/`Uci_Set_Str` without type conversion.

3. **API success ≠ injection success**: `{"success": true}` only means the handler function returned without error. It does NOT mean the injected command executed. The ONLY reliable verification is the attacker monitor callback (wget hitting your listener).

4. **Firmware version mismatch**: The same `topicurl` may map to different handler functions in different firmware versions. Source code analysis must match the actual device firmware. If a PoC should work but doesn't, check if the function pointer in the routing table matches your source code.

5. **`Uci_Set_Str` vs `Uci_Add_List` vs `doSystem`**: These are different execution paths. `Uci_Set_Str` writes to UCI config then may trigger a shell command. `Uci_Add_List` appends to a list value — if the list is later joined with a separator (e.g., semicolon) and passed to shell execution, injection still works but the payload must be the first field. `doSystem` directly executes shell commands.

6. **Parameter selection strategy**: When a handler has multiple parameters, prefer the one that:
   - Goes through `snprintf` string concatenation (not `atoi` conversion)
   - Is a string type (not numeric/boolean)
   - Is used in a shell command context (search for `system`, `CsteSystem`, `doSystem`, `popen` in the source)

### Troubleshooting Checklist

When a PoC fails (no monitor callback):

1. Is `addEffect` set to `"1"`? (for rule-adding endpoints)
2. Does the injected parameter pass through `atoi()`? (check source code)
3. Is the injection delimiter correct? (backtick is safest, `$()` may not work in all firmware shells)
4. Does the handler use `Uci_Set_Str` or a different path? (adjust parameter accordingly)
5. Does the request format match the device? (JSON for Totolink, form-urlencoded for Wavlink)
6. Is the `Referer` header present? (required for Totolink)
7. Does the source code match the actual firmware version?

## Language

Code comments, prompts, and CLI help are in Chinese. The project targets Chinese-speaking security researchers.
