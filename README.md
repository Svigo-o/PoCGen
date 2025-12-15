# PoCGen：基于大模型的命令注入（HTTP）PoC 生成器

PoCGen 用于从“若干代码文件 + 漏洞描述”中，让大模型自动生成命令注入类漏洞的 HTTP 请求 PoC。项目采用可扩展架构，后续可平滑扩展到其他漏洞类型（SQLi、SSTI、SSRF 等）。

## 功能特性
- 输入：多份代码文件（原始文本）+ 漏洞描述（文本）
- 输出：一条或多条“原始 HTTP 请求”作为 PoC（.http 文件）
- 基于 OpenAI Python SDK 的 LLM 调用，保留“思考模式”开关
- 基础 HTTP 报文解析与校验，自动保存到 `output/`
- 通过处理器（Handler）机制扩展不同漏洞类型
- 支持“采样 -> 生成 -> 自动验证 -> 攻击机回调监控”的多轮迭代，直到满足成功条件或达到最大迭代次数
- 采样到的 HTTP 范本会额外落盘到 `collect/` 目录，便于复现与比对
- 浏览器登录采样（Playwright）：自动尝试表单登录、点击按钮、提交表单，采集最终页面/响应；获取到的 Cookie 会按原始 HTTP 报文保存
- 原始报文落盘（统一输出根目录，默认 `output/`）：
   - PoC 请求：`output/poc/poc_<timestamp>_nn.http`
   - 采样样本：`output/collect/sample_<timestamp>.txt`
   - 浏览器 Cookie 原始报文：`output/cookie/<YYYYMMDD_HHMMSS>-cookies.json`
   - 浏览器最终请求/响应原始报文：`output/cookie/<YYYYMMDD_HHMMSS>-cookie.http`

## 目录结构与模块说明

- `config/`
   - `config.py`：配置加载器，支持从环境变量读取或使用默认值。
      - 预置 `qwen` 与 `deepseek` 两个提供商，分别使用 `POCGEN_QWEN_*` / `POCGEN_DS_*` 环境变量配置 base_url、api_key、model。
      - `POCGEN_DEFAULT_PROVIDER` 控制默认调用哪个提供商（默认 `qwen`）。
      - `POCGEN_TIMEOUT` 指定 OpenAI SDK 请求超时时间（秒）。

- `llm/`
   - `client.py`：LLM 客户端封装，使用 OpenAI Python SDK 直接调用 Chat Completions。
      - 负责将系统+用户消息发送给大模型，返回文本结果。

- `prompts/`
   - `templates.py`：提示词模板与拼装逻辑。
      - `build_prompt_command_injection_http`：根据描述与代码文本构建“命令注入（HTTP）”场景的 System/User 消息。

- `core/`
   - `models.py`：核心数据结构
      - `HTTPMessage`：表示 HTTP 请求，含解析函数 `parse`。
      - `GenerationResult`：生成结果（原始输出、解析后的请求、保存路径）。
      - `VulnHandler`：漏洞类型处理器基类。
   - `ingest.py`：输入文件读取（支持通配符），合并为文本列表。
   - `generator.py`：主流程
      - 选择处理器 -> 组装消息 -> 调用 LLM -> 分割/保存输出 -> 返回结果。
      - 当前注册处理器：`command_injection_http`。
   - `postprocess.py`：将 LLM 输出切分为多条 HTTP 报文、解析与落盘。
   - `validators.py`：对 HTTP 报文做最小化校验（请求行、Host、Content-Length 等）。

- `cli.py`：命令行入口，便于一键运行。
- `tests/`：最小单元测试（解析与提示拼装）。
- `output/poc/`：生成的 .http PoC 文件输出目录。
- `output/collect/`：采集到的 HTTP 报文样本存档目录。
- `output/cookie/`：浏览器采样阶段保存的原始报文（包含 Cookie 和完整请求/响应）。
- `tools/`：预留工具位（例如后续的“安全发送器”“格式转换器”等）。

## 安装与环境要求

1. Python 3.9+（建议 3.10 或以上）
2. 安装依赖：
```powershell
python -m pip install -r .\PoCGen\requirements.txt
```

## 配置（可选）

支持通过环境变量覆盖默认配置：

- `POCGEN_QWEN_BASE_URL`（默认：`http://222.20.126.36:30000/v1`）
- `POCGEN_QWEN_API_KEY`（默认：`QWEN3@C402`）
- `POCGEN_QWEN_MODEL`（默认：`qwen`）
- `POCGEN_DS_BASE_URL`（默认：`http://222.20.126.32:30000/v1`）
- `POCGEN_DS_API_KEY`（默认：`DeepseekV3.1_32@C402`）
- `POCGEN_DS_MODEL`（默认：`deepseek`）
- `POCGEN_DEFAULT_PROVIDER`（默认：`qwen`，可切换到 `deepseek` 等）
- `POCGEN_TIMEOUT`（LLM 请求超时秒数，默认 60）
- `POCGEN_OUTPUT_ROOT`（输出根目录，默认 `PoCGen/output`）
- `POCGEN_OUTPUT_DIR`（PoC 输出目录，默认 `${POCGEN_OUTPUT_ROOT}/poc`）
- `POCGEN_COLLECT_DIR`（采样目录，默认 `${POCGEN_OUTPUT_ROOT}/collect`）
- `POCGEN_COOKIE_DIR`（浏览器报文目录，默认 `${POCGEN_OUTPUT_ROOT}/cookie`）
- `POCGEN_VULN_TYPE`（默认：`command_injection_http`）
- `POCGEN_ATTACKER_URL`（注入 payload 需要访问的攻击机 URL）
- `POCGEN_HTTP_PROXY`（可选，若希望采样/验证流量经 Burp，可设置为 `http://127.0.0.1:8080`）
- `POCGEN_BRIDGE_URL`（预留，指向 `tools/bridge.py` 服务，默认 `http://127.0.0.1:7002`）
- `POCGEN_SAMPLE_TIMEOUT`、`POCGEN_VALIDATION_TIMEOUT`（采样/验证 HTTP 请求超时时间，秒）
- `POCGEN_SAMPLE_PREVIEW`（采样响应截断长度，默认 2000 字符）
- `POCGEN_MAX_ITERS`（默认最大尝试次数，默认 1）
- `POCGEN_STOP_ON_SUCCESS`（是否在监控到 wget 回调后立即停止，默认 true）
- `POCGEN_MONITOR_TIMEOUT`（每轮验证后等待 wget 回调的秒数，默认 10）
- `BROWSER_HEADLESS`（浏览器采样是否无头，默认 true；可设为 false 观察界面）
- `POCGEN_SAMPLE_PREVIEW_CHARS`（采样预览长度，默认 2000，可覆盖）

PowerShell 示例：
```powershell
# 切换默认模型到 deepseek，并改写对应的 URL / Key
$env:POCGEN_DEFAULT_PROVIDER = "deepseek"
$env:POCGEN_DS_BASE_URL = "http://222.20.126.32:30000/v1"
$env:POCGEN_DS_API_KEY = "DeepseekV3.1_32@C402"

# 可选：
# $env:POCGEN_QWEN_BASE_URL = "http://222.20.126.36:30000/v1"
# $env:POCGEN_QWEN_API_KEY = "QWEN3@C402"
# $env:POCGEN_OUTPUT_DIR = "C:\\Temp\\poc_outputs"
# $env:POCGEN_VULN_TYPE = "command_injection_http"
```

## 快速开始

准备一份漏洞描述（可参考 `PoCGen/data/desc.txt`），以及若干代码文件（可直接传入路径或通配符）。然后执行：

```powershell
# 最小示例（输出目录使用默认设置）
python -m PoCGen.cli --desc .\PoCGen\data\desc.txt --code .\VulnAgent\agent\*.py

# 带目标提示（仅用于提示词构造，不会真实发包）
python -m PoCGen.cli --desc .\PoCGen\data\desc.txt --code .\VulnAgent\agent\*.py --target http://192.168.0.1:80

# 启用目标探测 + 自动验证（确保 target 可达，且必要时设置 POCGEN_HTTP_PROXY 让流量经过 Burp）
python -m PoCGen.cli --desc desc.txt --code src/*.c --target http://192.168.6.2 --probe-target --auto-validate

# 多轮迭代示例（最多 5 轮，监控回调 15 秒）
python -m PoCGen.cli --desc desc.txt --code src/*.c --target http://192.168.6.2 \
   --probe-target --auto-validate --max-iters 5 --monitor-timeout 15

# 浏览器登录采样 + 自动验证（获取 Cookie 并落盘原始报文）
python -m PoCGen.cli --code src/*.c --target http://192.168.6.2 \
   --probe-target --browser-login --login-url http://192.168.6.2/ \
   --login-username admin --login-password admin --auto-validate
```

成功后，生成的 PoC 会以时间戳命名的 `.http` 文件保存在 `output/` 目录中。所有迭代共用同一目录，文件名如 `poc_20250101_120000_01.http`，若出现重名会自动附加序号避免覆盖。

## 运行机制（数据流）

1. `cli.py` 接收参数：漏洞描述路径 + 代码文件路径（可通配）+ 可选目标。
2. `ingest.py` 读取与聚合代码文本。
3. 选择处理器（默认 `command_injection_http`），由 `prompts/templates.py` 拼装 System/User 消息。
4. `llm/client.py` 调用大模型（附带 `extra_body` 启用思考模式）。
5. `postprocess.py` 分割模型输出为多条 HTTP 报文，做最小校验，写入 `output/`（所有迭代共享目录）。
6. 若启用了 `--probe-target`，采集到的 HTTP 报文会写入 `collect/`，供复现与提示词调优。
7. 若启用了 `--browser-login`，Playwright 会尝试登录、点击按钮、提交表单，并将：
   - 登录后的 Cookie 以原始 `Set-Cookie` 报文形式写入 `cookie/<ts>-cookies.json`；
   - 终态请求/响应的原始 HTTP 报文写入 `cookie/<ts>-cookie.http`。
7. 返回 `GenerationResult`（包含原始输出、解析对象与保存路径）。

## 浏览器自动化 + Burp 联动验证（可选）

PoC 生成完成后，可通过“浏览器驱动 + 桥接服务 + Burp 扩展”自动访问目标、捕获并导出真实请求：

1. **加载 Burp 扩展**：在 `burp_extender/` 运行 `./gradlew fatJar`，把生成的 `build/libs/burp-extender-llm-controller-all.jar` 加载到 Burp（Extender → Add），确认控制台出现 `HTTP API listening on http://127.0.0.1:7001`。Burp Proxy 需监听 `127.0.0.1:8080`。
2. **启动浏览器驱动**（默认 headless）：
   ```bash
   export BURP_PROXY="http://127.0.0.1:8080"
   export BROWSER_DRV_HOST="127.0.0.1"
   export BROWSER_DRV_PORT="7000"
   # 如需可视化，可在存在 X server / xvfb 的环境下将 BROWSER_HEADLESS=false
   export BROWSER_HEADLESS="true"
   python PoCGen/tools/browser_driver.py
   ```
3. **启动桥接服务**：
   ```bash
   export BRIDGE_HOST="127.0.0.1"
   export BRIDGE_PORT="7002"
   export BROWSER_API="http://127.0.0.1:7000"
   export BURP_API="http://127.0.0.1:7001"
   python PoCGen/tools/bridge.py
   ```
4. **最小验证**：
   ```bash
   # 导航到目标
   curl -X POST "http://127.0.0.1:7002/browser/navigate" \
        -H "Content-Type: application/json" \
        -d '{"url":"http://192.168.6.2"}'

   # 列出在 Burp 中捕获的请求
   curl "http://127.0.0.1:7002/burp/list" | jq

   # 导出第 0 条请求的原始字节
   curl -o raw_0.bin "http://127.0.0.1:7002/burp/get_raw?id=0"
   ```

浏览器所有流量都会走 Burp 代理，Burp 扩展管理请求缓存并提供导出/重放接口，桥接服务将两者封装成统一 REST API，方便 LLM 或脚本调用。

## 自动采样与自验证（实验特性）

- `--probe-target`：在调用 LLM 前，PoCGen 会主动访问 `--target`（或 `POCGEN_HTTP_PROXY` 指向的代理后端）并采集响应样本（Content-Type、编码、body 截断）。采样结果会追加到 Prompt，为模型提供真实页面结构作为范本。
- `--auto-validate`：在生成 `.http` 请求后，PoCGen 会立即把请求通过 HTTP 发送到目标（可选经由 Burp 代理），并将响应状态、预览打印到终端。
- `--login-*` / `--browser-login`：先以表单或 Playwright 浏览器方式登录目标，采集/验证阶段都会复用获取到的 Cookie（日志写入 `logs/playwright_login.log`），适合需要认证才能访问的场景。
- 当 `--auto-validate` 开启时，PoCGen 默认会根据 `POCGEN_MAX_ITERS` 自行循环：每轮都会把上一轮的解析错误、验证反馈（如缺失 Cookie、状态码 403）以及攻击机回调情况整理后再喂给模型，促使其修正请求。
- 攻击机地址由 `POCGEN_ATTACKER_URL` 或 `--attacker` 控制，PoCGen 会在本地启动监听（端口需与 URL 一致）。若在 `POCGEN_MONITOR_TIMEOUT` 秒内收到来自目标设备的 `wget` 请求，即认为成功并在 `POCGEN_STOP_ON_SUCCESS` 为 true 时提前结束迭代。
- 若监听失败或未收到回调，反馈会自动告诉模型尝试修改 payload（例如调整参数、补齐 Cookie）。
- 两个流程均使用 `httpx`，如果想让探测/验证流量被 Burp 捕获，只需设置 `POCGEN_HTTP_PROXY=http://127.0.0.1:8080`，并确保 Burp 代理保持监听。
- 验证与监控结果会写入 `GenerationResult.attempts`，保留每轮的请求、响应与回调摘要，便于调试和复盘。

## 扩展指南：新增一个漏洞类型

1. 在 `prompts/` 新增该漏洞类型的提示词与拼装函数。
2. 在 `core/` 新建继承自 `VulnHandler` 的处理器类，实现 `build_messages`。
3. 在 `core/generator.py` 的 `HANDLERS` 字典中注册该处理器。
4. 通过 `--vuln-type 新类型key` 或设置 `POCGEN_VULN_TYPE` 使用。

## 注意事项

- 该工具仅生成 PoC，不实际发送请求；请在合规、授权的环境中使用。
- 模型输出可能存在格式细节差异，项目已做最小容错与校验；若需更严格规范，可在 `validators.py` 中增强规则。
- “思考模式”通过 `extra_body={"chat_template_kwargs": {"thinking": true}}` 默认开启，如需关闭可在配置中覆写。
- 若在无桌面环境中使用浏览器驱动，保持 `BROWSER_HEADLESS=true`（默认）；如需可视化，请在提供 X server 或使用 `xvfb-run` 后将其改为 `false`。

---

如需我基于你提供的具体“漏洞描述 + 代码样例”直接生成一批初版 PoC，我可以立即运行并将 .http 文件输出到 `PoCGen/output/` 供你审阅。
