# PoCGen：基于大模型的命令注入（HTTP）PoC 生成器

PoCGen 用于从“若干代码文件 + 漏洞描述”中，让大模型自动生成命令注入类漏洞的 HTTP 请求 PoC。项目采用可扩展架构，后续可平滑扩展到其他漏洞类型（SQLi、SSTI、SSRF 等）。

## 功能特性
- 输入：多份代码文件（原始文本）+ 漏洞描述（文本）
- 输出：一条或多条“原始 HTTP 请求”作为 PoC（.http 文件）
- OpenAI 兼容接口调用，内置“思考模式”开关
- 基础 HTTP 报文解析与校验，自动保存到 outputs/
- 通过处理器（Handler）机制扩展不同漏洞类型

## 目录结构与模块说明

- `config/`
   - `config.py`：配置加载器，支持从环境变量读取或使用默认值。
      - `base_url` 默认 `http://222.20.126.32:30000/v1`
      - `api_key` 默认 `DeepseekV3.1_32@C402`
      - `extra_body` 默认 `{"chat_template_kwargs": {"thinking": true}}`（启用“思考模式”）

- `llm/`
   - `client.py`：LLM 客户端封装（OpenAI Chat Completions 兼容），基于 httpx。
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
- `outputs/`：生成的 .http PoC 文件输出目录。
- `tools/`：预留工具位（例如后续的“安全发送器”“格式转换器”等）。

## 安装与环境要求

1. Python 3.9+（建议 3.10 或以上）
2. 安装依赖：
```powershell
python -m pip install -r .\PoCGen\requirements.txt
```

## 配置（可选）

支持通过环境变量覆盖默认配置：

- `POCGEN_API_BASE_URL`（默认：`http://222.20.126.32:30000/v1`）
- `POCGEN_API_KEY`（默认：`DeepseekV3.1_32@C402`）
- `POCGEN_MODEL`（默认：`deepseek`）
- `POCGEN_OUTPUT_DIR`（默认：项目内 `PoCGen/outputs`）
- `POCGEN_VULN_TYPE`（默认：`command_injection_http`）

PowerShell 示例：
```powershell
$env:POCGEN_API_BASE_URL = "http://222.20.126.32:30000/v1"
$env:POCGEN_API_KEY = "DeepseekV3.1_32@C402"
# 可选：
# $env:POCGEN_MODEL = "deepseek"
# $env:POCGEN_OUTPUT_DIR = "C:\\Temp\\poc_outputs"
# $env:POCGEN_VULN_TYPE = "command_injection_http"
```

## 快速开始

准备一份漏洞描述（可参考 `PoCGen/data/desc.txt`），以及若干代码文件（可直接传入路径或通配符）。然后执行：

```powershell
# 最小示例
python -m PoCGen.cli --desc .\PoCGen\data\desc.txt --code .\VulnAgent\agent\*.py --out .\PoCGen\outputs

# 带目标提示（仅用于提示词构造，不会真实发包）
python -m PoCGen.cli --desc .\PoCGen\data\desc.txt --code .\VulnAgent\agent\*.py --target http://192.168.0.1:80 --out .\PoCGen\outputs
```

成功后，生成的 PoC 会以时间戳命名的 `.http` 文件保存在 `outputs/` 目录中。每个文件包含一条原始 HTTP 请求；若模型输出多条请求，会按顺序拆分为多个文件。

## 运行机制（数据流）

1. `cli.py` 接收参数：漏洞描述路径 + 代码文件路径（可通配）+ 可选目标。
2. `ingest.py` 读取与聚合代码文本。
3. 选择处理器（默认 `command_injection_http`），由 `prompts/templates.py` 拼装 System/User 消息。
4. `llm/client.py` 调用大模型（附带 `extra_body` 启用思考模式）。
5. `postprocess.py` 分割模型输出为多条 HTTP 报文，做最小校验，写入 `outputs/`。
6. 返回 `GenerationResult`（包含原始输出、解析对象与保存路径）。

## 扩展指南：新增一个漏洞类型

1. 在 `prompts/` 新增该漏洞类型的提示词与拼装函数。
2. 在 `core/` 新建继承自 `VulnHandler` 的处理器类，实现 `build_messages`。
3. 在 `core/generator.py` 的 `HANDLERS` 字典中注册该处理器。
4. 通过 `--vuln-type 新类型key` 或设置 `POCGEN_VULN_TYPE` 使用。

## 注意事项

- 该工具仅生成 PoC，不实际发送请求；请在合规、授权的环境中使用。
- 模型输出可能存在格式细节差异，项目已做最小容错与校验；若需更严格规范，可在 `validators.py` 中增强规则。
- “思考模式”通过 `extra_body={"chat_template_kwargs": {"thinking": true}}` 默认开启，如需关闭可在配置中覆写。

---

如需我基于你提供的具体“漏洞描述 + 代码样例”直接生成一批初版 PoC，我可以立即运行并将 .http 文件输出到 `PoCGen/outputs/` 供你审阅。
