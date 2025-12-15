# 浏览器自动化 + Burp 拦截/重放：使用指南

本指南演示如何让“浏览器自动访问网页（经 Burp 代理）→ Burp 捕获请求 → 导出原始字节 → 按原样修改/重放”。

组件：
- 浏览器驱动（Playwright）：`PoCGen/tools/browser_driver.py`
- 桥接服务（统一 API）：`PoCGen/tools/bridge.py`
- Burp 扩展（提供 HTTP API）：`PoCGen/burp_extender/`

## 0. 预备条件
- Python 3.9+（建议 3.10+）
- Playwright 运行时（`python -m playwright install`）
- Git + JDK 21（与 `build.gradle` 中的 Java toolchain 对应）+ Gradle 8.11+
- 任意终端：PowerShell、bash 或其它 shell 均可

## 1. 安装依赖
```powershell
python -m pip install -r .\PoCGen\requirements.txt
python -m playwright install
```

若需加速 Python 依赖下载，可临时设置：
```powershell
$env:PIP_INDEX_URL = "https://pypi.tuna.tsinghua.edu.cn/simple"
```

## 2. 启动 Burp 代理并编译加载扩展
1) 启动 Burp Suite，确保代理监听在 127.0.0.1:8080（Proxy → Proxy settings）。

2) 准备 API 依赖并构建扩展 JAR：
```powershell
cd .\PoCGen\burp_extender
# 若 libs 下没有 burp-extender-api.jar，请将 Burp 提供的 API JAR 复制到 libs/ 下
# 然后构建胖 JAR（Linux/macOS 可使用 ./gradlew）：
./gradlew fatJar
```
构建成功后，生成 `build/libs/burp-extender-llm-controller-all.jar`（包含 NanoHTTPD 等依赖）。

3) 在 Burp 中加载扩展：Extender → Extensions → Add → 选择上一步生成的 JAR。
   - 成功后在 Burp 扩展控制台会看到：`HTTP API listening on http://127.0.0.1:7001`。

安全提醒：扩展仅在本机 127.0.0.1:7001 提供无鉴权 API，请仅在受控环境使用。

## 3. 启动浏览器驱动（所有流量走 Burp）
```powershell
# 可选：自定义参数
$env:BROWSER_DRV_HOST = "127.0.0.1"
$env:BROWSER_DRV_PORT = "7000"
$env:BURP_PROXY = "http://127.0.0.1:8080"
# 无桌面环境时保持 headless（默认 true）；若希望看到浏览器界面，可在有 X server / xvfb 的情况下设为 false
$env:BROWSER_HEADLESS = "true"

python .\PoCGen\tools\browser_driver.py
```
在 Linux/macOS，可使用 `export` 与 `python PoCGen/tools/browser_driver.py`。启动日志出现 `Browser driver listening on http://127.0.0.1:7000, proxy http://127.0.0.1:8080` 即成功。

## 4. 启动桥接服务（统一入口）
```powershell
$env:BRIDGE_HOST = "127.0.0.1"
$env:BRIDGE_PORT = "7002"
$env:BROWSER_API = "http://127.0.0.1:7000"
$env:BURP_API = "http://127.0.0.1:7001"

python .\PoCGen\tools\bridge.py
```
同样可用 bash：
```bash
export BRIDGE_HOST="127.0.0.1"
export BRIDGE_PORT="7002"
export BROWSER_API="http://127.0.0.1:7000"
export BURP_API="http://127.0.0.1:7001"
python PoCGen/tools/bridge.py
```
看到输出：`Bridge listening on http://127.0.0.1:7002` 即成功。

## 5. 最小验证：自动访问 → 拦截 → 导出 → 重放
在新的 PowerShell 终端执行：
```powershell
# 5.1 导航到页面（例如 http://example.com）
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:7002/browser/navigate" -Body (@{ url = "http://example.com" } | ConvertTo-Json) -ContentType "application/json"

# 5.2（可选）点击/输入
Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:7002/browser/click" -Body (@{ selector = "text=More information" } | ConvertTo-Json) -ContentType "application/json"
# 输入示例：
# Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:7002/browser/fill" -Body (@{ selector = "input[name='q']"; text = "test" } | ConvertTo-Json) -ContentType "application/json"

# 5.3 在 Burp 里应能看到被代理的请求

# 5.4 枚举捕获请求（返回 id、method、url、host、port、https）
Invoke-RestMethod -Method Get -Uri "http://127.0.0.1:7002/burp/list" | Format-List

# 5.5 获取 id=0 的原始请求字节到本地 raw.bin（PowerShell）
Invoke-WebRequest -Method Get -Uri "http://127.0.0.1:7002/burp/get_raw?id=0" -OutFile raw.bin
# Bash 可用： curl -o raw.bin "http://127.0.0.1:7002/burp/get_raw?id=0"

# 5.6 原样重放（指定目标主机/端口/是否 https）
# 例如：重放到 example.com:80（http），返回的服务端响应原始字节保存到 replay_resp.bin
Invoke-WebRequest -Method Post -Uri "http://127.0.0.1:7002/burp/replay_raw?host=example.com&port=80&https=false" -InFile raw.bin -ContentType "application/octet-stream" -OutFile replay_resp.bin
```

说明：重放通过 Burp 的 `callbacks.makeHttpRequest` 进行，仍受 Burp 的规则、上游代理等影响，便于联动调试。

## 6. 常见问题（FAQ）
- Playwright 报错或找不到浏览器 → 需先运行 `python -m playwright install`。
- 无 X server 时提示 “Looks like you launched a headed browser …” → 保持 `BROWSER_HEADLESS=true` 或使用 `xvfb-run python browser_driver.py`。
- 构建提示缺少 `burp-extender-api.jar` → 手动放入 `PoCGen/burp_extender/libs/` 后再构建。
- 接口 7001/7002 无法访问 → 确认服务在本机监听且未被占用；检查防火墙。
- 稍作防护 → 可把所有服务仅绑定到 127.0.0.1，并在桥接层增加 allowlist/rate limit。
- 若希望 PoCGen 的 `--probe-target` / `--auto-validate` 流量被 Burp 捕获，只需在运行 PoCGen 前设置 `export POCGEN_HTTP_PROXY=http://127.0.0.1:8080`（或同等 PowerShell 语法），即可让采样与验证请求走 Burp，并由扩展记录。

---
以上即可完成“浏览器自动化 → Burp 拦截 → 导出原始请求 → 修改并重放”的闭环。如需进一步把这些接口暴露给 LLM 工具链，可直接调用桥接服务（7002）的 REST 接口。