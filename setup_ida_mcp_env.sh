#!/usr/bin/env bash
# 用途：
#   1) 在指定目录创建 ida-mcp 专用虚拟环境
#   2) 安装 IDA idalib 绑定 + ida-pro-mcp
#
# 典型用法：
#   chmod +x ./setup_ida_mcp_env.sh
#   ./setup_ida_mcp_env.sh \
#     --env-dir /home/li/LLM_POC/PoCGen/ida-mcp-env \
#     --ida-home /home/li/ida9.1
#
# 查看帮助：
#   ./setup_ida_mcp_env.sh --help

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ENV_DIR="${ENV_DIR:-$ROOT_DIR/ida-mcp-env}"
PY_VER="${PY_VER:-3.11}"
IDA_HOME="${IDA_HOME:-}"
MCP_SOURCE="${MCP_SOURCE:-git+https://github.com/mrexodia/ida-pro-mcp.git}"
SKIP_APT=0

print_help() {
  cat <<'EOF'
setup_ida_mcp_env.sh - 安装 ida-mcp 专用虚拟环境

必选参数:
  --ida-home <path>       IDA 安装目录（例如 /home/li/ida9.1）

可选参数:
  --env-dir <path>        虚拟环境安装目录（默认: PoCGen/ida-mcp-env）
  --python <ver>          Python 版本号（默认: 3.11）
  --mcp-source <src>      ida-pro-mcp 安装源（默认 GitHub；可传本地目录）
  --skip-apt              跳过 apt 安装 python 步骤
  -h, --help              显示帮助

示例:
  ./setup_ida_mcp_env.sh \
    --env-dir /home/li/LLM_POC/PoCGen/ida-mcp-env \
    --ida-home /home/li/ida9.1

GitHub 不通时可用本地源码：
  ./setup_ida_mcp_env.sh \
    --ida-home /home/li/ida9.1 \
    --mcp-source /home/li/ida-pro-mcp
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env-dir)
      ENV_DIR="$2"
      shift 2
      ;;
    --ida-home)
      IDA_HOME="$2"
      shift 2
      ;;
    --python)
      PY_VER="$2"
      shift 2
      ;;
    --mcp-source)
      MCP_SOURCE="$2"
      shift 2
      ;;
    --skip-apt)
      SKIP_APT=1
      shift
      ;;
    -h|--help)
      print_help
      exit 0
      ;;
    *)
      echo "未知参数: $1" >&2
      echo "使用 --help 查看帮助。" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$IDA_HOME" ]]; then
  echo "缺少必选参数: --ida-home" >&2
  exit 1
fi

PY_BIN="python${PY_VER}"
IDA_PY_DIR="$IDA_HOME/idalib/python"
VENV_DIR="$ENV_DIR/.venv"

echo "[1/7] 检查 Python ${PY_VER}..."
if ! command -v "$PY_BIN" >/dev/null 2>&1; then
  if [[ "$SKIP_APT" -eq 1 ]]; then
    echo "未找到 $PY_BIN，且设置了 --skip-apt，已退出。" >&2
    exit 1
  fi
  echo "未找到 $PY_BIN，尝试安装 python${PY_VER} 与 venv 组件..."
  sudo apt update
  sudo apt install -y "python${PY_VER}" "python${PY_VER}-venv"
fi

echo "[2/7] 创建专用目录: $ENV_DIR"
mkdir -p "$ENV_DIR"

echo "[3/7] 创建虚拟环境: $VENV_DIR"
if [ ! -d "$VENV_DIR" ]; then
  "$PY_BIN" -m venv "$VENV_DIR"
fi

echo "[4/7] 升级 pip/setuptools/wheel"
"$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel

echo "[5/7] 安装 IDA idalib 绑定"
if [ ! -d "$IDA_PY_DIR" ]; then
  echo "未找到目录: $IDA_PY_DIR" >&2
  echo "请检查 --ida-home 是否正确。" >&2
  exit 1
fi
"$VENV_DIR/bin/python" -m pip install "$IDA_PY_DIR"
"$VENV_DIR/bin/python" "$IDA_PY_DIR/py-activate-idalib.py"
"$VENV_DIR/bin/python" -c "import idapro; print('idapro import OK')"

echo "[6/7] 安装 ida-pro-mcp"
"$VENV_DIR/bin/python" -m pip install "$MCP_SOURCE"

echo "[7/7] 完成，验证版本"
"$VENV_DIR/bin/python" -c "import idapro; print('idapro version:', getattr(idapro, '__version__', 'unknown'))"
"$VENV_DIR/bin/idalib-mcp" --help >/dev/null

echo
echo "安装完成。"
echo "激活环境："
echo "  source $VENV_DIR/bin/activate"
echo "启动无头 MCP 示例（手动指定项目）："
echo "  idalib-mcp /path/to/target.bin"
echo "服务默认地址通常为：http://127.0.0.1:8745/mcp"
