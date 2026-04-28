#!/usr/bin/env bash
# Unified bootstrap for PoCGen.
# - Creates the main project virtual environment (default: PoCGen/.venv)
# - Installs PoCGen runtime dependencies
# - Optionally installs IDA idalib bindings + ida-pro-mcp into the same venv
#
# Examples:
#   ./setup_env.sh
#   ./setup_env.sh --python 3.11
#   ./setup_env.sh --with-ida --ida-home /home/li/ida9.1
#   ./setup_env.sh --with-ida --ida-home /home/li/ida9.1 --env-dir /tmp/ida-mcp-env

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PY_VER="${PY_VER:-3.11}"
PY_BIN_OVERRIDE="${PYTHON_BIN:-}"
VENV_DIR="${VENV_DIR:-$ROOT_DIR/.venv}"
IDA_HOME="${IDA_HOME:-}"
MCP_SOURCE="${MCP_SOURCE:-git+https://github.com/mrexodia/ida-pro-mcp.git}"
WITH_IDA=0
SKIP_APT=0

print_help() {
  cat <<'EOF'
setup_env.sh - 统一安装 PoCGen 运行环境

默认行为:
  - 使用 Python 3.11 创建 PoCGen/.venv
  - 安装 PoCGen 运行依赖

可选参数:
  --python <ver>          Python 版本号（默认: 3.11）
  --python-bin <path>     指定 Python 解释器路径，优先级高于 --python
  --venv-dir <path>       直接指定虚拟环境目录（默认: PoCGen/.venv）
  --env-dir <path>        兼容旧参数，实际使用 <path>/.venv
  --with-ida              在同一个虚拟环境中安装 IDA idalib + ida-pro-mcp
  --ida-home <path>       IDA 安装目录，例如 /home/li/ida9.1
  --mcp-source <src>      ida-pro-mcp 安装源（默认 GitHub；也可传本地目录）
  --skip-apt              缺少 Python 时不自动 apt install
  -h, --help              显示帮助

示例:
  ./setup_env.sh
  ./setup_env.sh --with-ida --ida-home /home/li/ida9.1
  ./setup_env.sh --python 3.11 --venv-dir /home/li/LLM_POC/PoCGen/.venv
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --python)
      PY_VER="$2"
      shift 2
      ;;
    --python-bin)
      PY_BIN_OVERRIDE="$2"
      shift 2
      ;;
    --venv-dir)
      VENV_DIR="$2"
      shift 2
      ;;
    --env-dir)
      VENV_DIR="$2/.venv"
      shift 2
      ;;
    --with-ida)
      WITH_IDA=1
      shift
      ;;
    --ida-home)
      IDA_HOME="$2"
      WITH_IDA=1
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

if [[ -n "$PY_BIN_OVERRIDE" ]]; then
  PY_BIN="$PY_BIN_OVERRIDE"
else
  PY_BIN="python${PY_VER}"
fi

ensure_python() {
  echo "[1/6] 检查 Python 解释器: $PY_BIN"
  if command -v "$PY_BIN" >/dev/null 2>&1; then
    return 0
  fi

  if [[ "$SKIP_APT" -eq 1 ]]; then
    echo "未找到 $PY_BIN，且设置了 --skip-apt，已退出。" >&2
    exit 1
  fi

  if [[ -n "$PY_BIN_OVERRIDE" ]]; then
    echo "未找到指定解释器: $PY_BIN_OVERRIDE" >&2
    exit 1
  fi

  echo "未找到 $PY_BIN，尝试安装 python${PY_VER} 与 venv 组件..."
  sudo apt update
  sudo apt install -y "python${PY_VER}" "python${PY_VER}-venv"
}

ensure_venv() {
  echo "[2/6] 创建虚拟环境: $VENV_DIR"
  mkdir -p "$(dirname "$VENV_DIR")"
  if [[ ! -d "$VENV_DIR" ]]; then
    "$PY_BIN" -m venv "$VENV_DIR"
  fi
}

install_pocgen_deps() {
  echo "[3/6] 升级 pip/setuptools/wheel"
  "$VENV_DIR/bin/python" -m pip install --upgrade pip setuptools wheel

  echo "[4/6] 安装 PoCGen 依赖"
  "$VENV_DIR/bin/python" -m pip install -r "$ROOT_DIR/requirements.txt"

  # 保留额外依赖安装，兼容当前项目的实际使用方式。
  "$VENV_DIR/bin/python" -m pip install "numpy<1.25" "scipy<1.11" langchain_classic websocket-client
}

install_ida_deps() {
  local ida_py_dir
  ida_py_dir="$IDA_HOME/idalib/python"

  if [[ -z "$IDA_HOME" ]]; then
    echo "启用 --with-ida 时必须提供 --ida-home。" >&2
    exit 1
  fi
  if [[ ! -d "$ida_py_dir" ]]; then
    echo "未找到目录: $ida_py_dir" >&2
    echo "请检查 --ida-home 是否正确。" >&2
    exit 1
  fi

  echo "[5/6] 安装 IDA idalib 绑定"
  "$VENV_DIR/bin/python" -m pip install "$ida_py_dir"
  "$VENV_DIR/bin/python" "$ida_py_dir/py-activate-idalib.py"
  "$VENV_DIR/bin/python" -c "import idapro; print('idapro import OK')"

  echo "[6/6] 安装 ida-pro-mcp"
  "$VENV_DIR/bin/python" -m pip install "$MCP_SOURCE"
  "$VENV_DIR/bin/python" -c "import idapro; print('idapro version:', getattr(idapro, '__version__', 'unknown'))"
  "$VENV_DIR/bin/idalib-mcp" --help >/dev/null
}

ensure_python
ensure_venv
install_pocgen_deps

if [[ "$WITH_IDA" -eq 1 ]]; then
  install_ida_deps
else
  echo "[5/6] 跳过 IDA 安装（未指定 --with-ida）"
  echo "[6/6] 主环境安装完成"
fi

echo
echo "安装完成。建议使用："
echo "  PYTHONNOUSERSITE=1 $VENV_DIR/bin/python -m PoCGen.cli ..."
if [[ "$WITH_IDA" -eq 1 ]]; then
  echo "  $VENV_DIR/bin/idalib-mcp /path/to/target.bin"
fi
