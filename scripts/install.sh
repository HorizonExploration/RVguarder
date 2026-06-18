#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3.13}"
VENV_DIR="${PROJECT_DIR}/.venv"

echo "[Openclaw Guard] 检查 Python 版本..."
if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "未找到 ${PYTHON_BIN}，请先安装 Python 3.13+。"
  exit 1
fi

echo "[Openclaw Guard] 创建虚拟环境..."
"${PYTHON_BIN}" -m venv "${VENV_DIR}"
source "${VENV_DIR}/bin/activate"

echo "[Openclaw Guard] 安装项目..."
python -m pip install --upgrade pip
python -m pip install -e "${PROJECT_DIR}"

echo "[Openclaw Guard] 创建运行目录..."
mkdir -p "${PROJECT_DIR}/output" "${PROJECT_DIR}/runtime" "${PROJECT_DIR}/exports"

echo "[Openclaw Guard] 安装完成。"
echo "启动命令："
echo "  source ${VENV_DIR}/bin/activate && python -m openclaw_guard.main launch"

