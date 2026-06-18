#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[Openclaw Guard] 清理虚拟环境与运行产物..."
rm -rf "${PROJECT_DIR}/.venv"
rm -rf "${PROJECT_DIR}/runtime/ui"
rm -f "${PROJECT_DIR}/output/audit/audit.db"
rm -f "${PROJECT_DIR}/output/audit/audit.jsonl"
rm -f "${PROJECT_DIR}/runtime/controlled-actions.json"
rm -f "${PROJECT_DIR}/runtime/latest-baseline.json"

echo "[Openclaw Guard] 卸载完成。未修改系统库，也不会触碰 OpenClaw 源码。"

