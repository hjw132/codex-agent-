#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SYNC_FILE="${SYNC_FILE:-$ROOT_DIR/AGENT_SYNC.md}"
MAX_TURNS="${MAX_TURNS:-20}"
SANDBOX_MODE="${SANDBOX_MODE:-workspace-write}"
AGENTS="${AGENTS:-LEAD,DEV,QA}"
LEAD_AGENT="${LEAD_AGENT:-}"
AGENT_PERMISSIONS="${AGENT_PERMISSIONS:-}"
MODEL_NAME="${MODEL_NAME:-}"
REASONING_EFFORT="${REASONING_EFFORT:-}"

if ! command -v codex >/dev/null 2>&1; then
  CODEX_FALLBACK="$(ls -1d "$HOME"/.vscode/extensions/openai.chatgpt-*/bin/linux-*/codex 2>/dev/null | sort -V | tail -n 1 || true)"
  if [[ -n "${CODEX_FALLBACK}" ]]; then
    export CODEX_BIN="${CODEX_BIN:-$CODEX_FALLBACK}"
    export PATH="$(dirname "$CODEX_BIN"):$PATH"
    echo "[multi-agent] PATH 未找到 codex，已自动使用: $CODEX_BIN"
  fi
fi

if [[ $# -lt 1 ]]; then
  echo "用法:"
  echo "  $0 \"任务描述\" [附加 auto_dual_agent.py 参数]"
  echo
  echo "环境变量快捷项:"
  echo "  AGENTS=LEAD,ARCH,BACKEND,FRONTEND,QA"
  echo "  LEAD_AGENT=LEAD"
  echo "  AGENT_PERMISSIONS=LEAD=read-only,DEV=workspace-write,QA=read-only"
  echo "  MODEL_NAME=gpt-5.3-codex"
  echo "  REASONING_EFFORT=low|medium|high|xhigh"
  echo
  echo "示例:"
  echo "  AGENTS=LEAD,BACKEND,FRONTEND,QA LEAD_AGENT=LEAD MODEL_NAME=gpt-5.3-codex REASONING_EFFORT=high $0 \"搭建一个博客网页，包含前后端\" --dangerous --max-turns 30 --agent-role BACKEND=负责后端API --agent-role FRONTEND=负责前端页面 --agent-role QA=负责测试与回归"
  exit 1
fi

TASK="$1"
shift

CMD=(
  python3 "$ROOT_DIR/scripts/auto_dual_agent.py"
  --workspace "$ROOT_DIR"
  --sync-file "$SYNC_FILE"
  --task "$TASK"
  --agents "$AGENTS"
  --max-turns "$MAX_TURNS"
  --sandbox "$SANDBOX_MODE"
)

if [[ -n "$LEAD_AGENT" ]]; then
  CMD+=(--lead "$LEAD_AGENT")
fi

if [[ -n "$MODEL_NAME" ]]; then
  CMD+=(--model "$MODEL_NAME")
fi

if [[ -n "$REASONING_EFFORT" ]]; then
  CMD+=(--reasoning-effort "$REASONING_EFFORT")
fi

if [[ -n "$AGENT_PERMISSIONS" ]]; then
  IFS=',' read -r -a _perm_items <<< "$AGENT_PERMISSIONS"
  for _perm in "${_perm_items[@]}"; do
    _perm_trimmed="$(echo "$_perm" | xargs)"
    if [[ -n "$_perm_trimmed" ]]; then
      CMD+=(--agent-permission "$_perm_trimmed")
    fi
  done
fi

CMD+=("$@")
"${CMD[@]}"
