#!/usr/bin/env bash
#
# Talos Control Panel — Linux/macOS launcher (monorepo).
#
# Auto-detects the Talos repo root and the integrated control panel tree.
# On first run (or whenever pieces are missing) it:
#   1. Creates TALOS_ROOT/.venv and installs Talos editable
#   2. Creates talos-control-panel/backend/.venv and installs backend deps
#   3. Runs npm install in the frontend when node_modules is missing
# Then starts backend + frontend, opens the browser, and tears both down
# cleanly on Ctrl+C.
#
# Usage (from anywhere):
#   ./scripts/run-control-panel.sh
#   CP_BACKEND_PORT=8421 CP_FRONTEND_PORT=5174 ./scripts/run-control-panel.sh
#
# Optional overrides (env):
#   TALOS_ROOT, CP_ROOT, TALOS_HOME, TALOS_VENV, CP_BACKEND_PORT, CP_FRONTEND_PORT
#   TALOS_CP_CLI_TIMEOUT (seconds for CP-invoked CLI; default 600 / 10 min)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# scripts/ lives at <repo>/scripts → repo root is parent
DEFAULT_TALOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

_is_talos_repo_root() {
    [[ -n "${1:-}" && -f "$1/pyproject.toml" ]]
}

_is_cp_root() {
    [[ -n "${1:-}" && -d "$1/backend" && -d "$1/frontend" ]]
}

_is_under_path() {
    local child="${1:-}"
    local parent="${2:-}"
    [[ -n "$child" && -n "$parent" ]] || return 1
    [[ "$child" == "$parent" || "$child" == "$parent"/* ]]
}

# Honor TALOS_ROOT only when it actually looks like this repo. A leftover
# env var (common after a GitHub zip extract named talos-main) used to win
# over the clone that contains this script.
_ENV_TALOS_ROOT="${TALOS_ROOT:-}"
if _is_talos_repo_root "$_ENV_TALOS_ROOT"; then
    TALOS_ROOT="$_ENV_TALOS_ROOT"
elif _is_talos_repo_root "$DEFAULT_TALOS_ROOT"; then
    if [[ -n "$_ENV_TALOS_ROOT" ]]; then
        echo "[warn] TALOS_ROOT=$_ENV_TALOS_ROOT is not a Talos repo (missing pyproject.toml)."
        echo "[warn] Ignoring stale TALOS_ROOT and using $DEFAULT_TALOS_ROOT"
    fi
    TALOS_ROOT="$DEFAULT_TALOS_ROOT"
elif [[ -n "$_ENV_TALOS_ROOT" ]]; then
    TALOS_ROOT="$_ENV_TALOS_ROOT"
else
    TALOS_ROOT="$DEFAULT_TALOS_ROOT"
fi

DEFAULT_CP_ROOT="$TALOS_ROOT/talos-control-panel"
_ENV_CP_ROOT="${CP_ROOT:-}"
_REMAPPED_TALOS_ROOT=0
if [[ -n "$_ENV_TALOS_ROOT" && "$TALOS_ROOT" != "$_ENV_TALOS_ROOT" ]]; then
    _REMAPPED_TALOS_ROOT=1
fi
if _is_cp_root "$_ENV_CP_ROOT" && ! { [[ "$_REMAPPED_TALOS_ROOT" -eq 1 ]] && _is_under_path "$_ENV_CP_ROOT" "$_ENV_TALOS_ROOT" && _is_cp_root "$DEFAULT_CP_ROOT"; }; then
    CP_ROOT="$_ENV_CP_ROOT"
elif _is_cp_root "$DEFAULT_CP_ROOT"; then
    if [[ -n "$_ENV_CP_ROOT" ]]; then
        echo "[warn] CP_ROOT=$_ENV_CP_ROOT is not a Control Panel tree (missing backend/ or frontend/), or it sits under a stale TALOS_ROOT."
        echo "[warn] Ignoring stale CP_ROOT and using $DEFAULT_CP_ROOT"
    fi
    CP_ROOT="$DEFAULT_CP_ROOT"
elif [[ -n "$_ENV_CP_ROOT" ]]; then
    CP_ROOT="$_ENV_CP_ROOT"
else
    CP_ROOT="$DEFAULT_CP_ROOT"
fi

: "${CP_BACKEND_PORT:=8420}"
: "${CP_FRONTEND_PORT:=5173}"
: "${TALOS_HOME:=$HOME/.talos}"
# Long budget for large IV/attack enqueue and slow hosts (override via env).
: "${TALOS_CP_CLI_TIMEOUT:=600}"
export TALOS_CP_CLI_TIMEOUT

DEFAULT_TALOS_VENV="$TALOS_ROOT/.venv"
_ENV_TALOS_VENV="${TALOS_VENV:-}"
if [[ "$_REMAPPED_TALOS_ROOT" -eq 1 && -n "$_ENV_TALOS_VENV" ]] && _is_under_path "$_ENV_TALOS_VENV" "$_ENV_TALOS_ROOT"; then
    echo "[warn] TALOS_VENV=$_ENV_TALOS_VENV is under stale TALOS_ROOT."
    echo "[warn] Ignoring stale TALOS_VENV and using $DEFAULT_TALOS_VENV"
    TALOS_VENV="$DEFAULT_TALOS_VENV"
else
    TALOS_VENV="${TALOS_VENV:-$DEFAULT_TALOS_VENV}"
fi

CP_BACKEND_DIR="$CP_ROOT/backend"
CP_FRONTEND_DIR="$CP_ROOT/frontend"
CP_BACKEND_VENV="$CP_BACKEND_DIR/.venv"
FRONTEND_LOG="$CP_ROOT/frontend.log"
PID_FILE="$CP_ROOT/.frontend.pid"

if [[ ! -f "$TALOS_ROOT/pyproject.toml" ]]; then
    echo "[error] TALOS_ROOT does not look like the Talos repo: $TALOS_ROOT"
    echo "        Expected pyproject.toml at that path."
    echo "        Unset TALOS_ROOT if a stale env var points at an old extract"
    echo "        (often .../talos-main), or set it to the clone that contains this script."
    exit 1
fi
if [[ ! -d "$CP_BACKEND_DIR" || ! -d "$CP_FRONTEND_DIR" ]]; then
    echo "[error] Control panel not found under: $CP_ROOT"
    echo "        Expected backend/ and frontend/ directories."
    echo "        Unset CP_ROOT if a stale env var points at an old extract"
    echo "        (often .../talos-main/talos-control-panel)."
    exit 1
fi

TALOS_PY="$TALOS_VENV/bin/python"
CP_PY="$CP_BACKEND_VENV/bin/python"
if [[ "$(uname -s)" == "Darwin" ]]; then
    OPEN_CMD=(open)
else
    OPEN_CMD=(xdg-open)
fi

echo "== Talos Control Panel launcher =="
echo "    TALOS_ROOT=$TALOS_ROOT"
echo "    CP_ROOT=$CP_ROOT"
echo "    TALOS_HOME=$TALOS_HOME"
echo "    backend=http://127.0.0.1:${CP_BACKEND_PORT}"
echo "    frontend=http://127.0.0.1:${CP_FRONTEND_PORT}"

for bin in python3 node npm; do
    command -v "$bin" >/dev/null 2>&1 || {
        echo "[error] '$bin' not found in PATH"
        exit 1
    }
done

# ---- 1. Talos core venv + editable install ----
# Do NOT use bare `import talos` as readiness: started from the repo root,
# cwd is on sys.path and the source tree imports without pip (deps missing).
if [[ ! -x "$TALOS_PY" ]]; then
    echo "[setup] Creating Talos venv at $TALOS_VENV"
    python3 -m venv "$TALOS_VENV"
    "$TALOS_PY" -m pip install --upgrade pip
fi
if [[ ! -x "$TALOS_VENV/bin/talos" ]] || ! "$TALOS_PY" -c "import httpx" >/dev/null 2>&1; then
    echo "[setup] Installing talos package (editable) from $TALOS_ROOT"
    "$TALOS_PY" -m pip install -e "$TALOS_ROOT"
else
    echo "[setup] Talos venv OK ($TALOS_VENV)"
fi

# ---- 2. Control panel backend venv + deps ----
if [[ ! -x "$CP_PY" ]]; then
    echo "[setup] Creating control panel backend venv"
    python3 -m venv "$CP_BACKEND_VENV"
    "$CP_PY" -m pip install --upgrade pip
fi
if ! "$CP_PY" -c "import fastapi, uvicorn, httpx" >/dev/null 2>&1; then
    echo "[setup] Installing control panel backend dependencies"
    "$CP_PY" -m pip install -r "$CP_BACKEND_DIR/requirements.txt"
else
    echo "[setup] Control panel backend venv OK"
fi

# ---- 3. Frontend deps ----
if [[ ! -d "$CP_FRONTEND_DIR/node_modules" ]]; then
    echo "[setup] Installing frontend dependencies (npm install)"
    (cd "$CP_FRONTEND_DIR" && npm install)
else
    echo "[setup] Frontend node_modules OK"
fi

export TALOS_HOME TALOS_ROOT
export TALOS_PYTHON="$TALOS_PY"
export CP_PORT="$CP_BACKEND_PORT"
export VITE_API_BASE="http://127.0.0.1:${CP_BACKEND_PORT}"

FRONTEND_PID=""
BACKEND_PID=""
_cleaning_up=0

# Recursively terminate a process and all of its descendants.
_kill_tree() {
    local pid="$1"
    local sig="${2:-TERM}"
    local child
    [[ -n "$pid" ]] || return 0
    while read -r child; do
        [[ -n "$child" ]] || continue
        _kill_tree "$child" "$sig"
    done < <(pgrep -P "$pid" 2>/dev/null || true)
    kill -"$sig" "$pid" 2>/dev/null || true
}

# Kill a setsid session (process group == leader PID) with tree fallback.
_kill_session() {
    local pid="$1"
    [[ -n "$pid" ]] || return 0
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM -- "-$pid" 2>/dev/null || _kill_tree "$pid" TERM
        sleep 0.3
        kill -KILL -- "-$pid" 2>/dev/null || _kill_tree "$pid" KILL
        wait "$pid" 2>/dev/null || true
    fi
}

cleanup() {
    if [[ "$_cleaning_up" -eq 1 ]]; then
        return
    fi
    _cleaning_up=1
    local code=$?
    echo ""
    echo "[run] Shutting down..."
    _kill_session "$FRONTEND_PID"
    _kill_session "$BACKEND_PID"
    while read -r child; do
        [[ -n "$child" ]] || continue
        _kill_tree "$child" TERM
    done < <(pgrep -P $$ 2>/dev/null || true)
    sleep 0.2
    while read -r child; do
        [[ -n "$child" ]] || continue
        _kill_tree "$child" KILL
    done < <(pgrep -P $$ 2>/dev/null || true)
    rm -f "$PID_FILE"
    trap - EXIT INT TERM
    exit "$code"
}
trap cleanup EXIT INT TERM

# ---- 4. Frontend in its own session (background; logs to file) ----
echo "[run] Starting frontend in background (logs -> $FRONTEND_LOG)"
: > "$FRONTEND_LOG"
if command -v setsid >/dev/null 2>&1; then
    setsid bash -c 'cd "$1" && exec npm run dev -- --port "$2" --strictPort' \
        bash "$CP_FRONTEND_DIR" "$CP_FRONTEND_PORT" \
        >"$FRONTEND_LOG" 2>&1 &
else
    bash -c 'cd "$1" && exec npm run dev -- --port "$2" --strictPort' \
        bash "$CP_FRONTEND_DIR" "$CP_FRONTEND_PORT" \
        >"$FRONTEND_LOG" 2>&1 &
fi
FRONTEND_PID=$!
echo "$FRONTEND_PID" > "$PID_FILE"

# ---- 5. Open browser once frontend responds ----
# Use 127.0.0.1 (matches vite host bind); "localhost" can be IPv6-only.
FRONTEND_URL="http://127.0.0.1:${CP_FRONTEND_PORT}"
(
    for _ in $(seq 1 60); do
        if curl -s -o /dev/null --connect-timeout 1 "$FRONTEND_URL" 2>/dev/null; then
            if command -v "${OPEN_CMD[0]}" >/dev/null 2>&1; then
                "${OPEN_CMD[@]}" "$FRONTEND_URL" >/dev/null 2>&1 || true
            else
                echo "[run] Frontend ready: $FRONTEND_URL"
            fi
            exit 0
        fi
        sleep 0.5
    done
    echo "[warn] Frontend did not become ready in time — open $FRONTEND_URL manually"
) &

# ---- 6. Backend in its own session; wait so its logs stay on this TTY ----
echo "[run] Starting backend on port $CP_BACKEND_PORT (Ctrl+C to stop everything)"
cd "$CP_BACKEND_DIR"
if command -v setsid >/dev/null 2>&1; then
    setsid "$CP_PY" -m uvicorn talos_ui.main:app --reload \
        --host 127.0.0.1 --port "$CP_BACKEND_PORT" &
else
    "$CP_PY" -m uvicorn talos_ui.main:app --reload \
        --host 127.0.0.1 --port "$CP_BACKEND_PORT" &
fi
BACKEND_PID=$!

# Keep backend logs in this terminal via wait; signals hit our trap.
wait "$BACKEND_PID" 2>/dev/null || true
