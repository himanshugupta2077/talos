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

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# scripts/ lives at <repo>/scripts → repo root is parent
DEFAULT_TALOS_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TALOS_ROOT="${TALOS_ROOT:-$DEFAULT_TALOS_ROOT}"
CP_ROOT="${CP_ROOT:-$TALOS_ROOT/talos-control-panel}"

: "${CP_BACKEND_PORT:=8420}"
: "${CP_FRONTEND_PORT:=5173}"
: "${TALOS_HOME:=$HOME/.talos}"
TALOS_VENV="${TALOS_VENV:-$TALOS_ROOT/.venv}"

CP_BACKEND_DIR="$CP_ROOT/backend"
CP_FRONTEND_DIR="$CP_ROOT/frontend"
CP_BACKEND_VENV="$CP_BACKEND_DIR/.venv"
FRONTEND_LOG="$CP_ROOT/frontend.log"
PID_FILE="$CP_ROOT/.frontend.pid"

if [[ ! -f "$TALOS_ROOT/pyproject.toml" ]]; then
    echo "[error] TALOS_ROOT does not look like the Talos repo: $TALOS_ROOT"
    echo "        Expected pyproject.toml at that path."
    exit 1
fi
if [[ ! -d "$CP_BACKEND_DIR" || ! -d "$CP_FRONTEND_DIR" ]]; then
    echo "[error] Control panel not found under: $CP_ROOT"
    echo "        Expected backend/ and frontend/ directories."
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
if ! "$CP_PY" -c "import fastapi, uvicorn" >/dev/null 2>&1; then
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
