# Talos Control Panel

Local web UI for Talos operators: browse project data, resolve UUIDs by
clicking instead of copy-paste, manage **layered Talos configuration**
(`/talos-config` — global + project effective values with source attribution),
and run any Talos CLI command from a form instead of a terminal.

The control panel lives **inside the Talos repository** (`talos-control-panel/`).
It is a separate application (FastAPI + React) but not a separate product.

## Architecture rule

**This app never implements Talos business logic.**

| Concern | How |
|---------|-----|
| Reads | Read-only SQLite / registry; Endpoint Workspace also uses core **policy resolver** (`endpoint_reads.py`) so effective priority/exclusion/qualification match `talos endpoint list` |
| Mutations | Always `python -m talos ...` via subprocess (`talos_ui/cli.py`); bulk endpoint ops pass **all IDs in one argv** |

The Talos CLI remains the single source of truth for writes.

```
talos/                          ← Talos core (business logic + CLI)
talos-control-panel/
├── backend/                    FastAPI (reads SQLite / resolver, shells out to CLI)
│   └── talos_ui/
│       ├── main.py             app + router wiring
│       ├── config.py           env / monorepo path defaults
│       ├── db.py               read-only SQLite helpers
│       ├── endpoint_reads.py   resolved endpoint inventory (policy engine)
│       ├── cli.py              only place that mutates Talos
│       ├── command_tree.py     declarative CLI surface (Console / Helper)
│       └── routers/            one router per domain
└── frontend/                   React + TypeScript + Vite + Tailwind + DaisyUI
    └── src/pages/endpoints/    Endpoint Workspace tabs
```

## Quick start (recommended)

From the **Talos repo root**, one command sets up missing pieces and launches
both servers:

```bash
# Linux / macOS
./scripts/run-control-panel.sh

# Windows (PowerShell — recommended; clean Ctrl+C, no orphan servers)
.\scripts\run-control-panel.ps1

# Windows (cmd / double-click — thin wrapper around the .ps1)
scripts\run-control-panel.bat
```

The launcher will, if needed:

1. Create `TALOS_ROOT/.venv` and `pip install -e .` (Talos editable)
2. Create `talos-control-panel/backend/.venv` and install `requirements.txt`
3. Run `npm install` in `frontend/` when `node_modules` is missing
4. **Windows:** free stale Control Panel ports/processes from a previous crashed run
5. Start backend (port **8420**) and frontend (port **5173**)
6. Open the browser when the frontend is ready

Ctrl+C stops both processes. On Windows, children are bound to a Job Object so closing the terminal also kills them (no more background uvicorn/vite leftovers). The managed Talos proxy is independent — stop it from the Proxy page or `talos proxy stop` if needed.

### Prerequisites

- Python 3.11+
- Node.js + npm
- curl (optional; used to auto-open the browser)

### Optional environment overrides

| Variable | Default | Meaning |
|----------|---------|---------|
| `TALOS_ROOT` | monorepo root (auto) | Talos package / `pyproject.toml` |
| `CP_ROOT` | `$TALOS_ROOT/talos-control-panel` | Control panel tree |
| `TALOS_HOME` | `~/.talos` | On-disk Talos state |
| `TALOS_VENV` | `$TALOS_ROOT/.venv` | Talos virtualenv |
| `CP_BACKEND_PORT` | `8420` | FastAPI port |
| `CP_FRONTEND_PORT` | `5173` | Vite port |

Example:

```bash
CP_BACKEND_PORT=8421 CP_FRONTEND_PORT=5174 ./scripts/run-control-panel.sh
```

## Manual run (without the launcher)

**Backend**

```bash
cd talos-control-panel/backend
python3 -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Point at the monorepo Talos venv for CLI mutations
export TALOS_ROOT=../..                              # repo root
export TALOS_PYTHON="$TALOS_ROOT/.venv/bin/python"   # Windows: ...\.venv\Scripts\python.exe
export TALOS_HOME=~/.talos

uvicorn talos_ui.main:app --reload --port 8420
```

**Frontend** (second terminal)

```bash
cd talos-control-panel/frontend
npm install
npm run dev
```

Open `http://localhost:5173`. Override the API base with `VITE_API_BASE` if
needed (see `frontend/.env.example`).

## Notes

- Bound to `127.0.0.1` only — single local operator, no auth.
- CORS origins in `config.py` include the Vite dev ports (5173/4173).
- Console **Raw** tab runs any `talos` argv list without a command-tree entry.
