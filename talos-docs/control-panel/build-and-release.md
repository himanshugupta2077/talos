# Build and release

How to set up, develop, and build the Control Panel. There is no separate packaging/release pipeline for the Control Panel in this repository beyond monorepo checkout + launchers.

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| Python 3.11+ | Launchers call `python3` (Unix) or `python` (Windows) |
| Node.js + npm | For Vite frontend |
| curl | Optional; browser auto-open on Windows/Unix poll |
| Git monorepo checkout | Control Panel expects to live under Talos repo root |

Talos runtime dependencies (e.g. `httpx`, mitmproxy stack as required by the Talos package) are installed into the **Talos** venv via editable install—not into the Control Panel backend venv.

---

## Recommended: launcher setup

From monorepo root:

```bash
./scripts/run-control-panel.sh
# or (Windows PowerShell)
.\scripts\run-control-panel.ps1
```

The launcher:

1. Creates `$TALOS_ROOT/.venv` if needed
2. `pip install -e $TALOS_ROOT` when Talos entry/deps missing
3. Creates `talos-control-panel/backend/.venv` if needed
4. `pip install -r backend/requirements.txt` when FastAPI stack missing
5. `npm install` in frontend when `node_modules` missing
6. Starts dev servers

This is the supported “first run” path. Details: [startup.md](./startup.md).

---

## Backend setup (manual)

```bash
cd talos-control-panel/backend
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

`requirements.txt`:

```text
fastapi>=0.111
uvicorn[standard]>=0.30
pydantic>=2.7
```

Ensure Talos itself is installed in a separate venv:

```bash
cd "$TALOS_ROOT"
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Point the Control Panel at that interpreter:

```bash
export TALOS_ROOT=/path/to/talos-repo
export TALOS_PYTHON="$TALOS_ROOT/.venv/bin/python"
export TALOS_HOME=~/.talos
```

Run API:

```bash
cd talos-control-panel/backend
source .venv/bin/activate
uvicorn talos_ui.main:app --reload --host 127.0.0.1 --port 8420
```

Package import path: `talos_ui` is loaded from the `backend/` working directory (no separate `pip install` of the control panel package required for the documented workflow).

---

## Frontend setup (manual)

```bash
cd talos-control-panel/frontend
npm install
```

Optional: copy `.env.example` → `.env.local` and set `VITE_API_BASE`.

### Development mode

```bash
npm run dev
```

- Vite binds `127.0.0.1:5173` with `strictPort: true` (`vite.config.ts`)
- Hot module replacement enabled by Vite
- API calls go to `VITE_API_BASE` (not a Vite proxy)

### Production build

```bash
npm run build
```

Runs `tsc -b && vite build`, producing static assets under `frontend/dist/` (Vite default).

Preview production build locally:

```bash
npm run preview
```

Default preview port is Vite’s 4173; CORS allows `localhost`/`127.0.0.1:4173`.

**Note:** The stock launchers always start **dev** mode (`npm run dev` + uvicorn `--reload`). Serving the production build behind a reverse proxy or static file server is possible but not automated by `run-control-panel.*`.

There is no backend “production” settings module (no Gunicorn config, no multi-worker recipe in-tree).

---

## Launcher scripts

| Script | Role |
|--------|------|
| `scripts/run-control-panel.sh` | Unix end-to-end setup + run |
| `scripts/run-control-panel.ps1` | Windows end-to-end setup + run (only Windows launcher) |

Both treat the monorepo as the unit of deployment: Talos + Control Panel together.

---

## Other scripts

| Script | Role |
|--------|------|
| `talos-control-panel/bundle.sh` | Bundles source/diffs for AI review (`commit` or `dir` mode). **Not** part of runtime or release. |

---

## Development mode characteristics

| Aspect | Behaviour |
|--------|-----------|
| Backend reload | Uvicorn `--reload` watches Python files |
| Frontend HMR | Vite default |
| Logging | Backend on TTY; frontend in `frontend.log` |
| Data | Real `TALOS_HOME` on disk (not sandboxed) |
| Auth | None |

---

## Versioning

- FastAPI app declares `version="1.0.0"` in `main.py`
- Frontend `package.json` version `1.0.0`
- No separate Control Panel release tags observed in this documentation task; versioning follows the monorepo

---

## Checklist for a clean machine

1. Install Python 3.11+, Node.js, npm  
2. Clone monorepo  
3. Run launcher once  
4. Confirm `GET http://127.0.0.1:8420/api/health`  
5. Confirm UI at `http://127.0.0.1:5173`  
6. Create/open a project and verify CLI mutations (command drawer shows `python -m talos …`)
