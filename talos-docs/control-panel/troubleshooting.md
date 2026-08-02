# Troubleshooting

Common failures and how they map to the current implementation. Prefer checking launcher logs and the UI command drawer before changing code.

---

## Startup failures

### `TALOS_ROOT does not look like the Talos repo`

Launcher cannot find `pyproject.toml` at `TALOS_ROOT`.

- Run from the monorepo or set `TALOS_ROOT` to the clone root
- Ensure you are not pointing at `talos-control-panel/` alone

### `Control panel not found under CP_ROOT`

Missing `backend/` or `frontend/` under `CP_ROOT`.

- Default is `$TALOS_ROOT/talos-control-panel`
- Override `CP_ROOT` only if the tree was relocated

### `python3` / `python` / `node` / `npm` not found

Install prerequisites and ensure they are on `PATH`. Windows message explicitly asks for Python 3.11+.

### Launcher exits during pip / npm install

- Inspect terminal output for network or compiler errors
- Retry after fixing the underlying install error
- Readiness probes re-run on next launch

---

## Missing dependencies

### CLI stderr: could not find Python at `TALOS_PYTHON`

Backend cannot execute `TALOS_PYTHON`.

- Run the launcher so `$TALOS_ROOT/.venv` is created
- Or export `TALOS_PYTHON` to an interpreter that has `talos` installed (`python -m talos`)

### Commands fail with ModuleNotFoundError for talos deps

Talos venv incomplete. Launcher checks `import httpx` and the `talos` console script; if those pass but another dep is missing, reinstall:

```bash
"$TALOS_ROOT/.venv/bin/python" -m pip install -e "$TALOS_ROOT"
```

### Backend fails: No module named fastapi / uvicorn

Control Panel backend venv incomplete:

```bash
talos-control-panel/backend/.venv/bin/python -m pip install -r talos-control-panel/backend/requirements.txt
```

### Frontend blank / module not found

```bash
cd talos-control-panel/frontend && rm -rf node_modules && npm install
```

---

## CLI failures

### Steps show `ok: false` in command drawer

Open the Command drawer (auto-opens on failure). Inspect `stderr` and `cmd_str`.

Common causes:

- No project open / wrong project id
- Invalid UUID for flow/endpoint/finding
- Talos validation error (business rules)
- Missing auth configuration for attacks/replay

### Timed out (`timed_out: true`)

Default timeout is 60s (`TALOS_CP_CLI_TIMEOUT`).

- Raise the env var for long-running attacks
- Prefer scheduler enqueue instead of blocking CLI for heavy work

### `project open` succeeds but second step fails

Scoped commands always open first. The second step’s stderr is the real error; open may still leave that project active in Talos.

### Mutations seem ignored by capture

Proxy addon may still be running with old state.

- Ensure project is **active** (Open on Projects page), not only selected
- Confirm proxy was restarted after role/module/mutation/auth changes
- Manually stop/start proxy on Proxy page

---

## Port conflicts

### Backend will not start (address already in use)

Port 8420 (or `CP_BACKEND_PORT`) taken.

```bash
CP_BACKEND_PORT=8421 CP_FRONTEND_PORT=5174 ./scripts/run-control-panel.sh
```

Also set matching `VITE_API_BASE` if starting frontend manually.

### Frontend: strictPort failure

Vite is configured with `strictPort: true`. If 5173 is busy, Vite exits instead of picking another port.

- Free the port or set `CP_FRONTEND_PORT`

### Proxy: port still in use after stop

ProcessManager restart waits for port release; if another process holds the mitm port (default 8080), restart returns an error.

- Stop orphaned mitmdump/proxy processes
- Choose another listen port on the Proxy page

### ProcessManager lost track of proxy after backend restart

In-memory registry is empty; OS process may still run.

- Kill orphan proxy/mitmdump manually
- Start proxy again from the UI

---

## Database issues

### Dashboard: No talos.db found

Expected for a brand-new project until traffic is captured or Talos initializes the DB.

- Open the project in Talos
- Start proxy and send traffic through it

### Empty lists despite traffic

- Wrong project selected in the UI
- Registry `data_dir` points elsewhere than expected
- Confirm `GET /api/health` → `talos_home` matches where data was written

### 404 on detail routes

Entity id not in selected project’s DB, or DB path wrong for that project id.

### Schema errors / SQL exceptions

Control Panel SQL assumes Talos schema. After Talos upgrades that rename columns, panel queries may throw 500s.

- Compare error traceback to router SQL
- Use Console CLI to read data until panel is updated

### Registry corrupt

`load_registry` returns `{}` on JSON decode errors — UI shows no projects.

- Inspect `~/.talos/projects/registry.json` validity

---

## Open directory failures

`POST /api/projects/{id}/open-directory` opens a predefined project folder in the OS file explorer. **Copy path** is browser clipboard only and does not call this endpoint.

| Symptom / detail | Cause | Fix |
|------------------|-------|-----|
| `project not found` | Unknown project id | Refresh project list; select a valid project |
| `Project data directory does not exist` | Resolved path missing on disk | Create/open project so Talos creates the data dir; check registry `data_dir` override |
| `unsupported operating system` | Not Linux or Windows | Open the path manually; macOS is not supported by this helper |
| `xdg-open was not found` | Missing FreeDesktop opener | Install `xdg-utils` (or distro equivalent) |
| `Failed to launch directory opener` | Process spawn / startfile OS error | Check permissions; open path manually from a terminal |
| Validation 422 on `target` | Client sent non-enum target or path-like string | UI must send only `data_dir` or `database_dir` |

Notes:

- Backend resolves paths from project identity + registry; arbitrary browser paths are never accepted.
- Registry `data_dir` outside `~/.talos/projects/<id>` is **valid** and must not be rejected solely for location.
- Opening the database target opens the **parent directory** of `talos.db`, not SQLite or a DB GUI.
- Success means the open request was **issued** (non-blocking); the explorer window is not tracked.

---

## Frontend issues

### UI loads but all API calls fail

- Backend not running
- Wrong `VITE_API_BASE` (must match backend host/port; set before Vite start)
- CORS: API called from a host/port not in `CORS_ORIGINS` (only 5173/4173 localhost variants)

### UI selection lost after refresh

Selection is in `localStorage` key `talos-cp-selected-project`. If the id is gone from registry, falls back to active/first.

### Stale data after CLI from terminal

Pages only reload on their own effects/actions. Refresh the page or re-trigger load.

### Theme / styling broken

Ensure `npm install` completed (Tailwind, DaisyUI). Check browser console for CSS issues.

---

## Backend issues

### Health OK but CLI always fails

`TALOS_PYTHON` points at wrong interpreter; health only reports paths, does not run CLI.

### CORS errors in browser console

Origin not allowlisted. Dev server must be on 5173/4173 localhost/127.0.0.1 unless `CORS_ORIGINS` is code-changed.

### Uvicorn reload restarts mid-command

Editing backend Python while a long CLI command runs can kill the worker. Avoid editing during long runs; note launchers always use `--reload`.

---

## Launcher issues

### Browser does not open

- curl missing (Windows warns)
- Frontend never became ready within poll window
- No `xdg-open` / `open` (Unix): URL is printed instead

Open `http://127.0.0.1:<CP_FRONTEND_PORT>` manually.

### Frontend keeps running after Ctrl+C

Unix trap should kill process sessions; if `setsid` unavailable, tree kill may be incomplete.

- Check `frontend.log` / `.frontend.pid`
- Kill leftover node/vite processes

### Windows frontend orphan

After abnormal exit, use Task Manager or re-run cleanup logic: stop PID in `.frontend.pid` and children.

### Logs

| Log | Content |
|-----|---------|
| Terminal | Backend uvicorn |
| `talos-control-panel/frontend.log` | Vite |
| `frontend-error.log` | Windows Vite stderr |
| UI Command drawer | CLI stdout/stderr |
| Proxy page live log | ProcessManager buffer |

---

## Quick diagnostic checklist

1. `curl -s http://127.0.0.1:8420/api/health | jq`  
2. Confirm `registry_exists` and `talos_home`  
3. `TALOS_PYTHON -m talos project list` from shell  
4. Reproduce action in UI; read Command drawer  
5. Compare with same argv in a terminal under `TALOS_ROOT`  
6. Check ports with `ss`/`netstat` if binds fail  
7. Confirm selected project is **active** when proxy/capture is involved  
