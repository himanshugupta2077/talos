# Configuration

All configurable options for the Control Panel as implemented in launchers, backend `config.py`, and frontend Vite env.

---

## Environment variables

### Launcher / process environment

| Variable | Default | Set by launcher? | Used by |
|----------|---------|------------------|---------|
| `TALOS_ROOT` | Monorepo root (auto) | Optional override | Launcher, backend config, CLI cwd |
| `CP_ROOT` | `$TALOS_ROOT/talos-control-panel` | Optional | Launcher only |
| `TALOS_HOME` | `~/.talos` / `%USERPROFILE%\.talos` | Yes (export) | Backend config, Talos CLI children |
| `TALOS_VENV` | `$TALOS_ROOT/.venv` | Optional | Launcher (path to Talos python) |
| `TALOS_PYTHON` | `$TALOS_VENV/bin/python` or Scripts | Yes | Backend CLI invocations |
| `CP_BACKEND_PORT` | `8420` | Maps to `CP_PORT` | Launcher uvicorn `--port` |
| `CP_FRONTEND_PORT` | `5173` | No backend use | Launcher vite `--port` |
| `CP_PORT` | `8420` | Yes (from backend port) | Backend config module |
| `VITE_API_BASE` | `http://127.0.0.1:8420` | Yes | Frontend API base at Vite start |
| `TALOS_BIN` | defaults to `TALOS_PYTHON` | Optional | Health payload only |
| `TALOS_CP_CLI_TIMEOUT` | `60` | Optional | `cli.run` timeout seconds |
| `CP_HOST` | `127.0.0.1` | Optional | Config constant; launcher hardcodes uvicorn host |

### Frontend-only (Vite)

| Variable | Default | Notes |
|----------|---------|-------|
| `VITE_API_BASE` | `http://127.0.0.1:8420` | Must be set before `npm run dev` / build to bake in |

See `frontend/.env.example`.

### Not configurable via env (hardcoded)

| Item | Value / location |
|------|------------------|
| CORS origins | Vite ports 5173 and 4173 on localhost and 127.0.0.1 (`config.CORS_ORIGINS`) |
| Uvicorn reload | Always `--reload` in launcher |
| Uvicorn host in launcher | Always `127.0.0.1` |
| ProcessManager log buffer | 2000 lines |
| Project selection storage key | `talos-cp-selected-project` |
| Status poll interval | 3000 ms |
| Proxy page poll | 2000 ms |
| Scheduler poll | 4000 ms |
| Command log max entries | 100 |
| Proxy listen defaults | `127.0.0.1:8080` when not specified |

---

## Ports

| Service | Default port | Bind address | Configurable via |
|---------|--------------|--------------|------------------|
| Control Panel API | 8420 | 127.0.0.1 | `CP_BACKEND_PORT` / `CP_PORT` |
| Vite dev server | 5173 | 127.0.0.1 | `CP_FRONTEND_PORT` / vite CLI |
| Vite preview | 4173 | (vite default) | npm preview flags |
| Talos proxy (mitm) | 8080 | operator choice | Proxy page / start body |

Port conflicts: see [troubleshooting.md](./troubleshooting.md).

---

## Filesystem layout

### Source (monorepo)

```text
TALOS_ROOT/
├── pyproject.toml
├── talos/                          # Talos package
├── scripts/run-control-panel.*
└── talos-control-panel/
    ├── backend/
    │   ├── requirements.txt
    │   ├── .venv/                  # created at first launch
    │   └── talos_ui/
    └── frontend/
        ├── package.json
        ├── .env.example
        ├── .env.local              # optional, not committed typically
        └── node_modules/           # created at first launch
```

### Runtime state (operator machine)

```text
TALOS_HOME/                         # default ~/.talos
└── projects/
    ├── registry.json
    └── <project_id>/
        ├── talos.db
        ├── archive/
        └── auth_sessions/
            └── <role_id>.txt
```

### Launcher artifacts

```text
talos-control-panel/
├── frontend.log
├── frontend-error.log              # Windows
└── .frontend.pid
```

### Backend monorepo root detection

`config.py` sets:

```text
_MONOREPO_ROOT = Path(__file__).resolve().parents[3]
# talos_ui/config.py → backend → talos-control-panel → TALOS_ROOT
```

If the package is moved without updating this, `TALOS_ROOT` must be set explicitly.

---

## Configurable options summary

| Option | Default | Where defined |
|--------|---------|---------------|
| Talos state home | `~/.talos` | `TALOS_HOME` |
| Talos package root | monorepo root | `TALOS_ROOT` |
| CLI Python | `$TALOS_ROOT/.venv/.../python` | `TALOS_PYTHON` |
| CLI timeout | 60s | `TALOS_CP_CLI_TIMEOUT` |
| API listen port | 8420 | `CP_PORT` / launcher |
| Frontend port | 5173 | launcher / vite |
| API base URL (browser) | `http://127.0.0.1:8420` | `VITE_API_BASE` |
| Project data dir | `TALOS_HOME/projects/<id>` | registry `data_dir` override |
| CORS | fixed list | `config.CORS_ORIGINS` |

---

## Defaults matrix (fresh clone)

| Component | Default without env |
|-----------|---------------------|
| Launcher TALOS_ROOT | parent of `scripts/` |
| Backend TALOS_ROOT | parents[3] of config.py |
| Backend TALOS_PYTHON | `$TALOS_ROOT/.venv/bin/python` (Unix) |
| Frontend API | port 8420 on 127.0.0.1 |
| Active project in UI | localStorage → registry active → first project |

---

## Interaction with Talos configuration

### Layered Talos configuration (CLI-022) vs Control Panel process config

These are **two different concepts**:

| Concept | What it is | Surface |
|---------|------------|---------|
| **Control Panel process config** | Paths, ports, `TALOS_PYTHON`, CORS, timeouts for the UI processes | This document (`talos_ui/config.py`, env vars) |
| **Talos layered configuration** | Runtime/execution settings: proxy, capture, scheduler, attack, mutation | `~/.talos/config.yaml`, `project.yaml`, `talos config …`, Control Panel **Talos Configuration** workspace |

The Control Panel does **not** re-implement merge or source attribution. The **Talos Configuration** workspace (`/talos-config`) is a thin UI over:

```text
talos config show | effective | get | set | unset | schema --format json
```

Backend router: `talos_ui/routers/configuration.py` (`/api/configuration/*`).

| Scope | Read | Write |
|-------|------|-------|
| Project | `talos --project <id> config …` | `run_scoped` → `config set/unset` |
| Global | `talos config …` (no project open required) | `cli.run` → `config set/unset --global` |

Precedence (owned by Talos core):

```text
built-in defaults → global config → legacy project bridge → project.yaml → CLI overrides
→ EffectiveConfig (+ ValueSource per leaf)
```

The older note below still applies to **process** env inheritance (not layered YAML):

The Control Panel does not parse Talos layered YAML configs for its own process startup. It inherits:

- Whatever the Talos CLI reads when subprocesses run under `TALOS_HOME` / `TALOS_ROOT`
- Project registry and DB written by Talos

Changing Talos’s own config is out of band (CLI / files under `TALOS_HOME`); the panel surfaces some project settings only through dedicated routes (scope, constraints, scheduler config, IV config, etc.).
