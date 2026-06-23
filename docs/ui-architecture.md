# Talos UI — Web App Architecture

---

## Overview

The Talos UI is a **read-mostly, locally-served web application** that provides a browser-based view over the data captured and managed by the Talos CLI. It is started via `talos ui` and serves on `http://127.0.0.1:8000/` by default. It is **never** exposed to the internet — it is a local operator tool.

The app has three distinct interaction modes:

| Mode | Used for | Rendering |
|------|----------|-----------|
| **Server-side HTML** | Flow viewer, endpoint viewer, project overview | Jinja2 templates rendered on the server |
| **JS shell + REST API** | Management pages (roles, modules, access, mutations, etc.) | Shell HTML template; JavaScript fetches `/api/*` and mutates DOM |
| **SSE live-sync** | Flows list, endpoints list, scheduler queue | `EventSource` on `/api/stream`; DOM patched in-place, no reload |

All write operations go through the REST API. The Jinja-rendered pages are **strictly read-only** from the server's perspective.

The SSE stream is a continuous, read-only observer of the DB — it emits incremental events as new data is written by the worker. It never triggers full-page reloads or replaces entire table bodies.

---

## Technology Stack

| Layer | Technology |
|-------|-----------|
| HTTP server | uvicorn (ASGI) |
| Web framework | FastAPI |
| Template engine | Jinja2 (via `fastapi.templating.Jinja2Templates`) |
| Database access | `sqlite3` stdlib — read-only URI connections (`?mode=ro`) |
| HTTP client (replay) | httpx (async) — via `talos.replay.engine` |
| Schema validation | Pydantic v2 (request bodies) |
| Fonts | JetBrains Mono (Google Fonts CDN import in CSS) |

---

## Module Structure

```
talos/ui/
    __init__.py
    app.py           — FastAPI app factory; all HTML routes; mounts /api router; lifespan hook
    cli.py           — talos ui CLI handler; starts uvicorn
    db.py            — read-only data access layer (registry + SQLite)
    proxy_manager.py — ProxyManager singleton; spawns/stops mitmdump; broadcasts log lines to SSE subscribers
    api/
        __init__.py
        _deps.py     — shared FastAPI dependency providers
        access.py    — /api/access  (read + write access matrix)
        attacks.py   — /api/attacks  (unauth attack module: coverage, enqueue, auto-run toggle)
        auth.py      — /api/auth    (show + set + clear auth config)
        endpoints.py — /api/endpoints  (read-only)
        flows.py     — /api/flows  (read-only)
        modules.py   — /api/modules  (create + activate)
        mutations.py — /api/mutations  (create + toggle + delete)
        outscope.py  — /api/outscope  (add + remove block-list domains)
        projects.py  — /api/projects  (create + open + close + scope + constraints)
        proxy.py     — /api/proxy  (start + stop + status; lifecycle control)
        replay.py    — /api/replay  (enqueue or execute immediate replays)
        roles.py     — /api/roles  (create + activate)
        scheduler.py — /api/scheduler  (status + config + clear queue)
        stream.py    — /api/stream   (SSE live-sync; DB delta polling + proxy log/status events)
    templates/
        base.html        — CSS design system + shared layout skeleton
        _nav.html        — project_nav Jinja2 macro (per-project tab bar)
        projects.html    — project list
        project.html     — project overview
        flows.html       — paginated flow list
        flow.html        — Burp-style split flow detail
        endpoints.html   — paginated endpoint list
        endpoint.html    — endpoint detail (params + linked flows)
        access.html      — access matrix shell (JS-driven)
        roles.html       — role management shell (JS-driven)
        modules.html     — module management shell (JS-driven)
        proxy.html       — proxy lifecycle control panel (JS-driven; SSE log stream)
        replay.html      — replay controls shell (JS-driven)
        scheduler.html   — scheduler queue + config shell (JS-driven)
        mutations.html   — mutation management shell (JS-driven)
        outscope.html    — out-of-scope domain management shell (JS-driven)
        attacks.html     — attack modules shell (JS-driven; 10 s auto-refresh)
```

---

## Startup and Lifecycle

```
talos ui [--host HOST] [--port PORT]
    │
    ├── talos.ui.cli.run_inspect_cli()
    │       parse --host / --port
    │       talos.ui.app.create_app(projects_root)
    │           → _lifespan context manager
    │               startup:  app.state.proxy_manager = ProxyManager(projects_root)
    │               shutdown: await app.state.proxy_manager.cleanup()
    │           → FastAPI(title="Talos UI", docs_url=None, redoc_url=None,
    │                     lifespan=_lifespan)
    │           → app.state.projects_root = projects_root
    │           → Jinja2Templates(directory=<templates_dir>)
    │           → register all HTML routes (GET)
    │           → build /api APIRouter
    │                 include_router × 13 (one per api module)
    │           → app.include_router(_api)
    │           → return app
    │
    └── uvicorn.run(app, host=host, port=port, log_level="warning")
            blocks until SIGINT / SIGTERM
```

`create_app()` is a factory function — it returns a configured `FastAPI` instance rather than creating a module-level singleton. This makes the app testable and composable.

`docs_url=None, redoc_url=None` — OpenAPI docs are disabled; this is an operator tool, not a public API.

`ProxyManager` is instantiated once per server lifecycle via the lifespan hook and stored on `app.state.proxy_manager`. On shutdown the lifespan hook calls `cleanup()`, which terminates any running mitmdump subprocess to prevent orphan processes.

---

## Dependency Injection (`talos.ui.api._deps`)

Two typed `Annotated` aliases are used across all API route modules:

```
ProjectsRoot = Annotated[Path, Depends(_projects_root)]
```
Extracts `app.state.projects_root` from the request. Used by routes that need
registry access but do not require an active project (e.g. `POST /api/projects`).

```
ActiveProject = Annotated[Project, Depends(_active_project)]
```
Resolves `ProjectManager(root).active()`. Raises `HTTP 422` if no project is
currently open. Used by all routes that operate on per-project data.

Every `/api/*` route that touches project data declares `project: ActiveProject`
as a parameter. No route module contains its own project resolution logic.

---

## Rendering Modes

### Mode 1 — Server-Side HTML (Jinja2)

Used for read-heavy views where all data is available server-side and no client
interaction is needed.

```
GET /project/{id}/flows?page=2&limit=50
    │
    ├── idb.get_project_record()   — registry.json lookup
    ├── idb.get_flow_count()       — COUNT(*) on flows table
    ├── idb.list_flows()           — paginated SELECT with role/module JOIN
    │
    └── _render(request, "flows.html", context)
            → templates.TemplateResponse(request, template, context)
            → HTML response
```

Pages in this mode:
- `/` — project list
- `/project/{id}` — project overview (counts, archive size, scope)
- `/project/{id}/flows` — paginated flow list (+ SSE live-sync; see Mode 3)
- `/project/{id}/flows/{flow_id}` — Burp-style split request/response view
- `/project/{id}/endpoints` — paginated endpoint list (+ SSE live-sync; see Mode 3)
- `/project/{id}/endpoints/{endpoint_id}` — endpoint detail

### Mode 3 — SSE Live-Sync

The flows list, endpoints list, and scheduler pages open a persistent `EventSource`
connection to `GET /api/stream` after initial HTML render. The server polls the DB
every 2 seconds and pushes incremental events; the client patches only the affected
DOM nodes.

```
GET /project/{id}/flows  →  HTML render (initial state)
        │
        └── JS EventSource("/api/stream")
                │
                ├── event: connected  → dot turns green
                ├── event: flow       → prepend <tr> to #flow-tbody
                │                      increment #flow-total counter
                │                      show "↑ N new" badge if scrolled down
                ├── event: endpoint_count → update #ep-total
                │                           show badge; badge click re-fetches
                │                           /api/endpoints and re-renders tbody
                └── event: sched_counts   → call load() on scheduler page
                                            (re-renders stats row + jobs list)
```

Stability rules enforced by the client:
- Never resets scroll position
- Never replaces a full table — only prepends rows or re-renders tbody data
- Batches burst arrivals into a pending queue; flushes on scroll-to-top or badge click
- `EventSource` reconnects automatically on disconnect (browser built-in)

Pages in this mode: flows (partial), endpoints (partial), scheduler (partial).

### Mode 2 — JS Shell + REST API

Used for management pages where the user needs to create, activate, or delete
items. The server renders a minimal HTML shell; JavaScript fetches `/api/*`
on load and handles user interactions via `fetch()` + DOM mutation.

```
GET /project/{id}/roles
    │
    └── _render(request, "roles.html", {"project": project})
            → HTML shell with <script> block that calls:
                  GET /api/roles     → populate role list
                  POST /api/roles    → create role
                  POST /api/roles/{name}/activate → set active
                  DELETE /api/roles/active         → reset to global
```

Pages in this mode: roles, modules, access, proxy, replay, scheduler, mutations, outscope, attacks.

---

## Route Map

### HTML Routes (all GET, all server-side Jinja2)

```
GET  /                                         → projects.html
GET  /project/{project_id}                     → project.html
GET  /project/{project_id}/flows               → flows.html  (paginated; ?page=N&limit=N)
GET  /project/{project_id}/flows/{flow_id}     → flow.html   (Burp split view)
GET  /project/{project_id}/flows/{flow_id}/json→ JSONResponse (inline fetch from flows list)
GET  /project/{project_id}/endpoints           → endpoints.html
GET  /project/{project_id}/endpoints/{eid}     → endpoint.html
GET  /project/{project_id}/roles               → roles.html   (JS shell)
GET  /project/{project_id}/modules             → modules.html (JS shell)
GET  /project/{project_id}/access              → access.html  (JS shell)
GET  /project/{project_id}/proxy               → proxy.html   (JS shell + SSE log stream)
GET  /project/{project_id}/replay              → replay.html  (JS shell)
GET  /project/{project_id}/scheduler           → scheduler.html (JS shell)
GET  /project/{project_id}/mutations           → mutations.html (JS shell)
GET  /project/{project_id}/outscope            → outscope.html  (JS shell)
GET  /project/{project_id}/attacks             → attacks.html   (JS shell)
```

### API Routes (`/api/*`)

All routes require `ActiveProject` (HTTP 422 if no active project) unless noted.

#### `/api/projects` — no ActiveProject requirement; uses ProjectsRoot

```
GET    /api/projects                  list all projects (active first)
POST   /api/projects                  create project (name, description, scope[])
POST   /api/projects/{id}/open        activate project (writes registry)
POST   /api/projects/{id}/close       deactivate project (writes registry)
PUT    /api/projects/{id}/scope       replace scope list
PUT    /api/projects/{id}/constraints replace capture constraints
```

#### `/api/proxy`

```
GET    /api/proxy/status          current proxy state and pid → {status, pid}
POST   /api/proxy/start           start mitmdump for the active project (optional: port, listen_host)
POST   /api/proxy/stop            stop the running mitmdump process
```

All three routes extract `ProxyManager` from `app.state` rather than using `ActiveProject`.
`POST /api/proxy/start` validates the active project itself via `ProjectManager.active()` inside
`ProxyManager.start()` — the UI never starts the proxy when no project is open.

#### `/api/flows` — read-only

```
GET    /api/flows                     paginated flow list (?page=N&limit=N)
GET    /api/flows/{flow_id}           single flow detail (bytes → UTF-8 or base64)
```

#### `/api/endpoints` — read-only

```
GET    /api/endpoints                 paginated endpoint list (hit_count, roles, modules)
GET    /api/endpoints/{endpoint_id}   endpoint + parameters + linked flows + roles
```

#### `/api/roles`

```
GET    /api/roles                     list all roles (id, name, is_active)
POST   /api/roles                     create role → 409 if duplicate
POST   /api/roles/{name}/activate     set active role for flow tagging
DELETE /api/roles/active              reset active role to "global"
```

#### `/api/modules`

```
GET    /api/modules                   list all modules (id, name, description, is_active)
POST   /api/modules                   create module → 409 if duplicate
POST   /api/modules/{name}/activate   set active module for flow tagging
DELETE /api/modules/active            reset active module to "global"
```

#### `/api/access`

```
GET    /api/access                    full role × module access matrix
PUT    /api/access                    set client or server access state (allow|deny|unknown)
DELETE /api/access/{role}/{module}    remove entire access-map row
GET    /api/access/coverage           per-(role,module) flow + endpoint counts
GET    /api/access/signals            four-section BAC signal report
```

#### `/api/replay`

```
POST   /api/replay/flow/{flow_id}              enqueue flow replay job → job_id
POST   /api/replay/flow/{flow_id}/now          execute flow replay immediately → outcome
POST   /api/replay/endpoint/{endpoint_id}      enqueue endpoint replay job → job_id
POST   /api/replay/endpoint/{endpoint_id}/now  execute endpoint replay immediately → outcome
```

`/now` routes are `async` — they call `await replay_engine.replay_flow/endpoint()` which sends the outbound HTTP request. They are the only routes in the UI that do I/O beyond reading SQLite.

#### `/api/scheduler`

```
GET    /api/scheduler              queue status (counts by status, pending jobs, config)
GET    /api/scheduler/jobs         jobs filtered by ?status=<status> (?limit=N&offset=N)
PUT    /api/scheduler/config       update min_delay / max_delay / max_queue_size
DELETE /api/scheduler/queue        clear all pending jobs (returns count deleted)
```

`GET /api/scheduler/jobs?status=done` returns up to 200 jobs (configurable via `limit`) for
the given status ordered by `finished_at DESC` for terminal states or `created_at DESC` otherwise.
Each job dict includes `replayed_flow_id` — the UUID of the replay flow generated by that job,
which the UI renders as a direct hyperlink to `/project/{id}/flows/{replayed_flow_id}`.

#### `/api/attacks`

```
GET    /api/attacks/unauth                coverage dict + paginated endpoint list + auto_run flag
GET    /api/attacks/unauth/auto           {"enabled": bool}
PUT    /api/attacks/unauth/auto           set auto_run flag (body: {"enabled": bool})
POST   /api/attacks/unauth/run-untested   bulk-enqueue AUTH_TEST jobs for all untested endpoints
POST   /api/attacks/unauth/{endpoint_id}  enqueue AUTH_TEST job for one endpoint → 409 if duplicate
```

Coverage and per-endpoint status are **derived**, not stored — calculated on-the-fly from
`auth_test_results` and `scheduler_jobs`. The `auto_run` flag lives in the `attack_config`
table (key `unauth_auto_run`). Verdicts: `BYPASS` (200 replay), `SECURE` (401/403/3xx),
`UNKNOWN` (error or non-200 original).

Each endpoint row returned by `GET /api/attacks/unauth` now includes `unauth_replay_flow_id` —
the UUID of the replay flow produced by the most recent auth test for that endpoint.  The attacks
page uses this to render a direct **"view"** hyperlink in the coverage detail panel.

#### `/api/mutations`

```
GET    /api/mutations           list all request mutations (id, type, key, value, enabled)
POST   /api/mutations           add mutation (type="header", key, value)
PATCH  /api/mutations/{id}      toggle enabled ↔ disabled
DELETE /api/mutations/{id}      delete mutation → 404 if not found
```

#### `/api/outscope`

```
GET    /api/outscope            list out-of-scope domains (id, domain, created_at)
POST   /api/outscope            add domain to block-list (lowercased; no-op if duplicate)
DELETE /api/outscope/{domain}   remove domain → 404 if not found
```

#### `/api/stream` — SSE, read-only

```
GET    /api/stream              open SSE stream for the active project
```

Holds an open `text/event-stream` response for the life of the client connection.
Polls the project DB every 2 seconds. Emits three event types:

| Event | Payload | Trigger |
|-------|---------|--------|
| `connected` | `{project: id}` | On first connection |
| `flow` | flow row dict (id, method, host, path, query, status_code, captured_at, role_name, module_name) | Each new flow persisted since last poll |
| `endpoint_count` | `{total: N}` | When the normalised endpoint count changes |
| `sched_counts` | status → count dict | When any scheduler status counter changes |
| `proxy_log` | `{line: str}` | Each line from mitmdump stdout/stderr |
| `proxy_status` | `{status: "running"\|"stopped"}` | When proxy process starts or stops |

Capped at 50 new-flow events per poll cycle. Emits SSE comment `: keepalive` every
cycle to prevent proxy/LB timeouts. Headers: `Cache-Control: no-cache`,
`X-Accel-Buffering: no`.

Proxy events are emitted by draining a per-client `asyncio.Queue` published to by
`ProxyManager`. On connect the client receives the last 500 buffered log lines and
the current proxy status before the poll loop begins. On disconnect the queue is
unsubscribed from the manager. If the queue fills (slow client) lines are dropped
on the producer side without affecting the SSE connection.

---

## Proxy Manager (`talos.ui.proxy_manager`)

`ProxyManager` is the single in-process owner of the mitmdump subprocess. One instance
lives on `app.state.proxy_manager` for the lifetime of the uvicorn server; it is
created by the lifespan hook and cleaned up on shutdown.

### Key behaviour

| Concern | Detail |
|---------|--------|
| Subprocess | `asyncio.create_subprocess_exec` with `stdout=PIPE`, `stderr=STDOUT` (merged stream) |
| Addon | `talos/proxy/addon.py` passed to mitmdump via `-s`; resolved relative to the package |
| Log buffer | `deque(maxlen=500)` — rolling window of the last 500 lines (per server lifetime) |
| Pub/sub | Each SSE client gets an `asyncio.Queue(maxsize=200)`; producer drops lines if queue full |
| History on connect | `subscribe()` pre-seeds the returned queue with all buffered lines + current status |
| Status | `"running"` or `"stopped"` — transitions broadcast to all subscriber queues |
| Stop sequence | `SIGTERM` → 5 s wait → `SIGKILL` if still alive → cancel reader task |
| Orphan prevention | `cleanup()` called by lifespan shutdown; always terminates the child process |

### Invariants

- Only one mitmdump process runs at a time; `start()` is a no-op if already running.
- `start()` calls `ProjectManager.active()` — no subprocess is spawned without an active project.
- CAPTURE/SKIP events from the addon reach the ProxyManager log stream via the subprocess
  stdout/stderr pipe (addon uses `logger.debug`; mitmdump forwards addon log output to its own
  stdout). No ANSI codes, no direct stdout writes from the addon.

---

## Data Access Layer (`talos.ui.db`)

The `db` module is the only place that touches SQLite. It:
- Opens **read-only** connections using the SQLite URI syntax: `file:<path>?mode=ro`
- Never holds a persistent connection — every function opens and closes its own context
- Guards every query with `_table_exists()` to handle partially-migrated DBs gracefully
- Returns `list[dict]` or `dict | None` — never `sqlite3.Row` objects

Write paths (access map, roles, modules, mutations, outscope, scheduler config)
go through the existing `talos.projects.*` modules, not through `talos.ui.db`.

### Key queries

| Function | SQL pattern | Used by |
|----------|-------------|---------|
| `list_flows()` | `SELECT ... JOIN roles JOIN modules ORDER BY captured_at DESC LIMIT ? OFFSET ?` | flows list page + API |
| `get_flow_detail()` | `SELECT f.* + role/module names WHERE f.id = ?` | flow detail page + API |
| `get_adjacent_flows()` | window `LAG/LEAD` CTE over `captured_at DESC` | flow detail prev/next nav |
| `list_endpoints()` | `GROUP BY e.id` with `COUNT(flows)`, `GROUP_CONCAT(roles/modules)` | endpoints list + API |
| `get_endpoint_detail()` | single endpoint row by id | endpoint detail |
| `get_endpoint_parameters()` | `WHERE endpoint_id = ? ORDER BY location, name` | endpoint detail |
| `get_endpoint_flows()` | `WHERE endpoint_id = ? ORDER BY captured_at DESC LIMIT 20` | endpoint detail |
| `get_adjacent_endpoints()` | Python-side neighbour lookup after ordered ID fetch | endpoint prev/next nav |
| `list_endpoint_roles()` | `JOIN roles ON endpoint_roles` | endpoint detail + API |
| `list_endpoints_multi_role()` | `HAVING COUNT(role_id) > 1` | signals API |
| `detect_server_deny_endpoints()` | `JOIN access_map WHERE server_expected='DENY'` | signals API |
| `detect_deny_with_flows()` | `client_allowed='DENY' AND flow_count > 0` | signals API |
| `detect_allow_without_flows()` | `client_allowed='ALLOW' AND flow_count = 0` | signals API |
| `get_access_coverage()` | `GROUP BY role_id, module_id` with flow + endpoint counts | coverage API |
| `get_latest_flow_captured_at()` | `SELECT captured_at FROM flows ORDER BY captured_at DESC LIMIT 1` | stream cursor seed |
| `list_flows_after()` | `WHERE captured_at > ? ORDER BY captured_at ASC LIMIT ?` | stream flow delta |
| `get_unauth_coverage()` | CTE over `endpoints LEFT JOIN auth_test_results LEFT JOIN scheduler_jobs`; aggregate CASE counts | attacks coverage API |
| `list_endpoint_unauth_status()` | same CTE; per-row derived status + `unauth_replay_flow_id`; ORDER BY BYPASS-first | attacks endpoint list |
| `detect_server_deny_endpoints()` | `JOIN access_map WHERE server_expected='DENY'`; returns `flow_ids` list (up to 10) | signals API |

---

## Template System

All templates extend `base.html` via Jinja2 `{% extends %}`.

### `base.html`
- Defines the full CSS design system via CSS custom properties (`:root` block)
- Palette: black (`#000000`) background, neon green (`#39ff14`) accent, JetBrains Mono font
- Provides `{% block title %}`, `{% block content %}`, `{% block scripts %}` extension points
- Contains shared nav bar (`<nav>`) and page layout structure

### `proxy.html`
Proxy lifecycle control panel (Mode 2 — JS shell + SSE log stream).
- Start/stop buttons with mutual exclusion gated on current proxy status.
- Port and listen_host config inputs (defaults: `8080` / `127.0.0.1`).
- Status indicator (green dot when running, grey when stopped) and PID display.
- Append-only log pane with auto-scroll; disengages on user scroll-up.
- Lines prefixed with `[talos]` highlighted green.
- Listens on `EventSource("/api/stream")` for `proxy_log` and `proxy_status` events.
- "Clear" button clears the log pane DOM without affecting the server buffer.

### `_nav.html`
- Defines a single `project_nav(project_id, active='')` Jinja2 **macro**
- Renders the per-project tab strip: About, Flows, Endpoints, Access, Proxy, Replay, Scheduler, Mutations, Attacks
- Imported via `{% from '_nav.html' import project_nav %}` in each project-scoped template

### Template helpers (defined in `app.py`, used in route handlers)

| Helper | Purpose |
|--------|---------|
| `_render()` | Wraps `templates.TemplateResponse()` with Starlette 0.28+ call signature |
| `_fmt_bytes()` | Converts byte count to human-readable string (B/KB/MB/GB) |
| `_parse_json_field()` | Safe JSON parse; returns `{}` on failure |
| `_decode_body()` | Decodes `bytes \| None` → `(str, is_truncated)` |
| `_maybe_pretty_json()` | Attempts `json.dumps(..., indent=2)`; returns original on failure |
| `_flatten_headers()` | Converts header dict (with possible list values) → flat `[(name, value)]` list |

### Flow detail rendering pipeline

```
DB row (raw)
    │
    ├── request_headers (JSON string) → _parse_json_field() → dict → _flatten_headers()
    ├── request_body    (BLOB)        → _decode_body()      → (str, truncated)
    │       if starts with { or [    → _maybe_pretty_json()
    ├── response_headers (JSON string)→ _parse_json_field() → dict → _flatten_headers()
    ├── response_body    (BLOB)       → _decode_body()      → (str, truncated)
    │       if content_type has "json"→ _maybe_pretty_json()
    ├── status_code      → resp_status_class (status-2xx / 3xx / 4xx / 5xx / null)
    └── prev_id / next_id → get_adjacent_flows()
                         → inline navigation links on flow detail page
```

---

## Write Operations — What the UI Can Mutate

The UI is not purely read-only. The following tables can be written via API routes:

| Table | Operations | Route |
|-------|-----------|-------|
| `registry.json` | create project, open, close, set scope, set constraints | `/api/projects/*` |
| `roles` | INSERT | `POST /api/roles` |
| `roles.is_active` | UPDATE | `POST /api/roles/{name}/activate`, `DELETE /api/roles/active` |
| `modules` | INSERT | `POST /api/modules` |
| `modules.is_active` | UPDATE | `POST /api/modules/{name}/activate`, `DELETE /api/modules/active` |
| `access_map` | UPSERT, DELETE | `PUT /api/access`, `DELETE /api/access/{role}/{module}` |
| `request_mutations` | INSERT, UPDATE enabled, DELETE | `POST/PATCH/DELETE /api/mutations/*` |
| `out_of_scope_domains` | INSERT, DELETE | `POST/DELETE /api/outscope/*` |
| `scheduler_jobs` | INSERT, DELETE pending | `POST /api/replay/*`, `DELETE /api/scheduler/queue`, `POST /api/attacks/unauth/*` |
| `scheduler_config` | UPSERT | `PUT /api/scheduler/config` |
| `attack_config` | UPSERT | `PUT /api/attacks/unauth/auto` |
| `flows` (replay) | INSERT | `POST /api/replay/*/now` |
| `replay_diffs` | INSERT | `POST /api/replay/*/now` |

Write routes call into existing `talos.projects.*` modules (access, mutation, outscope, auth, annotations) — the UI API layer contains no direct SQL for writes except the mutation toggle (`PATCH /api/mutations/{id}` uses inline SQL because the `talos.projects.mutation` module does not expose a toggle function).

---

## Security Constraints

- **Local only**: `talos ui` defaults to `--host 127.0.0.1`. There is no authentication layer.
- **No CSRF protection**: The API uses JSON bodies over a local loopback interface; CSRF is not a meaningful threat in this deployment model.
- **OpenAPI disabled**: `docs_url=None, redoc_url=None`. The interactive docs endpoint is not exposed.
- **Read-only DB connections**: `talos.ui.db` opens SQLite with `?mode=ro`. Any accidental write call from the read path raises a `sqlite3.OperationalError` at the DB level rather than silently mutating data.
- **No credential storage**: Auth config stores field *names* only — never token values or passwords.
- **Replay write gating**: `/api/replay/*/now` routes send outbound HTTP requests. They respect the same annotation guards as the CLI: endpoints tagged `logout` are blocked unconditionally; the engine checks annotations before sending.

---

## Failure Points

| Failure | Location | Behavior |
|---------|----------|----------|
| No active project | `_active_project()` dep | HTTP 422 with `"No active project"` detail |
| Project not found in registry | HTML route handlers | HTTP 404 |
| Flow not found | `GET /api/flows/{id}`, flow detail page | HTTP 404 |
| Endpoint not found | `GET /api/endpoints/{id}`, endpoint detail page | HTTP 404 |
| DB file absent | `talos.ui.db.*` functions | Return 0 / `[]` / `None`; never raise |
| Table absent (old schema) | `_table_exists()` guard | Return 0 / `[]` / `None`; never raise |
| JSON field unparseable | `_parse_json_field()` | Returns `{}` silently |
| Body not UTF-8 decodable | `_decode_body()` | Returns `"(binary, N bytes)"` |
| Pretty-print fails | `_maybe_pretty_json()` | Returns original string unchanged |
| Role/module already exists | `POST /api/roles`, `POST /api/modules` | HTTP 409 |
| Role/module not found for activate | `POST /api/roles/{name}/activate` | HTTP 404 |
| Mutation not found for toggle/delete | `PATCH/DELETE /api/mutations/{id}` | HTTP 404 |
| Domain not found for removal | `DELETE /api/outscope/{domain}` | HTTP 404 |
| Replay engine: flow not found | `POST /api/replay/flow/{id}/now` | HTTP 404 |
| Replay engine: no qualifying flow | `POST /api/replay/endpoint/{id}/now` | HTTP 404 |
| Replay engine: network error | `POST /api/replay/*/now` | Returns outcome dict with `success=False`, `failure_reason` set |
| `uvicorn` not installed | `talos.ui.cli` | Prints error message; exits 1 |
| SSE: DB absent on poll cycle | `stream._stream_events()` | Skips cycle; stream stays open |
| SSE: scheduler table missing | `stream._stream_events()` | `sched_counts` cursor initialised to `{}`; no events emitted until table exists |
| SSE: client disconnects | Starlette `StreamingResponse` | Generator exits on next yield; no error |
| Proxy already running | `POST /api/proxy/start` | Returns `{ok: false, detail: "already running"}` |
| Proxy not running | `POST /api/proxy/stop` | Returns `{ok: false, detail: "not running"}` |
| No active project on proxy start | `ProxyManager.start()` | Returns `{ok: false, detail: "No active project"}` |
| mitmdump not on PATH | `ProxyManager.start()` | Subprocess raises `FileNotFoundError`; returns `{ok: false, detail: ...}` |
| Proxy crashes after start | `ProxyManager._read_output()` | Reader task ends; status broadcasts `stopped`; SSE clients receive `proxy_status` event |

---

## Data Flow Diagrams

### HTML page request (read path)

```
Browser
  GET /project/{id}/flows?page=2
        │
        ▼
  uvicorn → FastAPI route handler
        │
        ├── idb.get_project_record(projects_root, project_id)
        │       registry.json → dict | None → 404 if None
        │
        ├── idb.get_flow_count(db_path)
        │       sqlite3.connect(file:talos.db?mode=ro)
        │       SELECT COUNT(*) FROM flows
        │
        ├── idb.list_flows(db_path, offset, limit)
        │       SELECT f.id, method, host, path, query, status_code,
        │              role_name, module_name
        │       FROM flows JOIN roles JOIN modules
        │       ORDER BY captured_at DESC LIMIT ? OFFSET ?
        │
        └── _render(request, "flows.html", context)
                Jinja2 → HTML string → HTMLResponse
```

### JS shell request + API interaction

```
Browser
  GET /project/{id}/access
        │
        ▼
  HTML shell page (empty table, <script> block)
        │
        ├── JS: fetch("/api/access") → GET /api/access
        │         _active_project() → ProjectManager.active()
        │         idb.get_access_map_rows(project.db_path)
        │         → JSON list of rows → JS renders table
        │
        └── JS: fetch("/api/access", {method:"PUT", body:...}) → PUT /api/access
                  _active_project() → project
                  Pydantic validates body (role, module, layer, state)
                  acc.set_client_access() OR acc.set_server_access()
                      sqlite3.connect(talos.db) — read-write
                      INSERT OR REPLACE INTO access_map
                  → JSON confirmation → JS updates row in table
```

### SSE stream (continuous read path)

```
Browser
  GET /api/stream
        │
        ▼
  FastAPI async route → StreamingResponse(media_type="text/event-stream")
        │
        └── _stream_events(db_path, project_id, proxy_manager)  ← async generator
              │
              │  seed cursors from current DB state
              │      flow_cursor    ← get_latest_flow_captured_at()
              │      endpoint_count ← get_endpoint_count()
              │      sched_counts   ← sched_db.get_queue_status()
              │
              │  subscribe to proxy_manager
              │      proxy_queue   ← proxy_manager.subscribe()
              │      flush history: drain queue (log history + current status)
              │
              │  yield: event: connected
              │
              └── loop every 2s:
                      list_flows_after(db_path, flow_cursor)
                          → for each new flow: yield event: flow
                          → advance flow_cursor
                      get_endpoint_count()
                          → if changed: yield event: endpoint_count
                      sched_db.get_queue_status()
                          → if changed: yield event: sched_counts
                      drain proxy_queue (non-blocking get_nowait loop)
                          → ("log", line):    yield event: proxy_log  {line}
                          → ("status", val):  yield event: proxy_status {status}
                      yield: : keepalive
              │
              finally: proxy_manager.unsubscribe(proxy_queue)
```

### Proxy lifecycle (JS shell + SSE log stream)

```
Browser
  GET /project/{id}/proxy
        │
        ▼
  HTML shell (proxy.html) — loadStatus() on page load
        │
        ├── fetch("/api/proxy/status") → GET /api/proxy/status
        │         app.state.proxy_manager.status / pid
        │         → {status, pid} → update Start/Stop button + status dot
        │
        ├── Start button → fetch("/api/proxy/start", {method:"POST", body:{port, listen_host}})
        │         ProxyManager.start()
        │             ProjectManager.active() → validate active project
        │             asyncio.create_subprocess_exec("mitmdump", "-s", addon.py, ...)
        │             _read_output() task → readline() loop
        │             _broadcast_status("running")
        │         → {ok, detail}
        │
        ├── Stop button  → fetch("/api/proxy/stop",  {method:"POST"})
        │         ProxyManager.stop()
        │             process.terminate() → 5s timeout → SIGKILL
        │             cancel _reader_task
        │             _broadcast_status("stopped")
        │         → {ok, detail}
        │
        └── EventSource("/api/stream")
                │
                ├── event: proxy_status → re-call loadStatus() → update UI
                └── event: proxy_log    → append line to log pane
                                           auto-scroll if user is at bottom
```

### Immediate replay (async write path)

```
Browser
  POST /api/replay/flow/{flow_id}/now
        │
        ▼
  FastAPI async route handler
        │
        ├── _active_project() → project
        │
        └── await replay_engine.replay_flow(
                  flow_id, db_path, project_id,
                  source="manual_replay", replay_reason="testing"
              )
              │
              ├── load flow from DB (talos.replay.db)
              ├── check annotation (logout → blocked)
              ├── reconstruct HTTP request
              ├── httpx.AsyncClient.send() → outbound HTTP
              ├── capture response
              ├── INSERT new flow into flows table
              ├── compute diff (talos.replay.diff)
              └── INSERT into replay_diffs
              │
              → ReplayOutcome → JSON response
```
