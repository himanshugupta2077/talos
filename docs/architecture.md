# Talos — System-Level Documentation

---

## Architecture (Logical)

```
CLI (talos.__main__)
    │
    ├── talos project <cmd>
    │       │
    │       └── ProjectManager (talos.projects.manager)
    │               │
    │               ├── Registry (projects_root/registry.json)
    │               │       Tracks all projects + active state
    │               │
    │               └── Per-Project Storage (~/.talos/projects/<id>/)
    │                       ├── talos.db        (SQLite, WAL)
    │                       └── archive/        (raw HTTP, JSONL/blobs)
    │
    ├── talos proxy start
    │       │
    │       ├── Hard gate: requires active project (exits 1 if none)
    │       │       Scope empty → WARNING, proxy still starts
    │       │
    │       └── mitmdump --ssl-insecure + TalosAddon (talos.proxy.addon)
    │               │   Instantiation raises NoActiveProject if no project set
    │               │   Loads headers_drop.txt once at startup
    │               │
    │               ├── Request hook — mutation injection (TalosAddon.request)
    │               │       Fires before request leaves proxy (pre-server)
    │               │       Loads enabled mutations from request_mutations table at startup
    │               │       Applies each header mutation: flow.request.headers[key] = value
    │               │       Overwrites any pre-existing value; applies to all methods
    │               │       Injected headers are present in stored flows and all replays
    │               │       Controlled via: talos mutation add|list|delete
    │               │       Why request hook, not response hook: response fires after
    │               │       the server has already received the request — too late
    │               │
    │               ├── Scope check (talos.proxy.scope)
    │               │       Exact: "example.com"
    │               │       Wildcard: "*.api.example.com"
    │               │       Out-of-scope → silent return (no log, no queue)
    │               │
    │               ├── Out-of-scope override (talos.proxy.scope.is_out_of_scope)
    │               │       Loaded from out_of_scope_domains table once at startup
    │               │       host == domain OR host.endswith('.<domain>') → silent return
    │               │       Overrides scope allow-list — checked after in_scope()
    │               │
    │               ├── Extraction (_extract_flow)
    │               │       Assigns flow_id (UUID4)
    │               │       Strips URL fragment
    │               │       Filters noisy headers (headers_drop.txt)
    │               │       Bounds bodies (store_bodies, max_body_size)
    │               │       No normalization. No DB writes. No project_id.
    │               │       role_id/module_id resolved once at startup
    │               │       and stamped onto every enqueued flow
    │               │
    │               └── FlowQueue (talos.proxy.queue)
    │                       Bounded in-memory queue (2 000 default)
    │                       Overflow → drop + WARNING, never block
    │
    ├── FlowWorker (talos.worker.worker)
    │       Started by TalosAddon.__init__; stopped in TalosAddon.done()
    │       Daemon thread — runs independently of proxy thread
    │
    │       ├── Consume from FlowQueue (0.2 s timeout poll)
    │       ├── Validate flow (method / url / status_code / request_start
    │       │                  / role_id / module_id)
    │       │       Invalid → WARNING log, drop — never reaches DB
    │       ├── Out-of-scope safety backstop (is_out_of_scope)
    │       │       Blocked domains loaded once at worker startup
    │       │       Catches any flow that bypassed the proxy addon check
    │       │       Match → WARNING log, drop — never reaches DB
    │       ├── Attach project_id (never done in proxy thread)
    │       ├── Normalize path/query for stable endpoint identity
    │       │       failure → NULL endpoint_id, flow still stored
    │       ├── Upsert endpoint by (method, host, normalized_path)
    │       │       failure → rollback, NULL endpoint_id, flow still stored
    │       ├── INSERT into flows table with cleaned query + endpoint_id
    │       ├── Update endpoint_roles in the same transaction
    │       ├── COMMIT (flow + endpoint + endpoint_roles)
    │       ├── Extract parameters (query params, JSON body, form body)
    │       ├── Upsert parameters per endpoint (type convergence, dedup, 5-sample cap)
    │       ├── COMMIT parameters (failure → rollback param writes only; flow unaffected)
    │       └── Append to archive/flows-<date>.jsonl
    │               bytes values base64-encoded for JSON portability
    │               Rotates file at UTC midnight
    │               Flush after every write
    │
    ├── ReplayScheduler (talos.scheduler.scheduler)
    │       Started by TalosAddon.__init__; stopped in TalosAddon.done()
    │       Daemon thread — consumes pending scheduler jobs independently of proxy
    │
    │       ├── Resets stale running jobs on startup
    │       ├── Reads scheduler_config each cycle (min_delay, max_delay, max_queue_size)
    │       ├── _annotation_pre_check: logout → skip; dangerous + priority < PRIORITY_MANUAL → skip
    │       ├── Pops highest-priority pending job → marks running → executes:
    │       │       replay_flow     → replay_flow(flow_id, db_path, project_id)
    │       │       replay_endpoint → replay_endpoint(endpoint_id, db_path, project_id)
    │       │       auth_test       → run_auth_bypass_test(endpoint_id, db_path, project_id)
    │       ├── Marks job done / failed / skipped based on outcome
    │       └── Sleeps min_delay..max_delay jitter between cycles
    │
    ├── talos ui
    │       │
    │       └── FastAPI + Jinja read-only inspection UI
    │               Routes:
    │               /                          project list
    │               /project/<id>              project overview
    │               /project/<id>/flows        captured flows
    │               /project/<id>/flows/<id>   flow detail
    │               /project/<id>/endpoints    endpoint list
    │               /project/<id>/endpoints/<id>
    │                                          endpoint detail
    │
    ├── talos role / module / access
    │       │
    │       └── Per-project access modeling + capture context
    │               role/module set            change capture-time tagging
    │               access show                display access matrix
    │               access coverage            expected vs observed counts
    │               access signals             4-section BAC/IDOR signal report:
    │                                          cross-role exposure, module boundary
    │                                          violation, client=DENY with flows,
    │                                          client=ALLOW without flows
    │
    ├── talos replay
    │       │
    │       ├── Hard gate: requires active project (exits 1 if none)
    │       │
    │       ├── talos replay flow <flow_id> [--right-now]
    │       │       default:     enqueue REPLAY_FLOW job (PRIORITY_MANUAL) → print job ID
    │       │       --right-now: load flow from DB by id
    │       │                    → send exact stored request (no mutation, no header stripping)
    │       │                    → store result as new flow (source=manual_replay, replay_reason=testing)
    │       │                    → compute diff (talos.replay.diff) → store in replay_diffs
    │       │                    → exit 1 if flow_id not found
    │       │
    │       └── talos replay endpoint <endpoint_id> [--right-now]
    │               → validate endpoint exists (exit 1 if not)
    │               default:     enqueue REPLAY_ENDPOINT job (PRIORITY_MANUAL) → print job ID
    │               --right-now: select best flow: status_code=200, source=proxy_capture,
    │                                              most recent captured_at
    │                            → exit 1 if no qualifying flow exists
    │                            → replay selected flow (same path as above)
    │
    ├── talos auth
    │       │
    │       ├── Hard gate: requires active project (exits 1 if none)
    │       │
    │       ├── talos auth set --cookie <name> ... --header <name> ...
    │       │       → additive upsert into auth_config table
    │       │
    │       ├── talos auth show
    │       │       → read and print auth_config (cookies + headers)
    │       │
    │       ├── talos auth clear
    │       │       → delete all rows from auth_config
    │       │
    │       └── talos auth test <endpoint_id> [--right-now]
    │               → validate endpoint exists (exit 1 if not)
    │               default:     enqueue AUTH_TEST job (PRIORITY_MANUAL) → print job ID
    │               --right-now: exit 1 if auth_config empty
    │                            → select best flow: status_code=200, source=proxy_capture
    │                            → exit 1 if no qualifying flow
    │                            → _strip_auth(flow, auth_config)
    │                                → remove matching headers (case-insensitive)
    │                                → remove matching cookie keys, rebuild Cookie header
    │                            → send stripped request (talos.replay.auth_strip)
    │                            → store as auto_replay flow (replay_reason=auth_test)
    │                            → compute diff → store in replay_diffs
    │                            → compute auth verdict (SECURE | BYPASS | UNKNOWN)
    │                            → store in auth_test_results
    │
    │       ├── talos auth mark-login <role_id> <flow_id>
    │       │       → validate role exists (exit 1 if not)
    │       │       → validate flow exists (exit 1 if not)
    │       │       → upsert role_auth.login_flow_id
    │       │
    │       ├── talos auth mark-checkpoint <role_id> <flow_id>
    │       │       → validate role exists (exit 1 if not)
    │       │       → validate flow exists (exit 1 if not)
    │       │       → upsert role_auth.checkpoint_flow_id
    │       │
    │       ├── talos auth generate <role_id>
    │       │       → exit 1 if no login_flow_id assigned to role
    │       │       → replay login flow (source=manual_replay, replay_reason=session_generate)
    │       │       → exit 1 if replay failed
    │       │       → search response body for JWT regex (eyJ…)
    │       │       → exit 1 if no JWT found
    │       │       → store_session_token() → deactivate old tokens, insert new active token
    │       │       → print token_id and masked token
    │       │
    │       ├── talos auth inject-session-token <role_id> <session_token_id>
    │       │       → validate role exists (exit 1 if not)
    │       │       → exit 1 if token not found for this role
    │       │       → deactivate all other tokens for role → activate selected token
    │       │
    │       └── talos auth validate <role_id>
    │               → exit 1 if role not found
    │               → get_active_session_token()
    │               if no token: → _auto_generate() (same path as 'generate')
    │               if token exists:
    │                   → exit 1 if no checkpoint_flow_id assigned
    │                   → replay checkpoint flow (source=auto_replay, replay_reason=session_validate)
    │                   → exit 1 if replay failed
    │                   if status 200:   → print "Token valid"
    │                   if status 401/403: → _auto_generate() → print new token details
    │
    ├── talos scheduler
    │       │
    │       ├── Hard gate: requires active project (exits 1 if none)
    │       │
    │       ├── talos scheduler status
    │       │       → counts by status (pending, running, done, failed, skipped)
    │       │       → lists pending jobs in priority order
    │       │       → shows execution metrics (total jobs, avg delay, last executed)
    │       │       → shows current scheduler config
    │       │
    │       ├── talos scheduler config [--min-delay N] [--max-delay N] [--max-queue-size N]
    │       │       → with no flags: display current config
    │       │       → with flags: validate, write to scheduler_config, display result
    │       │
    │       ├── talos scheduler enqueue flow <flow_id> [--priority N] [--force]
    │       │       → dedup check: skip if identical pending job exists
    │       │       → overflow check: warn + confirm if active jobs ≥ max_queue_size
    │       │       → INSERT one row into scheduler_jobs; print job details
    │       │
    │       ├── talos scheduler enqueue endpoint <endpoint_id> [--type replay|auth-test] [--priority N] [--force]
    │       │       → same dedup + overflow guards as above
    │       │       → INSERT one row into scheduler_jobs; print job details
    │       │
    │       └── talos scheduler clear [--force]
    │               → counts pending jobs; exits early if none
    │               → asks for confirmation unless --force
    │               → DELETE all pending rows from scheduler_jobs; prints count
    │
    └── [FUTURE] talos attack run
            Requires active project — hard gate

    ├── talos endpoint
            │
            ├── talos endpoint mark <endpoint_id> --logout | --dangerous | --safe
            │       → validate endpoint exists
            │       → --logout    → adds 'logout' tag (blocks all replay modes)
            │       → --dangerous → adds 'dangerous' tag (blocks auto_replay only)
            │       → --safe      → clears all annotation tags (restore default)
            │
            ├── talos endpoint unmark <endpoint_id> --logout | --dangerous
            │       → removes the specified tag (no-op if not present)
            │
            └── talos endpoint show <endpoint_id>
                    → prints endpoint method/host/path + current annotation tags
```


## Full System Flow (CURRENT STATE)

```
[USER / OPERATOR]
    │
    │  (CLI control)
    ▼
[CLI LAYER]
    talos project / role / module / access / proxy / replay / auth / scheduler
    │
    ▼
[PROJECT MANAGER]
    - active project enforcement
    - registry + per-project storage
    │
    ▼
[PROXY START]
    mitmdump + TalosAddon
    │
    ▼
[TRAFFIC CAPTURE]
    Browser → Proxy intercept
    │
    ▼
[SCOPE FILTER]
    in_scope(host)
    ├── NO → drop
    └── YES
    │
    ▼
[FLOW EXTRACTION]
    - raw request/response
    - headers filtered
    - bodies truncated if needed
    - role_id + module_id stamped
    │
    ▼
[IN-MEMORY QUEUE]
    (bounded, drop if full)
    │
    ▼
[WORKER THREAD]
    │
    ├── validate flow
    ├── attach project_id
    ├── normalize URL
    ├── upsert endpoint
    ├── store flow (DB)
    ├── extract parameters
    ├── update endpoint_roles
    └── write raw archive
    │
    ▼
[STRUCTURED STORAGE]
    SQLite:
        - flows
        - endpoints
        - parameters
        - roles/modules
        - access_map
    + JSONL archive (raw truth)
    │
    ▼
[STATE LAYER]
    - endpoint clustering (method + normalized_path)
    - role ↔ endpoint mapping
    - parameter intelligence
    │
    ▼
[ACCESS MODEL]
    (manual input)
    - client_allowed
    - server_expected
    │
    ▼
[REPLAY ENTRY POINT]
    CLI:
        talos replay flow / endpoint
        talos auth test
    │
    ├── DEFAULT → enqueue job
    └── --right-now → immediate execution
    │
    ▼
[SCHEDULER]
    - priority queue
    - annotation checks (logout/dangerous)
    │
    ▼
[REPLAY ENGINE]
    - exact request reconstruction
    - no mutation (type 1)
    │
    OR
    - auth stripped replay (type 2)
    │
    ▼
[HTTP EXECUTION]
    httpx async request
    │
    ▼
[REPLAY RESULT STORAGE]
    - new flow inserted
    - linked to original_flow_id
    │
    ▼
[DIFF ENGINE]
    compare:
        - status
        - length
        - structure
    → verdict: SAME / DIFFERENT / ERROR
    │
    ▼
[AUTH VERDICT (if auth test)]
    SECURE / BYPASS / UNKNOWN
    │
    ▼
[ANALYSIS LAYER]
    CLI:
        talos access coverage
        talos access signals
    │
    ▼
[OUTPUT]
    - CLI output
    - optional read-only UI
```

---

## Access Model (Two-Layer)

Talos separates **observed client behaviour** from **intended server enforcement**.
Both must be set explicitly — nothing is auto-inferred.

```
role + module
    │
    ├── client_allowed   — what the UI exposes for this pair
    │       Derived from: visible navigation, enabled buttons, accessible pages
    │       Set via: talos access client set <role> <module> <allow|deny|unknown>
    │
    └── server_expected  — what the backend SHOULD enforce
            Your explicit assertion of intended security
            Used to drive BAC test generation
            Set via: talos access server set <role> <module> <allow|deny|unknown>
```

### Tri-State Values

| Value | Meaning |
|-------|---------|
| `ALLOW` | Permitted |
| `DENY` | Blocked |
| `UNKNOWN` | Not yet assessed — prevents incorrect test generation |

`NULL` means the field has not been set at all (distinct from `UNKNOWN`).

### Detection Logic (future attack phase)

| client | server_expected | actual (replay) | Verdict |
|--------|-----------------|-----------------|--------|
| ALLOW  | DENY            | DENY            | Correct restriction |
| DENY   | DENY            | ALLOW           | **BAC vulnerability** |
| DENY   | UNKNOWN         | ALLOW           | Likely client-side-only control |
| ALLOW  | ALLOW           | DENY            | Logic inconsistency / bug |

### Access Map Commands

```
talos role add <name>                                     create role
talos role list                                           list all roles
talos role set <name>                                     activate for flow tagging
talos role unset                                          reset to global

talos module add <name>                                   create module
talos module list                                         list all modules
talos module set <name>                                   activate for flow tagging
talos module unset                                        reset to global

talos access client set   <role> <module> <allow|deny|unknown>
talos access client unset <role> <module>                 set client_allowed = NULL
talos access server set   <role> <module> <allow|deny|unknown>
talos access server unset <role> <module>                 set server_expected = NULL
talos access delete       <role> <module>                 remove entire row
talos access show                                         display matrix
talos access coverage                                     compare expected vs observed traffic
talos access signals                                      show immediate BAC signal candidates

talos endpoint mark   <endpoint_id> --logout | --dangerous | --safe
talos endpoint unmark <endpoint_id> --logout | --dangerous
talos endpoint show   <endpoint_id>
```

---

## Component Responsibilities

| Component | Responsibility | Does NOT do |
|-----------|---------------|-------------|
| `talos.__main__` | Parse top-level command; wire config → manager → CLI handler | Business logic |
| `talos.config.TalosConfig` | Resolve storage root from env or default | Create directories |
| `talos.projects.model.Project` | Data shape + serialization only | I/O, side effects |
| `talos.projects.model.ScopeConstraints` | Capture constraint values + serialization | Enforcement |
| `talos.projects.db` | Schema init for one project's SQLite DB | Hold connections, run queries |
| `talos.projects.manager.ProjectManager` | Full project lifecycle; enforce single-active invariant | UI, formatting |
| `talos.projects.access` | CRUD for roles, modules, access map (client + server tri-state) | Enforcement, inference |
| `talos.projects.access_cli` | Argument parsing + output for role/module/access commands | State management |
| `talos.projects.cli` | Argument parsing + output formatting for project commands | State management |
| `talos.ui.app` | FastAPI read-only inspection UI over project registry + SQLite data | Mutation, capture, normalization |
| `talos.ui.db` | Read-only query layer for flows, endpoints, access coverage, and BAC signals | Writes, migrations |
| `talos.projects.endpoints` | Canonicalize raw paths/queries into stable endpoint identities | DB writes, access inference |
| `talos.projects.parameters` | Extract query/body parameters from flows; upsert per-endpoint parameter inventory with type inference and deduplication | DB schema changes, advanced classification |
| `talos.projects.outscope` | CRUD for per-project out-of-scope domain list; load_domain_set() for proxy/worker startup | Enforcement, scope inference |
| `talos.projects.outscope_cli` | Argument parsing + output for `project outscope add/list/remove` commands | State management |
| `talos.projects.mutation` | CRUD for per-project request mutations (add, delete, list); load_mutations() returns enabled mutations for proxy startup; only 'header' type supported | Enforcement, application |
| `talos.projects.mutation_cli` | Argument parsing + output for `mutation add/list/delete` commands | State management |
| `talos.proxy.scope` | Domain pattern matching (exact + wildcard); in_scope() and is_out_of_scope() predicates | Configuration, logging |
| `talos.proxy.queue.FlowQueue` | Bounded thread-safe queue; drop-on-full | Processing, persistence |
| `talos.proxy.addon.TalosAddon` | mitmproxy hook; **request hook** applies all enabled `request_mutations` (header injections) before request reaches server; scope filter → out-of-scope override → header filter → extract → stamp role/module IDs → enqueue; coloured stdout per flow; starts/stops worker and scheduler daemon threads | DB writes, normalization, session detection |
| `talos.proxy.cli` | Argument parsing; active-project gate; launch mitmdump | Proxy logic |
| `talos.worker.FlowWorker` | Drain queue; validate; out-of-scope backstop drop; attach project_id; normalize flows into stable endpoints; persist to DB + archive; update endpoint_roles and parameter inventory transactionally | Proxy logic, access inference |
| `talos.projects.auth` | CRUD for per-project auth config (cookie/header names); additive set, clear | Enforcement, inference, credential storage |
| `talos.projects.auth_cli` | Argument parsing + output for auth set/show/clear/test commands; `auth test` default path enqueues scheduler job; `--right-now` executes immediately | State management, HTTP I/O |
| `talos.projects.annotations` | CRUD for endpoint safety tags (logout, dangerous); read-only guard consumed by replay engine and auth-strip | Enforcement, inference |
| `talos.projects.endpoint_cli` | Argument parsing + output for endpoint mark/unmark/show commands | State management, replay execution |
| `talos.replay.db` | Read flow/endpoint records for replay input; insert replayed flows, diff rows, and auth test results; calls `migrate_project_db` on every entry | Business logic, HTTP I/O |
| `talos.replay.diff` | Pure diff computation between original and replay flow; produces DiffResult (verdict, status_diff, length_diff) | DB access, I/O |
| `talos.replay.engine` | Async exact (Type 1) replay via httpx; reconstruct request from stored flow; capture response; compute + store diff; store result linked to original | Mutation, auth stripping |
| `talos.replay.auth_strip` | Type 2 replay: strip auth fields from request, send, diff, compute auth-bypass verdict (SECURE/BYPASS/UNKNOWN); store replay + diff + auth_test_result | Auth config management, endpoint selection |
| `talos.replay.cli` | Argument parsing; active-project gate; dispatch `replay flow` / `replay endpoint`; default path enqueues scheduler job; `--right-now` executes immediately; print outcome or job ID | HTTP I/O, DB writes |
| `talos.scheduler.scheduler.ReplayScheduler` | Daemon thread: consume pending jobs from scheduler_jobs; annotation pre-check (logout/dangerous); per-cycle config reload; configurable jitter; mark job done/failed/skipped | Direct execution (delegates to replay/auth engines), CLI parsing |
| `talos.scheduler.db` | CRUD for scheduler_jobs (enqueue, next pending, mark running/done/failed/skipped, clear, dedup, status counts); read/write scheduler_config; compute queue metrics | HTTP I/O, replay execution |
| `talos.scheduler.cli` | Argument parsing + output for scheduler status/config/enqueue/clear commands | Scheduling logic, HTTP I/O |

---

## Data Lifecycle

### Project Creation
```
CLI: talos project create <name>
  → make_project_id(name) → slug
  → check registry for collision
  → mkdir <projects_root>/<id>/
  → mkdir <projects_root>/<id>/archive/
  → init_project_db(<id>/talos.db)   ← schema created here
  → copy default_headers_drop.txt → <id>/headers_drop.txt
  → write to registry.json
     (includes scope: [], constraints: {defaults})
```

### Project Activation
```
CLI: talos project open <id>
  → load registry
  → set any current ACTIVE → INACTIVE
  → set target → ACTIVE
  → save registry
```
Single-active invariant is enforced here. No two projects can be ACTIVE simultaneously.

### Scope + Constraints Configuration
```
CLI: talos project scope <id> example.com *.api.example.com
  → replaces project.scope list in registry

CLI: talos project constraints <id> --store-bodies true --max-body-size 2097152
  → replaces project.constraints in registry
```

### Proxy Startup
```
CLI: talos proxy start [--port 8080] [--listen-host 127.0.0.1] [--quiet]
  → manager.active() → None → exit 1
  → project.scope empty → WARNING printed to stderr (proxy still starts)
  → seed_default_context(project.db) ensures global role/module exist
  → resolve active role_id + module_id once at proxy startup
  → prints startup summary (scope entries, store_bodies, max_body_size, listen addr)
  → launch: mitmdump --listen-host 127.0.0.1 --listen-port 8080
                     --ssl-insecure -s addon.py
      POSIX   → os.execvp (replaces current process)
      Windows → subprocess.run (blocks; KeyboardInterrupt swallowed on Ctrl+C)
```

### Capture Flow Path
```
browser → mitmdump (TLS intercept)
       → TalosAddon.response(flow)
           → in_scope(host, project.scope)
               → False → _cprint(SKIP line) → return
               → True  → _extract_flow(flow, constraints, drop_headers)
                           → assign flow_id (UUID4)
                           → strip URL fragment
                           → _capture_body(request, constraints)
                               → store_bodies=False → body=None
                               → len > max_body_size → truncate, truncated=True
                           → _capture_body(response, constraints)
                           → _filter_headers(headers, drop_headers)
                           → flow dict:
                               flow_id, request_start, response_end,
                               method, url, host, path, query,
                               request_headers, request_cookies,
                               request_body, request_body_truncated,
                               status_code, response_headers,
                               response_body, response_body_truncated,
                               role_id, module_id
                             (project_id NOT included — attached at worker layer)
                       → flow_queue.put(flow_dict)
                           → queue full → drop + WARNING log
                             → queue ok  → enqueued for worker
               → _cprint(CAPTURE line with flow_id prefix + status)
```

### Worker Pipeline
```
FlowQueue → FlowWorker._run() (daemon thread)
    poll get(timeout=0.2s)
        → None (empty) → loop, check stop_event
        → flow dict
            → _validate_flow()
                method missing   → drop + WARNING
                url missing      → drop + WARNING
                status_code None → drop + WARNING
                bad timestamp    → drop + WARNING
                missing role_id  → drop + WARNING
                missing module_id → drop + WARNING
            → attach project_id
            → _persist_db(flow, db_path)
                normalize_flow_url(path, query)
                  remove utm_*, fbclid, gclid, known cache-busters
                  sort remaining params
                  collapse duplicate slashes and strip trailing slash
                  keep host + method unchanged
                endpoint identity = (method, host, normalized_path)
                upsert endpoint first_seen/last_seen/auth signal/roles_seen
                  INSERT INTO flows (
                      id, project_id, captured_at, response_end,
                      method, url, host, path, query,
                      request_headers (JSON), request_cookies (JSON),
                      request_body (BLOB), request_body_truncated,
                      status_code,
                      response_headers (JSON), response_body (BLOB),
                  response_body_truncated,
                  content_type, session_id, endpoint_id,
                  role_id, module_id, tags,
                  source,             -- 'proxy_capture' for all worker-written flows
                  original_flow_id,   -- NULL for proxy_capture flows
                  replay_error        -- NULL for proxy_capture flows
                  )
                  per-operation connection
                  on normalization failure → NULL endpoint_id, flow still stored
                  on endpoint upsert failure → rollback, NULL endpoint_id, flow stored
                  COMMIT (flow + endpoint + endpoint_roles)
                  upsert endpoint_roles(endpoint_id, role_id, first_seen, last_seen)
                  extract parameters (query params, JSON body, form body)
                  upsert parameters per endpoint (type inference, dedup, 5-sample cap)
                  COMMIT parameters
                  on parameter failure → rollback param writes only; flow unaffected
            → _persist_archive(flow)
                  file: <data_dir>/archive/flows-YYYY-MM-DD.jsonl
                  bytes → {"_b64": "..."}  (base64, lossless)
                  append + flush per write
                  rotate file handle at UTC midnight

Shutdown:
    TalosAddon.done() called by mitmproxy on exit
    → stop_event.set()
    → drain remaining queue items (no flows lost on clean exit)
    → close archive file handle
```

### Per-Project Storage
```
~/.talos/
  registry.json          ← index of all projects + constraints
  projects/
    <id>/
      talos.db           ← all structured data for this project
      archive/
        flows-YYYY-MM-DD.jsonl  ← ground truth; one JSON line per flow
      headers_drop.txt   ← per-project header filter (copied from global template)
```

### DB vs Archive
| Store | Role | Format |
|-------|------|--------|
| `talos.db` `flows` table | Structured truth — queryable, indexed | SQLite rows |
| `archive/flows-*.jsonl` | Ground truth — exact capture, audit, replay source | JSONL; bytes as `{"_b64": "..."}` |

### Data Isolation
- No table is shared across projects.
- Each project has its own SQLite database and archive directory.
- `project_id` is stored on top-level traffic/domain tables such as `flows`, `endpoints`, and `sessions`.
- Context and relation tables such as `roles`, `modules`, `access_map`, `parameters`, and `endpoint_roles` are isolated by database, not by a row-level `project_id` column.
- The registry is the only cross-project file; it stores metadata only (no traffic data).

---

## Scope Matching Rules

| Pattern | Matches | Does NOT match |
|---------|---------|----------------|
| `example.com` | `example.com` | `sub.example.com`, `www.example.com` |
| `*.example.com` | `sub.example.com`, `www.example.com` | `example.com` |
| `*.api.example.com` | `v1.api.example.com` | `api.example.com` |

Implementation: `talos.proxy.scope.in_scope()` — pure function, no side effects.
Port suffixes in host values are stripped before matching.
Empty scope list → nothing captured (strict opt-in).

---

## Capture Constraints

| Field | Default | Effect |
|-------|---------|--------|
| `capture_in_scope_only` | `True` | Always enforced; not user-configurable |
| `store_bodies` | `True` | Set False to skip body storage entirely |
| `max_body_size` | `1 048 576` (1 MB) | Bodies exceeding this are truncated; `*_body_truncated=True` in flow dict |

---

## Database Schema (per project)

```
schema_version      version: 15

flows               raw captured HTTP exchanges
  → references sessions.id (nullable until session resolved)
  → references endpoints.id (nullable until normalized)
  → capture-time role_id and module_id are mandatory
  → tags stored as JSON array
  → source: 'proxy_capture' | 'manual_replay' | 'auto_replay'
      proxy_capture  — traffic recorded by the proxy addon
      manual_replay  — user-triggered via `talos replay flow/endpoint`
      auto_replay    — system-triggered (BAC engine, IDOR module, etc.)
  → original_flow_id: FK to flows.id (NULL for proxy_capture flows)
  → replay_error: NULL on success; error label on network/HTTP failure
  → replay_reason: NULL for proxy_capture; 'testing' for manual_replay;
                   'bac_test' | 'idor_test' | 'validation' | 'auth_test' for auto_replay

endpoints           deduplicated (method + host + normalized_path)
  → unique per project

parameters          per-endpoint parameter intelligence
  → FK → endpoints.id

sessions            detected identities (cookie / bearer / basic)

roles               identity types for access-control modeling
  id, name, is_active
  "global" always present; seeded on DB init

modules             logical application feature areas
  id, name, description, is_active
  "global" always present; seeded on DB init

access_map          two-layer access model — BAC ground truth
  role_id           FK → roles.id
  module_id         FK → modules.id
  client_allowed    TEXT  — ALLOW | DENY | UNKNOWN | NULL
  server_expected   TEXT  — ALLOW | DENY | UNKNOWN | NULL
  PRIMARY KEY (role_id, module_id)

endpoint_roles      observed role → endpoint access pairs
  endpoint_id       FK → endpoints.id
  role_id           FK → roles.id
  first_seen        TEXT
  last_seen         TEXT
  PRIMARY KEY (endpoint_id, role_id)

replay_diffs        structural diff result for each replay flow
  replay_flow_id    PK FK → flows.id
  original_flow_id  TEXT NOT NULL
  verdict           TEXT — SAME | DIFFERENT | ERROR
  status_changed    INTEGER (boolean)
  status_diff       TEXT — e.g. "200→403"; NULL when unchanged
  length_diff       INTEGER — signed byte delta (replay - original)

auth_config         per-project auth field names (manual input)
  type              TEXT — 'cookie' | 'header'
  name              TEXT — e.g. 'sessionid', 'Authorization'
  PRIMARY KEY (type, name)

auth_test_results   verdict for each auth-bypass test replay
  replay_flow_id    PK FK → flows.id
  original_flow_id  TEXT NOT NULL
  verdict           TEXT — SECURE | BYPASS | UNKNOWN

endpoint_annotations  safety tags applied manually per endpoint
  endpoint_id       FK → endpoints.id
  tag               TEXT — 'logout' | 'dangerous'
  created_at        TEXT — UTC ISO-8601
  PRIMARY KEY (endpoint_id, tag)

role_auth           per-role login and checkpoint flow assignments
  role_id           PK FK → roles.id
  login_flow_id     TEXT (nullable) — FK → flows.id; flow replayed to generate a token
  checkpoint_flow_id TEXT (nullable) — FK → flows.id; flow replayed to validate a token

role_session_tokens  generated session tokens per role
  id                TEXT PK — UUID
  role_id           TEXT NOT NULL FK → roles.id
  token             TEXT NOT NULL — raw extracted JWT or session string
  created_at        TEXT — UTC ISO-8601
  active            INTEGER — boolean; at most one active token per role at any time

scheduler_jobs      replay job queue
  job_id            TEXT PK
  job_type          TEXT — 'replay_flow' | 'replay_endpoint' | 'auth_test'
  endpoint_id       TEXT (nullable; FK → endpoints.id for endpoint/auth-test jobs)
  flow_id           TEXT (nullable; FK → flows.id for flow jobs)
  priority          INTEGER — higher value runs first; PRIORITY_MANUAL=100, PRIORITY_AUTO=10
  status            TEXT — 'pending' | 'running' | 'done' | 'failed' | 'skipped'
  created_at        TEXT — UTC ISO-8601
  scheduled_at      TEXT — UTC ISO-8601; set when job transitions to running
  started_at        TEXT — UTC ISO-8601; set when job transitions to running
  finished_at       TEXT — UTC ISO-8601; set when job completes
  failure_reason    TEXT — error description; None on success/skipped
  replayed_flow_id  TEXT — UUID of resulting replay flow; None until done
  verdict           TEXT — outcome label (nullable)

scheduler_config    single-row scheduler settings per project
  min_delay         REAL    — minimum seconds between jobs (default: 2.0)
  max_delay         REAL    — maximum seconds between jobs (default: 6.0)
  max_queue_size    INTEGER — ceiling on pending + running jobs (default: 200)

out_of_scope_domains  domains that must never be captured or processed
  id                TEXT PK — UUID
  project_id        TEXT NOT NULL
  domain            TEXT NOT NULL — lowercased; e.g. 'api.stripe.com'
  created_at        TEXT — UTC ISO-8601
  UNIQUE (project_id, domain)
  Matching: host == domain OR host.endswith('.'+domain)

request_mutations   static header injections applied to every outgoing request
  id                TEXT PK — UUID
  type              TEXT NOT NULL — 'header' (only supported type)
  key               TEXT NOT NULL — header name (e.g. 'X-HackerOne-Research')
  value             TEXT NOT NULL — header value
  enabled           INTEGER — 1 = active, 0 = paused (DEFAULT 1)
```

WAL mode enabled on every database. Foreign keys enforced. Indexes exist for
role/module scoped flow analysis and endpoint role lookups.

`migrate_project_db(db_path)` in `talos.projects.db` upgrades existing databases
in-place. Called automatically by `talos.replay.db` on every replay operation.

| Migration | Change |
|-----------|--------|
| v6 → v7   | Add `source`, `original_flow_id`, `replay_error` columns to flows |
| v7 → v8   | Add `replay_reason` column to flows |
| v8 → v9   | Add `replay_diffs` table |
| v9 → v10  | Add `auth_config` and `auth_test_results` tables |
| v10 → v11 | Add `endpoint_annotations` table |
| v11 → v12 | Add `scheduler_jobs` table |
| v12 → v13 | Add `scheduled_at` column to `scheduler_jobs`; add `scheduler_config` table |
| v14 → v15 | Add `request_mutations` table |
| v15 → v16 | Add `attack_config` table |
| v16 → v17 | Add `attack_host_exclusions` table |
| v17 → v18 | Rebuild `attack_host_exclusions` with `path` column; update PRIMARY KEY |
| v21 → v22 | Add `matched_section`, `matched_group`, `matched_rules` columns to `bac_results` for rich decision evidence |

---

## Failure Points

| Failure | Location | Behavior |
|---------|----------|----------|
| Registry file corrupted (bad JSON) | `_load_registry()` | Raises `ProjectError` with clear message; no silent fallback |
| Duplicate project name | `create()` | Raises `ProjectAlreadyExists` before any disk write |
| DB init fails mid-create | `create()` | Directory may exist; registry is NOT written → registry stays clean |
| No active project at proxy start | `TalosAddon.__init__` | Raises `NoActiveProject`; mitmproxy logs it and aborts |
| Scope list empty at proxy start | `proxy.cli.cmd_start` | WARNING printed to stderr; proxy starts but captures nothing |
| `headers_drop.txt` missing from project dir | `_load_drop_headers()` | WARNING log; all headers pass through (non-fatal) |
| `default_headers_drop.txt` template missing from install | `_copy_headers_drop_template()` | WARNING log; project created without filter file |
| `TALOS_DATA_DIR` points to unwritable path | `ProjectManager.__init__` | `mkdir` raises `PermissionError` immediately |
| Active role/module missing in DB | `seed_default_context()` | Global role/module are inserted and activated before capture starts |
| Worker DB insert fails | `FlowWorker._process()` | Logs ERROR; archive write skipped for that flow; both stores stay consistent |
| Worker archive write fails | `FlowWorker._process()` | Logs ERROR; DB row already committed; archive line missing for that flow |
| URL normalization raises unexpectedly | `_persist_db()` | Logs ERROR; endpoint_id set to NULL; flow stored with raw query |
| Endpoint upsert fails during DB write | `_persist_db()` | Logs ERROR; transaction rolled back for endpoint work; flow stored with NULL endpoint_id |
| Parameter extraction fails | `_persist_db()` | Logs ERROR; parameter writes rolled back; flow and endpoint already committed and unaffected |
| Flow missing `role_id` or `module_id` | `_validate_flow()` | Logs WARNING; flow dropped before persistence |
| Queue full at shutdown | `FlowWorker.stop()` | Drain loop consumes remaining items before thread exits; flows not silently lost |
| Replay: flow_id not found | `replay_flow()` | Returns `ReplayOutcome(failure_reason='flow_not_found')`; CLI exits 1 |
| Replay: endpoint has no 200 OK proxy_capture flow | `replay_endpoint()` | Returns `ReplayOutcome(failure_reason='no_qualifying_flow')`; CLI exits 1 |
| Replay: connection refused / unreachable | `_execute_replay()` | Stores flow with `replay_error='connection_error'`, `status_code=NULL`; outcome marked failed |
| Replay: request times out (>30 s) | `_execute_replay()` | Stores flow with `replay_error='timeout'`, `status_code=NULL`; outcome marked failed |
| Replay: HTTP protocol error | `_execute_replay()` | Stores flow with `replay_error='http_error'`, `status_code=NULL`; outcome marked failed |
| Replay: unexpected exception | `_execute_replay()` | Stores flow with `replay_error='unexpected_error'`; never silently discarded |
| Diff storage fails after replay | `_execute_replay()` / `_execute_stripped_replay()` | Logs ERROR; replay flow already committed and unaffected; diff row missing for that replay |
| Auth test: auth_config empty | `run_auth_bypass_test()` | Returns `auth_verdict='UNKNOWN'`, `failure_reason='auth_config_empty'`; CLI exits 1 |
| Auth test: no qualifying flow | `run_auth_bypass_test()` | Returns `auth_verdict='UNKNOWN'`, `failure_reason='no_qualifying_flow'`; CLI exits 1 |
| Auth test result storage fails | `_execute_stripped_replay()` | Logs ERROR; replay flow and diff already committed and unaffected |
| Replay/auth test: endpoint tagged logout | `replay_flow()` / `replay_endpoint()` / `run_auth_bypass_test()` | Returns `failure_reason='endpoint_annotated_logout'`; CLI exits 1; no request sent |
| Replay: endpoint tagged dangerous (auto mode) | `replay_endpoint()` | Returns `failure_reason='endpoint_annotated_dangerous'`; CLI exits 1; no request sent |
| Auth test: endpoint tagged dangerous | `run_auth_bypass_test()` | Returns `failure_reason='endpoint_annotated_dangerous'`; CLI exits 1; no request sent |
| Scheduler: job endpoint tagged logout | `ReplayScheduler._annotation_pre_check()` | Job marked skipped; logged; no request sent |
| Scheduler: job endpoint tagged dangerous (auto priority) | `ReplayScheduler._annotation_pre_check()` | Job marked skipped; logged; no request sent |
| Scheduler: underlying replay/auth engine fails | `ReplayScheduler._execute_job()` | Job marked failed; error logged; scheduler continues to next cycle |
| Scheduler: unknown job type | `ReplayScheduler._run()` | Job marked skipped; scheduler continues |

---

## Configuration

| Source | Key | Default | Purpose |
|--------|-----|---------|---------|
| Environment | `TALOS_DATA_DIR` | `~/.talos` | Override storage root (test isolation, custom path) |

---

## Implemented Subsystems

- [x] Project management (`talos.projects`)
- [x] Proxy layer — scope enforcement, header filtering, flow extraction (`talos.proxy`)
- [x] Flow queue — in-memory, bounded, drop-on-full (`talos.proxy.queue`)
- [x] Worker pipeline — validate, persist to DB + archive (`talos.worker`)
- [x] Access model — roles, modules, two-layer client/server tri-state map (`talos.projects.access`)
- [x] Access analysis — coverage and signal reporting from captured flows (`talos.ui.db`, `talos.projects.access_cli`)
- [x] Flow normalization — endpoint deduplication, parameter extraction (`talos.projects.endpoints`, `talos.projects.parameters`)
- [x] Read-only inspection UI — project, flow, and endpoint views (`talos.ui`)
- [x] Replay engine — exact (Type 1) replay; endpoint and flow entry points; `auto_replay` flow storage (`talos.replay`)
- [x] Diff engine — structural comparison of original vs replay; verdict SAME/DIFFERENT/ERROR; stored in `replay_diffs` (`talos.replay.diff`)
- [x] Auth bypass testing — Type 2 replay (auth stripped); SECURE/BYPASS/UNKNOWN verdict; stored in `auth_test_results` (`talos.replay.auth_strip`, `talos.projects.auth`)
- [x] Endpoint safety annotations — manual tagging (logout/dangerous); guard layer in replay engine and auth-strip blocks unsafe execution (`talos.projects.annotations`, `talos.projects.endpoint_cli`)
- [x] Replay scheduler — daemon thread started alongside proxy; priority queue with dedup and overflow guards; annotation pre-checks; configurable jitter; `talos scheduler` CLI for status/config/enqueue/clear (`talos.scheduler`)
- [x] Out-of-scope domain list — per-project block list that overrides the scope allow-list; enforced at proxy capture and worker persist; CLI via `talos project outscope` (`talos.projects.outscope`, `talos.projects.outscope_cli`)
- [x] Request mutation layer — `request_mutations` table stores static header injections per project; `TalosAddon.request()` hook applies all enabled mutations before each request reaches the server; injected headers are stored in captured flows and carried through all replays; controlled via `talos mutation add|list|delete` (`talos.projects.mutation`, `talos.projects.mutation_cli`)
- [x] Attack modules — deterministic auth bypass (unauth) module: per-endpoint AUTH_TEST jobs strip credentials, replay, and diff to produce SECURE/BYPASS/UNKNOWN verdicts; coverage derived from `auth_test_results` + `scheduler_jobs`; auto-run toggle in `attack_config` table; bulk-enqueue and per-endpoint run via Attacks UI page (`talos.projects.attack_config`, `talos.ui.api.attacks`, `talos.ui.templates.attacks.html`)

## Pending Subsystems

- [ ] Queue stage 2 — Redis backing store
- [ ] Session detection
- [ ] Endpoint clustering
- [ ] Attack modules — IDOR, BAC engine, parameter tampering
