# Talos CLI Cheat Sheet

This cheat sheet reflects the commands currently exposed by the installed Talos CLI.

## Quick Notes

- Run `talos` with no arguments to see the top-level command list.
- Commands under `role`, `module`, `access`, and `endpoint` require an active project.
- `proxy start` also requires an active project.
- In PowerShell, quote wildcard scope patterns such as `"*.example.com"`.
- Example placeholder values used below:
  - project name or id: `qa-smoke`
  - host pattern: `"*.example.com"`
  - role: `admin`
  - module: `orders`

## Command Tree

```text
talos
├─ project
│  ├─ create
│  ├─ open
│  ├─ close
│  ├─ delete
│  ├─ list
│  ├─ scope
│  ├─ constraints
│  ├─ status
│  └─ outscope
│     ├─ add domain
│     ├─ list
│     └─ remove domain
├─ proxy
│  └─ start
├─ ui
├─ role
│  ├─ create
│  ├─ add
│  ├─ list
│  ├─ set
│  └─ unset
├─ module
│  ├─ create
│  ├─ add
│  ├─ list
│  ├─ set
│  └─ unset
├─ access
│  ├─ client set
│  ├─ client unset
│  ├─ server set
│  ├─ server unset
│  ├─ delete
│  ├─ show
│  ├─ coverage
│  └─ signals
└─ replay
   ├─ flow
   └─ endpoint
└─ auth
   ├─ set
   ├─ show
   ├─ clear
   ├─ test
   ├─ mark-login
   ├─ mark-checkpoint
   ├─ generate
   ├─ inject-session-token
   └─ validate
└─ endpoint
   ├─ mark
   ├─ unmark
   └─ show
└─ scheduler
   ├─ status
   ├─ config
   ├─ enqueue
   │  ├─ flow
   │  └─ endpoint
   └─ clear
└─ mutation
   ├─ add
   ├─ list
   └─ delete
```

## Top-Level Commands

### `talos`

Show the top-level CLI usage and command groups.

```powershell
talos
```

### `talos project`

Show project command help.

```powershell
talos project --help
```

### `talos proxy`

Show proxy command help.

```powershell
talos proxy --help
```

### `talos ui`

Start the Talos web UI on the default host and port.

```powershell
talos ui
```

### `talos role`

Show role command help.

```powershell
talos role --help
```

### `talos module`

Show module command help.

```powershell
talos module --help
```

### `talos access`

Show access command usage.

```powershell
talos access
```

### `talos auth`

Show auth command help.

```powershell
talos auth --help
```

## Project Commands

### `talos project create <name> [-d|--description TEXT] [-s|--scope HOST ...]`

Create a new project, optionally with a description and initial scope.

```powershell
talos project create qa-smoke --description "QA smoke run" --scope "*.example.com"
```

### `talos project open <id>`

Open a project and mark it as the active project.

```powershell
talos project open qa-smoke
```

### `talos project close`

Close the currently active project.

```powershell
talos project close
```

### `talos project delete <id> [--force]`

Remove a project from the registry while preserving on-disk data.

```powershell
talos project delete qa-smoke --force
```

### `talos project list`

List all registered projects.

```powershell
talos project list
```

### `talos project scope <id> [PATTERN ...]`

Show the current scope when no patterns are supplied, or replace the scope when patterns are supplied.

```powershell
talos project scope qa-smoke "*.example.com" api.example.com
```

### `talos project constraints <id> [--store-bodies BOOL] [--max-body-size BYTES]`

Show current capture constraints or update body storage and truncation limits.

```powershell
talos project constraints qa-smoke --store-bodies true --max-body-size 1048576
```

### `talos project status`

Show the currently active project.

```powershell
talos project status
```

## Out-of-Scope Commands

- All commands require an active project.
- Out-of-scope domains override the scope allow-list — matching hosts are never captured or stored.
- Matching rule: `host == domain` OR `host.endswith('.' + domain)` — blocks the domain and all subdomains.
- Changes take effect on next proxy restart (domains are loaded once at proxy startup).

### `talos project outscope add domain <domain>`

Add a domain to the out-of-scope block list.

```powershell
talos project outscope add domain api.stripe.com
talos project outscope add domain cdn.segment.com
```

### `talos project outscope list`

List all out-of-scope domain entries for the active project.

```powershell
talos project outscope list
```

### `talos project outscope remove domain <domain>`

Remove a domain from the out-of-scope block list.

```powershell
talos project outscope remove domain api.stripe.com
```

## Proxy Commands

### `talos proxy start [--port PORT] [--listen-host HOST] [--quiet]`

Start the capture proxy for the active project.

```powershell
talos proxy start --listen-host 127.0.0.1 --port 8080
```

**Verifying capture is working:**

When you stop the proxy (Ctrl+C), the final log line shows capture statistics:
```
FlowWorker stopped — project=X processed=16 dropped=0 db_errors=0 queue_drops=0
```

- `processed=N` indicates N flows were successfully captured and stored in the database
- Check the UI or database to see flows and endpoints

## UI Command

### `talos ui [--host HOST] [--port PORT]`

Start the Talos web UI.

Normalized endpoints are grouped by `(method, host, normalized_path)`. Query strings used for flow storage and coverage drop tracking noise such as `utm_*`, `fbclid`, `gclid`, and known cache-buster keys.

```powershell
talos ui --host 127.0.0.1 --port 8010
```

## Role Commands

### `talos role create <name>`

Create a new role in the active project.

```powershell
talos role create admin
```

### `talos role add <name>`

Create a new role using the alias form of `create`.

```powershell
talos role add support
```

### `talos role list`

List all roles in the active project.

```powershell
talos role list
```

### `talos role set <name>`

Set the active role used to tag future captured flows.

```powershell
talos role set admin
```

### `talos role unset`

Reset the active role back to `global`.

```powershell
talos role unset
```

## Module Commands

### `talos module create <name> [-d|--description TEXT]`

Create a new module in the active project.

```powershell
talos module create orders --description "Order history and detail flows"
```

### `talos module add <name> [-d|--description TEXT]`

Create a new module using the alias form of `create`.

```powershell
talos module add billing --description "Billing area"
```

### `talos module list`

List all modules in the active project.

```powershell
talos module list
```

### `talos module set <name>`

Set the active module used to tag future captured flows.

```powershell
talos module set orders
```

### `talos module unset`

Reset the active module back to `global`.

```powershell
talos module unset
```

## Access Commands

### `talos access client set <role> <module> <allow|deny|unknown>`

Set the UI-observed client access state for a role and module pair.

```powershell
talos access client set admin orders allow
```

### `talos access client unset <role> <module>`

Clear the UI-observed client access state for a role and module pair.

```powershell
talos access client unset admin orders
```

### `talos access server set <role> <module> <allow|deny|unknown>`

Set the expected server enforcement state for a role and module pair.

```powershell
talos access server set admin orders allow
```

### `talos access server unset <role> <module>`

Clear the expected server enforcement state for a role and module pair.

```powershell
talos access server unset admin orders
```

### `talos access delete <role> <module>`

Delete the entire access-map row for a role and module pair.

```powershell
talos access delete admin orders
```

### `talos access show`

Display the full access matrix for the active project.

```powershell
talos access show
```

### `talos access coverage`

Compare access-map expectations against observed captured traffic.

```powershell
talos access coverage
```

### `talos access signals`

Show immediate BAC/IDOR signals across four sections:
1. **Cross-role exposure** — endpoints hit by more than one distinct role (IDOR / privilege confusion candidates).
2. **Module boundary violation** — specific endpoint URLs reached under `(role, module)` pairs where `server_expected = DENY` (missing server-side enforcement).
3. **client=DENY with observed flows** — role/module marked blocked in the UI but traffic was captured (potential UI bypass).
4. **client=ALLOW without observed flows** — role/module marked accessible but no traffic seen (coverage gap).

```powershell
talos access signals
```

## Replay Commands

- Both commands require an active project.
- By default both commands enqueue a scheduler job and print the job ID. Use `--right-now` to execute immediately in-process.
- The replayed request is sent exactly as captured — no mutation, no header stripping, no token refresh.
- CLI-triggered replays are stored with `source=manual_replay` and `replay_reason=testing`. System-triggered replays (BAC engine, IDOR module) use `source=auto_replay` with a specific `replay_reason` (`bac_test`, `idor_test`, `auth_test`, etc.).
- Every replay attempt (success or failure) is stored as a new flow linked to the original via `original_flow_id`.
- Failed replays (connection error, timeout, HTTP error) are stored with `replay_error` set and `status_code` NULL.
- A diff result is stored in `replay_diffs` for every replay: `verdict` is SAME, DIFFERENT, or ERROR.
- Example placeholder values below use a UUID-style ID; real IDs are full UUIDs shown by `talos ui`.

### `talos replay flow <flow_id> [--right-now]`

Enqueue a flow replay job for the scheduler (default). Use `--right-now` to execute immediately in-process.

```powershell
talos replay flow 3f2a1b4c-0000-0000-0000-000000000001
talos replay flow 3f2a1b4c-0000-0000-0000-000000000001 --right-now
```

### `talos replay endpoint <endpoint_id> [--right-now]`

Enqueue a replay job for the best qualifying flow of an endpoint (default). Use `--right-now` to execute immediately.
Selection rule: most recent `proxy_capture` flow with `status_code = 200`.
Exits 1 with a clear error if the endpoint is not found.

```powershell
talos replay endpoint 9e8d7c6b-0000-0000-0000-000000000002
talos replay endpoint 9e8d7c6b-0000-0000-0000-000000000002 --right-now
```

## Auth Commands

- All commands require an active project.
- Auth config stores **names only** (cookie names, header names) — never credential values.
- Config is global per project, not tied to specific endpoints.
- `set` is additive — re-running with the same names is a no-op (INSERT OR IGNORE).
- `auth test` enqueues an auth-bypass job by default; use `--right-now` to execute immediately. Stores the result in `auth_test_results` with verdict SECURE, BYPASS, or UNKNOWN.

### `talos auth set [--cookie NAME ...] [--header NAME ...]`

Add cookie and/or header names to the auth config. At least one flag required.

```powershell
talos auth set --cookie sessionid --cookie auth_token --header Authorization --header X-API-Key
```

### `talos auth show`

Display the current auth config for the active project.

```powershell
talos auth show
```

### `talos auth clear`

Remove all auth config entries for the active project.

```powershell
talos auth clear
```

### `talos auth test <endpoint_id> [--right-now]`

Enqueue an auth-bypass test job for the scheduler (default). Use `--right-now` to run immediately: strips configured auth fields, replays, diffs, produces verdict SECURE / BYPASS / UNKNOWN.
Exits 1 if endpoint not found (both modes). `--right-now` also exits 1 if no qualifying flow, auth config is empty, or endpoint is annotated logout/dangerous.

```powershell
talos auth test 9e8d7c6b-0000-0000-0000-000000000002
talos auth test 9e8d7c6b-0000-0000-0000-000000000002 --right-now
```

## Role-Based Session Management Commands

- All commands require an active project.
- Purpose: enable automated replay, BAC, and IDOR testing without manual login by giving Talos a way to obtain and validate authenticated sessions for each role.
- Session tokens are extracted from the login flow response body using a JWT regex (`eyJ…`). Non-JWT token formats are not supported at this time.
- At most one token per role is active at any time. `inject-session-token` and `generate` both set the active token.
- `validate` handles the full lifecycle: check → validate → regenerate on expiry.

### `talos auth mark-login <role_id> <flow_id>`

Assign a login flow to a role. Talos replays this flow when it needs to obtain a new session token for the role.

```powershell
talos auth mark-login <role_uuid> <flow_uuid>
```

### `talos auth mark-checkpoint <role_id> <flow_id>`

Assign a checkpoint flow to a role (e.g. `GET /api/me`). Talos replays this flow to check whether a stored token is still valid. A `200` response means valid; `401` or `403` means expired.

```powershell
talos auth mark-checkpoint <role_uuid> <flow_uuid>
```

### `talos auth generate <role_id>`

Replay the login flow for a role, extract the JWT from the response body, store it in the database, and mark it active.

```powershell
talos auth generate <role_uuid>
```

### `talos auth inject-session-token <role_id> <session_token_id>`

Set a previously generated token (by its UUID) as the active token for a role. All other tokens for the role are deactivated.

```powershell
talos auth inject-session-token <role_uuid> <token_uuid>
```

### `talos auth validate <role_id>`

Full validation lifecycle for a role's session:
1. If no active token exists — generate one via the login flow.
2. If an active token exists — replay the checkpoint flow.
3. If checkpoint returns `200` — token is valid; print confirmation.
4. If checkpoint returns `401` or `403` — token is expired; automatically generate a fresh one.

```powershell
talos auth validate <role_uuid>
```

## Endpoint Commands

- All commands require an active project.
- Annotations are manual — no auto-detection.
- Tags control replay safety: `logout` blocks all replay; `dangerous` blocks automated replay only.
- `mark --safe` clears all annotations, restoring the default (allow all).

### `talos endpoint mark <endpoint_id> --logout | --dangerous | --safe`

Add a safety annotation to an endpoint, or clear all annotations.

```powershell
# Mark as logout — replay and auth test are blocked in all modes
talos endpoint mark 9e8d7c6b-0000-0000-0000-000000000002 --logout

# Mark as dangerous — blocked in automated replay; manual 'replay flow' still allowed
talos endpoint mark 9e8d7c6b-0000-0000-0000-000000000002 --dangerous

# Restore safe default — removes all annotations
talos endpoint mark 9e8d7c6b-0000-0000-0000-000000000002 --safe
```

### `talos endpoint unmark <endpoint_id> --logout | --dangerous`

Remove a specific annotation tag. No-op if the tag is not present.

```powershell
talos endpoint unmark 9e8d7c6b-0000-0000-0000-000000000002 --logout
talos endpoint unmark 9e8d7c6b-0000-0000-0000-000000000002 --dangerous
```

### `talos endpoint show <endpoint_id>`

Display endpoint details and its current annotation tags.

```powershell
talos endpoint show 9e8d7c6b-0000-0000-0000-000000000002
```

## Scheduler Commands

- All commands require an active project.
- The scheduler runs automatically as a daemon thread when the proxy starts — it does not need to be started manually.
- `replay flow`, `replay endpoint`, and `auth test` enqueue jobs to the scheduler by default. Use `--right-now` to bypass the queue and execute immediately.
- `enqueue` supports `--force` to skip the overflow confirmation prompt.

### `talos scheduler status`

Show queue depth by status, pending jobs in execution order, execution metrics, and current config.

```powershell
talos scheduler status
```

### `talos scheduler config [--min-delay N] [--max-delay N] [--max-queue-size N]`

Read or update the scheduler config. With no flags, display the current values.

```powershell
talos scheduler config
talos scheduler config --min-delay 3.0 --max-delay 8.0 --max-queue-size 100
```

### `talos scheduler enqueue flow <flow_id> [--priority N] [--force]`

Add a flow replay job directly to the scheduler queue.

```powershell
talos scheduler enqueue flow 3f2a1b4c-0000-0000-0000-000000000001
```

### `talos scheduler enqueue endpoint <endpoint_id> [--type replay|auth-test] [--priority N] [--force]`

Add an endpoint replay or auth-test job directly to the scheduler queue.

```powershell
talos scheduler enqueue endpoint 9e8d7c6b-0000-0000-0000-000000000002
talos scheduler enqueue endpoint 9e8d7c6b-0000-0000-0000-000000000002 --type auth-test
```

### `talos scheduler clear [--force]`

Remove all pending jobs from the queue. Running and completed jobs are unaffected.

```powershell
talos scheduler clear
talos scheduler clear --force
```

## Mutation Commands

- All commands require an active project.
- A mutation is a static transformation applied to every outgoing request before it reaches the server.
- Only `header` mutations are supported: inject a fixed header name/value on every request.
- Mutations are loaded once at proxy startup — changes take effect on next proxy restart.
- Injected headers overwrite any pre-existing header with the same name.
- Injected headers are stored in captured flows and carried through all replays automatically.

### `talos mutation add <type> <key> <value>`

Add a new request mutation to the active project. Only `header` is a valid type.

```powershell
talos mutation add header X-HackerOne-Research himanshu_2077
talos mutation add header X-Custom-Tag recon-pass-1
```

### `talos mutation list`

List all request mutations for the active project, including their IDs and enabled state.

```powershell
talos mutation list
```

### `talos mutation delete <id>`

Delete a mutation by its UUID. Exits 1 if the ID is not found.

```powershell
talos mutation delete 3f2a1b4c-0000-0000-0000-000000000001
```

Use this short sequence when you want a clean end-to-end Talos session.

```powershell
talos project create qa-smoke --description "QA smoke run"
talos project open qa-smoke
talos project scope qa-smoke "*.example.com"
talos role create admin
talos module create orders --description "Order flows"
talos role set admin
talos module set orders
talos access client set admin orders allow
talos access server set admin orders allow
talos proxy start --port 8080
talos ui --port 8010
talos access coverage
talos access signals
```

---

## Attack Modules (UI only — no CLI commands)

Attack modules are managed exclusively through the Talos UI at
`/project/<id>/attacks`. There are no CLI commands for them.

### Unauthenticated Execution

Strips auth credentials from a captured 200 OK flow for each endpoint, replays
it, and diffs the response to determine whether the endpoint enforces
authentication.

**Verdicts**

| Verdict | Meaning |
|---------|---------|
| `SECURE` | Replay returned 401, 403, or a redirect — auth is enforced |
| `BYPASS` | Replay returned 200 — auth is NOT enforced (finding) |
| `UNKNOWN` | Replay returned 5xx, error, or original was not 200 OK |

**Auto-Run**

When enabled via the Attacks page toggle, the scheduler automatically
enqueues `AUTH_TEST` jobs for untested endpoints every ~30 seconds (30 idle
polling ticks). The setting is stored in `attack_config` key `unauth_auto_run`
in the project database. No proxy restart required.

**Coverage is derived**, not stored — status is calculated on-the-fly from the
`auth_test_results` and `scheduler_jobs` tables. Rerunning a test overwrites
the previous result.