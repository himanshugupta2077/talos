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
   ├─ unset
   ├─ show
   ├─ clear
   └─ test
└─ auth-config
   ├─ add-flow
   ├─ remove-flow
   ├─ list-flows
   ├─ set-extractor
   ├─ show-extractor
   ├─ edit-extractor
   ├─ remove-extractor
   ├─ test
   ├─ validate
   ├─ refresh
   ├─ status
   ├─ show
   ├─ set-ttl
   ├─ add-expiry-signal
   ├─ clear-expiry-signals
   ├─ set-validation
   ├─ clear-validation
   ├─ add-control-flow
   ├─ remove-control-flow
   └─ list-control-flows
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
└─ attack
   ├─ unauth
   │  └─ exclude
   │     ├─ add
   │     ├─ remove
   │     └─ list
   └─ bac
      ├─ session-swap  [--role NAME] [--auto-generate]
      ├─ method-fuzz   [--role NAME] [--auto-generate]
      ├─ content-type  [--role NAME] [--auto-generate]
      ├─ url-fuzz      [--role NAME] [--auto-generate]
      ├─ header-inject [--role NAME] [--auto-generate]
      ├─ host-fuzz     [--role NAME] [--auto-generate]
      └─ role-inject   [--role NAME] [--auto-generate]
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
- Auth config stores **required artifact names only** (cookie names, header names) — never credential values.
- Config is global per project, not tied to specific endpoints.
- `set` is additive — re-running with the same names is a no-op (INSERT OR IGNORE).
- `unset` removes specific names without clearing the entire config.
- `auth test` runs Type 2 unauth bypass testing (strips auth, replays, diffs). It does NOT manage session tokens.
- For role-based session management, token generation, and session health — use `talos auth-config`.

### `talos auth set [--cookie NAME ...] [--header NAME ...]`

Add cookie and/or header artifact names to the auth requirements. At least one flag required. Additive.

```powershell
talos auth set --cookie sessionid --header Authorization
talos auth set --cookie sessionid --cookie csrf --header Authorization --header X-API-Key
```

### `talos auth unset [--cookie NAME ...] [--header NAME ...]`

Remove specific cookie and/or header names from the auth requirements.

```powershell
talos auth unset --cookie sessionid
talos auth unset --header Authorization
talos auth unset --cookie csrf --header X-API-Key
```

### `talos auth show`

Display the current required auth artifacts for the active project.

```powershell
talos auth show
```

### `talos auth clear`

Remove all auth requirement entries for the active project.

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

## Auth-Config Commands

- All commands require an active project.
- The auth-config model replaces the old `mark-login` / `generate` / `validate` single-flow approach.
- Supports multiple login flows per role, each with a Python extractor that returns `{artifact_name: value}` pairs.
- The Session Health Engine automatically refreshes auth state before it expires, preventing stale sessions during long attack queues.

### Setup Workflow

```
1. talos auth set --cookie sessionid --header Authorization   # define what's required
2. talos auth-config add-flow admin <flow_uuid>               # attach login flow
3. talos auth-config set-extractor admin <flow_uuid> login.py # attach extractor
4. talos auth-config refresh admin                            # generate initial auth state
5. talos attack bac session-swap                              # run attack — health maintained automatically
```

### Extractor Script Format

```python
def extract(response):
    # response.status   (int)  — HTTP status code
    # response.headers  (dict) — lowercase header names
    # response.body     (str)  — decoded body
    # response.cookies  (dict) — cookie name → value
    return {
        "sessionid": response.cookies.get("sessionid", ""),
        "Authorization": "Bearer " + response.body.split('"token":"')[1].split('"')[0],
    }
```

### Flow Management

```powershell
talos auth-config add-flow <role_id> <flow_id>      # add a login flow
talos auth-config remove-flow <role_id> <flow_id>   # remove a flow
talos auth-config list-flows <role_id>              # list configured flows
```

### Extractor Management

```powershell
talos auth-config set-extractor <role_id> <flow_id> <extractor.py>   # set extractor from file
talos auth-config show-extractor <role_id> <flow_id>                 # print extractor code
talos auth-config edit-extractor <role_id> <flow_id>                 # open in $EDITOR
talos auth-config remove-extractor <role_id> <flow_id>               # clear extractor
```

### Runtime

```powershell
talos auth-config test <role_id> <flow_id>    # run one flow + extractor, show artifacts (no state stored)
talos auth-config validate <role_id>          # run all flows, show pass/fail per required artifact
talos auth-config refresh <role_id>           # force full refresh, store new auth state
talos auth-config status <role_id>            # show current auth state + TTL age
talos auth-config show <role_id>              # show complete config (flows, extractors, health settings)
```

### Session Health — Layer 1: TTL Configuration

Proactive pre-refresh before token expires. Primary mechanism — catches 90–95% of expirations.

```powershell
# Refresh 2 minutes before a 20-minute token expires (at the 18-minute mark)
talos auth-config set-ttl <role_id> --ttl 1200 --refresh-before 120

# Refresh 5 minutes before a 60-minute token expires
talos auth-config set-ttl <role_id> --ttl 3600 --refresh-before 300
```

### Session Health — Layer 2: Expiry Signals

Response-based detection. Never triggers refresh directly — increments suspicion counter only.

```powershell
talos auth-config add-expiry-signal <role_id> --body "session expired" --body "please login"
talos auth-config add-expiry-signal <role_id> --status 419 --status 440
talos auth-config add-expiry-signal <role_id> --header location /login
talos auth-config clear-expiry-signals <role_id>   # remove all signals
```

### Session Health — Layer 3: Validation Endpoint

Authoritative session check. Runs only when suspicion is detected.

```powershell
talos auth-config set-validation <role_id> https://api.example.com/api/me \
    --expected-status 200 \
    --body-contains '"username"' \
    --body-not-contains '"login"'

talos auth-config clear-validation <role_id>
```

### Session Health — Layer 4: Control Flows

Strongest health signal. Replays stable harmless authenticated flows to judge liveness.

```powershell
talos auth-config add-control-flow <role_id> <flow_id>     # add a control flow
talos auth-config remove-control-flow <role_id> <flow_id>  # remove a control flow
talos auth-config list-control-flows <role_id>             # list all control flows
```

**Rule:** Session is healthy if ≥ 1 control flow returns 200. Dead if all fail.

## Role-Based Session Management (Legacy Reference)

The following commands have been **removed** and replaced by `talos auth-config`:

| Old command | New equivalent |
|---|---|
| `talos auth mark-login <role> <flow>` | `talos auth-config add-flow <role> <flow>` + `set-extractor` |
| `talos auth mark-checkpoint <role> <flow>` | `talos auth-config add-control-flow <role> <flow>` |
| `talos auth generate <role>` | `talos auth-config refresh <role>` |
| `talos auth validate <role>` | `talos auth-config validate <role>` |
| `talos auth inject-session-token <role> <token>` | Replaced by extractor model — not needed |

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

## Attack Modules

### Unauthenticated Execution (`talos attack unauth`)

Strips auth credentials from captured flows, replays them, and diffs the response
to detect endpoints that serve data without authentication (forced browsing).

#### `talos attack unauth exclude add <target>`

Exclude a host or host+path prefix from unauthenticated testing.

```powershell
talos attack unauth exclude add api.internal.example.com
talos attack unauth exclude add test.com/api/v1
```

#### `talos attack unauth exclude remove <target>`

Remove an exclusion.

```powershell
talos attack unauth exclude remove test.com/api/v1
```

#### `talos attack unauth exclude list`

List all exclusions.

```powershell
talos attack unauth exclude list
```

**Verdicts** stored in `auth_test_results`:

| Verdict | Meaning |
|---------|---------|
| `SECURE` | Replay returned 401, 403, or a redirect — auth is enforced |
| `BYPASS` | Replay returned 200 — auth is NOT enforced (finding) |
| `UNKNOWN` | Replay returned 5xx, error, or original was not 200 OK |

---

### BAC Attack Modules (`talos attack bac`)

BAC (Broken Access Control) attacks scan the access matrix for role pairs where
one role should NOT have access to a module but another role does.  For each
candidate, Talos generates scheduler jobs that replay target-role flows with
the attacker role's session token and/or an additional HTTP mutation.

**Auth prerequisites per attacker role (checked before job generation):**
1. `login_flow_id` configured — `talos auth mark-login <role_id> <flow_id>`
2. `checkpoint_flow_id` configured — `talos auth mark-checkpoint <role_id> <flow_id>`
3. Auth config non-empty — `talos auth set --cookie <name>` or `--header <name>`
4. Active session token — `talos auth generate <role_id>` or `--auto-generate`

**Candidate logic:**
- Target role: `server_expected = ALLOW` for a module
- Attacker role: `server_expected = DENY` or `UNKNOWN` for the same module
- At least one 200 OK `proxy_capture` flow exists for (target_role, module)

**Verdicts** stored in `bac_results`:

| Verdict | Meaning |
|---------|---------|
| `POSSIBLE_BAC` | Attacker received 200 — access was NOT blocked (finding) |
| `SECURE` | Attacker received 401, 403, or a redirect |
| `UNKNOWN` | Network error, 5xx, or original baseline was not 200 |

#### `talos attack bac session-swap [--role NAME] [--auto-generate]`

Direct session swap. Replays all target-role flows for a module using the
attacker role's session token. This is the core BAC test.

```powershell
talos attack bac session-swap
talos attack bac session-swap --role customer
talos attack bac session-swap --role customer --auto-generate
```

#### `talos attack bac method-fuzz [--role NAME] [--auto-generate]`

HTTP Method Manipulation. Applies all method variants on top of the session swap:
`GET→POST`, `GET→PUT`, `GET→HEAD`, `POST→GET`, `POST→PUT`, `POST→PATCH`,
`PUT→PATCH`, `X-HTTP-Method-Override: PUT/DELETE`.

```powershell
talos attack bac method-fuzz
talos attack bac method-fuzz --role customer --auto-generate
```

#### `talos attack bac content-type [--role NAME] [--auto-generate]`

Content-Type Confusion. Changes the Content-Type header to confuse server-side
parsers: JSON→Form, JSON→Multipart, Form→JSON, XML→JSON, invalid type.

```powershell
talos attack bac content-type
talos attack bac content-type --role customer
```

#### `talos attack bac url-fuzz [--role NAME] [--auto-generate]`

URL Manipulation. Applies path transformations to bypass path-based controls:
trailing slash, double slash, dot segment, back-traversal, percent-encoded
first char, mixed case.

```powershell
talos attack bac url-fuzz
talos attack bac url-fuzz --role customer
```

#### `talos attack bac header-inject [--role NAME] [--auto-generate]`

Header Manipulation. Injects proxy/routing headers to exploit reverse-proxy
misconfiguration: `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`,
`X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP`.

```powershell
talos attack bac header-inject
talos attack bac header-inject --role customer
```

#### `talos attack bac host-fuzz [--role NAME] [--auto-generate]`

Host Header Changes. Replaces the `Host` header with `example.com`, `localhost`,
or `127.0.0.1` to test Host-based routing bypass.

```powershell
talos attack bac host-fuzz
talos attack bac host-fuzz --role customer
```

#### `talos attack bac role-inject [--role NAME] [--auto-generate]`

Role Parameter Injection. Injects role-escalation parameters via query string
and headers: `isAdmin=true`, `role=admin`, `admin=1`, `access_level=999`,
`permissions=["admin"]`, duplicate `role` param, `X-Role: admin`, `X-Admin: true`.

```powershell
talos attack bac role-inject
talos attack bac role-inject --role customer
```