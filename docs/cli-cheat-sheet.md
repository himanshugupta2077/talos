# Talos CLI Cheat Sheet

This cheat sheet reflects the current state of the Talos CLI.

## Quick Notes

- Run `talos --help` or `talos -h` to see all commands and subcommands at once.
- Most commands require an active project. Run `talos project open <id>` first.
- `proxy start` requires an active project.
- In shell, quote wildcard scope patterns: `"*.example.com"`.
- Example placeholder values used below:
  - project id: `qa-smoke`
  - host pattern: `"*.example.com"`
  - role name: `admin`
  - module name: `orders`
  - UUID: `3f2a1b4c-0000-0000-0000-000000000001`

---

## Command Tree

```text
talos [-h|--help]
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
│
├─ proxy
│  └─ start
│
├─ ui
│
├─ role
│  ├─ create
│  ├─ add
│  ├─ list
│  ├─ set
│  └─ unset
│
├─ module
│  ├─ create
│  ├─ add
│  ├─ list
│  ├─ set
│  └─ unset
│
├─ access
│  ├─ client set
│  ├─ client unset
│  ├─ server set
│  ├─ server unset
│  ├─ delete
│  ├─ show
│  ├─ coverage
│  └─ signals
│
├─ auth
│  ├─ set
│  ├─ unset
│  ├─ show
│  ├─ clear
│  └─ test
│
├─ auth-config
│  ├─ add-flow
│  ├─ remove-flow
│  ├─ list-flows
│  ├─ set-extractor
│  ├─ show-extractor
│  ├─ edit-extractor
│  ├─ remove-extractor
│  ├─ test
│  ├─ validate
│  ├─ refresh
│  ├─ status
│  ├─ show
│  ├─ set-ttl
│  ├─ add-expiry-signal
│  ├─ clear-expiry-signals
│  ├─ set-validation
│  ├─ clear-validation
│  ├─ add-control-flow
│  ├─ remove-control-flow
│  └─ list-control-flows
│
├─ endpoint
│  ├─ mark
│  ├─ unmark
│  ├─ show
│  ├─ export
│  ├─ priority
│  │  ├─ set endpoint
│  │  ├─ set path
│  │  ├─ clear endpoint
│  │  └─ clear path
│  ├─ exclude
│  │  ├─ endpoint
│  │  └─ path
│  ├─ include
│  │  ├─ endpoint
│  │  └─ path
│  └─ rules list
│
├─ replay
│  ├─ flow
│  └─ endpoint
│
├─ flow
│  ├─ show
│  └─ export
│
├─ scheduler
│  ├─ status
│  ├─ config
│  ├─ enqueue
│  │  ├─ flow
│  │  └─ endpoint
│  └─ clear
│
├─ mutation
│  ├─ add
│  ├─ list
│  └─ delete
│
├─ attack
│  ├─ unauth
│  │  └─ exclude
│  │     ├─ add
│  │     ├─ remove
│  │     └─ list
│  └─ bac
│     ├─ session-swap  [--role NAME] [--auto-generate]
│     ├─ method-fuzz   [--role NAME] [--auto-generate]
│     ├─ content-type  [--role NAME] [--auto-generate]
│     ├─ url-fuzz      [--role NAME] [--auto-generate]
│     ├─ header-inject [--role NAME] [--auto-generate]
│     ├─ host-fuzz     [--role NAME] [--auto-generate]
│     ├─ role-inject   [--role NAME] [--auto-generate]
│     └─ filter
│        ├─ init
│        ├─ show
│        └─ validate
│
└─ input-validation
   ├─ run              [--host H | --endpoint ID | --parameter UUID] [--ignore-cache]
   ├─ config           [--enable|--disable] [--workers N] [--analysis-on/off PHASE]
   ├─ status
   ├─ resume           [--host H | --endpoint ID | --parameter P]
   ├─ clear-cache
   ├─ exclude
   │  ├─ endpoint <id>
   │  └─ host <host>
   ├─ include
   │  ├─ endpoint <id>
   │  └─ host <host>
   ├─ show <parameter_uuid>
   ├─ export
   │  ├─ parameter <parameter_uuid>
   │  ├─ host <host>
   │  └─ csv
   ├─ baseline         [--host H | --endpoint ID | --parameter UUID] [--force]
   ├─ identifier       [--host H | --endpoint ID | --parameter UUID] [--force]
   ├─ characters       [--host H | --endpoint ID | --parameter UUID] [--force]
   ├─ length           [--host H | --endpoint ID | --parameter UUID] [--force]
   ├─ types            [--host H | --endpoint ID | --parameter UUID] [--force]
   ├─ transformations  [--host H | --endpoint ID | --parameter UUID] [--force]
   ├─ reflection       [--host H | --endpoint ID | --parameter UUID] [--force]
   └─ validation       [--host H | --endpoint ID | --parameter UUID] [--force]
```

---

## Recommended Attack Workflow

This is the standard workflow for a full BAC assessment.

```bash
# 1. Project setup
talos project create target-app --description "Bug bounty target"
talos project open target-app
talos project scope target-app "*.target.com" "api.target.com"

# 2. Create roles and modules
talos role create admin
talos role create user
talos module create dashboard
talos module create admin-panel

# 3. Define access expectations
talos access client set admin dashboard allow
talos access client set user  dashboard allow
talos access client set admin admin-panel allow
talos access client set user  admin-panel deny     # user should not see this
talos access server set admin dashboard allow
talos access server set user  dashboard allow
talos access server set admin admin-panel allow
talos access server set user  admin-panel deny     # assertion: server enforces this

# 4. Configure auth
talos auth set --cookie sessionid --header Authorization

# 5. Capture traffic with role context
talos role set admin && talos module set dashboard
talos proxy start --port 8080
# ... browse as admin, then ...
talos role set user && talos module set dashboard
# ... browse as user ...

# 6. Set up auth-config for the attacker role (user trying to hit admin endpoints)
talos auth-config add-flow user <login_flow_uuid>
talos auth-config set-extractor user <login_flow_uuid> extractor.py
talos auth-config refresh user

# 7. Run BAC tests
talos attack bac session-swap --role user
talos scheduler status   # watch progress

# 8. (Optional) Enable Input Validation for deeper parameter intelligence
talos input-validation config --enable --workers 2
talos input-validation run
talos input-validation status

# 9. Review results in UI
talos ui --port 8010
```

---

## Project Commands

### `talos project create <name> [-d TEXT] [-s HOST ...]`

```bash
talos project create qa-smoke --description "QA smoke run" --scope "*.example.com"
```

### `talos project open <id>`

```bash
talos project open qa-smoke
```

### `talos project close`

```bash
talos project close
```

### `talos project delete <id> [--force]`

```bash
talos project delete qa-smoke --force
```

### `talos project list`

```bash
talos project list
```

### `talos project scope <id> [PATTERN ...]`

```bash
talos project scope qa-smoke "*.example.com" api.example.com
```

### `talos project constraints <id> [--store-bodies BOOL] [--max-body-size BYTES]`

```bash
talos project constraints qa-smoke --store-bodies true --max-body-size 1048576
```

### `talos project status`

```bash
talos project status
```

### Out-of-scope

```bash
talos project outscope add domain api.stripe.com
talos project outscope list
talos project outscope remove domain api.stripe.com
```

---

## Proxy

```bash
talos proxy start --listen-host 127.0.0.1 --port 8080
```

---

## UI

```bash
talos ui --host 127.0.0.1 --port 8010
```

---

## Role Commands

```bash
talos role create admin
talos role list
talos role set admin
talos role unset
```

---

## Module Commands

```bash
talos module create orders --description "Order history"
talos module list
talos module set orders
talos module unset
```

---

## Access Commands

```bash
talos access client set admin orders allow
talos access server set admin orders allow
talos access client unset admin orders
talos access server unset admin orders
talos access delete admin orders
talos access show
talos access coverage
talos access signals
```

---

## Auth Commands

Auth config stores **artifact names only** (cookie/header names), not credential values.

```bash
talos auth set --cookie sessionid --header Authorization
talos auth set --cookie sessionid --cookie csrf --header Authorization --header X-API-Key
talos auth unset --cookie sessionid
talos auth show
talos auth clear
talos auth test <endpoint_id>
talos auth test <endpoint_id> --right-now
```

---

## Auth-Config Commands

Auth-config manages role-specific login flows, extractors, and session health.

### Setup workflow

```bash
# 1. Define required auth artifacts
talos auth set --cookie sessionid --header Authorization

# 2. Attach a login flow and extractor
talos auth-config add-flow admin <flow_uuid>
talos auth-config set-extractor admin <flow_uuid> login_extractor.py

# 3. Generate initial auth state
talos auth-config refresh admin

# 4. Verify
talos auth-config status admin
```

### Extractor format

```python
def extract(response):
    # response.status, response.headers, response.body, response.cookies
    return {
        "sessionid": response.cookies.get("sessionid", ""),
        "Authorization": "Bearer " + response.body.split('"token":"')[1].split('"')[0],
    }
```

### Flow management

```bash
talos auth-config add-flow <role> <flow_id>
talos auth-config remove-flow <role> <flow_id>
talos auth-config list-flows <role>
```

### Extractor management

```bash
talos auth-config set-extractor <role> <flow_id> extractor.py
talos auth-config show-extractor <role> <flow_id>
talos auth-config edit-extractor <role> <flow_id>
talos auth-config remove-extractor <role> <flow_id>
```

### Runtime

```bash
talos auth-config test <role> <flow_id>   # test one flow+extractor (no state stored)
talos auth-config validate <role>          # check all required artifacts are satisfied
talos auth-config refresh <role>           # force full refresh + store auth state
talos auth-config status <role>            # show current state + TTL age
talos auth-config show <role>              # show full config (flows, extractors, health)
```

### Session health

```bash
# Layer 1: TTL (proactive pre-refresh)
talos auth-config set-ttl <role> --ttl 1200 --refresh-before 120

# Layer 2: Expiry signals (response-based detection)
talos auth-config add-expiry-signal <role> --body "session expired" --body "please login"
talos auth-config add-expiry-signal <role> --status 419 --status 440
talos auth-config add-expiry-signal <role> --header location /login
talos auth-config clear-expiry-signals <role>

# Layer 3: Validation endpoint (authoritative check)
talos auth-config set-validation <role> https://api.example.com/api/me \
    --expected-status 200 \
    --body-contains '"username"' \
    --body-not-contains '"login"'
talos auth-config clear-validation <role>

# Layer 4: Control flows (strongest health signal)
talos auth-config add-control-flow <role> <flow_id>
talos auth-config remove-control-flow <role> <flow_id>
talos auth-config list-control-flows <role>
```

---

## Endpoint Commands

```bash
# Safety annotations
talos endpoint mark <endpoint_id> --logout
talos endpoint mark <endpoint_id> --dangerous
talos endpoint mark <endpoint_id> --safe
talos endpoint unmark <endpoint_id> --logout
talos endpoint unmark <endpoint_id> --dangerous
talos endpoint show <endpoint_id>

# Export complete endpoint dossier
talos endpoint export <endpoint_id>

# Priority
talos endpoint priority set endpoint <endpoint_id> CRITICAL
talos endpoint priority set path "/api/admin/*" HIGH
talos endpoint priority clear endpoint <endpoint_id>
talos endpoint priority clear path "/api/admin/*"

# Exclusions
talos endpoint exclude endpoint <endpoint_id>
talos endpoint exclude path "/static/*"
talos endpoint include endpoint <endpoint_id>
talos endpoint include path "/static/*"

# Rules
talos endpoint rules list
```

---

## Replay Commands

```bash
talos replay flow <flow_id>
talos replay flow <flow_id> --right-now
talos replay endpoint <endpoint_id>
talos replay endpoint <endpoint_id> --right-now
```

---

## Flow Commands

Inspect replay flows generated by any Talos subsystem.

```bash
talos flow show <flow_id>

talos flow export <flow_id>

talos flow export --module input_validation
talos flow export --module bac

talos flow export --parameter <parameter_uuid>

talos flow export --endpoint <endpoint_id>

talos flow export --flows <flow_id> <flow_id> ...
```

---

## Scheduler Commands

```bash
talos scheduler status
talos scheduler config
talos scheduler config --min-delay 3.0 --max-delay 8.0 --max-queue-size 100
talos scheduler enqueue flow <flow_id>
talos scheduler enqueue endpoint <endpoint_id>
talos scheduler enqueue endpoint <endpoint_id> --type auth-test
talos scheduler clear
talos scheduler clear --force
```

---

## Mutation Commands

```bash
talos mutation add header X-HackerOne-Research himanshu_2077
talos mutation list
talos mutation delete <mutation_id>
```

---

## Attack — Unauth

Strips auth credentials from captured flows and replays them to detect endpoints
that serve data without authentication.

```bash
talos attack unauth exclude add api.internal.example.com
talos attack unauth exclude add test.com/api/v1
talos attack unauth exclude remove test.com/api/v1
talos attack unauth exclude list
```

**Verdicts:** `SECURE` | `BYPASS` | `UNKNOWN`

---

## Attack — BAC

**Auth prerequisites per attacker role:**
1. Auth-config flows + extractors configured (`talos auth-config add-flow` + `set-extractor`)
2. Auth config non-empty (`talos auth set`)
3. Active auth state (`talos auth-config refresh <role>` or `--auto-generate`)

**Candidate logic:**
- Target role: `server_expected = ALLOW` for a module
- Attacker role: `server_expected = DENY` or `UNKNOWN` for the same module

```bash
# Core session swap (most important)
talos attack bac session-swap
talos attack bac session-swap --role customer
talos attack bac session-swap --role customer --auto-generate

# Additional attack vectors
talos attack bac method-fuzz   --role customer
talos attack bac content-type  --role customer
talos attack bac url-fuzz      --role customer
talos attack bac header-inject --role customer
talos attack bac host-fuzz     --role customer
talos attack bac role-inject   --role customer
```

**Verdicts:** `POSSIBLE_BAC` | `SECURE` | `UNKNOWN`

### BAC Decision Filter

The decision filter refines verdicts based on response patterns, replacing
simple status-code-only heuristics with application-specific rules.

```bash
talos attack bac filter init      # create BAC-decision-filter.yaml from template
talos attack bac filter show      # display the current filter config
talos attack bac filter validate  # validate the filter config syntax
```

Filter file location: `<project_data_dir>/BAC-decision-filter.yaml`

---

## Input Validation Engine

The Input Validation Engine actively characterizes every input the application
accepts. It is **disabled by default** — enable it explicitly.

Unlike Endpoint Intelligence (passive), this engine sends controlled requests to
understand how each parameter behaves. It does **not** attempt exploitation.

### Enable and configure

```bash
talos input-validation config --enable
talos input-validation config --enable --workers 4
talos input-validation config --disable
talos input-validation config --analysis-off reflection   # disable one phase
talos input-validation config                              # show current config
```

### Run

```bash
# Schedule jobs for the entire project
talos input-validation run

# Scope to a single host
talos input-validation run --host api.example.com

# Scope to a single endpoint
talos input-validation run --endpoint <endpoint_id>

# Scope to a single parameter everywhere it appears
talos input-validation run --parameter username

# Force re-run (ignore cache)
talos input-validation run --ignore-cache
```

### Status and resume

```bash
talos input-validation status    # show progress (total/completed/running/queued/failed)
talos input-validation resume    # continue from unfinished analyses
```

### Cache management

```bash
talos input-validation clear-cache                     # delete all IV cache data
talos input-validation clear-cache --host api.example.com   # scoped to one host
talos input-validation clear-cache --endpoint <id>     # scoped to one endpoint
talos input-validation clear-cache --parameter username # scoped to one parameter name
```

Note: `--host`, `--endpoint`, and `--parameter` are mutually exclusive.
Useful when debugging a single endpoint without discarding work on the rest.

### Run individual phases

Each phase command supports `--host`, `--endpoint`, `--parameter`, `--force`.

```bash
talos input-validation baseline        # Phase 1: capture baseline response
talos input-validation identifier      # Phase 2: traceable identifier injection
talos input-validation characters      # Phase 3: character acceptance testing
talos input-validation length          # Phase 4: length behaviour
talos input-validation types           # Phase 5: type characterization
talos input-validation transformations # Phase 6: transformation detection
talos input-validation reflection      # Phase 7: per-endpoint reflection analysis
talos input-validation validation      # Phase 8: validation behaviour and errors

# With targeting
talos input-validation characters --parameter username
talos input-validation reflection --endpoint <endpoint_id>
talos input-validation types --host api.example.com --force
```

### Exclusions

Input Validation respects the endpoint policy exclusion system.
Additional IV-only exclusions can be added here.

```bash
talos input-validation exclude endpoint <endpoint_id>
talos input-validation exclude host api.internal.example.com
talos input-validation include endpoint <endpoint_id>
talos input-validation include host api.internal.example.com
```

### Results

```bash
# Display the complete parameter profile
talos input-validation show <parameter_uuid>

# Export one parameter
talos input-validation export parameter <parameter_uuid>

# Export host-level Input Validation
talos input-validation export host api.example.com

# Export all probe results
talos input-validation export csv
```

`show` displays the complete parameter characterization, including:

- Parameter Intelligence
- Every Input Validation phase
- Every replay flow generated
- Exact payload sent
- Replay flow ID
- HTTP status code
- Phase observations
- Raw HTTP request
- Raw HTTP response

Parameter exports contain the complete evidence for that parameter across every
endpoint where it appears.

---

## Endpoint Intelligence

Endpoint Intelligence is populated automatically by the FlowWorker during
traffic capture. No manual commands required.

For each captured flow, Talos extracts and stores:

| Input surface | Location value | Examples |
|---------------|---------------|----------|
| Path segments | `path` | `/users/{user_id}` → `user_id` |
| Query string | `query` | `?page=1&sort=name` |
| JSON body | `body` | `{"email": "x", "role": "admin"}` |
| Nested JSON | `body` | `address.city`, `items[].price` |
| Form / multipart | `body` | `username=x`, `file` field |
| XML / SOAP | `body` | element names |
| GraphQL variables | `body` | `variables.userId` |
| Security headers | `header` | `Authorization`, `X-Forwarded-For`, `Origin`, `X-Tenant` |
| Cookies | `cookie` | `sessionid`, `csrftoken` |

**Semantic types inferred:** `uuid` · `jwt` · `email` · `objectid` · `url` · `ip` · `hash` · `timestamp` · `filename` · `boolean` · `integer` · `float` · `array` · `string`

**Passive reflection** is also detected: if a parameter value appears in the
response body (raw, HTML-encoded, or URL-encoded), it is recorded automatically.

View parameter intelligence in the UI or via `talos input-validation show <param>`.
