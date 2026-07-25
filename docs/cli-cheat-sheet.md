# Talos CLI Cheat Sheet

**Purpose:** Complete CLI reference for Talos. Source of truth for command syntax is the live CLI (`talos <command> -h`). This document must match argparse and root help.

**Related documents:**

| Document | Purpose |
|----------|---------|
| `README.md` | Overview, installation, quick start |
| `docs/cli-cheat-sheet.md` | Complete CLI reference (this file) |
| `docs/architecture.md` | Internal architecture and subsystem design |
| `docs/updates.md` | Release notes / change log |
| `docs/about-talos.md` | Vision / design notes (non-authoritative) |

## Quick Notes

- Run `talos --help` or `talos -h` for the full command catalogue.
- Most commands require a **project context** (one of):
  - Interactive: `talos project open <id>` (sets registry ACTIVE)
  - Per command: `talos --project <id> <command> …` (does **not** rewrite registry)
  - Environment: `TALOS_PROJECT=<id> talos <command> …` (same process / children)
- `proxy start` requires a project context (registry ACTIVE or override).
- Scope uses **Basic Scope URL prefixes** (one complete prefix per entry). Do not
  comma-separate hosts on one line. Wildcards are not supported.
- **Identifiers:**
  - Projects and access-map commands: **names**.
  - **Roles and modules accept a name or UUID** where scoped (auth-config
    `<role>`, BAC `--role` / `--module`, flow/endpoint `--role` filters). Prefer
    the name. Discover with `talos role list` / `talos module list` (or `show`).
  - Endpoints, flows, findings, parameters (for `show` / export): **UUIDs**.
    Discover endpoint UUIDs with `talos endpoint list` (optional filters:
    `--host`, `--method`, `--qualified`, `--role`, etc.).
    Discover flow UUIDs with `talos flow list` (optional filters:
    `--endpoint`, `--status-code`, `--role`, `--source`, `--limit`).
- Example placeholders:
  - project id: `qa-smoke`
  - role name or UUID: `<role>` (e.g. `admin`)
  - module name or UUID: `orders` / `<module>`
  - endpoint / flow / finding UUID: `<endpoint_id>`, `<flow_id>`, `<finding_uuid>`

### Output conventions (CLI-011 / CLI-014)

Commands share one user-facing style via `talos.cli_output`:

| Kind | Where | Shape |
|------|-------|--------|
| Success | stdout | Summary line; optional labeled fields (`Label:` then value) |
| Warning | stderr | `Warning:` blank line, then body |
| Error | stderr | `Error:` blank line, then body |
| Cancel | stdout | `Cancelled.` when you decline a prompt |
| Data (list/show/status) | stdout | Default human **table**; or **`--format json`** for automation |

#### `--format table|json` (CLI-014)

Most list / show / status commands accept:

```bash
talos endpoint list --format json
talos endpoint show <uuid> --format json
talos project status --format json
talos finding list --format json | jq .
talos role list --format json
talos scheduler status --format json
talos scheduler jobs list --status failed --format json
```

| Format | Behavior |
|--------|----------|
| `table` (default) | Human-readable tables and labeled blocks (backward compatible) |
| `json` | One JSON document on stdout (`indent=2`). Empty lists → `[]`. |

Errors and warnings stay on stderr in the shapes below. Exit codes are unchanged.

Examples:

```text
Error:

Endpoint not found.

Warning:

No endpoints matched.

Enqueued.

Job:
7f42-...

Cancelled.
```

Scripts can match failures on the leading `Error:` line. Prefer
`--format json` over scraping tables.

### Confirmation policy (CLI-015)

Destructive operations use one shared rule (`confirm_or_exit` + `--force`):

| Context | Behavior |
|---------|----------|
| Interactive terminal | Prompt `[y/N]`; decline → `Cancelled.` and exit **130** |
| Non-interactive (CI, pipes) | Require `--force`; otherwise exit **2** with `Operation requires --force in non-interactive mode.` |
| `--force` | Skip prompt always |

`--force` is **only** for confirmation bypass. Re-running Input Validation
analysis uses `--ignore-cache` on `run` and phase shortcuts (CLI-019).

Covered: `project delete` / `project delete --purge` (purge also needs a
second interactive confirmation unless `--force`), `role|module delete`,
`config http delete`, `access delete`, `auth clear`,
`auth-config clear-expiry-signals`, `scheduler clear` / overflow enqueue /
`scheduler prune`, `input-validation clear-cache`,
`finding confirm|reject|reopen --linked`, `finding group remove`.

```bash
# CI / scripts — always pass --force for destructive ops
talos config http delete "$RULE_ID" --force
talos project delete qa-smoke --force
# Full wipe (registry + disk):
talos project delete qa-smoke --purge --force
```

### Exit codes (CLI-012)

| Code | Meaning |
|------|---------|
| **0** | Success (including intentional no-ops such as “already complete”) |
| **1** | General failure (not found, operation failed) |
| **2** | Invalid arguments / unknown command / missing `--force` (non-interactive) |
| **3** | Preconditions failed (no project bound, auth not ready, policy block) |
| **130** | User cancelled a confirmation prompt |

Examples: resource not found → `1`; unknown `--project` id → `1`; no project bound → `3`; declined delete → `130`; CI delete without `--force` → `2`.

```bash
talos endpoint show "$UUID"
if [ $? -eq 0 ]; then
  echo "endpoint exists"
fi
```

---

## Project context (CLI-013)

Most subsystem commands need a bound project. Prefer explicit context in
scripts and CI so concurrent jobs never fight over registry ACTIVE.

| Mechanism | Example | Mutates registry? |
|-----------|---------|-------------------|
| Interactive open | `talos project open qa-smoke` | Yes — sets ACTIVE |
| Root flag | `talos --project qa-smoke endpoint list` | No |
| Environment | `TALOS_PROJECT=qa-smoke talos endpoint list` | No |

Resolution order: `--project` → `TALOS_PROJECT` → registry `ACTIVE`.

```bash
# Automation-safe (parallel scripts)
talos --project pentest endpoint list
talos --project=pentest finding list
TALOS_PROJECT=pentest talos access coverage

# Interactive session (unchanged)
talos project open pentest
talos endpoint list
talos project status    # shows ACTIVE or process override
```

Unknown `--project` / `TALOS_PROJECT` id → exit **1**. No project bound at
all → exit **3**.

---

## Command Tree

```text
talos [--project ID] [-h|--help]
├─ project
│  ├─ create
│  ├─ open
│  ├─ close
│  ├─ delete [--purge] [--force]
│  ├─ rename
│  ├─ description
│  ├─ list
│  ├─ scope                  # Basic Scope (URL-prefix allow list)
│  │  ├─ add <prefix>
│  │  ├─ remove <prefix>
│  │  ├─ list [--format]
│  │  ├─ clear [--force]
│  │  └─ import <file> [--replace]
│  │  # legacy: scope <id> [PREFIX…]  (display or replace entire list)
│  ├─ constraints
│  ├─ status
│  └─ outscope               # same Basic Scope model; overrides in-scope
│     ├─ add <prefix>
│     ├─ remove <prefix>
│     ├─ list [--format]
│     ├─ clear [--force]
│     └─ import <file> [--replace]
│
├─ config                    # layered config (CLI-022)
│  ├─ show                   # paths + layer summary [--format]
│  ├─ effective              # merged values + sources [--section] [--format]
│  ├─ get <key>              # value + inheritance source
│  ├─ set <key> <value>      # project override; --global for ~/.talos/config.yaml
│  ├─ unset <key>            # remove override → inherit
│  ├─ edit                   # $EDITOR on project.yaml or --global
│  └─ proxy|capture|scheduler|attack|mutation
│     └─ show|set|unset|edit
│
├─ proxy
│  ├─ start                  # [--upstream URL | --no-upstream] one-shot
│  └─ config                 # show | --upstream URL | --no-upstream (persist)
│
├─ role
│  ├─ create
│  ├─ add                    # alias for create
│  ├─ list                   # UUID, Name, Active
│  ├─ show                   # name or UUID
│  ├─ set
│  └─ unset
│
├─ module
│  ├─ create
│  ├─ add                    # alias for create
│  ├─ list                   # UUID, Name, Active
│  ├─ show                   # name or UUID
│  ├─ set
│  └─ unset
│
├─ access
│  ├─ client set|unset
│  ├─ server set|unset
│  ├─ delete [--force]
│  ├─ show
│  ├─ coverage
│  └─ signals
│
├─ auth
│  ├─ set
│  ├─ unset
│  ├─ show
│  ├─ clear [--force]
│  └─ test
│
├─ auth-config               # <role> = role name or UUID
│  ├─ set-provider
│  ├─ show-provider
│  ├─ set-session            # [path] | apply
│  ├─ clear-session          # recovery: clear manual session config
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
│  ├─ set-ttl                # Session Health Layer 1
│  ├─ add-expiry-signal      # Session Health Layer 2
│  ├─ clear-expiry-signals [--force]
│  ├─ reset-health           # recovery: reset Layer 2 suspicion counter
│  ├─ add-control-flow       # Session Health Layer 3 (validation flows)
│  ├─ remove-control-flow
│  └─ list-control-flows
│
├─ endpoint
│  ├─ list                   # UUID, Method, Host, Path, Priority, Qualified, Excluded
│  │                         # --format table|json (resolved policy JSON for UI)
│  ├─ mark <id> [<id> ...]   # --logout | --dangerous | --safe (atomic bulk)
│  ├─ unmark <id> [<id> ...]
│  ├─ show <id>              # --format table|json
│  ├─ policy <id>            # effective-policy explanation (--format table|json)
│  ├─ export [<id>] [--endpoints <id>...]
│  ├─ notes set|clear <endpoint_id>   # set reads notes from stdin
│  ├─ tags add|remove|set|clear <id> [<id> ...] [--tag T...]
│  ├─ priority set|clear endpoint|path   # endpoint accepts multi-ID
│  ├─ exclude|include endpoint|path      # endpoint accepts multi-ID
│  ├─ rule add|update|delete|list|show|preview  # canonical path-rule resource
│  └─ rules                  # alias for rule list (no nested "list")
│
├─ replay
│  ├─ flow
│  └─ endpoint
│
├─ flow
│  ├─ list                   # UUID, Endpoint, Method, Status, Role, Source, Created
│  ├─ show
│  └─ export
│
├─ scheduler
│  ├─ status
│  ├─ config
│  ├─ enqueue flow|endpoint
│  ├─ jobs list|show         # inventory / inspect one job
│  ├─ cancel <id>            # pending or paused → cancelled
│  ├─ prune --status …       # delete terminal history [--force]
│  ├─ clear [--force]        # pending jobs only
│  ├─ pause
│  └─ resume
│
├─ mutation
│  ├─ add
│  ├─ list
│  ├─ edit
│  ├─ enable
│  ├─ disable
│  └─ delete [--force]
│
├─ attack
│  ├─ unauth
│  │  ├─ run [--technique NAME]
│  │  ├─ config [show] [--auto-run on|off]
│  │  └─ filter init|show|validate
│  └─ bac                    # --role / --module = name or UUID
│     ├─ session-swap
│     ├─ method-fuzz
│     ├─ content-type
│     ├─ url-fuzz
│     ├─ header-inject
│     ├─ host-fuzz
│     ├─ role-inject
│     ├─ parser-confuse
│     └─ filter init|show|validate
│
├─ input-validation
│  ├─ run [--budget TIER] [--host H | --endpoint ID | --parameter NAME]
│  │      [--ignore-cache] [--include-auth-artifacts]
│  ├─ config [--probe-strategy|--budget TIER] [--max-requests-per-param N] …
│  ├─ status [--format json]   # budget, requests_used, confidence, plan
│  ├─ resume
│  ├─ synthesize [--host|--param-uuid] [--dry-run]
│  ├─ candidates [--attack] [--min-score] [--host] [--capability]
│  ├─ clear-cache [--force]   # --force = confirm bypass only
│  ├─ exclude|include endpoint|host
│  ├─ show <parameter_uuid> | --endpoint ID | --host H
│  ├─ export parameter|host [--format markdown|json]
│  ├─ export csv
│  └─ baseline|multiprobe|identifier|…|validation
│     [--host|--endpoint|--parameter] [--ignore-cache]
│
└─ finding
   ├─ list [--status STATUS] [--linked | --all]
   ├─ show <uuid>
   ├─ confirm|reject|reopen <uuid> [--linked] [--force]
   ├─ duplicate <uuid> --of <uuid>
   ├─ note set|clear <uuid>   # set reads notes from stdin
   ├─ group create|add|remove|list
   └─ report <uuid> | --group <group>
```

**Finding relationships:** Related successful techniques form a PRIMARY + LINKED cluster. Default list shows PRIMARY rows with a linked count. Status changes are independent unless you pass `--linked` on a PRIMARY.

---

## Recommended Attack Workflow

```bash
# 1. Project setup
talos project create target-app --description "Bug bounty target"
talos project open target-app
# Or for scripts/CI without open: prefix commands with --project target-app
talos project scope add example.com
talos project scope add api.target.com

# 2. Create roles and modules (UUID shown on create and in role/module list/show)
talos role create admin
# → Role created: admin  (id: <admin_role_uuid>)
talos role create user
# → Role created: user  (id: <user_role_uuid>)
talos module create dashboard
# → Module created: dashboard  (id: <dashboard_module_uuid>)
talos module create admin-panel

# 3. Define access expectations (names, not UUIDs)
talos access client set admin dashboard allow
talos access client set user  dashboard allow
talos access client set admin admin-panel allow
talos access client set user  admin-panel deny
talos access server set admin dashboard allow
talos access server set user  dashboard allow
talos access server set admin admin-panel allow
talos access server set user  admin-panel deny

# 4. Auth artifact names (what to strip / inject)
talos auth set --cookie sessionid --header Authorization

# 5. Capture traffic with role context
talos role set admin && talos module set dashboard
talos proxy start --port 8080
# ... browse as admin, then ...
talos role set user && talos module set dashboard
# ... browse as user ...

# 6a. Auth config — AUTO provider (role name or UUID)
# Discover login / health-check flow UUIDs after capture:
talos flow list --source proxy_capture --role user
talos auth-config set-provider user auto
talos auth-config add-flow user <login_flow_uuid>
talos auth-config set-extractor user <login_flow_uuid> extractor.py
talos auth-config add-control-flow user <health_check_flow_uuid>
talos auth-config refresh user

# 6b. Auth config — MANUAL provider
talos auth-config set-provider user manual
talos auth-config add-control-flow user <health_check_flow_uuid>
talos auth-config set-session user path
# → edit the printed session file, then:
talos auth-config set-session user

# 7. Run BAC tests
talos attack bac session-swap --role user
talos scheduler status
talos scheduler jobs list --status failed   # inspect failures without clearing

# 8. Review and triage findings
talos finding list
talos finding list --status TRIAGING
talos finding list --linked
talos finding list --all
talos finding show <finding_uuid>
echo "Confirmed with customer." | talos finding note set <finding_uuid>
talos finding confirm <finding_uuid>
talos finding reject <finding_uuid>
talos finding reject <primary_uuid> --linked
talos finding report <finding_uuid> > vuln-report.md
talos finding group create "Client Report"
talos finding group add "Client Report" <finding_uuid>
talos finding report --group "Client Report" > client-report.md

# 9. Unauthenticated Execution
talos attack unauth run
talos attack unauth run --technique baseline
talos attack unauth filter init

# 10. Input Validation (auth pre-check runs before scheduling)
talos input-validation config --enable --workers 2
talos input-validation run
talos input-validation status

# 11. Access analysis
talos access coverage
talos access signals
```

### Authentication lifecycle (MANUAL provider)

```
set-session <role>          # name or UUID
    │
    ├─ save manual_session_config (cookies, headers, expiry)
    ├─ apply artifacts to role_auth_state
    ├─ replay Layer 3 validation flow with current auth injected
    │     ├─ response status == baseline status → PASS
    │     └─ mismatch → FAIL → role_auth_state cleared
    │
    └─ scheduler jobs read role_auth_state on each execution
```

**Validation is mandatory** for roles used by BAC / session-gated paths:

1. Auth artifact names configured (`talos auth set`)
2. Session values present and not expired
3. At least one validation flow (`add-control-flow`)
4. Validation passes (flow replayed with current auth; status matches baseline)

**Session Health layers (authoritative):**

| Layer | Mechanism | CLI |
|-------|-----------|-----|
| **1** | TTL / proactive refresh | `set-ttl` |
| **2** | Expiry signals on responses | `add-expiry-signal`, `clear-expiry-signals`, `reset-health` |
| **3** | Validation control flows | `add-control-flow`, `remove-control-flow`, `list-control-flows` |

There is **no** URL-based validation CLI. Layer 3 uses captured flows only.

---

## Project Commands

### `talos project create <name> [-d TEXT] [-s HOST ...]`

```bash
talos project create qa-smoke --description "QA smoke run" --scope example.com api.example.com
```

### `talos project open <id>` / `close` / `list` / `status`

Interactive activation rewrites registry ACTIVE. For automation prefer
`talos --project <id> …` or `TALOS_PROJECT=<id>` (see Project context above).

```bash
talos project open qa-smoke
talos project status
talos --project qa-smoke project status   # effective bind; registry unchanged
TALOS_PROJECT=qa-smoke talos project status
talos project list
talos project close
```

### `talos project delete <id> [--purge] [--force]`

Without `--purge`: removes the project from the registry only. **Data on disk
is preserved** under the project directory.

With `--purge`: also permanently deletes the project directory (database,
archive, reports, auth sessions, filters). Irreversible. Interactive mode
requires a second confirmation unless `--force` is set.

```bash
# Unregister only (data kept)
talos project delete qa-smoke --force

# Full wipe (registry + disk)
talos project delete qa-smoke --purge --force
```

### `talos project rename <id> <new_name>`

Updates the display name. When the derived slug changes, re-keys the registry
and moves the project data directory. Status, scope, description, and
constraints are preserved. Fails if the new slug is already registered.

```bash
talos project rename old-client "Acme Q3 Assessment"
# → id becomes acme-q3-assessment; directory moved
talos project open acme-q3-assessment
```

### `talos project description <id> [TEXT…]`

Show the current description, or set a new one.

```bash
talos project description acme-q3-assessment
talos project description acme-q3-assessment "Production July Assessment"
```

### Basic Scope (URL-prefix allow list)

**Canonical resource API** (requires bound project: `open` / `--project` / `TALOS_PROJECT`):

```bash
talos project scope add example.com
talos project scope add example.com/api/
talos project scope add http://example.com:8000
talos project scope add https://example.com:8443/admin/
talos project scope remove example.com:8000
talos project scope list
talos project scope list --format json
talos project scope clear --force
talos project scope import ./scope.txt
talos project scope import ./scope.txt --replace
```

**Semantics (one complete prefix per entry — never comma-split):**

| Prefix | Matches |
|--------|---------|
| `example.com` | That host, HTTP **and** HTTPS, **any** port, any path |
| `http://example.com` | HTTP only, any port |
| `https://example.com` | HTTPS only, any port |
| `example.com:8000` | Port 8000 only (both schemes) |
| `http://example.com:8000` | HTTP port 8000 only |
| `example.com/api/` | Path prefix `/api/` on that host |
| `10.10.10.25` / `http://10.10.10.25:8000` | IP targets with the same rules |

- Subdomains are **not** implied (`example.com` does not match `api.example.com`).
- Wildcards (`*.example.com`) are **rejected** with an actionable error.
- Default ports canonicalize for identity (`http://h` ≡ `http://h:80`) but a **host-only** rule still matches any port.
- Query strings are not part of Basic Scope identity.

**Import file format (UTF-8):** one prefix per line; blank lines ignored; `#` comments; commas are not separators; invalid lines reject the **entire** import (atomic).

**Legacy compatibility** (still routed through the same validator):

```bash
talos project scope qa-smoke              # list
talos project scope qa-smoke example.com api.example.com   # replace entire list
```

### `talos project constraints <id> [--store-bodies BOOL] [--max-body-size BYTES]`

Defaults (when unset): `store_bodies=true`, `max_body_size=1048576` (1 MiB).

```bash
talos project constraints qa-smoke --store-bodies true --max-body-size 1048576
```

### Out-of-scope (bound project — same Basic Scope prefixes)

Out-of-scope **overrides** in-scope. Same parser/matcher as scope.

```bash
talos project outscope add analytics.example.com
talos project outscope add example.com/logout
talos project outscope add example.com:9000
talos project outscope list
talos project outscope remove analytics.example.com
talos project outscope clear --force
talos project outscope import ./outscope.txt
# legacy still accepted: outscope add domain <prefix>
```

---

## Config (layered — CLI-022)

Precedence (lowest → highest):

```text
Built-in defaults → global (~/.talos/config.yaml) → project (project.yaml + legacy) → CLI
```

Global file: `$TALOS_DATA_DIR/config.yaml` (default `~/.talos/config.yaml`).  
Project overrides: `<project_data_dir>/project.yaml` (created empty on `project create`).

```bash
# Paths and layer summary
talos config show
talos config show --format json

# Full merged view (every value shows its source)
talos config effective
talos config effective --section scheduler
talos config effective --format json

# Get / set / unset
talos config get proxy.upstream.url
talos config set proxy.upstream.url http://127.0.0.1:8081
talos config set scheduler.min_delay 3
talos config set scheduler.max_delay 8
talos config set attack.unauth_auto_run true
talos config set capture.store_bodies false
talos config unset scheduler.max_delay          # inherit global/default
talos config set scheduler.min_delay 2 --global # write global defaults
talos config edit
talos config edit --global

# Machine-readable schema (types, defaults, sections) for UIs / automation
talos config schema
talos config schema --format json

# Section resources (relative keys under that section)
talos config proxy
talos config proxy set upstream.url http://127.0.0.1:8081
talos config scheduler set max_delay 15
talos config attack set unauth_auto_run on
talos config capture show
talos config http list
```

| Section | Useful keys |
|---------|-------------|
| `proxy` | `upstream.enabled`, `upstream.url` |
| `capture` | `store_bodies`, `max_body_size`, `drop_headers` |
| `scheduler` | `min_delay`, `max_delay`, `max_queue_size` |
| `attack` | `unauth_auto_run` |
| `http` | `enabled`, `rules` (manage via `talos config http`, not raw set) |

### HTTP Manipulation Engine

Single rule engine for **request and response** modifications. Rules live in
layered config (global `config.yaml` and/or project `project.yaml`). Effective
rules = **concatenation** of all layers, sorted by priority (lower first).
Default: engine **on**, **zero rules** (traffic unmodified).

```bash
# List effective rules
talos config http list
talos config http list --format json
talos config http list --direction request --enabled-only

# Create (project layer by default; --global for global config)
talos config http create --name "Research header" \
  --action 'header.replace:X-HackerOne-Research=himanshu_2077'
talos config http create --name "Strip validators" --direction request \
  --action 'header.remove:If-None-Match' \
  --action 'header.remove:If-Modified-Since'
talos config http create --name "API only" \
  --match-host api.example.com --match-path '/v1/*' \
  --action 'header.replace:User-Agent=Talos'
talos config http create --name "Drop CSP" --direction response \
  --action 'header.remove:Content-Security-Policy' \
  --action 'header.remove:X-Frame-Options'

# Update (replace name / match / actions in one shot)
talos config http update <id> --name "New name" --priority 25 \
  --match-host api.example.com --match-path '/v1/*' \
  --action 'header.replace:X-Research=talos'
talos config http update <id> --clear-match --clear-actions

# Scope, actions, lifecycle
talos config http set-match <id> --host api.example.com --path '/admin/*'
talos config http clear-match <id>
talos config http add-action <id> 'header.replace:X-Debug=1'
talos config http remove-action <id> 0
talos config http set-priority <id> 50
talos config http enable <id>
talos config http disable <id>
talos config http reorder
talos config http delete <id> --force

# Master switch / export
talos config http disable-engine
talos config http enable-engine
talos config http export -o rules.yaml
talos config http import rules.yaml
talos config http actions          # opcode reference
```

Supported actions include header add/remove/replace/rename, cookie and query
ops, method/URL rewrite, body regex/append/prepend, response status override,
delay, drop, abort. Match conditions: host, path, method, status, headers,
endpoint_id, role/module, and module context flags.

Compatibility: `talos proxy config`, `talos scheduler config`, and
`talos attack unauth config` still work and dual-write project.yaml + SQLite.

---

## Proxy

Modes:

- **Direct** (default) — no upstream; mitmdump and outbound engines (replay / BAC / unauth) connect to the target
- **Upstream Proxy** — forward through Burp / ZAP / a corporate proxy

Upstream host, port, URL, and credentials are **never hardcoded**. They come from layered config (`talos config set proxy.upstream.url` / `talos proxy config`) or one-shot CLI overrides on `start`. Replay and attack engines use the same setting via `get_upstream_url` (layered). Config changes apply on the next `talos proxy start` (or immediately for one-shot flags).

```bash
# Start (reads layered project config; default Direct)
talos proxy start --listen-host 127.0.0.1 --port 8080
talos proxy start --port 8080 --quiet

# One-shot overrides for this start only (do not write project config)
talos proxy start --upstream http://127.0.0.1:8081
talos proxy start --no-upstream

# Persist project mode (also writes project.yaml)
talos proxy config
talos proxy config --upstream http://127.0.0.1:8081
talos proxy config --no-upstream

# Preferred layered form
talos config set proxy.upstream.url http://127.0.0.1:8081
talos config proxy show
```

---

## Role / Module

```bash
talos role create admin
# → Role created: admin  (id: <uuid>)
talos role list
# UUID                                  Name     Active
# ------------------------------------  -------  ------
# <uuid>                                admin    *
# <uuid>                                global
talos role show admin            # name or UUID; status, modules, auth, flows
talos role set admin
talos role unset
talos role rename admin administrator   # UUID unchanged; fix typos
talos role delete adminn         # confirms; shows refs (access map, flows, auth…)
talos role delete adminn --force # skip prompt
# Flows tagged with the deleted role reassign to global; access/auth/BAC config cascades.
# Built-in role `global` cannot be renamed or deleted.

talos module create orders --description "Order history"
# → Module created: orders  (id: <uuid>)
talos module list
# UUID                                  Name     Active
# ------------------------------------  -------  ------
# <uuid>                                orders   *
# <uuid>                                global
talos module show orders         # name or UUID; status, description, roles
talos module set orders
talos module unset
talos module rename orders order-history   # UUID unchanged
talos module delete old-module --force
# Same cascade rules as roles; built-in module `global` is protected.
```

`add` is an alias for `create` on both role and module.

Auth-config, BAC `--role` / `--module`, and other consumers accept a **name or
UUID**. Prefer the name; use `talos role list` / `talos module list` when you
need the UUID.

---

## Access

Values: `allow` | `deny` | `unknown`.

```bash
talos access client set admin orders allow
talos access server set admin orders allow
talos access client unset admin orders
talos access server unset admin orders
talos access delete admin orders --force
talos access show
talos access coverage
talos access signals
```

---

## Auth (artifact names)

Stores **names** of cookies/headers, not credential values.

```bash
talos auth set --cookie sessionid --header Authorization
talos auth set --cookie sessionid --cookie csrf --header Authorization --header X-API-Key
talos auth unset --cookie sessionid
talos auth show
talos auth clear --force
talos auth test <endpoint_id>
talos auth test <endpoint_id> --right-now
```

Default path enqueues a scheduler job; `--right-now` runs immediately.

---

## Auth-Config

All `<role>` arguments accept a **role name or UUID** (name preferred).
Discover UUIDs with `talos role list` / `talos role show <role>`.

### Provider

```bash
talos auth-config set-provider admin auto
talos auth-config set-provider admin manual
talos auth-config show-provider admin
```

### Manual session

Session file: `<project_data_dir>/auth_sessions/<role_uuid>.txt` (edit with any editor; Talos does not launch an editor for this file).

```bash
talos auth-config set-provider admin manual
talos auth set --header Authorization
talos auth-config add-control-flow admin <health_check_flow_uuid>
talos auth-config set-session admin path
# edit file, then:
talos auth-config set-session admin
talos auth-config status admin
```

### Session recovery

When a role is stuck in `WAITING_FOR_USER` or Layer 2 health confidence is
permanently degraded, recover through the CLI (no SQLite edits):

```bash
# Clear a bad / stuck manual session, then re-apply after editing the file
talos auth-config clear-session admin
# → Session cleared.
talos auth-config set-session admin path
# edit file, then:
talos auth-config set-session admin

# Reset Layer 2 suspicion counter after false expiry-signal storms
talos auth-config reset-health admin
# → Health suspicion reset.
talos auth-config status admin
```

### Auto provider

```bash
talos auth set --cookie sessionid --header Authorization
talos auth-config add-flow admin <flow_uuid>
talos auth-config set-extractor admin <flow_uuid> login_extractor.py
talos auth-config add-control-flow admin <health_check_flow_uuid>
talos auth-config refresh admin
talos auth-config status admin
```

Extractor shape:

```python
def extract(response):
    # response.status, response.headers, response.body, response.cookies
    return {
        "sessionid": response.cookies.get("sessionid", ""),
        "Authorization": "Bearer …",
    }
```

### Flows / extractors / runtime

```bash
talos auth-config add-flow admin <flow_id>
talos auth-config remove-flow admin <flow_id>
talos auth-config list-flows admin

talos auth-config set-extractor admin <flow_id> extractor.py
talos auth-config show-extractor admin <flow_id>
talos auth-config edit-extractor admin <flow_id>
talos auth-config remove-extractor admin <flow_id>

talos auth-config test admin <flow_id>                 # flow+extractor; no state stored
talos auth-config test admin <flow_id> --format json   # full extracted token values as JSON
talos auth-config validate admin
talos auth-config refresh admin
talos auth-config status admin
talos auth-config show admin
```

### Session Health

```bash
# Layer 1 — TTL
talos auth-config set-ttl admin --ttl 1200 --refresh-before 120

# Layer 2 — Expiry signals
talos auth-config add-expiry-signal admin --body "session expired" --body "please login"
talos auth-config add-expiry-signal admin --status 419 --status 440
talos auth-config add-expiry-signal admin --header location /login
talos auth-config clear-expiry-signals admin

# Layer 2 recovery — reset suspicion counter (no SQLite edits)
talos auth-config reset-health admin

# Layer 3 — Validation flows
talos auth-config add-control-flow admin <flow_id>
talos auth-config remove-control-flow admin <flow_id>
talos auth-config list-control-flows admin
```

---

## Endpoint

```bash
# Inventory / discovery (primary way to obtain endpoint UUIDs)
talos endpoint list
talos endpoint list --format json          # resolved policy for Control Panel / scripts
talos endpoint list --qualified
talos endpoint list --excluded
talos endpoint list --host api.example.com
talos endpoint list --method GET
talos endpoint list --priority HIGH
talos endpoint list --role admin
talos endpoint list --search /api/orders
talos endpoint list --qualified --host api.example.com --method POST

# Bulk-capable mutations (validate all IDs first; one transaction; no partial write)
talos endpoint mark <id> [<id> ...] --logout
talos endpoint mark <id> [<id> ...] --dangerous
talos endpoint mark <id> [<id> ...] --safe
talos endpoint unmark <id> [<id> ...] --logout
talos endpoint unmark <id> [<id> ...] --dangerous
talos endpoint show <endpoint_id>
talos endpoint show <endpoint_id> --format json
talos endpoint policy <endpoint_id>              # why effective priority/exclusion exists
talos endpoint policy <endpoint_id> --format json
talos endpoint export <endpoint_id>
talos endpoint export --endpoints <id> <id> <id>

# Analyst notes (stdin) and arbitrary tags (distinct from logout/dangerous mark)
echo "Authentication bypass observed." | talos endpoint notes set <endpoint_id>
talos endpoint notes clear <endpoint_id>
talos endpoint tags add <endpoint_id> admin critical          # legacy single-ID form
talos endpoint tags add <id1> <id2> --tag admin --tag triage  # bulk form
talos endpoint tags remove <id> [<id> ...] --tag admin
talos endpoint tags set <endpoint_id> triage q2
talos endpoint tags clear <id> [<id> ...]

talos endpoint priority set endpoint <id> [<id> ...] CRITICAL
talos endpoint priority set path "/api/admin/*" HIGH
talos endpoint priority clear endpoint <id> [<id> ...]
talos endpoint priority clear path "/api/admin/*"

talos endpoint exclude endpoint <id> [<id> ...]
talos endpoint exclude path "/static/*"
talos endpoint include endpoint <id> [<id> ...]
talos endpoint include path "/static/*"

# Canonical path-rule resource (preferred for Control Panel Add/Edit/Delete Rule)
talos endpoint rule add "/api/admin/*" --priority HIGH
talos endpoint rule add "/static/*" --exclude
talos endpoint rule add "/api/payroll/*" --priority CRITICAL --exclude
talos endpoint rule update <rule_id> --priority NORMAL
talos endpoint rule update <rule_id> --exclude
talos endpoint rule update <rule_id> --include
talos endpoint rule update <rule_id> --clear-priority
talos endpoint rule delete <rule_id>
talos endpoint rule list
talos endpoint rule list --format json
talos endpoint rule show <rule_id>
talos endpoint rule show <rule_id> --format json
talos endpoint rule preview "/api/admin/*"
talos endpoint rule preview "/api/admin/*" --priority HIGH
talos endpoint rule preview "/api/admin/*" --exclude --format json

# Compat alias (same as rule list)
talos endpoint rules
talos endpoint rules --format json
```

**Default columns:** UUID, Method, Host, Path, Priority (effective), Qualified, Excluded.

**JSON list** (`--format json`) returns resolved state:

```json
{
  "endpoints": [
    {
      "id": "...",
      "method": "POST",
      "origin": "https://api.example.com:8443",
      "host": "api.example.com",
      "path": "/api/users/{id}",
      "priority": { "effective": "HIGH", "source": "rule" },
      "qualified": true,
      "qualification_reason": "flow_2xx",
      "excluded": false,
      "exclusion_source": null,
      "dangerous": false,
      "logout": false,
      "roles_seen": ["admin"],
      "parameter_count": 4,
      "baseline_flow_id": "...",
      "baseline_status": 200,
      "tags": ["users", "bac"],
      "last_seen": "..."
    }
  ],
  "count": 1
}
```

`origin` is the canonical origin stored in `endpoints.host` (scheme + authority;
non-default ports preserved). Bulk mutations report `affected` / `unchanged`
counts and support `--format json`.

**Filters** (AND when combined):

| Flag | Effect |
|------|--------|
| `--method METHOD` | Case-insensitive HTTP method |
| `--host HOST` | Case-insensitive exact host or origin |
| `--qualified` | Only endpoints with a 2xx proxy_capture baseline |
| `--excluded` | Only endpoints excluded by flag or path rule |
| `--search TEXT` | Substring match on host or path |
| `--role NAME\|UUID` | Observed under this role (`roles_seen`) |
| `--priority LEVEL` | Effective priority: CRITICAL \| HIGH \| NORMAL \| LOW |

Copy a UUID from `list`, then use `show`, `export`, `replay endpoint`, `auth test`, or attack commands.

---

## Replay

```bash
talos replay flow <flow_id>
talos replay flow <flow_id> --right-now
talos replay endpoint <endpoint_id>
talos replay endpoint <endpoint_id> --right-now
```

Best qualifying flow selection uses recent `proxy_capture` flows in the **2xx** range (see architecture for details).

---

## Flow

```bash
# Inventory / discovery (primary way to obtain flow UUIDs)
talos flow list
talos flow list --source proxy_capture
talos flow list --status-code 200
talos flow list --role admin
talos flow list --endpoint <endpoint_id>
talos flow list --limit 20
talos flow list --source proxy_capture --status-code 200 --limit 10

talos flow show <flow_id>
talos flow export <flow_id>
talos flow export --module input_validation
talos flow export --module bac
talos flow export --parameter <parameter_uuid>
talos flow export --endpoint <endpoint_id>
talos flow export --flows <flow_id> <flow_id>
```

**Default columns:** UUID, Endpoint (`host`+`path`), Method, Status, Role, Source, Created.

**Filters** (AND when combined):

| Flag | Effect |
|------|--------|
| `--endpoint ENDPOINT_ID` | Exact endpoint UUID |
| `--status-code CODE` | Exact HTTP status |
| `--role NAME\|UUID` | Capture-time role |
| `--source SOURCE` | `proxy_capture` \| `manual_replay` \| `auto_replay` \| `iv_scan` |
| `--limit N` | At most N rows (most recent first) |

Copy a UUID from `list`, then use `show`, `export`, `replay flow`, or `auth-config add-flow`.

`--module` on export matches `flow_meta.generated_by` (for example `input_validation`, `bac`).

---

## Scheduler

```bash
talos scheduler status
talos scheduler config
talos scheduler config --min-delay 3.0 --max-delay 8.0 --max-queue-size 100
# Layered equivalent (preferred for globals / inheritance):
talos config set scheduler.min_delay 3
talos config set scheduler.max_delay 8
talos config scheduler show
talos scheduler enqueue flow <flow_id>
talos scheduler enqueue endpoint <endpoint_id>
talos scheduler enqueue endpoint <endpoint_id> --type auth-test

# Job inventory (CLI-016)
talos scheduler jobs list
talos scheduler jobs list --status failed
talos scheduler jobs list --type replay          # family: replay_flow + replay_endpoint
talos scheduler jobs list --type bac --limit 50
talos scheduler jobs list --status pending --format json
talos scheduler jobs show <job_id>               # full UUID or unique prefix
talos scheduler jobs show <job_id> --format json

# Single-job cancel (pending/paused only → cancelled)
talos scheduler cancel <job_id>

# History cleanup (terminal statuses only)
talos scheduler prune --status failed
talos scheduler prune --status done --force
talos scheduler prune --status skipped
talos scheduler prune --status cancelled --force

talos scheduler clear                 # pending only; confirmation prompt
talos scheduler clear --force
talos scheduler pause
talos scheduler resume
```

`jobs list` default limit is **50** (max 1000). `--type` accepts an exact job type
(`bac_session_swap`, `unauth_attack`, …) or a family prefix without underscore
(`replay`, `bac`, `iv`). Prefer `jobs list` / `cancel` / `prune` over `clear`
when debugging large queues.

`resume` validates MANUAL sessions only for roles referenced by pending/paused **BAC** jobs. Unauthenticated Execution, replay, Authentication Bypass tests, and Input Validation jobs do not block resume for missing role sessions.

The scheduler daemon starts with the proxy; there is no separate `scheduler start` command.

---

## HTTP Rules (HTTP Manipulation Engine)

See **Layered configuration → HTTP Manipulation Engine** above.
(`talos mutation` and `capture.header_rules` were removed; use `talos config http`.)

---

## Attack — Unauthenticated Execution

Generates `unauth_attack` scheduler jobs for every testable endpoint × recipe combination.

Pipeline for each job:

1. Remove all configured authentication
2. Apply unauth **technique**
3. Apply optional **request mutation** from the recipe
4. Replay and classify (`SECURE` | `BYPASS` | `UNKNOWN`)

Endpoint inclusion/exclusion is owned by **Endpoint Policy** (`talos endpoint exclude`). There is no `attack unauth exclude` command.

### CLI

```bash
talos attack unauth run
talos attack unauth run --technique baseline
talos attack unauth run --technique malformed_auth
talos attack unauth run --technique duplicate_malformed_header

talos attack unauth filter init
talos attack unauth filter show
talos attack unauth filter validate
```

Filter file: `<project_data_dir>/unauth-decision-filter.yaml`

### Techniques and recipes (from implementation)

**Core techniques** (no request mutation):

| technique |
|-----------|
| `baseline` |
| `empty_auth` |
| `malformed_auth` |
| `auth_null` |
| `auth_whitespace` |
| `duplicate_empty_header` |
| `duplicate_malformed_header` |

**Combined recipes** (`technique=baseline` + request mutation):

| request_mutation | request_type family |
|------------------|---------------------|
| `override_PUT` | bac_method_fuzz |
| `override_DELETE` | bac_method_fuzz |
| `x_original_url` | bac_header_inject |
| `x_rewrite_url` | bac_header_inject |
| `encoded_path` | bac_url_fuzz |
| `trailing_slash` | bac_url_fuzz |
| `dot_segment` | bac_url_fuzz |
| `x_forwarded_for_localhost` | bac_header_inject |
| `x_real_ip_localhost` | bac_header_inject |
| `x_forwarded_host` | bac_header_inject |

`--technique NAME` restricts to recipes whose technique field equals `NAME` (for example `--technique baseline` runs the baseline core recipe plus all baseline+mutation combinations).

Successful `BYPASS` verdicts create findings under attack module `unauth` (display label: **Unauthenticated Execution**).

**Auto-run** (scheduler auto-enqueues classic `auth_test` / Authentication Bypass
jobs for qualified endpoints that have no result yet). Distinct from
`talos attack unauth run`. Default is off.

```bash
talos attack unauth config show
# Auto Run : Disabled
talos attack unauth config --auto-run on
talos attack unauth config --auto-run off
```

---

## Attack — Broken Access Control (BAC)

**Auth prerequisites per attacker role** (provider-dependent):

- Auth artifact names: `talos auth set`
- AUTO: flows + extractors (`add-flow`, `set-extractor`) and successful refresh / `--auto-generate`
- MANUAL: session applied via `set-session` and validation flow configured
- Active auth state available for injection

**Candidate logic:**

- Target role: `server_expected = ALLOW` for a module
- Attacker role: `server_expected = DENY` or `UNKNOWN` for the same module
- Only **testable** endpoints (`qualified=1`, not excluded)
- Baseline flows: successful **2xx** `proxy_capture`

**Scopes** (mutually exclusive):

| Scope | Flag |
|-------|------|
| Project (default) | *(none)* |
| Module | `--module <name\|uuid>` |
| Endpoint | `--endpoint <uuid>` |

`--role NAME|UUID` filters attacker role within any scope.
`--module` accepts a module **name or UUID** (same rule as roles).

```bash
talos attack bac session-swap
talos attack bac session-swap --role customer
talos attack bac session-swap --role customer --auto-generate
talos attack bac session-swap --module payments
talos attack bac session-swap --module <module_uuid>
talos attack bac session-swap --endpoint <endpoint_uuid>

talos attack bac method-fuzz --role customer
talos attack bac content-type --role customer
talos attack bac url-fuzz --role customer
talos attack bac header-inject --role customer
talos attack bac host-fuzz --role customer
talos attack bac role-inject --role customer
talos attack bac parser-confuse --role customer

talos attack bac filter init
talos attack bac filter show
talos attack bac filter validate
```

Filter file: `<project_data_dir>/BAC-decision-filter.yaml`

**Verdicts:** `POSSIBLE_BAC` | `SECURE` | `UNKNOWN`  
`POSSIBLE_BAC` creates findings (display label: **Broken Access Control**).

Exclude endpoints from BAC (and other attacks):

```bash
talos endpoint exclude endpoint <uuid>
talos endpoint include endpoint <uuid>
```

---

## Input Validation

Disabled by default. Actively characterizes parameters; does not exploit.

Evidence foundations (Module 1), profile data model (Module 2), and offline
synthesis (Module 3) do not change the default probe matrix / request volume.
Module 3 builds versioned intelligence profiles from existing
`iv_probe_results` + flows (zero new HTTP). Profiles are written to
`iv_param_profiles` and shown under **Intelligence Profile** in `show` / export.

### Parameter identifier rules

| Command | `--parameter` / argument meaning |
|---------|----------------------------------|
| `run`, phase shortcuts, `resume`, `clear-cache` | **Parameter name** (string) |
| `show <param_uuid>` | **Parameter UUID** (parameters table row id) |
| `export parameter <uuid>` | **Parameter UUID** or param_uuid hash |
| `synthesize --param-uuid` | **Deterministic param_uuid** (`sha256(host\|location\|name)[:32]`) |

### Commands

```bash
talos input-validation config --enable
talos input-validation config --enable --workers 4
talos input-validation config --disable
talos input-validation config --analysis-off reflection
talos input-validation config --probe-strategy standard   # quick|standard|deep|exhaustive (planner budget)
talos input-validation config --max-requests-per-param 12  # optional hard HTTP cap (0 = tier default)
talos input-validation config --include-auth-artifacts     # Module 9: probe session cookies / Authorization
talos input-validation config --skip-auth-artifacts        # default: skip auth artifacts
talos input-validation config --analysis-on multiprobe
talos input-validation config

# Adaptive planner (Module 5): enqueues next wave only (baseline first), not full matrix
# Surfaces (Module 9): path, query, body (JSON/form/multipart/XML/GraphQL), header, cookie
# Operator path (Module 12): run --budget → show → candidates (no SQL required)
talos input-validation run --budget standard
talos input-validation run
talos input-validation run --host api.example.com
talos input-validation run --endpoint <endpoint_id>
talos input-validation run --parameter username
talos input-validation run --ignore-cache   # re-run (ignore cache); planner resumes waves
talos input-validation run --include-auth-artifacts  # one-shot: probe session/auth params

# Status: budget tier, requests_used, confidence buckets, pending plan actions
talos input-validation status
talos input-validation status --format json
talos input-validation resume

# Offline intelligence from existing probes (Module 3 — zero new HTTP)
talos input-validation synthesize
talos input-validation synthesize --host api.example.com
talos input-validation synthesize --param-uuid <param_uuid>
talos input-validation synthesize --dry-run
talos input-validation synthesize --format json

# Attack candidates (Module 11/12 — prioritization only, not confirmed vulns)
talos input-validation candidates
talos input-validation candidates --attack xss --min-score 60
talos input-validation candidates --host api.example.com --capability reflective_input
talos input-validation candidates --format json

talos input-validation clear-cache --force  # --force = skip confirm (CLI-015)
talos input-validation clear-cache --host api.example.com --force
talos input-validation clear-cache --endpoint <id> --force
talos input-validation clear-cache --parameter username --force

talos input-validation exclude endpoint <endpoint_id>
talos input-validation exclude host api.internal.example.com
talos input-validation include endpoint <endpoint_id>
talos input-validation include host api.internal.example.com

talos input-validation show <parameter_uuid>
talos input-validation show <parameter_uuid> --format json
# Module 10 multi-level intelligence summaries
talos input-validation show --endpoint <endpoint_id>
talos input-validation show --host api.example.com
talos input-validation show --endpoint <endpoint_id> --format json
# Export Markdown (default) or JSON (version fields + capabilities + candidates)
talos input-validation export parameter <parameter_uuid>
talos input-validation export parameter <parameter_uuid> --format json
talos input-validation export host api.example.com --format json
talos input-validation export csv
```

### Phase shortcuts

Each supports `--host`, `--endpoint`, `--parameter` (name), and
`--ignore-cache` to re-run a completed phase (CLI-019). `--force` is a
deprecated alias for `--ignore-cache` on these phase commands only; prefer
`--ignore-cache`. Elsewhere (`clear-cache`, deletes, etc.) `--force` means
skip confirmation.

```bash
talos input-validation baseline
talos input-validation multiprobe   # multi-signal canary + taxonomy (Module 4)
talos input-validation identifier
talos input-validation characters   # class representatives / drill-down (Module 6)
talos input-validation length       # binary/log length search (Module 6); not fixed-10 under standard
talos input-validation types          # type_confirm prune (M7); full matrix if exhaustive
talos input-validation transformations
talos input-validation reflection
talos input-validation validation     # core validation + semantic rules (M7); no SQLi/XSS under standard
# Parser/normalization (M8) is planner-driven via parser_probes (iv_parser jobs);
# not a separate phase CLI shortcut — run with probe_strategy standard|deep.
# Path/header/cookie/multipart/GraphQL/XML inject (M9) uses the same job types;
# auth artifacts skipped unless --include-auth-artifacts / config.

# Re-run a phase (ignore completed cache)
talos input-validation baseline --ignore-cache
talos input-validation reflection --endpoint <id> --ignore-cache
```

### IV surfaces and auth skip (Module 9)

| Surface | IV inject |
|---------|-----------|
| path | Yes — `{name}` segment from endpoint `normalized_path` |
| query | Yes |
| body JSON / form | Yes |
| body multipart field / filename | Yes |
| body GraphQL variables | Yes |
| body XML leaf | Yes |
| header | Yes (not hop-by-hop); header-safe payloads only |
| cookie | Yes (multi-cookie); cookie-safe payloads only |

Default **skip**: session-like cookies, `Authorization` / token headers, and
names from `talos auth set`. Reason stored on cache phase `surface` and profile
`skip_reason`.

**Transport skip** (not application failure): payloads illegal for the HTTP
client (NUL/CTL, leading/trailing SP on header values) → job/probe status
`skipped` with `transport_invalid_header` or `transport_invalid_cookie`.
Header/cookie multiprobe omits `null`/`control` classes; `norm:trim` uses an
internal space pad instead of outer spaces.

Limitations: no hidden-param discovery; no request smuggling.

### Multi-level learning (Module 10)

| Level | Key | CLI |
|-------|-----|-----|
| Parameter | `(host, location, name)` / param_uuid | `show <parameter_uuid>` |
| Endpoint | `endpoint_id` | `show --endpoint <id>` |
| Application | `host` | `show --host <host>` |

After synthesize (or live planner waves), parameter profiles roll up into
`iv_endpoint_profiles` and `iv_app_profiles`. New parameters inherit tested
negatives and parser expectations at confidence ≤75 until local confirm.
Under **standard**, host-level rejected control/null suppresses those probes;
**deep** re-confirms. Parameter `show` lists inheritance priors separately
from local observed evidence. `status` reports param / endpoint / app profile
counts.

---

## Endpoint Intelligence

Populated automatically by the FlowWorker during capture. No dedicated CLI.

Surfaces: path, query, body (JSON/form/multipart/XML/GraphQL), security headers, cookies. Semantic types and passive reflection are stored on the `parameters` table.

Inspect via `talos input-validation show <parameter_uuid>` or endpoint export.

### IV capabilities & attack candidates (Module 11)

After `synthesize` (or a completed planner run), parameter profiles store:

| Field | Meaning |
|-------|---------|
| `capabilities` | Behaviour flags (`reflective_input`, `html_context`, `url_like_value`, …) |
| `candidates` | Prioritization rows: `attack`, `score` 0–100, `confidence`, `reasons`, `evidence_flow_ids` |

```bash
talos input-validation show <parameter_uuid>           # human: candidates under Intelligence Profile
talos input-validation show <parameter_uuid> --format json   # capabilities + candidates keys
talos input-validation candidates --attack xss --min-score 60
talos input-validation export parameter <parameter_uuid>     # Markdown candidates table
talos input-validation export parameter <parameter_uuid> --format json  # schema_version visible
talos input-validation export host api.example.com --format json
```

**Important:** candidate scores are **not** confirmed vulnerabilities. They
only rank investigation order for future attack modules. Attack modules should
use `talos.input_validation.candidates.get_param_intelligence` rather than
parsing probe tables.

### Operator UX (Module 12) & migration

**Happy path**

```bash
talos input-validation config --enable
talos input-validation run --budget standard   # planner adaptive; ~10–18 req/param typical
# … wait for scheduler …
talos input-validation status                  # requests_used, confidence buckets, plan
talos input-validation show <parameter_uuid>   # profile + candidates (no SQL)
talos input-validation candidates --min-score 60
```

**Canaries (truth):** multiprobe uses high-entropy markers with prefix `TL` +
16 hex chars (not the legacy weak `__TL__` list). Identifier weak list runs
only under deep/exhaustive.

**Budget tiers:** `quick` ~5–8 · `standard` ~10–18 · `deep` ~25–40 ·
`exhaustive` ~70 (legacy full matrix escape hatch).

**Old IV cache / pre-revamp projects**

| Situation | What to do |
|-----------|------------|
| Probes exist, no profiles | `talos input-validation synthesize` (zero new HTTP) |
| Profiles missing candidates | `synthesize` again (or `candidates --recompute` for display) |
| Stale matrix after upgrade | `clear-cache --force` then `run --budget standard` |
| Fresh beta project | Preferred — open a new project after upgrades |

Schema tables (`iv_param_profiles`, `iv_endpoint_profiles`, `iv_app_profiles`)
are created on project open / migrate. No separate migration tool (beta).

Control Panel **Input Validation** page: status (budget/confidence), candidates
table, profiles list, parameter load with capabilities — same prioritization
disclaimer.

---

## Findings

Created automatically when attack modules produce trigger verdicts:

| Attack | Trigger verdict | Display label |
|--------|-----------------|---------------|
| BAC | `POSSIBLE_BAC` | Broken Access Control |
| Authentication Bypass (`talos auth test`) | `BYPASS` | Authentication Bypass |
| Unauthenticated Execution (`talos attack unauth`) | `BYPASS` | Unauthenticated Execution |

### Lifecycle

```
TRIAGING → CONFIRMED | REJECTED | DUPLICATE
CONFIRMED | REJECTED | DUPLICATE → TRIAGING (reopen)
```

```bash
talos finding list
talos finding list --status TRIAGING
talos finding list --linked
talos finding list --all
talos finding show <uuid>
talos finding confirm <uuid>
talos finding reject <uuid>
talos finding reopen <uuid>
talos finding reject <primary> --linked
talos finding confirm <primary> --linked --force
talos finding duplicate <uuid> --of <canonical_uuid>

# Analyst notes (appear in show + Markdown reports; timeline event recorded)
echo "Confirmed with customer." | talos finding note set <uuid>
talos finding note clear <uuid>

talos finding group create "Critical Findings"
talos finding group add "Critical Findings" <finding_uuid>
talos finding group remove "Critical Findings" <finding_uuid>
talos finding group remove "Sprint 4 Report" --force
talos finding group remove "Sprint 4 Report" --remove-findings --force
talos finding group list

talos finding report <uuid>
talos finding report <uuid> > report.md
talos finding report --group "Critical Findings"
```
