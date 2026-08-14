# Talos

**MITM-Based Web Application Penetration Testing Automation**

Talos is an open-source web application pentest automation framework built around a MITM proxy as the central intelligence layer. It captures real, authenticated browser traffic, structures it into a queryable attack surface, and runs deterministic security tests — Broken Access Control (BAC), Authentication Bypass, Unauthenticated Execution, and Input Validation — without requiring manual request crafting.

> Deterministic engine first. AI layered on top.

> ⚠️ **Early Development**: Talos is in active early-stage development. Core capture, replay, auth, scheduling, BAC, unauth, Input Validation, and findings are functional. Expect breaking changes.

> 🤖 **Zero AI — by design**: The current version contains no AI. Every decision, test, and result comes from structured logic. AI integration is planned for a future phase and will operate on top of the deterministic engine, not replace it.

---

## Document map

| Document | Purpose |
|----------|---------|
| `README.md` | Overview, installation, quick start (this file) |
| `docs/cli-cheat-sheet.md` | Complete CLI reference (incl. output conventions) |
| `docs/architecture.md` | Internal architecture and subsystem design |
| `docs/updates.md` | Release notes / change log |
| `docs/about-talos.md` | Vision / design notes (non-authoritative) |
| `docs/bac-decision-filter.md` | BAC decision filter configuration |
| `docs/burp-extension.md` | Burp upstream headers + Talos Burp extension |
| `talos-control-panel/README.md` | Integrated Control Panel (UI) setup and architecture |

---

## How It Works

You browse the target application normally through your browser. Talos intercepts traffic via mitmproxy, normalizes and stores every request/response, clusters them into endpoints, and builds a structured model of the attack surface. From there it replays traffic across sessions, strips or swaps auth, and diffs responses.

```
Browser (manual)
    ↓
mitmproxy (mitmdump)
    ↓
Talos Addon: capture only
    ↓
Flow Queue
    ↓
Worker Pipeline: normalize, persist, parametrize
    ↓
SQLite DB + Raw Archive
    ↓
Replay / Scheduler → Attack Modules → Findings
```

---

## Features

### Traffic Capture
- TLS interception via mitmproxy
- Basic Scope capture (Burp-style URL prefixes: host, scheme, port, path)
- Out-of-scope URL-prefix exclusions (same Basic Scope model; overrides in-scope)
- Configurable body size limits and noise header filtering
- Bounded in-memory queue (proxy thread never blocks)
- Optional upstream proxy mode (Burp / ZAP / corporate) — fully dynamic from project config or CLI; no hardcoded upstream host/port
- Burp Suite extension + `X-Talos-*` metadata headers so IV probes group as Input Validation → Endpoints in Burp (`docs/burp-extension.md`)

### Normalization and Endpoint Intelligence
- Strips tracking parameters; canonicalizes URLs
- Deduplicates endpoints by `(method, host, normalized_path)`
- Extracts and profiles parameters (type, source, reflection, sensitivity)
- Auto-priority scoring and endpoint qualification (2xx baseline)

### Session and Role Awareness
- Tag flows with role and module at capture time
- Access matrix: client and server expectations per `(role, module)`
- `access coverage` and `access signals` for privilege-confusion candidates
- Auth-config with AUTO or MANUAL providers and session health (TTL, signals, validation flows)

### Replay and Scheduler
- Exact replay and Authentication Bypass (auth-stripped) replay
- Diff engine: `SAME` / `DIFFERENT` / `ERROR`
- Priority scheduler with pause/resume, jitter, and annotation guards

### Attack Modules
- **Broken Access Control (BAC)** — session swap, method/URL/header/host fuzzing, role inject, parser confusion, decision filter
- **Unauthenticated Execution** — technique recipes with optional request mutations; decision filter
- **Authentication Bypass** — `talos auth test` strip-and-diff path
- **Input Validation** — eight-phase parameter characterization (disabled by default)

### Findings and Reports
- Automatic findings on trigger verdicts (`POSSIBLE_BAC`, `BYPASS`)
- PRIMARY/LINKED clusters, groups, Markdown reports

### HTTP Manipulation Engine
- Single declarative rule engine for **request and response** modifications
- Layered config (global / project) with host/path/method/endpoint match conditions
- Headers, cookies, query, body, status, delay/drop — via `talos config http`
- Default: engine on, no rules (traffic unmodified until you add rules)

---

## Installation

### Prerequisites

- **Python 3.11+**, **git**, and a browser you can point at a manual HTTP/HTTPS proxy

### Steps

```bash
git clone https://github.com/himanshugupta2077/talos.git
cd talos

python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate

pip install -e .
talos --help
```

### Proxy Certificate Setup (required for TLS interception)

1. Start the proxy: `talos proxy start --port 8080`
2. Point the browser at `127.0.0.1:8080` for HTTP and HTTPS
3. Visit `http://mitm.it` and install the mitmproxy CA for your OS/browser
4. On Windows you can import into Trusted Root Certification Authorities; Firefox needs its own certificate store

### Control Panel (optional GUI)

The Control Panel is a local FastAPI + React UI that ships **inside this repository** (`talos-control-panel/`). It does not implement Talos logic: reads use SQLite under `~/.talos`, and every mutation is a real `talos` CLI subprocess.

From the repo root (creates missing venvs / npm deps automatically):

```bash
# Linux / macOS
./scripts/run-control-panel.sh

# Windows (PowerShell — the only Windows launcher)
.\scripts\run-control-panel.ps1

# Windows from cmd.exe
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\run-control-panel.ps1
```

Then open `http://localhost:5173` (the launcher opens the browser when ready). Ctrl+C stops backend and frontend. See `talos-control-panel/README.md` for details and overrides.

---

## Quick Start

```bash
# Create and open a project
talos project create myapp --scope example.com api.example.com --description "Initial lab"
talos project open myapp
# Lifecycle (CLI-017):
#   talos project rename myapp "My App Prod"
#   talos project description my-app-prod "Production July Assessment"
#   talos project delete my-app-prod --force          # registry only
#   talos project delete my-app-prod --purge --force  # registry + disk
# Automation alternative (does not rewrite registry ACTIVE):
#   talos --project myapp endpoint list
#   TALOS_PROJECT=myapp talos endpoint list

# Roles and modules (name or UUID; full lifecycle: create/list/show/rename/delete)
talos role create admin
talos role list                  # shows UUID + name + active
talos role show admin            # details: status, modules, auth, flows
talos role rename admin administrator   # fix typos; UUID unchanged
talos module create billing
talos module list                # shows UUID + name + active
talos module show billing        # details: status, description, roles
talos role set administrator
talos module set billing
# talos role delete adminn --force   # typo cleanup; cascades config, reassigns flows

# Auth artifact names to strip during auth tests
talos auth set --cookie sessionid --header Authorization

# Capture
talos proxy start --port 8080
# Or: talos --project myapp proxy start --port 8080
# Browse the target through the proxy-configured browser

# Discover endpoints (copy UUID for later commands)
talos endpoint list
talos --project myapp endpoint list --qualified --host api.example.com
# Machine-readable (pipe into jq / scripts):
#   talos endpoint list --format json   # { "endpoints": [...], "count": N }
#   talos endpoint policy <id> --format json
#   talos endpoint rule list --format json
#   talos project status --format json
# Bulk mark / multi-ID priority (atomic, all-or-nothing):
#   talos endpoint mark <id1> <id2> --dangerous
#   talos endpoint priority set endpoint <id1> <id2> HIGH

# Analysis
talos access coverage
talos access signals

# Replay / Authentication Bypass
talos replay endpoint <endpoint_id> --right-now
talos auth test <endpoint_id> --right-now

# Findings
talos finding list
# talos finding list --format json
```

Full workflows (BAC, unauth, Input Validation, auth-config): see [docs/cli-cheat-sheet.md](docs/cli-cheat-sheet.md).

---

## Interface

Talos is **CLI-only**. Every operation is available through the `talos` command.

---

## CLI Reference

```
talos [--project ID]
├─ project   create / open / close / delete / rename / description /
│            list / scope / constraints / status / outscope
│            (scope/outscope: add|remove|list|clear|import)
├─ config    show / effective / get / set / unset / edit /
│            proxy | capture | scheduler | attack | mutation
├─ proxy     start / config
├─ role      create / add / list / show / rename / delete / set / unset
├─ module    create / add / list / show / rename / delete / set / unset
├─ access    client set|unset / server set|unset / delete / show / coverage / signals
├─ auth      set / unset / show / clear / test
├─ auth-config  set-provider / show-provider / set-session / clear-session /
│              flows / extractors / validate / refresh / status / show /
│              set-ttl / expiry signals / reset-health / control-flows
│              (<role> = name or UUID)
├─ endpoint  list / mark / unmark / show / export / notes / tags /
│            priority / exclude / include / rules
├─ replay    flow / endpoint
├─ flow      show / export
├─ scheduler status / config / enqueue / jobs / cancel / prune /
│            clear / pause / resume
├─ mutation  add / list / edit / enable / disable / delete
├─ attack    unauth (run, config, filter) / bac (modules + filter)
│              (BAC --role / --module = name or UUID)
├─ input-validation  run / config / status / phases / export / …
└─ finding   list / show / confirm / reject / reopen / duplicate /
             note / group / report
```

Run `talos --help` or see [docs/cli-cheat-sheet.md](docs/cli-cheat-sheet.md) for full syntax.

**Project context:** Interactive sessions use `talos project open <id>`. Scripts and CI should prefer `talos --project <id> …` or `TALOS_PROJECT=<id>` so concurrent jobs do not share mutable registry ACTIVE state.

**Destructive commands:** Interactive terminals prompt `[y/N]`. Non-interactive runs (CI, pipes) require `--force` or exit 2 — they never hang waiting for input (CLI-015).

**Note:** Role and module arguments accept a **name or UUID** (prefer the name). Use `talos role list` / `talos module list` to discover UUIDs. Layered settings: `talos config effective` / `talos config set <key> <value>` (defaults → global `~/.talos/config.yaml` → project `project.yaml` → CLI). Unauth auto-run: `talos config set attack.unauth_auto_run true` or `talos attack unauth config --auto-run on|off`. Endpoint/finding annotations: `talos endpoint notes set`, `talos endpoint tags add`, `talos finding note set`.

---

## Tech Stack

| Layer | Technology |
|---|---|
| Proxy | mitmproxy (mitmdump) |
| Runtime | Python 3.11+ |
| Storage | SQLite (WAL mode), schema v34 |
| Replay | httpx (async) |
| Queue | In-memory (bounded) |
| Interface | CLI (`talos`) |

---

## Roadmap

### Implemented (current)

- [x] Project management, scope, out-of-scope
- [x] MITM capture, worker pipeline, endpoint intelligence
- [x] Roles, modules, access matrix, coverage/signals
- [x] Replay, diff, Authentication Bypass tests
- [x] Scheduler with pause/resume
- [x] Auth-config (AUTO/MANUAL) and session health
- [x] Endpoint policy (priority, exclude, qualification)
- [x] Broken Access Control suite + decision filter
- [x] Unauthenticated Execution + decision filter
- [x] Input Validation engine
- [x] Findings (PRIMARY/LINKED), groups, reports
- [x] HTTP Manipulation Engine (request + response rules); proxy upstream mode

### Planned

- [ ] IDOR module: systematic cross-session identifier swapping
- [ ] Redis-backed queue (scale-out)
- [ ] State graph: workflow reconstruction and sequence attacks
- [ ] Race condition testing
- [ ] Broader injection testing module (payload libraries across parameters)
- [ ] JS endpoint extraction
- [ ] AI layer (MPC): target selection, strategy, result chaining

---

## Design Principles

- The proxy thread does **zero** heavy processing — capture and enqueue only
- Sessions are never mixed: role separation is strict
- Deterministic modules run first; AI operates on clean, structured data
- Every replay attempt is stored — nothing is silently discarded
- The system must work fully without AI

---

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE) for details.

Commercial licensing is available for organizations that need to use Talos in proprietary or closed-source products. Contact the maintainer for commercial inquiries.

---

## Contributing

Contributions are welcome. By submitting a pull request you agree to the Contributor License Agreement (CLA), which grants the maintainer the right to relicense your contribution under commercial terms. See [CLA.md](https://gist.github.com/himanshugupta2077/765a9e6fadaaf18ffdc2046fd07f1852) for details.
