# Talos

**MITM-Based Web Application Penetration Testing Automation**

Talos is an open-source web application pentest automation framework built around a MITM proxy as the central intelligence layer. It captures real, authenticated browser traffic, structures it into a queryable attack surface, and runs deterministic security tests — access control, injection, request manipulation, and more — without requiring manual request crafting.

> Deterministic engines first. A policy-gated AI agent layered on top.

> ⚠️ **Early Development**: Talos is in active early-stage development. Capture, replay, auth, scheduling, the attack modules below, the Control Panel, and the AI layer are functional. Expect breaking changes.

> 🔒 **Authorized use only**: Talos is for client-approved penetration tests and public bug bounty programs. It is authorized security-testing tooling.

> 🤖 **AI is suggest-first, never self-authorizing**: The deterministic engines run with zero AI and are fully usable on their own. The optional AI agent only proposes work — every action goes through a policy validator and a sealed execution plan before anything runs.

---

## Document map

| Document | Purpose |
|----------|---------|
| `README.md` | Overview, installation, quick start (this file) |
| `talos-docs/cli-cheat-sheet.md` | Complete CLI reference (incl. output conventions) |
| `talos-docs/architecture.md` | Internal architecture and subsystem design |
| `talos-docs/updates.md` | Release notes / change log |
| `talos-docs/about-talos.md` | Vision / design notes (non-authoritative) |
| `talos-docs/ai-usage-guide.md` | AI agent: setup, modes, policy, MCP |
| `talos-docs/input-validation.md` | Input Validation engine and phases |
| `talos-docs/intruder-cli-guide.md` | Intruder (high-volume mutation) guide |
| `talos-docs/bac-decision-filter.md` | BAC decision filter configuration |
| `talos-docs/burp-extension.md` | Burp upstream headers + Talos Burp extension |
| `talos-control-panel/README.md` | Integrated Control Panel (web UI) setup and architecture |

---

## How It Works

You browse the target application normally through your browser. Talos intercepts traffic via mitmproxy, normalizes and stores every request/response, clusters them into endpoints, extracts parameters, and builds a structured model of the attack surface. From there it replays traffic across sessions, strips or swaps auth, mutates entry points, and diffs responses to surface findings.

```
Browser (manual)
    ↓
mitmproxy (mitmdump)
    ↓
Talos Addon: capture only
    ↓
Flow Queue
    ↓
Worker Pipeline: normalize, persist, parametrize, URL-sink discovery
    ↓
SQLite DB + Raw Archive
    ↓
Replay / Scheduler → Attack Modules → Findings
    ↑
Control Panel (web UI)  ·  AI agent (policy-gated, suggest-first)
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
- Platform authentication (NTLMv2) toward origin hosts, independent of cookies
- Burp Suite extension + `X-Talos-*` metadata headers so probes group by module in Burp (`talos-docs/burp-extension.md`)

### Normalization and Endpoint Intelligence
- Strips tracking parameters; canonicalizes URLs
- Deduplicates endpoints by `(method, host, normalized_path)`
- Extracts and profiles parameters (type, source, reflection, sensitivity)
- URL Sink Discovery: parameter inventory + URL-feature detection, built automatically by the worker
- Auto-priority scoring and endpoint qualification (2xx baseline)

### Session and Role Awareness
- Tag flows with role and module at capture time
- Privilege ranks per role, with automatic BAC diffs between ranks
- Access matrix: client and server expectations per `(role, module)`
- `access coverage` and `access signals` for privilege-confusion candidates
- Auth-config with AUTO or MANUAL providers and three-layer session health (TTL, expiry signals, validation flows)

### Replay and Scheduler
- Exact replay and Authentication Bypass (auth-stripped) replay
- Diff engine: `SAME` / `DIFFERENT` / `ERROR`
- Priority scheduler with pause/resume, jitter, testing windows, and annotation guards
- Async transport (httpx) with NTLM support

### Attack Modules
- **Broken Access Control (BAC)** — session swap, method/URL/content-type/header/host fuzzing, role inject, parser confusion, decision filter
- **Authentication Bypass** — `talos auth test` strip-and-diff path
- **Unauthenticated Execution** — technique recipes with optional request mutations; decision filter
- **Input Validation** — multi-phase parameter characterization with an adaptive planner (disabled by default)
- **SQL Injection (SQLi)** — typed payload catalogue, per-DB selection, high-priority queue jump
- **XSS / HTML Injection** — typed catalogue with the `TalosXss` canary; confirms on unencoded JS/HTML sinks
- **Path Traversal / LFI** — traversal and local-file-inclusion catalogue
- **SSRF** — payload families with optional out-of-band collaborator host
- **Open Redirect** — redirect-target payload catalogue
- **CORS Misconfiguration** — origin payload catalogue, verdicts per technique
- **Host-Header Injection** — header payload catalogue
- **HTTP Request Smuggling** — CL/TE desync technique catalogue
- **JWT / Auth-Session Testing** — alg-degradation matrix and weak-validation tests, with its own decision filter

### Tooling Engines
- **Intruder** — high-volume mutation engine (sniper / pitchfork / zip / cluster-bomb), payload generators and processors, match/grep rules, extracted value pools, adaptive timing
- **Send (Repeater)** — edit → send → review with mutable lineage, parent→child trees, request/response diffs, and persistent tabs
- **Passive scanning** — secret-exposure and infrastructure-disclosure detectors over captured documents (HTML inline + source maps)
- **Error intelligence** — clusters error observations by fingerprint across flows, parameters, and endpoints

### Findings and Reports
- Automatic findings on trigger verdicts across every module
- PRIMARY/LINKED clusters, groups, lifecycle (triage → confirm/reject/reopen), Markdown reports

### HTTP Manipulation Engine
- Single declarative rule engine for **request and response** modifications
- Layered config (global / project) with host/path/method/endpoint match conditions
- Headers, cookies, query, body, status, delay/drop — via `talos config http`
- Default: engine on, no rules (traffic unmodified until you add rules)

### AI Agent (optional, policy-gated)
- Suggest-first autonomy: the model proposes; it never self-authorizes
- `PolicyValidator` + sealed `ExecutionPlan` + Executor gate every action
- Handlers call existing Talos Python APIs only — no freeform shell under the AI layer
- Configurable LLM provider, structured app notes, operator Markdown knowledge base, finding drafts (promote to TRIAGING only), full audit trail
- Ships an stdio MCP server over the same validator + executor (no network MCP)
- See `talos-docs/ai-usage-guide.md`

### Control Panel (web UI)
- Local FastAPI + React app in `talos-control-panel/` — browse project data, resolve UUIDs by clicking, manage layered config, and run any CLI command from a form
- Never implements business logic: reads SQLite / the policy resolver, mutates only by shelling out to the `talos` CLI
- See `talos-control-panel/README.md`

---

## Installation

### Prerequisites

- **Python 3.11+**, **git**, and a browser you can point at a manual HTTP/HTTPS proxy
- Node.js is only needed for the optional Control Panel

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

1. Start the proxy: `talos proxy start`
2. Point your browser at the proxy (default `127.0.0.1:8080`; confirm with `talos proxy status`)
3. Visit `http://mitm.it` in that browser and install the mitmproxy CA certificate for your OS/browser
4. Trust the certificate so HTTPS pages load without warnings

---

## Quick Start

```bash
# 1. Create and open a project
talos project create my-target
talos project open my-target

# 2. Define scope (Burp-style URL prefixes)
talos project scope add https://app.example.com

# 3. Start the capture proxy, browse the target through it
talos proxy start

# 4. Inspect the captured attack surface
talos endpoint list
talos flow list

# 5. Run an attack module (example: SQLi on one flow)
talos attack sqli run --flow <flow_uuid>

# 6. Review findings
talos finding list
talos finding show <uuid>
talos finding report <uuid>
```

For the full workflow (roles, modules, access matrix, auth, Input Validation, auth-config): see [talos-docs/cli-cheat-sheet.md](talos-docs/cli-cheat-sheet.md).

---

## Interfaces

- **CLI** — every operation is available through the `talos` command (source of truth for all writes)
- **Control Panel** — optional local web UI over the same CLI (`talos-control-panel/`)
- **Burp extension** — groups Talos probes by module inside Burp (`talos-docs/burp-extension.md`)

---

## CLI Reference

```
talos [--project ID]
├─ project   create / open / close / delete / rename / description / list /
│            scope / constraints / auth-mode / status / outscope
├─ config    show / effective / get / set / unset / edit / schema /
│            proxy | capture | scheduler | attack | http
├─ proxy     start / stop / kill / restart / status / config / auth
├─ role      create / add / list / show / rename / delete / set / unset
├─ module    create / add / list / show / rename / delete / set / unset
├─ access    client set|unset / server set|unset / delete / show / coverage / signals
├─ auth      set / unset / show / clear / test
├─ auth-config  set-provider / set-session / flows / extractors / validate /
│              refresh / status / show / set-ttl / expiry signals /
│              control-flows / bind-ntlm (<role> = name or UUID)
├─ endpoint  list / params / mark / unmark / show / policy / export / notes /
│            tags / priority / exclude / include / exclude-results / rule(s)
├─ replay    flow / endpoint
├─ send      from / edit / once / redo / dup / show / export / history /
│            tree / diff / note / tab   (Repeater)
├─ intruder  session / template / payload / strategy / timing / storage /
│            match / grep / pool / findings / suggest / results / run / status
├─ flow      list / show / export
├─ scheduler start / stop / status / config / enqueue / jobs / cancel /
│            prune / clear / pause / resume
├─ attack    unauth / bac / auth-session (JWT) / cors / sqli / xss /
│            path-traversal / ssrf / open-redirect / host-header / smuggle
├─ input-validation  run / config / status / resume / synthesize / candidates /
│                    reflections / export / show / phase shortcuts
├─ passive   status / config / rules / documents / detections / rescan
├─ error-intel  status / config / errors / observations / rescan / rollup
├─ ai        start / stop / resume / status / mode / suggest / approve / deny /
│            pending / plans / notes / kb / finding / mcp / config / audit
└─ finding   list / show / confirm / reject / reopen / duplicate /
             note / group / report
```

Run `talos --help` or see [talos-docs/cli-cheat-sheet.md](talos-docs/cli-cheat-sheet.md) for full syntax.

**Project context:** Interactive sessions use `talos project open <id>`. Scripts and CI should prefer `talos --project <id> …` or `TALOS_PROJECT=<id>` so concurrent jobs do not share mutable registry ACTIVE state.

**Destructive commands:** Interactive terminals prompt `[y/N]`. Non-interactive runs (CI, pipes) require `--force` or exit 2 — they never hang waiting for input.

**Exit codes:** `0` success · `1` general failure · `2` invalid arguments / missing `--force` · `3` preconditions failed (no project, auth/policy gate) · `130` user cancelled.

**Note:** Role and module arguments accept a **name or UUID** (prefer the name). Use `talos role list` / `talos module list` to discover UUIDs. Layered settings: `talos config effective` / `talos config set <key> <value>` (defaults → global `~/.talos/config.yaml` → project `project.yaml` → CLI).

---

## Tech Stack

| Layer | Technology |
|---|---|
| Proxy | mitmproxy (mitmdump) |
| Runtime | Python 3.11+ |
| Storage | SQLite (WAL mode), schema v64 |
| Replay | httpx (async) |
| Queue | In-memory (bounded) |
| CLI | `talos` |
| Control Panel | FastAPI (backend) + React / TypeScript / Vite / Tailwind / DaisyUI (frontend) |
| AI agent | Policy-gated planner/executor + pluggable LLM provider + stdio MCP |

---

## Roadmap

### Implemented (current)

- [x] Project management, scope, out-of-scope
- [x] MITM capture, worker pipeline, endpoint intelligence, URL Sink Discovery
- [x] Roles, privilege ranks, modules, access matrix, coverage/signals
- [x] Replay, diff, Authentication Bypass tests
- [x] Scheduler with pause/resume and testing windows
- [x] Auth-config (AUTO/MANUAL), three-layer session health, platform NTLM
- [x] Endpoint policy (priority, exclude, qualification, exclude-results)
- [x] Broken Access Control suite + decision filter
- [x] Unauthenticated Execution + decision filter
- [x] Input Validation engine (adaptive planner)
- [x] Injection suite: SQLi, XSS/HTMLi, path traversal/LFI, SSRF, open redirect, CORS, host-header, request smuggling
- [x] JWT / auth-session testing engine + decision filter
- [x] Intruder (high-volume mutation) and Send (Repeater)
- [x] Passive secret/infra-disclosure scanning; error intelligence
- [x] Findings (PRIMARY/LINKED), groups, reports
- [x] HTTP Manipulation Engine (request + response rules); proxy upstream mode; Burp extension
- [x] Control Panel web UI
- [x] AI agent (policy-gated, suggest-first) + stdio MCP

### Planned

- [ ] IDOR module: systematic cross-session identifier swapping
- [ ] Redis-backed queue (scale-out)
- [ ] State graph: workflow reconstruction and sequence attacks
- [ ] Race condition testing
- [ ] JS endpoint extraction
- [ ] Higher AI autonomy modes (experimental `auto-*`) toward GA

---

## Design Principles

- The proxy thread does **zero** heavy processing — capture and enqueue only
- Sessions are never mixed: role separation is strict
- Deterministic modules run first; the AI operates on clean, structured data and never self-authorizes
- Every replay attempt is stored — nothing is silently discarded
- The system must work fully without AI

---

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE.txt) for details.

Commercial licensing is available for organizations that need to use Talos in proprietary or closed-source products. Contact the maintainer for commercial inquiries.

---

## Contributing

Contributions are welcome. By submitting a pull request you agree to the Contributor License Agreement (CLA), which grants the maintainer the right to relicense your contribution under commercial terms. See [CLA.md](https://gist.github.com/himanshugupta2077/765a9e6fadaaf18ffdc2046fd07f1852) for details.
