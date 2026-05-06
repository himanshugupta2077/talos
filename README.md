# TALOS

**MITM-Based Web Application Penetration Testing Automation**

TALOS is an open-source web application pentest automation framework built around a MITM proxy as the central intelligence layer. It captures real, authenticated browser traffic, structures it into a queryable attack surface, and runs deterministic security tests: IDOR detection, auth bypass testing, parameter tampering, and more: without requiring manual request crafting.

> Deterministic engine first. AI layered on top.

> ⚠️ **Early Development**: TALOS is in active early-stage development. Core capture, replay, auth bypass, and scheduling subsystems are functional. Several attack modules and the AI layer are not yet implemented. Expect breaking changes.

> 🤖 **Zero AI: by design**: The current version contains no AI whatsoever. TALOS is a fully deterministic automation tool: every decision, test, and result comes from structured logic, not a model. AI integration is planned for a future phase and will operate on top of the deterministic engine: not replace it.

---

## How It Works

You browse the target application normally through your browser. TALOS intercepts all traffic via mitmproxy, normalizes and stores every request/response, clusters them into endpoints, and builds a structured model of the application's attack surface. From there, it replays traffic across sessions, strips auth credentials, and diffs responses to find broken access control.

```
Browser (manual)
    ↓
mitmproxy (mitmdump)
    ↓
TALOS Addon: capture only
    ↓
Flow Queue
    ↓
Worker Pipeline: normalize, persist, parametrize
    ↓
SQLite DB + Raw Archive
    ↓
Replay Engine → Diff Engine → Attack Modules
```

---

## Features

### Traffic Capture
- TLS interception via mitmproxy
- Scoped capture with exact and wildcard host patterns (`*.api.example.com`)
- Out-of-scope domain block list that overrides the allow-list
- Configurable body size limits and noise header filtering
- Bounded in-memory queue: proxy thread is never blocked

### Normalization
- Strips tracking parameters (`utm_*`, `fbclid`, `gclid`, cache busters)
- Canonicalizes URLs and deduplicates endpoints by `(method, host, normalized_path)`
- Extracts and profiles parameters: type, source, volatility, sensitivity

### Session and Role Awareness
- Tag every captured flow with a role (`admin`, `user`, `guest`) and module (`billing`, `orders`)
- Access matrix: define expected client-side and server-side access per `(role, module)` pair
- `access coverage` and `access signals` commands surface privilege confusion candidates and enforcement gaps

### Replay Engine
- Exact (Type 1) replay: every request reconstructed from DB and sent via httpx
- Auth-stripped (Type 2) replay: strips configured cookies and headers before replaying
- Diff engine compares status code, response length, and JSON structure; verdict: `SAME`, `DIFFERENT`, or `ERROR`
- Replay scheduler with priority queue, jitter, and annotation-based safety guards

### Attack Modules
- **Unauthenticated execution**: strips auth from each endpoint's best captured flow, replays, verdicts: `SECURE`, `BYPASS`, `UNKNOWN`
- Auto-run mode: scheduler continuously enqueues auth tests for untested endpoints
- Endpoint safety annotations: mark endpoints `logout` or `dangerous` to block automated replay

### Request Mutations
- Static header injections applied to every outgoing request before it reaches the server
- Useful for bug bounty headers (`X-HackerOne-Research`), custom tags, research flags
- Mutations are stored in captured flows and carried through all replays automatically

### Inspection UI
- Local-only FastAPI + Jinja2 web UI (`talos ui`)
- Paginated flow and endpoint views with SSE live-sync: table updates in-place as traffic is captured
- Burp-style split request/response flow detail view
- Attack module coverage dashboard with per-endpoint verdict tracking

---

## Quick Start

```bash
# Create a project
talos project create myapp --scope "*.example.com"
talos project open myapp

# Define roles and modules
talos role create admin
talos module create billing
talos role set admin
talos module set billing

# Configure auth credentials to strip during auth tests
talos auth set --cookie sessionid --header Authorization

# Start capture proxy
talos proxy start --port 8080

# Browse the target normally through your proxy-configured browser

# Open the inspection UI
talos ui

# Run access analysis
talos access coverage
talos access signals

# Replay a specific endpoint and test auth bypass
talos replay endpoint <endpoint_id> --right-now
talos auth test <endpoint_id> --right-now
```

---

## Interface

TALOS is primarily a CLI tool: every operation is available through `talos` commands. For operators who prefer a visual overview, TALOS also ships a locally-served web UI.

### CLI

The CLI is the core interface. All project management, proxy control, replay, auth testing, scheduling, and mutation operations are available as commands. It is the recommended interface for scripting, automation, and headless environments.

### Web UI

```bash
talos ui                          # default: http://127.0.0.1:8000
talos ui --host 127.0.0.1 --port 8010
```

The UI is **local-only**: it is never exposed to the network and is strictly an operator tool. It provides:

- **Project overview**: scope, flow counts, archive size, active role and module
- **Flow viewer**: paginated, filterable list of all captured flows with live-sync via SSE (new flows appear in-place without page reload)
- **Flow detail**: Burp-style split view of raw request and response
- **Endpoint viewer**: clustered endpoint list with parameter profiles and linked flows; live-sync as new endpoints are discovered
- **Proxy control panel**: start and stop the capture proxy from the browser; live log stream
- **Roles and modules**: create and activate roles/modules without restarting anything
- **Access matrix**: visual two-layer (client/server) access map per `(role, module)` pair; edit inline
- **Replay controls**: enqueue or immediately execute flow and endpoint replays
- **Scheduler**: monitor queue depth, pending jobs, execution metrics; adjust jitter and queue size config
- **Mutations**: add, toggle, and delete request header injections
- **Out-of-scope domains**: manage the block list without touching the CLI
- **Attack modules**: per-endpoint auth bypass coverage dashboard with `SECURE` / `BYPASS` / `UNKNOWN` verdicts; enable auto-run to have the scheduler continuously test untested endpoints

The UI and CLI share the same underlying database and engine: anything triggered from the UI is executed by the same replay and auth-strip code that the CLI uses.

---

## CLI Reference

```
talos
├─ project   create / open / close / delete / list / scope / constraints / status / outscope
├─ proxy     start
├─ ui
├─ role      create / list / set / unset
├─ module    create / list / set / unset
├─ access    client set|unset / server set|unset / delete / show / coverage / signals
├─ replay    flow / endpoint
├─ auth      set / show / clear / test
├─ endpoint  mark / unmark / show
├─ scheduler status / config / enqueue / clear
└─ mutation  add / list / delete
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Proxy | mitmproxy (mitmdump) |
| Runtime | Python 3.11+ |
| Storage | SQLite (WAL mode) |
| Replay | httpx (async) |
| Queue | In-memory (Redis-backed in roadmap) |
| UI | FastAPI + Jinja2 + uvicorn |

---

## Roadmap

- [ ] Session detection and identity separation
- [ ] IDOR module: cross-session identifier swapping
- [ ] BAC engine: broken access control at scale
- [ ] Parameter tampering module
- [ ] Redis-backed queue (Stage 2)
- [ ] State graph: workflow reconstruction and sequence attacks
- [ ] Race condition testing
- [ ] Injection testing module: automated payload injection across discovered parameters; user defines payload lists or selects built-in sets (SQLi, XSS, SSTI, path traversal, command injection, etc.); engine distributes payloads across all matching parameters in bulk, respects rate limits and per-request jitter, and diffs every response to surface anomalies: error messages, length deltas, status code changes, reflection, timing differences; results grouped by parameter and endpoint, ranked by signal strength for triage
- [ ] JS endpoint extraction
- [ ] AI layer (MPC): target selection, strategy, result chaining

---

## Design Principles

- The proxy thread does **zero** heavy processing: it only captures and enqueues
- Sessions are never mixed: role separation is strict
- Deterministic modules run first; AI operates on clean, structured data
- Every replay attempt is stored: nothing is silently discarded
- The system must work fully without AI

---

## License

GNU Affero General Public License v3.0: see [LICENSE](LICENSE) for details.

Commercial licensing is available for organizations that need to use TALOS in proprietary or closed-source products. Contact the maintainer for commercial inquiries.

---

## Contributing

Contributions are welcome. By submitting a pull request you agree to the Contributor License Agreement (CLA), which grants the maintainer the right to relicense your contribution under commercial terms. See [CLA.md](CLA.md) for details.
