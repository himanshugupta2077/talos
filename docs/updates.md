# Talos — Release Updates

All notable changes to Talos are documented here, organized by version.

---

## v0.6.0 — Input Validation: Per-Request Architecture + Universal Flow Metadata

### Summary

This release rearchitects the Input Validation Engine so that **every HTTP
probe produces its own independent replay flow**, making IV architecturally
identical to BAC: a generator of scheduler jobs backed by the replay engine.

### Core Architecture Changes

**Every probe = one scheduler job = one replay flow.**

Previously, an `iv_characters` job sent 29 HTTP requests and stored a single
aggregate result.  Now, each character probe is its own scheduler job with its
own replay flow, unique flow_id, request, response, timing, and metadata.

| Phase | HTTP requests |
|-------|--------------|
| baseline | 1 |
| identifier | 9 |
| characters | 29 |
| length | 10 |
| types | 12 |
| validation | 8 |
| transformations | 0 (pure analysis of existing flows) |
| reflection | 0 (pure analysis of existing flows) |

**Input Validation uses the Replay Engine.**

All HTTP execution goes through `replay_with_mutation()` in `replay/engine.py`.
Auth refresh, TTL checks, and session health gates apply automatically via
`session_health.ensure_healthy()` — identical to BAC.

**Deterministic parameter UUID.**

`param_uuid = sha256(f"{host}|{location}|{param_name}")[:32]`

Shared across all endpoints where the same parameter appears.  Used as the
primary key for `iv_probe_results`.

**Universal flow metadata.**

Every replay flow stores a `flow_meta` JSON column:

```json
{
    "generated_by": "input_validation",
    "analysis": "characters",
    "param_uuid": "...",
    "param_name": "ProductId",
    "location": "body",
    "host": "myapp.local",
    "payload": "<",
    "payload_class": "character",
    "payload_index": 17,
    "original_flow_id": "..."
}
```

Future modules (SQLi, XSS, SSRF) populate the same field with their own
structured metadata.

### New Database Tables (schema v27)

- `iv_probe_results` — per-HTTP-request IV evidence, one row per probe.
- `flows.flow_meta` — universal replay metadata column (TEXT JSON).

### Reflection Phase Fixed

`iv_reflection` is now correctly included in the scheduling sequence.
Transformation and Reflection phases are pure analysis (zero HTTP) that
consume existing probe flows.

### New CLI Commands

```bash
# IV exports (Markdown, written to <project>/exports/)
talos input-validation export parameter <param_uuid>
talos input-validation export host <host>
talos input-validation export endpoint <endpoint_id>
talos input-validation export csv           # per-probe CSV (all params)

# Universal flow inspector
talos flow show <flow_id>
talos flow export <flow_id>
talos flow export --module input_validation
talos flow export --parameter <param_uuid>
talos flow export --endpoint <endpoint_id>
talos flow export --flows <id> <id> ...
```

### Show Command Updated

`talos input-validation show <param_id>` now shows per-probe results from
`iv_probe_results` (one row per HTTP request with exact payload and HTTP
status), not phase-level summaries.

### Scheduler UI Improvements

Done-section jobs now display:
- IV analysis type (e.g. `characters`)
- Exact payload sent (e.g. `<`)
- Clickable flow link for every probe

### Flows Page

IV scan flows (`source=iv_scan`) are now visible in the flows filter and table.

---

## v0.5.0 — Endpoint Intelligence + Input Validation Engine

### Summary

This release expands Parameter Intelligence into a full **Endpoint Intelligence**
system and introduces the **Input Validation Engine** as an active analysis layer.

### Endpoint Intelligence (Parameter Intelligence expansion)

Parameter extraction now covers **every observable input surface**:

| Added | Previous |
|-------|---------|
| Path parameters (from normalized path pattern) | — |
| JSON body — nested (dotted path names) | Top-level only |
| JSON body — arrays | — |
| Multipart/form-data fields | — |
| XML / SOAP element names | — |
| GraphQL variables | — |
| Security-relevant headers (`Authorization`, `X-Forwarded-For`, `Origin`, `X-Tenant`, `X-CSRF-Token`, etc.) | — |
| Cookie parameters (individual names) | — |

**Richer semantic type inference.** Parameters now carry a `semantic_type` field:

```
uuid | jwt | email | objectid | url | ip | hash | timestamp |
filename | boolean | integer | float | array | string | unknown
```

**Passive reflection intelligence.** When a parameter value appears in the
response body, it is recorded automatically (raw, HTML-encoded, URL-encoded).
New per-parameter fields: `is_reflected`, `reflection_count`,
`reflection_locations`, `reflection_encoding`.

**Usage tracking.** New fields: `seen_count`, `appears_in_roles`,
`appears_in_modules`.

**Architecture clarification.** Parameter Intelligence is now explicitly one
analysis inside Endpoint Intelligence:

```
Captured Flow
      │
      ▼
Endpoint Intelligence
    ├── Parameter Intelligence  ← this module
    └── (more analyses to come)
```

### DB Schema — v25

The following changes are applied automatically via migration when an existing
project database is opened.

**parameters table** — new columns:
- `semantic_type TEXT NOT NULL DEFAULT 'unknown'`
- `seen_count INTEGER NOT NULL DEFAULT 1`
- `appears_in_roles TEXT NOT NULL DEFAULT '[]'`
- `appears_in_modules TEXT NOT NULL DEFAULT '[]'`
- `is_reflected INTEGER NOT NULL DEFAULT 0`
- `reflection_count INTEGER NOT NULL DEFAULT 0`
- `reflection_locations TEXT NOT NULL DEFAULT '[]'`
- `reflection_encoding TEXT NOT NULL DEFAULT '[]'`

**New tables:**
- `input_validation_config` — per-project IV engine configuration
- `iv_param_cache` — parameter-level analysis results, cached by `(host, location, param_name, phase)`
- `iv_reflection_cache` — endpoint-specific reflection analysis cache

### Input Validation Engine

New active analysis engine. **Disabled by default** — must be explicitly enabled.

```
talos input-validation config --enable
talos input-validation run
```

Analyzes every input surface across 8 phases:

| Phase | Analysis |
|-------|---------|
| 1: baseline | Capture normal endpoint behaviour |
| 2: identifier | Inject `__TL_xxxxxx__` markers for reflection/transformation detection |
| 3: characters | Character acceptance testing |
| 4: length | Length limits, truncation, hard rejection |
| 5: types | Semantic type verification |
| 6: transformations | Detect trim/lowercase/normalization/encoding |
| 7: reflection | Per-endpoint reflection analysis |
| 8: validation | Validation error behaviour |

**Design:** All execution goes through the Talos Scheduler — no requests are
sent directly by the engine. This keeps concurrency control centralized and
jobs visible/pausable/resumable.

**Resume support:** Completed phases are cached individually. Restart or scope
to a single parameter with `--parameter username` to continue from where you left off.

**Force refresh:** Use `--ignore-cache` to re-run all phases.

**New CLI commands:**

```bash
talos input-validation run [--host H | --endpoint ID | --parameter P] [--ignore-cache]
talos input-validation config [--enable|--disable] [--workers N] [--analysis-on/off PHASE]
talos input-validation status
talos input-validation resume
talos input-validation clear-cache
talos input-validation exclude endpoint <id>
talos input-validation exclude host <host>
talos input-validation include endpoint <id>
talos input-validation include host <host>
talos input-validation show <param_name>
talos input-validation export [--output FILE]

# Phase shortcuts (each supports --host/--endpoint/--parameter/--force)
talos input-validation baseline
talos input-validation identifier
talos input-validation characters
talos input-validation length
talos input-validation types
talos input-validation transformations
talos input-validation reflection
talos input-validation validation
```

### `talos --help` / `talos -h`

Running `talos --help` or `talos -h` now prints the **full command tree** with
all subcommands listed, without needing to run each group's `--help` separately.
Running `talos` with no arguments also prints the full tree.

### Schema migration on project open

`talos project open` now calls `init_project_db` on the target database,
ensuring the schema is always up to date when a project is activated. This
means existing projects created with older schema versions will be migrated
automatically on next `project open` — no manual migration step required.

### Scheduler job types

Eight new job type constants added to `talos.scheduler.job`:

```python
IV_BASELINE, IV_IDENTIFIER, IV_CHARACTERS, IV_LENGTH,
IV_TYPES, IV_TRANSFORMATIONS, IV_REFLECTION, IV_VALIDATION
```

---

## v0.4.x — auth-config, session health, BAC decision filter

### auth-config system (replaced old auth mark-login / generate model)

The old `talos auth mark-login`, `talos auth mark-checkpoint`, and
`talos auth generate` commands have been removed. They are superseded by:

```bash
talos auth-config add-flow <role> <flow_id>
talos auth-config set-extractor <role> <flow_id> extractor.py
talos auth-config refresh <role>
```

The extractor model supports multiple login flows per role, arbitrary
auth artifact extraction (cookies, headers, JSON body fields), and
automatic session health monitoring.

### Session Health Engine

Four-layer session health monitoring for automatic token refresh:

1. **TTL-based pre-refresh** — proactive refresh before expiry
2. **Expiry signal detection** — body/header/status signals increment suspicion
3. **Validation endpoint** — authoritative session check on suspicion
4. **Control flows** — replay stable authenticated flows to judge liveness

### BAC decision filter

```bash
talos attack bac filter init
talos attack bac filter show
talos attack bac filter validate
```

Replaces simple status-code-only BAC verdicts with configurable
pattern-matching rules per application.

### Endpoint Policy system

```bash
talos endpoint priority set endpoint <id> CRITICAL
talos endpoint priority set path "/api/admin/*" HIGH
talos endpoint exclude endpoint <id>
talos endpoint exclude path "/static/*"
talos endpoint rules list
```

---

## v0.3.x — BAC attack modules

Seven BAC attack modules added:

- `bac session-swap` — direct session swap
- `bac method-fuzz` — HTTP Method Manipulation
- `bac content-type` — Content-Type Confusion
- `bac url-fuzz` — URL Manipulation
- `bac header-inject` — Header Manipulation
- `bac host-fuzz` — Host Header Changes
- `bac role-inject` — Role Parameter Injection

Scheduler integration: all BAC attacks create scheduler jobs, not
immediate execution. Centralized concurrency + pause/resume.

---

## v0.2.x — Replay, diff, access model, scheduler

- ReplayScheduler daemon thread with priority queue
- Diff engine: status, length, JSON structure comparison
- Two-layer access model: client_allowed + server_expected
- `talos access signals` — BAC/IDOR signal report
- Per-project header drop file
- Request mutations (inject headers on every proxied request)

---

## v0.1.x — Initial capture pipeline

- MITM proxy (mitmproxy) integration
- FlowWorker daemon thread
- SQLite WAL storage
- Endpoint normalization and deduplication
- Role + module tagging
- JSONL raw archive
- Basic parameter extraction (query + JSON/form body)
- Read-only FastAPI UI
