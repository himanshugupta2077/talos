---
description: Historical vision and design notes for Talos. Non-authoritative.
---

> **Non-authoritative.** This file is vision / design notes only.
> For current CLI, use `docs/cli-cheat-sheet.md` and `talos --help`.
> For architecture and schema, use `docs/architecture.md`.
> Do not treat this document as a source of truth for commands or database schema.

# Talos — Full System Notes (MITM-Based Web App Pentest Automation)

---

# 1. Core Philosophy

* MITM proxy is the **central intelligence layer**
* Manual browser provides **real state + authenticated traffic**
* System converts traffic → **structured, replayable attack surface**
* Deterministic engine first, AI layered on top
* Focus:

  * state
  * identity
  * relationships
  * sequence

---

# 2. High-Level Architecture

```
Browser (manual)
    ↓
mitmproxy (mitmdump)
    ↓
Talos Addon (capture only)
    ↓
Queue
    ↓
Workers (processing engine)
    ↓
Storage (DB + raw archive)
    ↓
Replay Engine
    ↓
Diff Engine
    ↓
Attack Modules
    ↓
AI (MPC layer)
```

---

# 3. Technology Stack

## Core

* Python 3.11+
* mitmproxy (mitmdump mode)

## Storage

* Start: SQLite (WAL enabled)
* Later: PostgreSQL

## Replay

* httpx (async)

## Queue

* Start: Python queue
* Later: Redis + RQ / Celery

## Interface

* CLI only (`talos` commands)

---

# 4. Proxy Layer (mitmproxy)

## Responsibilities

* TLS interception
* capture request/response
* minimal processing only

## Hook

```python
def response(flow):
    if not in_scope(flow):
        return
    enqueue(flow)
```

## Strict rule

* NO heavy logic inside proxy thread

---

# 5. Queue System

## Purpose

Decouple:

* fast capture
* slow processing

## Flow

```
proxy → queue → workers
```

## Benefits

* prevents blocking
* handles traffic spikes
* enables scaling

## Evolution

* Stage 1: in-memory queue
* Stage 2: Redis-backed queue

---

# 6. Flow Capture Model

Capture:

* full request
* full response
* timestamps
* headers
* cookies
* body (truncate if large)

---

## Connection Grouping

Purpose: reconstruct flows

Signals:

* referer header
* redirect chains
* timing proximity
* shared parameters (e.g., order_id across requests)

---

# 7. Normalization Pipeline

## Steps

### 1. Strip Noise

#### Tracking Parameters

* utm_source
* utm_campaign
* fbclid
* gclid

#### Cache Busters

* `_t=timestamp`
* random query params

---

### 2. Canonicalize URLs

* remove trailing slashes
* sort query params
* normalize duplicate paths
* unify equivalent endpoints

---

### 3. Extract Data

* query params
* body params
* JSON structure
* headers
* cookies

---

# 8. Storage Design

## Do NOT use JSON as primary store

Problems:

* no indexing
* slow queries
* no relationships
* duplication
* concurrency issues

---

## Database (Primary)

Tables:

* flows
* endpoints
* parameters
* sessions
* replays
* anomalies

---

## Raw Archive (Secondary)

* compressed raw HTTP
* used for:

  * debugging
  * reprocessing
  * audit

Format:

* JSONL / blobs

---

# 9. Session System

## Purpose

Separate identities cleanly

## Detection

From:

* cookies
* Authorization headers
* tokens

---

## Model

```
session_id:
  auth_type
  token/cookie signature
```

---

## Manual Override

User defines:

* current role (admin, user, etc.)

---

# 10. Role + Module Tagging

User sets:

```
role = admin
module = billing
project = X
```

Each flow tagged accordingly.

---

## Important

* Role separation must be strict
* No mixing sessions across roles

---

# 11. Endpoint Model

Cluster using:

```
(method + normalized_path)
```

---

## Structure

```
endpoint:
  id
  method
  path
  normalized_path
  params
  auth_required
  roles_seen
  content_type
  examples
```

---

# 12. Endpoint Intelligence

Endpoint Intelligence is the canonical knowledge base for each endpoint. It is
built **passively** — only from captured traffic, never from probes.

```
Captured Flow
      │
      ▼
Endpoint Intelligence
    ├── Endpoint Metadata      (method, host, path, auth_required, roles_seen)
    ├── Parameter Intelligence (every observable input surface — see below)
    ├── Authentication Intel   (auth artifacts, extractor results, session health)
    ├── Role Intelligence      (which roles hit this endpoint, appears_in_roles per param)
    ├── Response Intelligence  (status codes, content-types, length ranges)
    ├── Reflection Intelligence (passive: values seen in responses)
    └── Secret Detection    (passive: secrets / disclosures in response bodies)
```

This layer answers only: **"What have we observed?"**

### Secret Detection / Source Intelligence (client-side secrets)

Talos scans captured **client-delivered** response bodies (HTML, JS, JSON, CSS,
source maps) on a separate `SourceScanWorker` thread — never on the proxy
capture path, never via outbound “is this key valid?” checks.

- High-confidence secrets become Findings (`attack_type=passive_secret`,
  verdict `EXPOSED`), clustered by secret fingerprint (`PRIMARY` / `LINKED`).
- Infrastructure disclosures (internal IPs, route tables, …) stay as
  detections for review; they do not auto-create findings by default.
- CLI: `talos passive status|config|rules|documents|detections|rescan`.

For active verification: use the Input Validation Engine (HTTP probes), not
the passive engine.

## Parameter Intelligence

Talos extracts every observable input surface for each captured flow:

| Location | What is extracted |
|---|---|
| `path` | Dynamic path segments resolved from normalized path pattern |
| `query` | All query string parameters; base64/URL-encoded JSON values are also walked into dotted leaves |
| `body` | JSON (nested), URL-encoded form, multipart fields, XML leaf elements, GraphQL variables; encoded JSON leaves expanded |
| `header` | Security + URL-ish allowlist (Authorization, Referer, Origin, Content-Location, Link, Destination, X-Original-URL, X-Rewrite-URL, X-Forwarded-*, …) **and** value-first custom headers whose values look like network resources |
| `cookie` | All request cookies as individual parameters |
| `response` | HTML hidden `<input>` fields + JS/bootstrap config URL keys (`__NEXT_DATA__`, `window.__CONFIG__`, common `apiUrl`/`baseUrl` assigns) — gated by name category or value score |

Headers and cookies are full attack surface — for BAC especially, headers are
often more important than query parameters. Response inventory is
**read-only characterization** (not a request injection surface for IV).

JWT-bearing values (Authorization, cookies, …) may also emit virtual parameters
such as `jwt.jku` / `jwt.iss` / `jwt.aud` when claims are URL-shaped (inventory
only; payload decoded without verification).

### Per parameter, Talos stores:

```
name
location          (path | query | body | header | cookie | response)
param_type        (int | float | bool | string | unknown)
semantic_type     (uuid | jwt | email | objectid | url | ip | hash | timestamp |
                   filename | boolean | integer | float | array | string)
example_values    (up to 5 sampled values)
seen_count        (number of flows where observed)
appears_in_roles  (which roles triggered flows containing this parameter)
appears_in_modules
is_reflected      (boolean: value seen in response)
reflection_count
reflection_locations  (html | json | xml | javascript | other)
reflection_encoding   (raw | html_encoded | url_encoded)
url_features      (JSON: passive URL Sink Discovery — value/name + structure evidence)
```

### URL Sink Discovery (passive + IV + capabilities)

Parameters may carry a `url_features` document (schema v53+) produced by
`talos.url_sink`: value-first detection of URLs/hostnames/IPs/paths plus a
categorized name catalog (redirect, webhook, remote_fetch, remote_asset, …).
Phase 2 also expands **structure discovery** (encoded JSON dotted paths, JWT
URL claims, HTML/JS response sinks) with evidence tokens such as
`decode:base64`, `jwt_claim`, `html_hidden`, `js_config`. Response-derived
params use `location=response` and are excluded from same-flow reflection
detection (values already came from that body). They are also **never scheduled
for IV injection** (inventory only). Virtual `jwt.*` claim rows are inventory
only as well — IV does not invent literal claim headers. HTML/JS inventory is
gated so weak catalog names with junk values (`next=1`) do not flood the table.

**Phase 3 (active IV):** when Input Validation runs and passive signals warrant
it, the planner schedules `url_sink_probes` (`iv_url_sink` jobs) with benign
canaries (`talos-canary.invalid`, path/IP forms; deep+ protocol variants),
gated by types analysis and `url_sink.iv_probes.enabled`. Responses are
fingerprinted for validation phrases, DNS/fetch/timeout classes, and Location
canary reflection. Results land in the IV param profile as `observed.url_sink`
(accepts_url/hostname/…, redirect_behavior, fetch_behavior, error_classes, …)
plus `tested.url_sink:*`.

**Phase 4 (consumer contract):** Module 11 derives `network_resource_sink` (plus
`redirect_sink` / `fetch_sink` / `webhook_sink`) from passive features + active
`url_sink` + type soft-accept. Attack candidates for `ssrf` are **value-first**
(e.g. `abc=https://…` ranks without name tokens); `open_redirect` requires a
redirect-shaped signal (name category / Location behavior); new labels
`webhook_abuse` and `oauth_redirect` bias webhook/OAuth surfaces. Still
**prioritization only** — not confirmed SSRF/open-redirect findings.

**Phase 5 (operator polish):** browse inventory with
`talos endpoint params <endpoint_id>`; IV `show` / `export` surface
`url_features` and `observed.url_sink` in table mode; layered config knobs under
`url_sink.*`.

This is characterization only — not exploit confirmation. Random-named values
like `abc=https://cdn.example/x` still score as network resources and can
produce SSRF candidates after URL accept evidence.

### Passive Reflection Intelligence

When a parameter value appears in the response body, Talos records it
automatically — no additional requests are sent. Raw values, HTML-encoded, and
URL-encoded forms are all detected.

## Who consumes Endpoint Intelligence?

```
Endpoint Intelligence
        │
        ├────────► Priority Engine      (auto-scoring)
        ├────────► Candidate Generator  (BAC candidate selection)
        ├────────► Attack Engine        (mutation context)
        ├────────► Input Validation Engine (parameter inventory to probe)
        ├────────► Reports
        └────────► Search
```

---

# 13. Input Validation Engine

The Input Validation Engine is an **active** analysis engine. Unlike Endpoint
Intelligence (passive), it sends controlled requests to understand how each
input behaves.

**Primary goal:** Learn how every input behaves once, store it, and let every
future attack module reuse it without repeating the same characterization work.

**Key design decisions:**
- Disabled by default — tester must explicitly enable it
- Never viewed as an attack engine — no exploit payloads
- All execution goes through the Talos Scheduler (centralized concurrency)
- Resumable — completed analyses are cached and skipped on re-run
- Force-refresh available for when the application changes
- Multi-level learning (Module 10): parameter → endpoint → application
  profiles; new params inherit middleware defaults (confidence capped)
  so standard-tier re-characterization spends fewer HTTP requests

```
Endpoint Intelligence (passive observations)
      │
      ▼
Input Validation Engine (active verification)
      │
      ├── parameter profiles
      ├── endpoint profiles (shared middleware)
      └── application/host profiles (inherit defaults)
      ▼
Attack Engine (XSS, SQLi, SSRF, BAC, etc.)
```

## Analysis Phases

Adaptive **planner** (Module 5) schedules waves by budget tier rather than
always running a fixed ~70-probe matrix. Default tier is **standard**
(~10–18 HTTP requests per unique parameter typical).

| Phase | Purpose |
|-------|---------|
| 1: Baseline | Capture normal endpoint behaviour before any mutations |
| 1b: Multiprobe | One multi-signal request: high-entropy `TL`+hex canary + taxonomy class samples |
| 2: Identifier | Additional reflection markers (legacy weak list: deep/exhaustive only) |
| 3: Characters | Class representatives / drill-down (skipped under standard when multiprobe confident) |
| 4: Length | Binary/log length search (fixed matrix only on exhaustive) |
| 5: Types | Passive-first type_confirm (pruned under standard; full on exhaustive). Boolean fields send **both** `true` and `false` as unique flows. JSON bodies inject native types (bool/number/array), not stringified values. |
| 5b: URL sink | Benign URL canaries when passive `url_features` warrants → `observed.url_sink` (Phase 3); Phase 4 → `network_resource_sink` + value-first candidates. JSON keys like `headers.Host` / `Location` / URL-shaped values get the same canaries as HTTP header surfaces. |
| 6: Transformations | Detect trim, lowercase, normalization, escaping, encoding (enriched by M8 pipeline) |
| 7: Reflection | Endpoint-specific reflection analysis (not globally cached) |
| 8: Validation | Semantic rules + type-family catalogs (boolean polarity, email shapes, array wrap/empty, numeric edges) + core validation; exploit-shaped strings deep+ only; each probe is its own replay flow; tested{} negatives |
| 8b: Parser | Normalization pipeline + parser fingerprint (dup keys, JSON null/empty, arrays); quick skips |

**Budget tiers:** `quick` · `standard` (default) · `deep` · `exhaustive` (legacy-like).

### Supported input surfaces (Module 9)

IV injects and profiles the same surfaces Endpoint Intelligence extracts:

| Location | Notes |
|----------|--------|
| `path` | Rewrites the segment mapped from `normalized_path` `{name}` |
| `query` | Query string parameters |
| `body` | JSON (dotted paths), form-urlencoded, multipart fields **and filenames**, XML leaves, GraphQL `variables.*` |
| `header` | Security-relevant headers; hop-by-hop headers are never mutated; payloads are **header-safe** only (no leading/trailing SP, no NUL/CTL) |
| `cookie` | Individual cookies in the Cookie header (multi-cookie safe); same transport rules as header field-values |

**Auth artifacts** (session cookies, `Authorization`, tokens configured via
`talos auth set`) are **skipped by default** with status reason `auth_artifact`.
Opt in: `talos input-validation run --include-auth-artifacts` or
`config --include-auth-artifacts`.

**Transport-illegal payloads** (e.g. raw NUL in a header value, leading spaces
from a trim probe) are **skipped** with `transport_invalid_header` /
`transport_invalid_cookie` — they never reach the application under the
standard HTTP client and must not be counted as application failures.

**Limitations:** IV does not discover hidden parameters (param miner); does not
perform HTTP request smuggling; GraphQL is JSON-shaped bodies (not pure query
language AST rewrite).

### Multi-level profiles (Module 10)

| Level | Purpose |
|-------|---------|
| Parameter | Primary unit — local observed evidence |
| Endpoint | Shared middleware / validation defaults |
| Application (host) | Host-wide priors for new parameters |

New parameters inherit tested negatives and parser expectations at reduced
confidence (cap 75). Inspect with `show --endpoint` / `show --host`.

### Capabilities & attack candidates (Module 11)

After synthesis, each parameter profile exposes:

- **capabilities** — flags such as `reflective_input`, `html_context`,
  `url_like_value`, `network_resource_sink` (+ `redirect_sink` / `fetch_sink` /
  `webhook_sink`), `duplicate_parameter`, surface kinds, …
- **candidates** — prioritization scores for `xss`, `sqli`, `open_redirect`,
  `ssrf`, `webhook_abuse`, `oauth_redirect`, `hpp`, `header_injection`,
  `path_traversal`, `mass_assignment` (value-first URL sink scoring for the
  network-resource family)

Each candidate includes `score` (0–100), `confidence`, `reasons[]`, and
`evidence_flow_ids[]`. **Scores rank where to look first; they are not
confirmed vulnerabilities.** Attack modules should import:

```python
from talos.input_validation.candidates import get_param_intelligence, list_candidates

intel = get_param_intelligence(db_path, param_id_or_uuid)
# intel["capabilities"], intel["candidates"], intel["profile"]
```

CLI: `show`, `candidates`, and `export parameter|host [--format json|markdown]`
display candidates. No findings are created by IV candidate scoring.

Control Panel: Attack → Input Validation module shows budget/status, candidates table,
and profiles (read APIs under `/api/input-validation/…`; UI at `/attack/input-validation`).

## Cache Strategy

- **Param-level phases (1–6, 8):** Cached by `(host, location, param_name)` — shared
  across all endpoints that contain the same parameter. One characterization serves all.
- **Reflection (Phase 7):** Cached per `(endpoint_id, param_name, location)` — must be
  tested independently for each endpoint.
- **Profiles:** `iv_param_profiles` / endpoint / app (versioned JSON with
  `schema_version`, capabilities, candidates). Offline rebuild:
  `talos input-validation synthesize`.
- **Resume:** On restart, planner continues from completed evidence. Use
  `run --ignore-cache` or `clear-cache` then `run` to wipe probe results and
  profiles for the scope and start at baseline. Phase shortcuts with
  `--ignore-cache` re-enqueue that phase only. `--force` is **not** used for
  re-analysis (CLI-019); it remains confirmation bypass only
  (e.g. `clear-cache --force`).

## Scope and Control

```bash
talos input-validation config --enable
talos input-validation run
talos input-validation run --host api.example.com
talos input-validation run --endpoint <id>
talos input-validation run --parameter username
talos input-validation run --ignore-cache
talos input-validation status
talos input-validation show <parameter_uuid>
talos input-validation candidates --attack xss --min-score 60
talos input-validation export parameter <uuid> --format json
talos input-validation baseline --ignore-cache
talos input-validation reflection --endpoint <id> --ignore-cache
```

**Migration (pre-revamp caches):** existing `iv_probe_results` →
`synthesize` (zero HTTP). Stale full-matrix cache after upgrade →
`clear-cache --force` then `run`. Fresh projects preferred
in beta.

---

# 14. Replay Engine

## Requirements

* exact request replay
* async execution
* high reliability

---

## Tool

* httpx

---

## Capabilities

* modify params
* modify headers
* change session
* parallel execution

---

## Token Refresh Hooks

Dynamic values:

* CSRF tokens
* JWT rotation
* nonce

---

### Mechanism

Extract:

* regex / JSONPath

Inject:

* header / param

---

## Dependency Handling

Example:

* request A returns order_id
* request B uses order_id

System:

* auto extract
* auto inject during replay

---

# 15. Diff Engine

## Compare

* status code
* response length
* JSON structure
* key fields
* headers

---

## Anomaly Signals

* 403 → 200 (high)
* new fields appear (high)
* error → success (high)
* large length delta (medium)

---

# 16. Attack Modules

## 1. IDOR

* swap identifiers across sessions

---

## 2. Auth Bypass

* remove tokens
* modify tokens
* mix sessions

---

## 3. Parameter Tampering

* remove param
* null value
* duplicate param
* change type

---

## 4. Boundary Values

* 0
* -1
* max int
* empty string
* long strings

---

## 5. Method Switching

* GET ↔ POST
* PUT ↔ PATCH

---

## 6. Replay Attacks

* repeat sensitive requests
* detect idempotency issues

---

# 17. Role-Based Attack Logic

For each endpoint:

* identify allowed roles
* replay with:

  * other roles
  * no auth
  * mixed auth

---

## Goal

Detect broken access control

---

# 18. Module Strategy

Modules are:

* human-defined
* for organization only

Engine must:

* operate per endpoint
* not depend on module boundaries

---

# 19. Global vs Local Testcases

## Global

* login
* JWT issues
* password reset
* session flaws

---

## Local (per endpoint)

* access control
* injection
* validation
* file upload

---

# 20. State Graph (Critical)

## Structure

```
node = endpoint
edge = transition
```

---

## Tracks

* sequence
* dependencies
* auth state

---

## Purpose

* reconstruct workflows
* enable sequence attacks

---

# 21. MPC (AI Layer)

## Tools

* list_endpoints
* get_endpoint
* get_param_profile
* get_sessions
* replay
* cross_session_replay
* diff
* get_anomalies

---

## AI Responsibilities

* choose targets
* choose attack strategies
* interpret results
* chain attacks

---

## AI Restrictions

* no raw request building
* no blind fuzzing

---

## Resources Provided

* endpoint graph
* param intelligence
* session map
* anomaly history

---

# 22. Execution Phases

## Phase 1 — Capture

* manual browsing
* role defined
* module defined

---

## Phase 2 — Structuring

* endpoint clustering
* param analysis
* session mapping

---

## Phase 3 — Attack

* deterministic modules first
* AI-driven exploration later

---

# 23. CLI Interface (Primary)

Examples:

```
talos set-role admin
talos set-module billing
talos endpoint list
talos replay --endpoint 12 --session user
talos run-test idor
```

> Live CLI uses `talos endpoint list` (see `docs/cli-cheat-sheet.md`).

---

## Principle

CLI = sole interface

---

# 24. Performance Constraints

* async replay
* multiprocessing workers
* indexed DB
* avoid large memory usage
* truncate large bodies

---

# 25. Critical Failure Modes

* processing inside proxy thread
* mixing sessions
* unreliable replay
* no normalization
* over-reliance on AI
* over-engineering modules

---

# 26. Minimum Viable Talos

System is valid when it can:

1. capture traffic reliably
2. normalize and store correctly
3. separate sessions cleanly
4. cluster endpoints
5. replay requests with valid tokens
6. perform cross-session replay
7. detect:

   * IDOR
   * missing auth
   * basic tampering effects

---

# 27. Long-Term Evolution

## Phase 2

* workflow reconstruction
* sequence attacks
* race conditions
* JS endpoint extraction

---

## Phase 3

* stealth browser integration
* partial automation

---

# 28. Core Principle (Final)

Deterministic system must work without AI.

AI operates on top of:

* clean data
* reliable replay
* structured state

Without that, system collapses.
