# URL Sink Discovery — Multi-PR Implementation Plan

## Goal

Add a first-class **URL Sink Discovery** intelligence layer so Talos can find parameters treated as URLs / hostnames / IPs / network resources **regardless of name**, then feed richer capabilities and attack candidates for:

- SSRF
- Open redirect
- Server-side fetch
- Webhook abuse
- OAuth redirect abuse
- URL parser inconsistencies
- (later) XXE external resource, SAML metadata fetch

This is **characterization and prioritization**, not exploit confirmation. No OAST exploit chains, no metadata-cloud RCE payloads as “findings,” no freeform shell.

---

## Architectural decision (locked)

**Do not bury this inside Input Validation as a name-list feature.**

Today:

```
Endpoint Intelligence (parameters.py)
        ↓
Input Validation (characterize behavior)
        ↓
Capabilities (flags)
        ↓
Attack Candidates (ssrf / open_redirect / …)
```

Target:

```
Endpoint Intelligence
    │
    ├── Parameter Extraction (+ structure discovery)
    │
    ├── URL Sink Discovery (passive)          ← NEW package
    │     value classifier
    │     name category classifier
    │     initial sink score / url_features
    │
    └── Input Validation
          generic characterization
          + URL sink characterization probes   ← IV extension only
                 │
                 ▼
        Unified Capabilities
          network_resource_sink (+ subfields)
          redirect_sink / fetch_sink / webhook_sink
                 │
                 ▼
        Candidate Engine
          ssrf | open_redirect | webhook_abuse | oauth_redirect | …
```

### Why this split

| Layer | Question it answers |
|-------|---------------------|
| URL Sink Discovery (passive) | “Does this input *look like* a network resource, and does its name suggest a sink *category*?” |
| Input Validation (active) | “How does the app *behave* when this input is URL-shaped?” |
| Capabilities | Stable consumer flags (not vulns) |
| Candidates | Prioritization only (`score >= 25`, reasons, evidence) |

### Home package

New package: **`talos/url_sink/`**

Mirrors existing pure-first modules (`error_intel`, `passive`, IV helpers):

| File | Responsibility |
|------|----------------|
| `value_classify.py` | Pure value → URL/hostname/IP/path/UNC/protocol features + score |
| `name_classify.py` | Pure name → sink category (redirect, webhook, media, …) |
| `features.py` | Compose `url_features` document + initial sink score |
| `catalog.py` | Categorized name dictionaries (replace flat token lists) |
| `decode.py` | Best-effort unwrap base64/URL-encoded JSON for structure walk |
| `jwt_claims.py` | Extract URL-bearing JWT claims as virtual params |
| `html_js_extract.py` | Hidden form fields + JS config URL keys → inventory candidates |
| `db.py` (optional later) | Persist sink features if not stored on parameters / IV profile |
| `cli.py` (later) | Operator inspection |

IV keeps ownership of **active** probes; candidates/capabilities remain in `talos/input_validation/` but consume sink features.

---

## Current baseline (what exists)

| Area | Today | Gap |
|------|-------|-----|
| EI extraction | query, form, JSON nested (dotted paths), GraphQL vars, multipart, XML leaves, path, cookies, **allowlisted** headers | No JWT claims, weak header allowlist for custom URL headers, no hidden forms / JS configs as params, no base64/URL-encoded JSON unwrap |
| Semantic typing | `url` only for `https?://` or thin name hints; hostnames → `string` | No hostname/path/UNC/protocol-relative/IPv6 richness |
| Name heuristics | Small open_redirect / SSRF token tuples in `candidates.py` | Flat, incomplete, not categorized |
| IV URL probe | Single type `https://talos.test/probe` | No scheme matrix, no canary host, no protocol/IP/path forms |
| Capabilities | `url_like_value`, `redirect_like` (booleans) | No `network_resource_sink` structure |
| Candidates | name + type soft-accept scoring | Misses random-named sinks; no fetch/DNS/timeout evidence |
| Attack engines | No SSRF/open-redirect verifier consuming candidates | Out of scope for this plan (handoff only) |

Key files to extend later:

- `talos/projects/parameters.py` — extract + semantic_type
- `talos/projects/db.py` — parameters schema / migrations
- `talos/input_validation/{type_intel,phases,planner,fingerprint,capabilities,candidates,profile,synthesize}.py`
- `tests/test_iv_candidates.py`, parameter extraction tests
- Docs: `docs/architecture.md`, `docs/input-validation.md`, `docs/cli-cheat-sheet.md`, `docs/updates.md`

---

## Data contracts (target)

### Passive: `url_features` (on parameter intelligence)

Stored either:

1. **Preferred Phase A–B:** JSON column / field on parameters inventory  
   e.g. `parameters.url_features` (TEXT JSON), or  
2. **Merge path:** `iv_param_profiles.observed.url_features` after first synthesize,  
   with passive copy always available pre-IV.

Shape:

```json
{
  "possible_url_value": true,
  "possible_hostname": false,
  "possible_ip": false,
  "possible_path": false,
  "possible_domain": false,
  "possible_unc": false,
  "possible_protocol": true,
  "protocols_seen": ["https"],
  "looks_like": ["url"],
  "name_category": "remote_asset",
  "name_categories": ["remote_asset", "remote_fetch"],
  "score": 95,
  "possible_network_resource": true,
  "evidence": ["value_scheme:https", "name:avatar"]
}
```

Rules:

- **Value dominates name** for score (e.g. `abc=https://…` ≈ 90–100).
- Email addresses are **ignored** (not network resource sinks).
- Name alone can set category + modest score, never invent “confirmed sink.”

### Active (post-IV): `network_resource_sink` capability payload

Prefer **structured observed block** + **capability flags**:

```json
"observed": {
  "url_sink": {
    "confidence": 92,
    "accepts_url": true,
    "accepts_hostname": false,
    "accepts_ip": true,
    "accepts_path": false,
    "accepts_unc": false,
    "accepts_protocol": true,
    "accepted_protocols": ["http", "https"],
    "requires_absolute": true,
    "requires_https": false,
    "dns_resolution_detected": false,
    "redirect_behavior": true,
    "fetch_behavior": true,
    "validation_behavior": "invalid_url_message",
    "error_classes": ["timeout", "connection_refused"]
  }
}
```

Flags (stable strings on `capabilities[]`):

- `network_resource_sink` (umbrella; confidence in observed)
- `redirect_sink`
- `fetch_sink`
- `webhook_sink`
- `protocol_support` (optional; detail in observed)

Keep `url_like_value` as **deprecated alias** → derived from `network_resource_sink` for one release so existing scorers/tests do not break.

### Candidate vocabulary extensions

Existing: `ssrf`, `open_redirect`

Add (emit only when score ≥ 25):

| Attack | Requires (conceptually) |
|--------|-------------------------|
| `ssrf` | `network_resource_sink` + (fetch \| DNS \| timeout behavior) **or** strong name category + URL accept |
| `open_redirect` | redirect category **or** redirect_behavior + network_resource_sink |
| `webhook_abuse` | callback/webhook category + fetch_behavior |
| `oauth_redirect` | redirect_uri-like name/path + redirect_behavior |

Keep prioritization-only contract; no Findings from this work.

---

## Name category catalog (replace flat lists)

Centralize the user-provided name list into **categories** in `catalog.py` (case-insensitive, `_`/`-`/`camelCase` normalized):

| Category | Examples (not exhaustive) |
|----------|---------------------------|
| `redirect` | redirect, return, returnTo, returnUrl, goto, next, continue, back, dest, destination, RelayState, cancel_url, success_url, failure_url, post_login, … |
| `webhook` | callback, callbackUrl, webhook, hook, notify, listener, receiver, event_url, … |
| `remote_fetch` | url, uri, fetch, resource, endpoint, origin, api_url, base_url, import, feed, sync, pull, … |
| `remote_asset` | avatar, image, logo, banner, photo, thumbnail, media, favicon, css, font, video, … |
| `import_metadata` | feed, rss, import, wsdl, xsd, swagger, openapi, metadata, opml, atom, schema, … |
| `infrastructure` | backend, proxy, gateway, upstream, host, hostname, server, cluster, node, pod, … |
| `network_probe` | healthcheck, probe, ping, validate, verify, check, lookup, resolve, dns, … |
| `path_like` | path, filepath, filename, file, document, download, upload, … |
| `oauth` | redirect_uri, redirect_url, return_uri, (claims later) |

Scoring: category biases **candidate family**, not whether a sink exists. Random names with URL values still score high via value classifier.

Full user list maps into these categories in PR-2 (no binary “is_url_param” only).

---

## Value classifier rules (passive)

`value_classify.classify(value: str) -> UrlValueFeatures`

Detect (in priority order; accumulate flags):

1. **Schemes:** http, https, ftp, ftps, gopher, dict, ldap, ldaps, ws, wss, file, jar, mailto (optional low weight), data, blob, sftp  
2. **IPv4** including private/link-local/loopback ranges (score as network resource; do not exploit)  
3. **IPv6** (`::1`, `fe80:`, `fd`, `2001:`, bracketed forms)  
4. **UNC** `\\host\share`  
5. **Filesystem paths** `/etc/passwd`, `C:\Windows` (path-like; lower score unless file://)  
6. **Hostname / domain** `example.com`, `foo.internal`, `*.local`  
7. **Fragments** `host:port`, `/path?a=b`, protocol-relative `//host/path`  
8. **Email** → ignore (`possible_network_resource=false`)

Score bands (illustrative):

| Pattern | Score |
|---------|------:|
| Absolute URL with scheme | 90–100 |
| Name-irrelevant full URL | 90–100 |
| IP literal | 70–85 |
| Hostname | 55–75 |
| Path-only / UNC | 40–65 |
| Name category only, value empty/unrelated | 15–35 |

`possible_network_resource = score >= threshold` (suggest **45** for inventory flag; candidates use richer rules).

---

## PR inventory (atomic, mergeable units)

### PR-1 — Pure value classifier

**Scope**

- Create `talos/url_sink/` package skeleton + module docs.
- Implement `value_classify.py` with tests for all pattern classes (URL, host, IPv4/IPv6, UNC, path, schemes, email ignore, protocol-relative).
- No DB, no EI wiring.

**Tests:** `tests/test_url_sink_value_classify.py`

**Docs:** package docstring only; short note in `docs/updates.md`.

---

### PR-2 — Categorized name catalog + classifier

**Scope**

- `catalog.py` with full categorized name list from product requirements.
- `name_classify.py`: normalize camelCase/snake/kebab; return primary + all matching categories.
- Unit tests for multi-match (`callback_url` → webhook + remote_fetch), nested leaf names (`config.oauth.metadata` → leaf `metadata`).

**Tests:** `tests/test_url_sink_name_classify.py`

**Out of scope:** wiring into candidates (still old tokens until PR-9).

---

### PR-3 — Compose `url_features` + attach to parameter inventory

**Scope**

- `features.py`: merge value + name → `url_features` document + score.
- Wire into `extract_flow_params` / `upsert_endpoint_params` path:
  - compute features from `sample_value` + `name`
  - persist JSON (migration on `parameters` table **or** store in an existing JSON bag if one exists — prefer new nullable `url_features TEXT` column with schema version bump in `db.py`).
- Expand `_semantic_type` lightly: map strong URL value features → `semantic_type=url` (and optionally `ip` stays ip).
- Hostnames that score as network resource should not force false `filename`.

**Tests:** parameter extract tests + feature compose tests.

**CLI:** optional `endpoint params` field display if cheap; else Phase E.

---

### PR-4 — Structure discovery: encoded & nested surfaces

**Scope**

- Extend body extractors:
  - Detect base64-encoded JSON blobs and URL-encoded JSON in form/query values; walk nested keys with **full dotted path** (`config.oauth.metadata.url`).
  - GraphQL variables already nested — ensure URL features attach per leaf.
  - Multipart: classify field values (not only filenames).
  - XML: existing leaf walk — attach features.
- JWT claim extraction (`jku`, `x5u`, `iss`, `aud` when URL-shaped; careful with `kid`):
  - emit virtual params e.g. name `jwt.jku`, location `header` or `cookie` with parent param link in features.evidence.
- Expand header allowlist for URL-ish headers:  
  `Referer`, `Origin`, `Content-Location`, `Link`, `Destination`, `X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-Host`, `X-Forwarded-Server`, `X-Forwarded-Proto` (proto may be scheme-only — low score), plus any header whose **value** classifies as network resource (value-first for custom headers).

**Tests:** encoded JSON, JWT claims, header value-first discovery.

**Risk control:** depth/size caps (mirror JSON depth ≤6); skip huge bodies; no recursive bomb.

---

### PR-5 — HTML hidden fields + JS configuration URL inventory

**Scope**

- New helpers in `url_sink/html_js_extract.py` (or extend passive HTML extractor **for inventory**, not only secrets):
  - Hidden `<input>` name/value pairs from HTML responses → candidate parameters associated with same host (and linking referrer path when known).
  - JS islands: `__NEXT_DATA__`, `__INITIAL_STATE__`, `window.__CONFIG__`, common `apiUrl`/`baseUrl` patterns — extract URL-shaped leaves with stable path names.
- Wire into FlowWorker **after** response body available (read-only inventory enrichment).
- Mark source: `url_features.evidence` includes `html_hidden` / `js_config`.

**Tests:** fixture HTML/JS (reuse `tests/fixtures/passive/` where possible).

**Risk control:** do not flood inventory with every static CDN string — require (name category **or** score ≥ threshold) and de-dupe by `(endpoint/host, path, name)`.

---

### PR-6 — IV: URL sink characterization probes

**Scope**

- New probe family / planner token e.g. `url_sink_probes` (standard when passive `possible_network_resource` **or** name category in {redirect, webhook, remote_fetch, remote_asset, import_metadata, infrastructure, network_probe}; deep always expands).
- Benign canaries only, e.g.:
  - `http://talos-canary.invalid/`
  - `https://talos-canary.invalid/`
  - hostname-only `talos-canary.invalid`
  - IPv4 loopback shape `127.0.0.1` (characterization; document as non-exploit)
  - path `/talos-canary`
  - optional UNC / `file://` on **deep+ only**
  - protocol variants on deep+: `ftp://`, `gopher://` (acceptance only)
- Record outcomes under `observed.types` / `observed.url_sink` / `tested.url_sink:*`.
- **Never** use real collaborator domains that imply confirmed SSRF finding in this PR.

**Files:** `phases.py`, `type_intel.py` or new `url_sink_probes.py` under IV, `planner.py`, `synthesize.py`.

**Tests:** planner selection + outcome synthesis fixtures (no live network required).

---

### PR-7 — Response fingerprinting for URL behavior

**Scope**

- Extend fingerprint/outcome classification for URL probe responses:
  - body/header phrases: invalid hostname, DNS lookup failed, cannot resolve, unable to fetch, unsupported protocol, timeout, connection refused, invalid redirect uri, host unreachable, malformed url, must be absolute URL, URL required, …
  - `Location` / redirect chain contains probe host → `redirect_behavior`
  - timing delta vs baseline → soft `fetch_behavior` / timeout class (threshold config)
  - status classes mapped into `observed.url_sink.error_classes`
- Pure analyzers + unit tests with canned bodies.

**Philosophy:** strong indicators for capabilities; still not Findings.

---

### PR-8 — Unified capabilities: `network_resource_sink`

**Scope**

- Add capability constants + derivation in `capabilities.py` / `profile.py`.
- Derive from:
  - passive `url_features`
  - IV `observed.url_sink`
  - existing type soft-accept
- Sub-capabilities: `redirect_sink`, `fetch_sink`, `webhook_sink` when category + behavior align.
- Preserve `url_like_value` as alias when network_resource_sink confidence ≥ X.
- Document capability table in `docs/input-validation.md`.

**Tests:** `test_iv_candidates` / new capability unit tests.

---

### PR-9 — Candidate engine rewrite (value-first)

**Scope**

- Replace narrow `_REDIRECT_NAME_TOKENS` / `_SSRF_NAME_TOKENS` with catalog categories + `url_features` + capabilities.
- Scoring principles:
  - Random name + URL value + accept → **emit ssrf/open_redirect candidates** (value-first).
  - Category biases which attack labels and score floors.
  - fetch/DNS/timeout/redirect behaviors reweight SSRF vs open_redirect.
  - New attacks: `webhook_abuse`, `oauth_redirect` (optional if want smaller PR: keep as reasons on ssrf/open_redirect first; prefer explicit labels for CP filters).
- Update `KNOWN_ATTACKS`, CLI filters, CP command tree, AI tool schemas if they enum attacks.
- Preserve `MIN_EMIT_SCORE = 25` and reason strings for operator trust.

**Tests:** extensive `test_iv_candidates.py` cases including `abc=https://…`.

---

### PR-10 — Operator surfaces (CLI, Control Panel, docs)

**Scope**

- CLI: show `url_features` on param intelligence; filter candidates by new attacks; optional `talos url-sink` inspect command (or under `input-validation show` / endpoint params).
- Control panel: display sink features + new capabilities on IV profile page; candidate attack filters.
- Docs: architecture diagram, input-validation capability/candidate tables, cli-cheat-sheet, updates.md phase notes, about-talos if needed.

**Tests:** route/CLI smoke as existing patterns.

---

### PR-11 (optional / later) — Endpoint & app rollups

**Scope**

- Endpoint/app profile aggregates: “N network_resource_sinks”, top categories.
- Inheritance: if app often accepts URLs, prioritize URL probes on new params (learning.py).

Can ship after Phase D if needed for prioritization at scale.

---

### Explicit non-goals (this program)

- Confirmed SSRF/open-redirect Findings modules / OAST verification engines
- Exploit payloads (cloud metadata smash, Redis gopher chains as attack confirmation)
- Freeform AI shell agents
- Client-data redaction pipeline
- Replacing BAC/unauth engines

---

## Execution phases (AI works one phase at a time)

Each phase = **mergeable vertical slice** combining 2–3 PRs, with tests green and docs updated for that slice. Implement phases **in order**.

### Phase 1 — Passive core (no HTTP)

**Includes:** PR-1 + PR-2 + PR-3  

**Deliverable:** Every extracted parameter can carry `url_features` with value-first scoring and categorized names. Inventory alone surfaces `abc=https://…` as possible network resource.

**Acceptance**

- [ ] Pure classifiers covered by unit tests (schemes, IP, host, UNC, path, email ignore)
- [ ] Full categorized catalog loaded; name normalize works for camelCase/snake
- [ ] Features persisted on parameter upsert from sample values
- [ ] `semantic_type=url` improved for URL-shaped values without names
- [ ] No IV/planner changes yet
- [ ] Docs: updates.md note + package docs

**Suggested AI prompt focus:** “Implement `talos/url_sink` value+name classifiers and wire `url_features` into parameter extract/upsert only.”

---

### Phase 2 — Structure discovery (still mostly passive)

**Includes:** PR-4 + PR-5  

**Deliverable:** Nested/encoded/JWT/header/HTML/JS surfaces expand the parameter inventory; full paths preserved (`config.callback.url`).

**Acceptance**

- [ ] Base64 + URL-encoded JSON walked with caps
- [ ] JWT claims emitted as virtual params when URL-shaped
- [ ] Header discovery value-first + expanded allowlist
- [ ] Hidden form + JS config extraction with de-dupe / score gate
- [ ] Regression: existing extraction tests still pass
- [ ] Docs: architecture EI section updated

**Suggested AI prompt focus:** “Expand EI extraction surfaces for URL sinks; do not touch candidate scoring yet.”

---

### Phase 3 — Active characterization (IV)

**Includes:** PR-6 + PR-7  

**Deliverable:** IV can probe URL-shaped params with benign canaries and record validation/fetch/redirect/DNS-like behaviors in `observed.url_sink`.

**Acceptance**

- [ ] Planner schedules URL probes when passive score/category warrants
- [ ] Standard budget remains controlled; deep+ expands protocols
- [ ] Fingerprint maps error phrases + Location reflection of canary
- [ ] Synthesis fills `observed.url_sink` without creating Findings
- [ ] Tests offline with canned fingerprints
- [ ] Docs: input-validation.md new probe family

**Suggested AI prompt focus:** “Add URL sink characterization probes and response fingerprinting to IV; characterization only.”

---

### Phase 4 — Capabilities + candidates (consumer contract)

**Includes:** PR-8 + PR-9  

**Deliverable:** Unified capabilities and value-first candidate generation for SSRF/open redirect/webhook/oauth prioritization.

**Acceptance**

- [ ] `network_resource_sink` (+ subflags) derived and listed in KNOWN_CAPABILITIES
- [ ] `url_like_value` still present as alias (compat)
- [ ] Random-named URL values produce candidates without name tokens
- [ ] Category biases attack label (redirect vs webhook vs ssrf)
- [ ] Behavior signals reweight scores; negatives still subtract
- [ ] `list_candidates` / CLI filters accept new attack names
- [ ] Heavy unit tests; golden reason strings stable enough for CP

**Suggested AI prompt focus:** “Wire sink features + IV url_sink observations into capabilities and rewrite open_redirect/ssrf scoring value-first.”

---

### Phase 5 — Operator polish + optional rollups

**Includes:** PR-10 + (optional PR-11)  

**Deliverable:** Operators can see and filter sink intelligence end-to-end; docs complete.

**Acceptance**

- [ ] CLI show/export includes url_features + network_resource_sink detail
- [ ] Control panel IV profile/candidates surfaces new fields
- [ ] architecture.md + cli-cheat-sheet + about-talos consistency
- [ ] Optional endpoint/app rollup if scheduled

**Suggested AI prompt focus:** “Expose URL sink intelligence in CLI and control panel; finish documentation.”

---

## Cross-phase dependency graph

```text
PR-1 ─┐
PR-2 ─┼─► PR-3 ─► Phase1 complete
      │            │
      │            ▼
      │         PR-4 ─┬─► PR-5 ─► Phase2 complete
      │               │
      └───────────────┘
                       │
                       ▼
                    PR-6 ─► PR-7 ─► Phase3 complete
                              │
                              ▼
                           PR-8 ─► PR-9 ─► Phase4 complete
                                     │
                                     ▼
                                  PR-10 (─► PR-11) Phase5
```

Phases 1→2→3→4 are **strict**. Phase 5 can start UI read-only work after Phase 1 if needed, but full filters need Phase 4.

---

## Testing strategy

| Layer | Approach |
|-------|----------|
| Pure classifiers | Table-driven unit tests (no DB) |
| Extraction | Fixtures: multipart, GraphQL, base64 form field, JWT Authorization, HTML hidden, NEXT_DATA |
| IV probes | Mock fingerprints / synthesize from synthetic probe rows |
| Capabilities/candidates | Extend `tests/test_iv_candidates.py` patterns |
| Regression | Existing IV suite + parameter suite green |

Run focus per phase:

```bash
# Phase 1
pytest tests/test_url_sink_*.py tests/test_endpoint*.py -q

# Phase 3–4
pytest tests/test_iv_*.py -q
```

---

## Config & safety

- New config knobs (under project/global, defaults safe):
  - `url_sink.passive.enabled` (default true)
  - `url_sink.html_js.enabled` (default true, with score gate)
  - `url_sink.iv_probes.enabled` (default true when IV runs)
  - `url_sink.score_threshold` (default 45)
  - `url_sink.iv_probe_tier` alignment with `probe_strategy`
- Auth artifacts remain skipped by IV surface rules unless `include_auth_artifacts`.
- JWT claim extraction is inventory-only; do not force IV mutation of production tokens by default without explicit opt-in.
- No client-data redaction module (product rule).

---

## Documentation deliverables (by phase)

| Phase | Docs |
|-------|------|
| 1 | `talos/url_sink` module docs; `updates.md` |
| 2 | `architecture.md` EI extraction surfaces |
| 3 | `input-validation.md` probe + fingerprint section |
| 4 | capability + candidate scoring tables; cheat-sheet attack filters |
| 5 | end-to-end narrative in architecture + about-talos |

Follow `docs/how to code.instructions.md`: purpose/IO/side-effects on modules; three-layer docs when behavior changes.

---

## Suggested merge / branch naming

```text
feat/url-sink-phase1-passive-core
feat/url-sink-phase2-structure
feat/url-sink-phase3-iv-probes
feat/url-sink-phase4-capabilities-candidates
feat/url-sink-phase5-operator
```

Within a phase, either stack PR-N branches or implement the phase as one PR if AI batch size prefers fewer merges — **phase acceptance criteria still apply**.

---

## Success metrics (product)

1. Parameter with name `abc` and value `https://cdn.example/x` gets high `url_features.score` without name catalog hit.
2. After IV, soft-accept / error-class evidence raises `network_resource_sink` confidence and SSRF candidate score.
3. `redirect` / `returnUrl` + Location behavior elevates `open_redirect` over generic SSRF when redirect-only.
4. `callback` / `webhook` + fetch-like behavior elevates webhook-biased scoring.
5. Name-only weak hits do not spam candidates (score floor + value/behavior gates).
6. IV remains free of exploit-shaped SSRF confirmation; candidates remain prioritization hints.

---

## Recommended first implementation order for the next agent

Start **Phase 1 only**:

1. Scaffold `talos/url_sink/`
2. Value classifier + tests
3. Name catalog + classifier + tests
4. `url_features` compose + parameters table migration + extract/upsert wire-up
5. Minimal docs

Do not start IV probes or candidate rewrite until Phase 1 is merged and green.


-----

start with phase 1

