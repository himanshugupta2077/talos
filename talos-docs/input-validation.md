# Input Validation Engine — How It Works

**Source of truth:** `talos/input_validation/`. When this document disagrees with code, the code wins.

**Related docs:** `docs/architecture.md` (subsystem map), `docs/cli-cheat-sheet.md` (CLI flags), `docs/updates.md` (operator UX / M12 notes).

---

## 1. Purpose and philosophy

The Input Validation (IV) engine **characterizes** how an application treats input. It does **not** exploit vulnerabilities.

It answers questions such as:

- What character classes are accepted vs rejected?
- How is input transformed (trim, encode, case fold)?
- Is the value reflected, and in which context (HTML, JSON, JS, URL)?
- Does a distinctive request value later appear on **another page/flow** (stored / cross-page reflection)?
- What length bounds and type constraints apply?
- How does the parser handle duplicates, nulls, arrays?

IV intentionally avoids exploit-shaped payloads on the `standard` limiter. Edge characterization (e.g. CRLF-style strings) is included on the unified operator scan (`deep`). Exhaustive remains a CLI-only full-matrix limiter.

**Candidates are prioritization hints, not confirmed findings.** Attack modules must still verify. IV never creates findings and never runs exploit chains.

**Stored / cross-page reflection** is **data-flow prioritization evidence** (value written on one endpoint observed later on a sink response). It is **not** XSS confirmation.

| Property | Value |
|----------|--------|
| Default state | **Disabled** — operator must enable |
| HTTP | Only via the Talos **scheduler** (no direct sends) |
| Burp | When `burp.enabled` and an upstream proxy is set, each probe carries `X-Talos-*` grouping headers (engine=`input-validation`, group=`endpoints`) |
| Scope unit | Parameter identity: `sha256(host\|location\|name)[:32]` |
| Output | Versioned intelligence profiles + attack **candidates** |

---

## 2. High-level pipeline

```
Endpoint Intelligence (parameters on qualified endpoints)
        │
        ▼
talos input-validation run  (auth pre-check → schedule)
        │
        ▼
Planner (adaptive DAG)  ──►  Scheduler jobs (iv_*)
        │                           │
        │                           ▼
        │                    Replay + inject probe value
        │                    (+ X-Talos-* headers when burp.enabled
        │                       and an upstream proxy is configured)
        │                           │
        │                           ▼
        │                    iv_probe_results (+ flow body)
        │                           │
        └──────── continue_param_plan() ──► next wave or synthesize
                                            │
                                            ▼
                              Offline synthesis (zero new HTTP)
                                            │
                    ┌───────────────────────┼───────────────────────┐
                    ▼                       ▼                       ▼
           classify_outcome          observed/tested           capabilities
           (per probe)               aggregates                + candidates
                    │                       │                       │
                    └───────────────────────┴───────────────────────┘
                                            │
                                            ▼
                              iv_param_profiles (+ endpoint/app rollup)
                                            │
                                            ▼
                              Consumer API / CLI / control panel
```

**Modules (code map):**

| Module | Package path | Role |
|--------|--------------|------|
| M1 Evidence | `fingerprint.py`, `outcomes.py` | Response fingerprints; outcome vocabulary + classifier |
| M2 Profile | `profile.py`, `db.py` | Versioned JSON shape; `iv_*_profiles` tables |
| M3 Synthesis | `synthesize.py` | Offline profile from `iv_probe_results` |
| M4 Multiprobe | `multiprobe.py` | Canary + multi-class single request |
| M5 Planner | `planner.py`, `engine.py` | Adaptive next-action DAG + job expansion |
| M6 Taxonomy / length | `taxonomy.py`, `length_search.py` | Class representatives; binary/log length |
| M7 Types / semantic | `type_intel.py` | Passive-first types; validation families |
| M8 Parser | `parser_intel.py` | Normalization + parser fingerprint |
| URL sink (Phase 3) | `url_sink_probes.py` + fingerprint helpers | Benign URL canaries → `observed.url_sink` |
| M9 Surface | `surface.py` | Path/header/cookie/multipart/GraphQL/XML inject |
| M10 Learning | `learning.py` | Endpoint + app aggregation; inheritance priors |
| M11 Candidates | `capabilities.py`, `candidates.py` | Flags + attack scores |
| M12 Operator UX | `cli.py`, control-panel routes | status / candidates / show / export |

---

## 3. Configuration and budgets

Stored in `input_validation_config` (per project). Defaults:

| Setting | Default | Notes |
|---------|---------|--------|
| `enabled` | `false` | Must enable before `run` |
| `auto_run` | `false` | Scheduler auto-enqueues unique untested parameters |
| `probe_strategy` / coverage | `deep` | **Unified operator scan.** `quick` \| `standard` \| `exhaustive` are CLI `--budget` limiters only. |
| `max_requests_per_param` | `0` | `0` → planner tier default (`deep` ≈ 40) |
| `include_auth_artifacts` | `false` | Skip session cookies / `Authorization` unless opted in |
| Analysis toggles | all on | baseline, multiprobe, identifier, characters, length, types, transformations, reflection, validation |

**Typical HTTP budget per parameter** (when no hard cap override):

| Tier | Approx. max requests | Behaviour |
|------|----------------------|-----------|
| `quick` | ~8 | Aggressive early stop (CLI limiter) |
| `standard` | ~18 | Multiprobe-first; class reps; pruned types (CLI limiter) |
| `deep` | ~40 | **Operator default.** Standard characterization + adaptive deep follow-ups |
| `exhaustive` | ~256 | Legacy full matrix (CLI limiter only — not used by Run or auto-run) |

`talos input-validation run` with no `--budget` uses the unified `deep` scan. Older projects that still have `standard` or `exhaustive` saved are upgraded on run/auto-run.

**Auto-run:** `talos input-validation config --auto-run on` (also enables the engine). The scheduler periodically starts the unified scan for unique untested parameters. Uniqueness:

- Endpoint: HTTP method + canonical origin + normalized path (five identical browser captures collapse to one endpoint).
- Parameter: `sha256(host|location|name)[:32]` — one plan even if the same name appears on several endpoints.

Synthesis and candidate listing are planner-driven. The Control Panel does not require a separate Synthesize action.

Auth is verified before scheduling (`verify_auth_for_iv_scan`). Cookie/header apps need a healthy per-role session. **NTLM / IIS Persistent-Auth** has no header to name — a credentialed `talos proxy auth` profile covering the scan hosts *is* the session (role `set-session` / session refresh is not required, even if leftover cookie or header names are configured).

Only **qualified** endpoints are probed (`endpoint_policy.qualified = 1` — at least one 2xx proxy capture).

---

## 4. Planner and probe phases

The planner is a pure state machine (`plan_next(PlanContext)`). The engine maps actions to scheduler job types and expands them into concrete probes.

### 4.1 State machine

```
INIT → ENSURE_BASELINE → MULTIPROBE → EVALUATE
                                    → CHAR_DRILLDOWN | LENGTH_BINARY | TYPE_CONFIRM
                                      | PARSER_PROBES | URL_SINK_PROBES | SEMANTIC_RULES | …
                                    → FINALIZE → SYNTHESIZE → DONE
```

After each IV job settles, the scheduler calls `continue_param_plan()` so the next wave is enqueued only when needed. Explicit phase CLI shortcuts can bypass the planner for a single phase.

**Re-run from baseline.** The planner treats `iv_probe_results` and profile `requests_used` / `synthesize_done` as completed work. `clear-cache` and `run --ignore-cache` therefore reset, for the selected scope:

- `iv_probe_results`
- `iv_param_profiles` plus scoped endpoint/app profiles
- `iv_param_cache` / `iv_reflection_cache`
- pending/paused `iv_*` scheduler jobs

A following planner `run` starts at baseline again. Phase shortcuts with `--ignore-cache` only re-enqueue that phase; they do not wipe other evidence.

### 4.2 Phases (what gets sent)

| Phase | Job type | What it measures |
|-------|----------|------------------|
| Baseline | `iv_baseline` | Unmutated (or reference) response fingerprint |
| Multiprobe | `iv_multiprobe` | One payload: high-entropy canary (`TL` + hex) + taxonomy class samples |
| Identifier | `iv_identifier` | High-entropy canaries (legacy weak list mainly on exhaustive) |
| Characters | `iv_characters` | Class representatives / drill-down (`char_drilldown`) |
| Length | `iv_length` | Log seeds + binary midpoints (`length_binary`) |
| Types | `iv_types` | Passive-first pruned type confirms (`type_confirm`). Boolean params send both `true` and `false`. JSON/GraphQL inject native types (see §4.4). |
| Validation | `iv_validation` | Core + semantic business rules + **type-family catalogs** (`semantic_rules`); no SQLi/XSS strings under standard |
| Parser | `iv_parser` | Dup keys, JSON null/empty/omit, array styles, normalization stages |
| URL sink | `iv_url_sink` | Benign URL canaries when passive `url_features` warrants (`url_sink_probes`) — see §4.3 |
| Transformations | analysis | Offline / finalize: trim, case, encode transforms |
| Reflection | analysis | Same-request reflection context (multiprobe / probe response) |

### 4.3 URL sink characterization probes (Phase 3)

**Source:** `talos.input_validation.url_sink_probes` + fingerprint helpers in `fingerprint.py`.  
**Philosophy:** Characterization only — no OAST collaborator domains, no SSRF exploit chains, no Findings. Phase 4 derives `network_resource_sink` (+ subflags) and value-first candidates from these observations.

**When scheduled**

Planner action `url_sink_probes` runs when passive Endpoint Intelligence warrants it:

- `url_features.possible_network_resource` **or** `url_features.score ≥ 45`, **or**
- `name_category` / `name_categories` in `{redirect, webhook, remote_fetch, remote_asset, import_metadata, infrastructure, network_probe, oauth}`, **or**
- `semantic_type=url`

Gated by the **types** analysis toggle **and** layered config
`url_sink.iv_probes.enabled` (default true). Score gate uses
`url_sink.score_threshold` (default 45). Runs even under standard **early stop**
when warranted so network-resource params still get canaries. Skipped when
`observed.url_sink` is already known or probes already completed.

**Inventory-only (never IV-scheduled):**

- `location=response` — HTML/JS response discovery rows (inject would be a no-op)
- Virtual `jwt.*` claim params — claim rewrite is not implemented; parent
  Authorization remains an auth artifact unless `--include-auth-artifacts`

**Config**

```bash
talos config set url_sink.iv_probes.enabled false --project
talos config set url_sink.score_threshold 50 --project
talos config set url_sink.html_js.enabled false --project   # FlowWorker response inventory
talos config set url_sink.passive.enabled false --project   # master passive kill-switch (worker)
```

**Canaries (benign only)**

| Label | Example payload | Tier |
|-------|-----------------|------|
| `url_sink:https` | `https://talos-canary.invalid/` | quick+ |
| `url_sink:http` | `http://talos-canary.invalid/` | standard+ |
| `url_sink:hostname` | `talos-canary.invalid` | quick+ |
| `url_sink:ipv4_loopback` | `127.0.0.1` | standard+ |
| `url_sink:path` | `/talos-canary` | standard+ |
| `url_sink:ftp` / `gopher` / `file` / `unc` | protocol / UNC forms | deep+ only |

Host uses the reserved **`.invalid`** TLD (never a real collaborator). Loopback/path/file forms are acceptance characterization, not exploit confirmation.

**Budget estimates**

| Tier | Approx. probes |
|------|----------------|
| `quick` | 2 |
| `standard` | 5 |
| `deep` | 8 |
| `exhaustive` | 9 |

**Response fingerprinting**

`analyze_url_sink_response` maps body/header phrases and Location into stable classes:

- DNS / resolve: `dns_lookup_failed`, …
- Fetch / connectivity: `unable_to_fetch`, `connection_refused`, `host_unreachable`, `timeout`
- Validation: `malformed_url`, `requires_absolute_url`, `requires_https`, `invalid_redirect_uri`, `unsupported_protocol`, `url_required`
- `Location` contains canary host → `redirect_behavior`
- Soft timing delta vs baseline (≥ ~800 ms) → `fetch_behavior`

**`accepts_*` discipline**

`accepts_url` / `accepts_hostname` / … are set only when there is evidence the value was
**processed** as a network resource:

- soft-accept that implies processing (`modified` / `encoded` / `normalized`), or
- soft-accept plus canary reflection / Location canary / DNS-or-fetch phrase classes, or
- any outcome with network-process error classes (DNS lookup failed, connection refused, …)

A pure fingerprint-identical `accepted` with no URL signals is recorded as `weak_accept`
under `evidence` only — the server may have ignored the mutation.

**Profile output**

Offline synthesis fills:

```json
"observed": {
  "url_sink": {
    "confidence": 0,
    "accepts_url": false,
    "accepts_hostname": false,
    "accepts_ip": false,
    "accepts_path": false,
    "accepts_unc": false,
    "accepts_protocol": false,
    "accepted_protocols": [],
    "requires_absolute": false,
    "requires_https": false,
    "dns_resolution_detected": false,
    "redirect_behavior": false,
    "fetch_behavior": false,
    "validation_behavior": "",
    "error_classes": [],
    "per_probe": {},
    "evidence": []
  }
}
```

Plus `tested.url_sink:*` family outcomes (positive and negative). **Does not** create Findings. Capability flags and candidates are derived in Module 11 (Phase 4).

### 4.4 Type-family probes and JSON native inject

**Source:** `type_intel.type_family_probes` / `json_native_probe_value` + `surface.inject_json_param`.

Large JSON bodies (dozens of keys) are already one IV parameter per dotted path (`address.city`, `headers.Host`, `items[].id`). Each probe is still one scheduler job and one unique replay flow. What was missing is **type-aware values** and **JSON type fidelity**.

**Native JSON inject.** Type-confirm and type-family probes that are meant to be scalars or arrays are written as JSON-native values:

| Observed field | Probe | Injected JSON |
|----------------|-------|----------------|
| `"enabled": true` | `boolean_false` | `"enabled": false` (not `"false"`) |
| `"count": 5` | `negative_int` | `"count": -999999` |
| `"tags": ["a"]` | `array_empty` | `"tags": []` |
| `"enabled": true` | `string` (type confusion) | `"enabled": "notabool"` |

Character / multiprobe / identifier payloads stay strings.

**Type-family catalogs** (selected first under `semantic_rules`, one unique flow each):

| Passive type | Standard | Deep+ |
|--------------|----------|-------|
| `boolean` | opposite polarity (`true` → `false`) | `yes` / `no` |
| `email` | plus-tag, display name, missing `@`, extra recipient | quoted local-part, newline (characterization, not exploit) |
| `array` | `[]`, `["talos"]`, string-instead-of-array | `{}`, `[[]]`, `[null]` |
| `integer` / `float` | existing negative / zero / huge | overflow, scientific notation; NaN/Infinity on exhaustive |
| `url` / Host-like JSON keys | URL sink canaries (§4.3) — same family as HTTP `Host` / `Location` | protocol / UNC / file forms |

JSON object keys that look like HTTP headers (`headers.Host`, `Location`, `Origin`, `Referer`) resolve to `semantic_type=url` so they get URL-sink canaries. Typed fields are **not** skipped just because multiprobe accepted character classes.

**Array paths.** `items[].id` and `items[0].id` rewrite the first (or indexed) array element. The array parameter itself (`tags`) is replaced as a whole.

**Cross-flow / stored reflection (parameter intelligence):** separately from the IV reflection analysis phase, every committed flow (proxy worker **and** replay/IV) can index distinctive request values and scan later response bodies for matches on the **same host**. Links are stored in `cross_flow_reflections` and merged into param profiles as `observed.reflection.cross_flow` (see §6–§7). Disabled by default:

```text
talos config set parameter_intel.cross_flow.enabled true --project
```

**Worker config reload:** the proxy `FlowWorker` reloads `parameter_intel.cross_flow` about every 60s while running, so enabling mid-session takes effect without a full restart (expect up to ~1 minute lag). Replay/CLI paths load project YAML on demand via `ensure_process_cross_flow_config`.

**Surfaces (M9):** inject locations include query, body, path segments, headers, cookies, multipart fields/filenames, GraphQL variables, XML leaves. Session/auth artifacts are skipped by default.

**Location-aware transport safety (headers/cookies):** IV characterizes application input handling, not HTTP client library validation. Header and cookie values must be legal for clients such as h11/httpx (no leading/trailing SP/HTAB; no CTL octets except HTAB mid-value; no NUL). The engine therefore:

| Layer | Behavior |
|-------|----------|
| Multiprobe / char probes | Header/cookie drop `null` and `control` class samples |
| Normalization (`norm:trim`) | Query/body use leading+trailing spaces; header/cookie use an internal double-space pad (transport-legal) |
| Validation / semantic | Header/cookie omit `null_byte`, SP-only `whitespace`, and `crlf` |
| Scheduler pre/post inject | `transport_skip_for_payload` / `transport_skip_for_headers` → probe **skipped** with `transport_invalid_header` or `transport_invalid_cookie` |
| Defense in depth | If replay still returns `Illegal header value` or an ASCII-codec encode error, status is **skipped** (not failed) |
| Non-ASCII header/cookie values | Sent as Latin-1 (or UTF-8 octets) — IV unicode (`é`) is a real probe, not a client crash |

Query, body, and path keep the full payload alphabet (path percent-encodes). Dedicated transport-parser / header-smuggling probes (raw sockets) are out of scope for default IV.

**Multi-level learning (M10):** after a param profile is written, endpoint and application (host) profiles are refreshed. Under `standard`/`quick`, inherited rejected classes (e.g. control/null) and known parser fingerprints can suppress repeat probe waves (confidence capped until local confirm).

---

## 5. Validation outcomes (IV outcome vocabulary)

Outcomes describe **how the application treated a mutation**, not exploit success.

Defined in `talos.input_validation.outcomes`:

| Outcome | Meaning |
|---------|---------|
| `accepted` | Response matches baseline (or identical fingerprint with reflection) |
| `modified` | Same success class; body/headers/schema differ |
| `encoded` | Value reflected after encoding (html/url/…) |
| `normalized` | Value reflected after trim/case/canonical transforms |
| `truncated` | Success class retained but body much shorter / reflected prefix shorter than sent |
| `rejected` | Clear validation/auth failure vs baseline (typically 2xx/3xx → 4xx/5xx, or new error payload) |
| `ignored` | Fingerprint identical and parameter effect known false |
| `unknown` | Insufficient or conflicting signal |

### 5.1 Soft-accept set

Several downstream systems treat these as “not hard-rejected”:

```
accepted | modified | encoded | normalized
```

Used for:

- Taxonomy class acceptance aggregation
- Capability flags (e.g. unicode support, URL-like value)
- Attack candidate scorers (`_SOFT_ACCEPT` in `candidates.py` / `capabilities.py` / `synthesize.py`)

`truncated` is special (length intelligence); it is **not** in the soft-accept set for class/type scoring, but length synthesis uses it explicitly.

### 5.2 Classification algorithm (`classify_outcome`)

Input: baseline `ResponseFingerprint`, probe fingerprint, optional `reflection_hints`.

Decision order (current implementation):

1. **Reject transition** — baseline success-like (2xx/3xx), probe error-like (4xx/5xx), or 2xx with new structured error signature → `rejected` (high confidence ~88–93).
2. **Encoded** — reflected and encoding not empty/`raw` → `encoded` (~85).
3. **Normalized** — reflected and transforms include trim/lowercase/uppercase/normalize/canonical → `normalized` (~80).
4. **Identical fingerprints**
   - `parameter_effect=false` → `ignored` (~75)
   - reflected → `accepted` (~90)
   - else → `accepted` (~70) (cannot prove the value was used)
5. **Truncation heuristic** — same success class + large relative/absolute body length drop → `truncated` (~65–78). Length probes may also upgrade soft-accept to `truncated` when only a proper prefix of a homogeneous payload is reflected.
6. **Modified** — same success class, content differs → `modified` (~72–95, boost if reflected / schema change).
7. **Odd status class changes** — e.g. 2xx→3xx → `modified` (~60); other → `unknown` (~45).
8. Else → `unknown`.

Fingerprints (`fingerprint.py`) compare status, content-type class, body length, normalized body hash, selected headers, JSON schema sketch, redirect summary, error signature, and optional timing.

### 5.3 From probe rows to profile fields

Offline synthesis (`synthesize_param_profile`) for each completed probe with a flow:

1. Build probe fingerprint from the flow body/status.
2. Detect reflection (or multiprobe canary analysis).
3. Call `classify_outcome` (baseline vs probe + reflection hints).
4. Aggregate into the parameter profile:

| Aggregate | Source analyses | Profile location |
|-----------|-----------------|------------------|
| Character / class acceptance | characters, multiprobe | `observed.acceptance.classes`, `observed.acceptance.chars` |
| Types | types | `observed.types` (+ `_summary`) |
| Length | length | `observed.length` |
| Validation families | validation | `tested{}`, `observed.semantic` |
| Parser | parser | `observed.parser`, `normalization_pipeline`, `tested.parser:*` |
| URL sink | url_sink | `observed.url_sink`, `tested.url_sink:*` |
| Reflection | multiprobe / reflection / payload presence | `observed.reflection` |
| Rejected classes | acceptance majority `rejected` | also `tested[class]` (negative evidence) |

**Class majority rule:** multiprobe per-class outcomes (preferred) and single-char probes vote into each taxonomy class; `_majority_outcome_entry` produces the class-level `{outcome, confidence, evidence_flow_ids}`.

**Taxonomy classes** (representatives drive multiprobe + char drill-down):

`alpha`, `digit`, `alnum`, `whitespace`, `control`, `quote`, `delimiter`, `operator`, `comment`, `path`, `separator`, `unicode`, `null`, `markup`, `encoding_meta`

Injection-relevant classes under standard when reflection/string-like: quote, delimiter, operator, markup, path, encoding_meta, comment. Structure classes (control, null, unicode) prefer deep+.

---

## 6. Capabilities (bridge from outcomes to candidates)

After aggregation, synthesis calls `enrich_profile_capabilities_and_candidates` (M11):

1. `apply_capabilities(profile)` → recompute `profile["capabilities"]`
2. `score_candidates(profile)` → write `profile["candidates"]`

Capabilities are **surface/behaviour flags**, not vulns. Derived from observed reflection, acceptance, types, length, baseline fingerprint, location, and parser block.

| Capability flag | Typical derivation |
|-----------------|-------------------|
| `reflective_input` | top-level, same-request, **or** cross-flow reflection state = reflected |
| `stored_reflection` | nested `cross_flow.state = reflected` (source→sink on another flow/page) |
| `html_context` / `js_context` / `json_context` / `url_context` | union of top-level + same_request + cross_flow sink contexts |
| `xml_body` | XML content-type / XML leaf surface / xml reflection |
| `json_parser` | JSON content-type or JSON parser keys present |
| `unicode_support` | unicode class soft-accepted |
| `strict_length` | length state `bounded` or `truncated` |
| `duplicate_parameter` | parser first/last/join on dup/array keys |
| `header_injection_surface` | location header (or header surface kind) |
| `path_parameter` | location path |
| `multipart_filename` / `graphql_variable` | surface kind |
| `redirect_like` | baseline fingerprint `redirect` true **or** `url_sink.redirect_behavior` |
| `url_like_value` | type `url` soft-accepted / primary type url; **also** compat alias when `network_resource_sink` confidence ≥ 45 |
| `network_resource_sink` | Umbrella: type URL soft-accept, passive `url_features` (score ≥ 45 / `possible_network_resource`), or active `observed.url_sink` accepts/behaviors (confidence in observed block) |
| `redirect_sink` | redirect/oauth name category **or** `url_sink.redirect_behavior` **or** baseline redirect + URL accept forms |
| `fetch_sink` | `fetch_behavior` / DNS / network error classes **or** NRS + remote_fetch-style categories |
| `webhook_sink` | webhook/callback name category (soft) + stronger when fetch/URL accept |
| `protocol_support` | `accepts_protocol` or non-empty `accepted_protocols` on `url_sink` |

Name alone does **not** invent `network_resource_sink` / `url_like_value` without value or accept evidence. `redirect_sink` / `webhook_sink` / `fetch_sink` also require measured signals (behavior, type soft-accept, or canary accepts) — not bare catalog names (`go`/`to`/`webhook`). Candidate scorers use **catalog categories** (not flat token lists) + value-first rules, and **do not emit** open_redirect/ssrf/webhook_abuse/oauth_redirect from name-only hits. High-priority score floors are skipped when type `url` is rejected.

---

## 7. Attack candidate creation from IV outcomes (detail)

### 7.1 Candidate shape

```json
{
  "attack": "xss",
  "score": 0,
  "confidence": 0,
  "reasons": ["human-readable evidence trail"],
  "evidence_flow_ids": ["flow-uuid", "..."],
  "reflection_modes": ["same_request", "cross_flow"],
  "stored_reflection": {
    "link_count": 1,
    "sinks": [
      {
        "method": "GET",
        "path": "/profile",
        "context": "html",
        "encoding": "raw",
        "reason": "value from username@POST /register reflected on GET /profile (html, raw)"
      }
    ]
  }
}
```

| Field | Role |
|-------|------|
| `attack` | Stable label (see vocabulary below) |
| `score` | Prioritization strength 0–100 |
| `confidence` | Quality of evidence used for the score (averaged from contributing **positive** entries) |
| `reasons` | Why this score exists (includes negative-evidence notes); stored reasons often first |
| `evidence_flow_ids` | Supporting flow UUIDs (capped at 20) |
| `reflection_modes` | Optional: `same_request` and/or `cross_flow` |
| `stored_reflection` | Optional: sink summary when cross-flow evidence contributed |

**Emit floor:** only candidates with `score >= MIN_EMIT_SCORE` (**25**) are kept. Sorted by score desc, then attack name.

**Vocabulary (`KNOWN_ATTACKS`):**

`xss` · `sqli` · `open_redirect` · `ssrf` · `webhook_abuse` · `oauth_redirect` · `hpp` · `header_injection` · `path_traversal` · `mass_assignment`

Scoring is pure: `score_candidates(profile)` does not touch the DB. Persistence happens when synthesis (or explicit recompute) writes the profile.

### 7.2 How IV outcomes enter the scorer

Each scorer reads a `_ProfileView` over:

| Input | How outcomes appear |
|-------|---------------------|
| `observed.acceptance.classes[cls].outcome` | Soft-accept / rejected for taxonomy classes (`quote`, `markup`, `control`, …) |
| `tested[key].outcome` | Validation/parser negatives and family keys (`crlf`, `quote`, `type:url`, …) |
| `observed.types[tname].outcome` | Soft-accept / rejected for type probes (e.g. `url`) |
| `observed.reflection` | top-level state/contexts; nested `same_request` + `cross_flow` when merged |
| `capabilities[]` | Derived flags (soft-accept + reflection + URL sink Phase 4) |
| `observed.parser` | Structural behaviours (not always outcome labels; behaviours like `first_wins`) |
| `observed.url_features` | Passive EI copy (score, categories, possible_network_resource) |
| `observed.url_sink` | Active canary characterization (accepts_*, redirect/fetch/DNS, error_classes) |
| `name` / `location` | Catalog name categories (via `url_sink.name_classify`) and surface biases |

Helpers:

- `class_soft_accept(cls)` → class outcome ∈ soft-accept  
- `class_rejected(cls)` → class outcome == `rejected`  
- `type_soft_accept` / `type_rejected` → same for types  
- `has(capability)` → flag present  

Negative evidence **lowers** scores and is recorded in `reasons` (e.g. “negative evidence: quotes rejected”).

---

### 7.3 XSS (`_score_xss`)

**Goal:** prioritize reflected injection-relevant parameters, especially HTML context with markup accepted. **Stored / cross-page reflection satisfies the reflection gate** the same way same-request reflection does.

| Signal | Score delta | IV outcome / evidence |
|--------|-------------|------------------------|
| Reflective input (any mode: same-request or cross-flow) | +30 | Multiprobe/reflection synthesis **or** stored links merged into profile |
| Stored / cross-flow specifically | +12 | Once per candidate when `cross_flow` reflected |
| `html_context` | +25 | Same-request or stored sink context / HTML content-type while reflected |
| `js_context` | +22 | JS/javascript context |
| `url_context` + reflected | +8 | URL context |
| `json_context` + reflected | +5 | JSON context (lower XSS relevance) |
| Class `markup` soft-accept | +28 | Outcome on markup representative (`<`, etc.) accepted/modified/encoded/normalized |
| Class `quote` soft-accept | +12 | Quote class soft-accept |
| Class `markup` **rejected** | −20 | Negative evidence |
| Class `quote` **rejected** | −8 | Negative evidence |
| **High-priority pattern:** reflected + HTML context + markup soft-accept | `score = max(score, 85)` | Combined |
| **Stored + HTML without markup tests** | `score = max(score, 55)` | Prioritization floor only |

**Gate:** if **not** reflected (neither same-request nor cross-flow) and running score &lt; 40 → **no XSS candidate** (avoids noise from pure markup acceptance without reflection).

**Profile requirement:** XSS candidates from stored reflection need an existing `iv_param_profiles` document (after synthesize, or recompute on an existing profile). Operators without IV still see `parameters.cross_flow_*` flags and raw links via `talos input-validation reflections`. Soft profile stubs on first link are **out of scope**.

**Evidence flows:** markup/quote class entries + reflection / cross-flow source+sink flow IDs.

**Reason example (stored-only):**

```text
value from username@POST /register reflected on GET /profile (html, raw)
```

---

### 7.4 SQLi (`_score_sqli`)

**Goal:** characterization priority for quote/operator/comment classes on string-like params. **Not** confirmation of SQL injection.

| Signal | Score delta | IV outcome / evidence |
|--------|-------------|------------------------|
| String-like primary/semantic type | +15 | Type summary / semantic (not reject/accept alone) |
| Primary integer/bool/float | −15 | Reduces classic SQLi priority |
| Class `quote` soft-accept | +30 | Core injection class outcome |
| Class `operator` soft-accept | +20 | |
| Class `comment` soft-accept | +18 | |
| Class `quote` rejected | −35 | Strong negative |
| Class `comment` rejected | −10 | |
| Class `operator` rejected | −10 | |
| Tested key `quote` / `class:quote` rejected | −20 (if not already noted) | Validation/tested negative |
| Quote + operator + comment all soft-accept | `score = max(score, 70)` | Combined |

**Emit:** only if score ≥ 25. No reflection gate (unlike XSS).

---

### 7.5 Open redirect (`_score_open_redirect`) — value-first (Phase 4)

| Signal | Score delta | IV outcome / evidence |
|--------|-------------|------------------------|
| Catalog category `redirect` | +35 | `url_features.name_categories` / classify_name |
| OAuth category (also redirect-relevant) | +18 | Soft bias; dedicated attack is `oauth_redirect` |
| Capability `redirect_sink` | +18 | Derived from category / redirect_behavior |
| `redirect_like` **or** `url_sink.redirect_behavior` | +30 | Baseline redirect or Location canary |
| URL accept (`url_like_value` / type soft-accept / `accepts_url`) | +28–30 | Type probe or url_sink |
| Value-first high `url_features.score` (≥45) without redirect name | +15–22 | Random-named URL values |
| Semantic type url/uri/redirect | +12 | Passive/semantic |
| Type `url` **rejected** | −25 | Negative type outcome |
| **High-priority:** redirect category + URL accept | `score = max(score, 80)` | Combined |
| Redirect-only (Location without fetch) | slight reweight | Ranks open_redirect over generic SSRF |

### 7.6 SSRF (`_score_ssrf`) — value-first (Phase 4)

Overlaps URL signals with **server-side fetch** category / behavior bias.

| Signal | Score delta | IV outcome / evidence |
|--------|-------------|------------------------|
| Catalog categories `remote_fetch` / `remote_asset` / `webhook` / … | +32 | Categorized name catalog |
| Capability `network_resource_sink` | +20 | Phase 4 umbrella flag |
| `fetch_sink` / `fetch_behavior` | +28 | Active url_sink synthesis |
| DNS resolution detected | +18 | Canary fingerprint |
| Network error classes (timeout, DNS fail, …) | +15 | `url_sink.error_classes` |
| URL accept / `accepts_url` | +28–30 | Type or canary |
| Value-first high `url_features.score` without SSRF category | +20–30 | **Name-independent** (e.g. `abc=https://…`) |
| Semantic url/uri/callback/webhook | +12 | |
| Redirect-only behavior (no fetch/DNS) on redirect names | −12 | Prefer open_redirect |
| Type `url` rejected | −30 | Negative |
| Path location without SSRF category / NRS | −10 | Surface penalty |
| **High-priority:** SSRF category + URL accept | `score = max(score, 78)` | Combined |
| **High-priority:** NRS + fetch/DNS | `score = max(score, 72)` | Value-first floor |

### 7.6b Webhook abuse (`_score_webhook_abuse`)

| Signal | Score delta | Evidence |
|--------|-------------|------------------------|
| Webhook/callback category | +35 | Catalog |
| Capability `webhook_sink` | +15 | Derived |
| `fetch_behavior` / `fetch_sink` | +30 | Server-side callback delivery |
| Else URL accept boost | +28 | Soft surface without fetch |
| **High-priority:** webhook + fetch | `score = max(score, 75)` | Combined |

### 7.6c OAuth redirect (`_score_oauth_redirect`)

| Signal | Score delta | Evidence |
|--------|-------------|------------------------|
| OAuth / redirect_uri-like name | +35 | Catalog `oauth` or name substring |
| `redirect_behavior` / `redirect_sink` | +30 | Active or capability |
| Else `redirect_like` | +22 | Baseline |
| URL accept | +28 | Type / canary |
| **High-priority:** oauth + redirect/URL | `score = max(score, 78)` | Combined |

`open_redirect`, `ssrf`, `webhook_abuse`, and `oauth_redirect` can co-exist on the same parameter; operators use scores/reasons to prioritize. **No Findings** from candidate scoring.

---

### 7.7 HPP (`_score_hpp`)

Driven by **parser fingerprint outcomes/behaviours**, not character soft-accept.

| Signal | Score delta | Source |
|--------|-------------|--------|
| Capability `duplicate_parameter` **or** parser key with behavior ∈ `first_wins` \| `last_wins` \| `join` | base 55 | M8 parser probes / synthesis |
| Each matching key among `duplicate_query`, `duplicate_form`, `array_repeat` | +15 | Per-key behaviour |
| Location query or body | +5 | HPP-relevant location |

If no duplicate capability and no matching parser behaviour → **no candidate**.

---

### 7.8 Header injection (`_score_header_injection`)

| Signal | Score delta | IV outcome / evidence |
|--------|-------------|------------------------|
| `header_injection_surface` **or** location `header` | +40 | Surface (required; else no candidate) |
| Class `control` soft-accept | +30 | Control-char outcome soft-accept |
| Class `control` rejected | −20 | Negative |
| Tested keys `crlf` / `validation:crlf` / `header_crlf` soft-accept | +25 | Validation family outcome |
| Same keys rejected | −15 | Negative |

CRLF families are recorded under `tested` from validation synthesis (`payload_type` `crlf` → tested key `crlf`). Under **standard**, edge exploit-shaped strings are limited; deep+ adds more CRLF characterization.

---

### 7.9 Path traversal (`_score_path_traversal`)

Prioritization only. Confirmation is `talos attack path-traversal` (file-content
signatures vs the captured baseline). Any one gate is enough to continue:

| Signal | Score delta | IV outcome / evidence |
|--------|-------------|------------------------|
| `path_parameter` **or** location `path` | +35 | Surface |
| `multipart_filename` | +35 | Upload filename surface |
| Name tokens (`path`, `file`, `filename`, `include`, `template`, `download`, …) | +20 | LFI-ish name |
| Semantic type `filename` / `filepath` / `path` / `file` | +20 | Passive type |
| Observed value looks like a filesystem path (`../`, `/etc/`, `C:\`, `.php`, `file://`, PHP wrappers) | +25 | Value-first (no name required) |
| Else none of the gates | **no candidate** | |
| Class `path` soft-accept | +25 | Path class (`/`, `\`, `.`, …) outcomes |
| Class `separator` soft-accept | +10 | |
| Class `null` soft-accept | +10 | Null-byte truncation (classic LFI) |
| Class `path` rejected | −25 | Negative |

---

### 7.10 Mass assignment (`_score_mass_assignment`)

Lightweight prioritization for JSON/body unexpected-field surfaces.

| Signal | Score delta | Source |
|--------|-------------|--------|
| Location body **or** `json_parser`, and at least one of `json_parser` / `json_context` / `graphql_variable` | base +20 | Surface + capabilities |
| `json_duplicate_key` behaviour present | +30 | Parser M8 |
| `duplicate_parameter` | +15 | Capability |
| Sensitive name tokens (`role`, `admin`, `privilege`, …) | +25 | Name heuristic |

If body/JSON/GraphQL surface gates fail → no candidate. Score must still clear 25.

---

### 7.11 End-to-end example (XSS)

1. Baseline establishes fingerprint A.  
2. Multiprobe reflects canary in HTML; markup sample survives → class `markup` outcome soft-accept; reflection contexts include `html`.  
3. Synthesis stores:
   - `observed.reflection.state = reflected`, `contexts = ["html"]`
   - `observed.acceptance.classes.markup.outcome = accepted` (or modified/encoded)
4. Capabilities: `reflective_input`, `html_context`.  
5. Scorer: +30 reflection +25 HTML +28 markup → high-priority boost to ≥85 → emit `{attack: "xss", score: ≥85, …}`.  
6. If later char drill-down shows markup **rejected**, re-synthesis applies −20 and lowers priority.

### 7.12 End-to-end example (SQLi negative evidence)

1. Quote class probes return 400 vs 200 baseline → outcome `rejected`.  
2. Acceptance class `quote` + `tested.quote` record rejected.  
3. SQLi scorer applies −35 (and possibly tested −20), often dropping below emit floor even if operator class is soft-accepted.

---

## 8. Consumer API and operator surfaces

### 8.1 Programmatic (stable imports)

```python
from talos.input_validation.candidates import (
    get_param_intelligence,
    list_candidates,
    score_candidates,
)

# Single parameter dossier (by parameters.id or param_uuid)
intel = get_param_intelligence(db_path, param_id_or_uuid, recompute=False)

# Project-wide prioritization board
rows = list_candidates(
    db_path,
    attack="xss",
    min_score=50,
    min_confidence=0,
    host=None,
    capability=None,
    limit=500,
    recompute=False,
)
```

`get_param_intelligence` returns identity, full profile, capabilities, candidates, observed/inferred/tested slices, and optional passive parameter fields. With `recompute=True`, capabilities/candidates are re-derived in memory (not persisted unless synthesis writes).

### 8.2 CLI (representative)

```bash
talos input-validation config --enable
talos input-validation run
talos input-validation status
talos input-validation synthesize [--host HOST | --param-uuid UUID]
talos input-validation show <parameter_uuid>
talos input-validation candidates [--attack xss] [--min-score 50] [--host HOST]
talos input-validation candidates --capability stored_reflection
talos input-validation reflections [--param-uuid UUID] [--host HOST]
talos input-validation export parameter <uuid> --format json|markdown

# Cross-flow / stored reflection index (layered config; default off)
talos config set parameter_intel.cross_flow.enabled true --project
```

`show` prints **same-request** and **cross-flow** passive flags, dual reflection modes on the intelligence profile, and stored sink reasons. `candidates` reasons may lead with cross-page strings; filter with `--capability stored_reflection`.

### 8.3 Control panel

Routes under `/attack/input-validation` (overview, candidates board, parameter/endpoint/host dossiers; legacy `/input-validation/*` redirects) backed by `/api/input-validation/*` (status, profiles, candidates, config/run wrappers). Candidates expand shows `reflection_modes` + stored sinks; capability badges highlight `stored_reflection`. See `docs/control-panel/pages.md`.

---

## 9. What IV does **not** do

- Create `findings` rows or mark confirmed vulns  
- Send exploit payloads (SQLi/XSS strings off the default path)  
- Bypass auth pre-check or send HTTP outside the scheduler  
- Replace BAC / unauth engines (candidates are a handoff for prioritization only)  
- Treat soft-accept as “safe” or reject as “secure” without manual review  
- Treat **stored reflection** as confirmed XSS (it is data-flow prioritization evidence only)  
- Produce XSS candidates from stored links **without** an `iv_param_profiles` row  

---

## 10. Data stores (quick reference)

| Store | Role |
|-------|------|
| `iv_probe_results` | Per-probe payloads, analysis label, status, flow_id |
| `iv_param_cache` / `iv_reflection_cache` | Phase resume / per-endpoint reflection (not the intelligence document) |
| `iv_param_profiles` | Parameter intelligence JSON (observed, tested, capabilities, candidates) |
| `iv_endpoint_profiles` / `iv_app_profiles` | Multi-level rollups (M10) |
| `input_validation_config` | Enablement, budget, analysis toggles, exclusions |
| `scheduler_jobs` | `iv_*` job types executed by the daemon |
| `value_index` | Cross-flow value index (host + value hash + source param; full match string ≤256) |
| `cross_flow_reflections` | Source→sink links (no full secrets; hash + value_len only) |
| `parameters.cross_flow_*` | Passive flags: `cross_flow_reflected`, count, sink endpoint list JSON |

Profile envelope: `schema_version`, `engine_version` (e.g. `iv-evidence-2`), `profile_version`, `updated_at`.

---

## 11. Implementation file map

| Concern | Primary file |
|---------|----------------|
| Orchestration / scheduling | `engine.py` |
| Next-action decisions | `planner.py` |
| Fingerprints | `fingerprint.py` |
| Outcome labels + classifier | `outcomes.py` |
| Profile skeleton | `profile.py` |
| Probe → profile | `synthesize.py` |
| Multiprobe canaries | `multiprobe.py` |
| Cross-flow value index / sink scan | `talos/projects/value_reflection.py` |
| Char classes | `taxonomy.py` |
| Length search | `length_search.py` |
| Types / validation families | `type_intel.py` |
| Parser / normalization | `parser_intel.py` |
| Inject surfaces | `surface.py` |
| Endpoint/app learning | `learning.py` |
| Capability flags | `capabilities.py` |
| Attack candidate scores | `candidates.py` |
| Config / CLI / DB | `config.py`, `cli.py`, `db.py` |

Unit coverage for candidate scoring: `tests/test_iv_candidates.py` (XSS high with reflected HTML + markup; redirect name + URL type; quote rejection reduces SQLi; consumer API).

---

## 12. Summary

1. IV **probes** parameters under a planner-controlled budget and records responses.  
2. Each probe is **classified** into a validation outcome against baseline (+ reflection hints).  
3. Outcomes are **aggregated** into acceptance classes, types, length, tested families, reflection, and parser behaviour.  
4. **Capabilities** summarize surfaces and soft-accept signals.  
5. **Candidates** score attack families from those outcomes and flags for prioritization only.  
6. Operators and future attack modules consume candidates via CLI, control panel, or `get_param_intelligence` / `list_candidates` — then verify independently.
