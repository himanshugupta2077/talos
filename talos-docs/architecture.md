# Talos — System-Level Documentation

## Document ownership

| Document | Purpose |
|----------|---------|
| `README.md` | Project overview, installation, quick start |
| `docs/cli-cheat-sheet.md` | Complete CLI reference (must match live argparse) |
| `docs/architecture.md` | Internal architecture and subsystem design (this file) |
| `docs/updates.md` | Release notes / change log |
| `docs/about-talos.md` | Vision and design notes (**non-authoritative**; do not use for CLI or schema) |
| `docs/bac-decision-filter.md` | BAC decision filter configuration reference |
| `docs/burp-extension.md` | Burp upstream metadata headers + Talos Burp extension |

**Source of truth:** implementation under `talos/`. When this document disagrees with code, the code wins.

**Canonical product name:** Talos (CLI package `talos`).

**Canonical attack labels:** Broken Access Control (BAC); Authentication Bypass; Unauthenticated Execution; Input Validation.

---

## Architecture (Logical)

```
CLI (talos.__main__)
    │
    ├── talos project <cmd>
    │       ProjectManager → registry.json + per-project storage
    │
    ├── talos config show|effective|get|set|unset|edit | <section>
    │       Layered configuration → EffectiveConfig (CLI-022)
    │
    ├── talos proxy start | config
    │       mitmdump + TalosAddon (capture) + optional upstream mode
    │       HTTP Manipulation Engine (request + response rules); scope; FlowQueue
    │       starts FlowWorker + ReplayScheduler daemons
    │
    ├── talos role | module | access
    │       capture tagging + access matrix + coverage/signals
    │
    ├── talos auth
    │       auth artifact names; Authentication Bypass test
    │
    ├── talos auth-config
    │       AUTO/MANUAL providers; flows; extractors; session health (L1–L3)
    │
    ├── talos endpoint
    │       list (inventory + filters), annotations, policy, priority,
    │       exclude/include, show, export
    │
    ├── talos replay | flow
    │       exact replay; flow inspection/export
    │
    ├── talos send
    │       Repeater Phase 2: draft → edit → send (once/Nx/parallel) →
    │       history/tree/diff/export (mutable; new flow per send)
    │
    ├── talos scheduler
    │       status/config/enqueue/clear/pause/resume (daemon runs with proxy)
    │
    ├── talos config http
    │       HTTP Manipulation Engine rules (create/list/match/actions/…)
    │
    ├── talos attack unauth | bac
    │       Unauthenticated Execution + Broken Access Control modules
    │
    ├── talos input-validation
    │       active parameter characterization (disabled by default)
    │
    ├── talos finding
    │       triage, groups, Markdown reports
    │
    ├── talos passive
    │       status/config/rules/documents/detections/rescan
    │
    └── talos ai
            WorkflowEngine: sessions, pin, budgets, audit;
            heuristic or LLM suggest/approve/deny; app notes; PTT;
            stdio MCP (tools/list + tools/call via engine);
            Tool Protocol (READ + notes + task_tree + role/module set-active);
            PolicyValidator → sealed ExecutionPlan → Executor
```

### Current CLI command tree

(Must match `docs/cli-cheat-sheet.md` and `talos --help`.)

```text
talos
├─ project   create / open / close / delete / rename / description /
│            list / scope (add|remove|list|clear|import) /
│            constraints / status / outscope (add|remove|list|clear|import)
├─ config    show / effective / get / set / unset / edit /
│            proxy | capture | scheduler | attack | mutation
├─ proxy     start / config
├─ role      create / add / list / show / rename / delete / set / unset
├─ module    create / add / list / show / rename / delete / set / unset
├─ access    client set|unset / server set|unset / delete / show / coverage / signals
├─ auth      set / unset / show / clear / test
├─ auth-config  set-provider / show-provider / set-session / clear-session /
│              add-flow / remove-flow / list-flows / set-extractor /
│              show-extractor / edit-extractor / remove-extractor / test /
│              validate / refresh / status / show / set-ttl /
│              add-expiry-signal / clear-expiry-signals / reset-health /
│              add-control-flow / remove-control-flow / list-control-flows
│              (<role> args accept name or UUID)
├─ endpoint  list / mark / unmark / show / policy / export / notes / tags /
│            priority / exclude / include / rule (CRUD+preview) / rules
├─ replay    flow / endpoint
├─ send      from / edit / once / redo / dup / show / export /
│            history / tree / diff / note   (Repeater — mutable send)
├─ flow      show / export
├─ scheduler status / config / enqueue / jobs list|show / cancel /
│            prune / clear / pause / resume
├─ mutation  add / list / edit / enable / disable / delete
├─ attack    unauth (run, config, filter) / bac (8 modules + filter)
├─ passive   status / config show|set / rules list /
│            documents list|show / detections list|show /
│            rescan --all|--document|--flow
│              (BAC --role / --module accept name or UUID)
├─ input-validation  run / config / status / resume / synthesize /
│                      candidates / show / export / clear-cache /
│                    exclude / include / show / export / 8 phase shortcuts
├─ finding   list / show / confirm / reject / reopen / duplicate /
│            note / group / report
└─ ai        start / stop / resume / reset-budget / status /
             mode set|clear-aggressive-ack /
             suggest / approve / deny / pending / plans show /
             notes show|edit|export / tools list /
             mcp serve / config show|set|unset|edit / audit list
```

---

## Full System Flow (CURRENT STATE)

```
[USER / OPERATOR]
    │
    │  (CLI control)
    ▼
[CLI LAYER]
    talos project / config / proxy / role / module / access / auth / auth-config /
    endpoint / replay / send / flow / scheduler / mutation / attack /
    input-validation / finding / ai
    │
    ▼
[PROJECT MANAGER]
    - effective project: --project / TALOS_PROJECT / registry ACTIVE
    - registry + per-project storage (open/close mutate ACTIVE only)
    - runs schema migration on project open and on override resolve (idempotent)
    │
    ▼
[PROXY START]
    mitmdump + TalosAddon
    │
    ▼
[TRAFFIC CAPTURE]
    Browser → Proxy intercept
    │
    ▼
[SCOPE FILTER]
    is_url_in_scope(full_url)   # Basic Scope: scheme+host+port+path    ├── NO → drop
    └── YES
    │
    ▼
[FLOW EXTRACTION]
    - raw request/response
    - headers filtered
    - bodies truncated if needed
    - role_id + module_id stamped
    │
    ▼
[IN-MEMORY QUEUE]
    (bounded, drop if full)
    │
    ▼
[WORKER THREAD]
    │
    ├── validate flow
    ├── attach project_id
    ├── normalize URL
    ├── upsert endpoint
    ├── store flow (DB)
    ├── update endpoint_roles
    │
    ├── ENDPOINT INTELLIGENCE (passive — built from captured traffic only)
    │   │
    │   └── Parameter Intelligence
    │           Extract all observable input surfaces:
    │             path params  (dynamic segments from normalized path)
    │             query params
    │             body params  (JSON nested, form, multipart, XML, GraphQL variables)
    │             security + URL-ish headers  (Authorization, Referer, Origin,
    │                                Content-Location, Link, Destination,
    │                                X-Original-URL, X-Rewrite-URL, X-Forwarded-*, …)
    │             value-first custom headers (value classifies as network resource)
    │             cookies
    │             response inventory (location=response): HTML hidden inputs + JS/bootstrap config
    │           Infer semantic types: uuid | jwt | email | objectid | url | ip |
    │                                 hash | timestamp | filename | boolean |
    │                                 integer | float | array | string
    │           URL Sink Discovery (passive, talos.url_sink — Phases 1–2):
    │             value classifier (URL/host/IP/path/UNC/schemes; email ignored)
    │             name category catalog (redirect, webhook, remote_fetch, …)
    │             compose url_features → parameters.url_features (JSON, schema v53)
    │             value-first scoring: abc=https://… surfaces as network resource
    │             Phase 2 structure discovery:
    │               base64 / URL-encoded JSON unwrap → full dotted paths
    │                 (e.g. config.oauth.metadata.url)
    │               JWT URL claims → virtual jwt.jku / jwt.iss / jwt.aud / …
    │                 (inventory only — IV surface skips jwt.* and location=response)
    │               HTML hidden + __NEXT_DATA__ (script id= or window.__NEXT_DATA__=)
    │                 / window.__CONFIG__ / apiUrl assigns
    │                 (score ≥ url_sink.score_threshold or name+network-shaped value;
    │                  empty only for strong sink categories; de-duped; no external script fetch;
    │                  location=response skipped by same-flow reflection and IV scheduling)
    │             Phase 3 active IV (talos.input_validation.url_sink_probes):
    │               planner url_sink_probes when passive warrants → iv_url_sink jobs
    │               gated by types analysis + url_sink.iv_probes.enabled
    │               benign canaries (talos-canary.invalid, path/IP/forms; deep+ protocols)
    │               fingerprint phrases + Location canary + soft timing
    │               → observed.url_sink + tested.url_sink:* (no Findings)
    │             Phase 4 capabilities / candidates (network_resource_sink, value-first)
    │             Phase 5 operator CLI: endpoint params; show/export url_features + url_sink
    │           Passive Reflection Intelligence (same-flow):
    │             detect if param values appear in **same** response (raw / html_encoded / url_encoded)
    │             record: is_reflected, reflection_count, reflection_locations, reflection_encoding
    │           Cross-flow / stored reflection (parameter_intel.cross_flow; default off):
    │             on_flow_committed after proxy param upsert **and** after insert_replayed_flow
    │             index distinctive request values → value_index; scan later response bodies
    │             persist source→sink links → cross_flow_reflections; flags on parameters.cross_flow_*
    │             merge into IV profiles as observed.reflection.cross_flow + stored_reflection capability
    │           Track: seen_count, appears_in_roles, appears_in_modules
    │
    ├── PASSIVE SOURCE INTELLIGENCE (source-like bodies → secrets / disclosure)
    │       is_source_candidate? → PassiveScanQueue → SourceScanWorker
    │
    ├── ERROR INTELLIGENCE (error-like responses — Phases 0–9 landed; Findings deferred)
    │       is_error_candidate? → ErrorIntelQueue → ErrorIntelWorker
    │       package: talos.error_intel — clusters + observations; no Findings in v1
    │       Control Panel: Testing hub Passive module + Flow Errors tab (`/testing/errors`)
    │
    ├── compute auto-priority score
    ├── update endpoint qualification (sets qualified/baseline_flow_id/qualification_reason)
    └── write raw archive
    │
    ▼
[STRUCTURED STORAGE]
    SQLite:
        - flows
        - endpoints
        - parameters  (v25: semantic_type, same-flow reflection; v42: cross_flow_*; v53: url_features)
        - value_index / cross_flow_reflections  (v42: stored / cross-page value links)
        - roles/modules
        - access_map
        - endpoint_policy  (priority + exclusion + qualification + baseline_flow_id)
        - iv_param_cache      (Input Validation Engine cache)
        - iv_reflection_cache (per-endpoint reflection cache)
        - input_validation_config
    + JSONL archive (raw truth)
    │
    ▼
[ENDPOINT INTELLIGENCE — consumed by:]
    ├── Priority Engine      → auto-scoring based on parameters + auth + method
    ├── BAC Candidate Generator → parameter-aware candidate selection
    ├── Attack Engine        → parameter context for mutation generation
    ├── Input Validation Engine → parameter inventory to drive active probing
    └── Reports              → parameter intelligence in findings
    │
    ▼
[INPUT VALIDATION ENGINE] (active — disabled by default; tester enables explicitly)
    │
    ├── Consumes Endpoint Intelligence (parameter inventory)
    ├── Operates ONLY on qualified endpoints (qualified = 1 in endpoint_policy)
    │       Qualification requires at least one 2xx proxy_capture flow
    │       Endpoints with only redirects, errors, or no response are skipped entirely
    ├── Schedules jobs via Talos Scheduler (centralized concurrency)
    ├── Does NOT send requests directly — jobs execute through scheduler daemon
    │
    ├── Evidence foundations (Module 1 — pure, no HTTP volume change):
    │     talos.input_validation.fingerprint
    │       ResponseFingerprint from flow dicts: status, content-type class,
    │       body length, normalized body hash, selected header hash, JSON schema
    │       sketch, redirect summary, error signature, duration_ms sample
    │       compare_fingerprints(baseline, probe) → structural delta
    │     talos.input_validation.outcomes
    │       Vocabulary: accepted|modified|encoded|normalized|truncated|
    │                    rejected|ignored|unknown
    │       classify_outcome(baseline, probe, reflection_hints?) →
    │         {outcome, confidence, reasons, delta}
    │       IV_PROFILE_SCHEMA_VERSION / profile_envelope() for stored profiles
    │     Limitations: SPA/A-B header noise; body normalization best-effort
    │
    ├── Profile data model (Module 2 — storage contract, no HTTP volume change):
    │     talos.input_validation.profile
    │       Versioned multi-level JSON: parameter / endpoint / application
    │       observed | inferred | tested | attempts | capabilities | candidates
    │       parser + normalization_pipeline (M8 fills); budget_tier
    │       empty_*_profile / ensure_profile_shape / serialize_profile
    │     Tables (schema v35): iv_param_profiles, iv_endpoint_profiles,
    │                          iv_app_profiles
    │     CRUD: talos.input_validation.db upsert/get/list/delete_*_profile
    │     Separate from iv_param_cache (phase resume) by design
    │
    ├── Offline synthesis (Module 3 — zero new HTTP):
    │     talos.input_validation.synthesize
    │       synthesize_param_profile(db, param_uuid) from iv_probe_results + flows
    │       Fingerprint each probe (M1), classify_outcome, reflection/transforms
    │       Aggregate: acceptance (chars + taxonomy classes), types, length,
    │         validation → tested[], attempts[]; M11 capabilities + candidates
    │       Partial flags in inferred.synthesis when analyses missing / conflicts
    │       Conflicting reflection → state=conflicting, reduced confidence
    │       CLI: talos input-validation synthesize [--host|--param-uuid] [--dry-run]
    │       Auto-run after transform/reflection analysis jobs when probes ready
    │       Race guard: analysis jobs skip while scan jobs still pending/running
    │       show / export parameter display intelligence profile sections
    │       Multiprobe rows folded into observed.acceptance.classes (M4)
    │
    ├── Event-driven planner (Module 5 — adaptive DAG, not full matrix up front):
    │     talos.input_validation.planner (pure; no HTTP)
    │       plan_next(PlanContext) → PlanAction[] | done
    │       States: INIT → ENSURE_BASELINE → MULTIPROBE → EVALUATE →
    │               FINALIZE → SYNTHESIZE → DONE
    │       Budget: quick|standard|deep|exhaustive (+ optional max_requests_per_param)
    │       High-confidence early stop; reflection unknown → extra multiprobe;
    │       budget hard stop → finalize only; never analysis-before-evidence
    │     engine: plan_and_enqueue_for_param / continue_param_plan
    │     scheduler: after each IV job settles → continue_param_plan()
    │     Phase CLI shortcuts still enqueue one phase directly (bypass planner)
    │     Module 6 tokens: char_drilldown, length_binary (real executors)
    │     Module 7 tokens: type_confirm, semantic_rules (real executors)
    │     Module 8 tokens: parser_probes (real executor)
    │     Module 9: no new planner tokens (surface inject in prepare_iv_probe)
    │     Module 10: inheritance priors on PlanContext (no new action tokens)
    │
    ├── Character taxonomy & length (Module 6):
    │     talos.input_validation.taxonomy — class map, tier representatives,
    │       drill-down sets; observed.acceptance.classes + tested negatives
    │     talos.input_validation.length_search — log seed (standard ≤5) +
    │       binary midpoints; truncated vs rejected; observed.length
    │       (max_accepted, min_rejected, truncation_at, method)
    │
    ├── Types, semantic validation & negative evidence (Module 7):
    │     talos.input_validation.type_intel — passive-first type pruning + type-family catalogs (bool/email/array)
    │       (semantic_type + examples + name hints); type conflict handling;
    │       semantic business-rule probes; core vs edge validation split;
    │       tested{} family keys (null, crlf, type:*, enum_outside, …)
    │     standard: ≤4 type confirms for integer-like; no SQLi/XSS strings;
    │       skip very_long when max_accepted known
    │     deep+: edge exploit-shaped strings + CRLF characterization
    │
    ├── Normalization & parser fingerprinting (Module 8):
    │     talos.input_validation.parser_intel — norm probes (trim/case/url_decode;
    │       deep: double-encode + unicode); parser probes (dup query/form,
    │       JSON null/empty/omit/dup-key, array styles); structural inject;
    │       observed.parser + normalization_pipeline + inferred.parser_family
    │     Job type iv_parser; prepare_iv_probe(injection_mode=…)
    │     standard ~5 cost-controlled; quick skips; deep extra encoding probes
    │     tested.parser:duplicate etc. when rejects; capability duplicate_parameter
    │     Fingerprint only — no HPP exploit chains
    │
    ├── URL sink characterization (URL Sink Discovery Phase 3):
    │     talos.input_validation.url_sink_probes — select_url_sink_probes when
    │       passive url_features / name category / semantic_type=url warrants
    │     Benign canaries only (talos-canary.invalid .invalid TLD; loopback/path;
    │       deep+: ftp/gopher/file/UNC) — no OAST collaborator, no Findings
    │     Job type iv_url_sink; planner action url_sink_probes
    │     fingerprint.analyze_url_sink_response — DNS/fetch/timeout/malformed-URL
    │       phrases, Location canary → redirect_behavior, soft timing → fetch
    │     Synthesis → observed.url_sink + tested.url_sink:*
    │
    ├── URL sink capabilities + candidates (URL Sink Discovery Phase 4):
    │     capabilities.py — network_resource_sink (+ redirect_sink / fetch_sink /
    │       webhook_sink / protocol_support); url_like_value kept as compat alias
    │     candidates.py — value-first ssrf / open_redirect; new webhook_abuse /
    │       oauth_redirect; catalog categories replace flat name-token lists
    │     observed.url_features attached on synthesize / get_param_intelligence
    │     CLI/CP/AI filters accept new attack names; prioritization only
    │
├── Surface completeness (Module 9):
    │     talos.input_validation.surface — path segment rewrite ({name} from
    │       normalized_path); hardened header/cookie inject; multipart field +
    │       filename; GraphQL variables; XML leaf; auth-artifact + hop-by-hop skip
    │     Transport-legal header/cookie gates (is_http_header_value_legal,
    │       transport_skip_for_payload / transport_skip_for_headers) so probes
    │       that h11/httpx would reject as Illegal header value are skipped
    │       (transport_invalid_header|cookie) instead of failed
    │     Location-aware multiprobe/char/norm/validation payloads (no NUL/CTL
    │       in header/cookie; header norm:trim uses internal space pad)
    │     prepare_iv_probe uses surface.inject_value for all locations
    │     Default: skip session cookies / Authorization (include_auth_artifacts)
    │     Profiles: observed.surface {location, kind}; capabilities per surface
    │     Status: phase=surface skipped with clear skip_reason
    │
    ├── Multi-level learning (Module 10):
    │     talos.input_validation.learning — pure aggregate + inherit helpers
    │       param profiles → endpoint profile (tested, parser, classes, timing)
    │       endpoint profiles → application/host profile
    │     Inheritance priors (inferred only; observed local wins):
    │       confidence capped at 75 until local confirm
    │       standard/quick: suppress control/null + parent parser re-probe
    │       deep/exhaustive: re-confirm control/null
    │     synthesize / planner: refresh endpoint+app after param upsert;
    │       PlanContext carries inherited_tested / suppress_* flags
    │     CLI: show --endpoint / show --host; status profile counts
    │
    ├── Capabilities & attack candidates (Module 11):
    │     talos.input_validation.capabilities — derive flags from observed
    │       reflective_input (same-request or cross-flow); stored_reflection
    │       URL Sink Phase 4: network_resource_sink (+ redirect_sink / fetch_sink /
    │         webhook_sink / protocol_support); url_like_value compat alias
    │     talos.input_validation.candidates — score prioritization candidates
    │       {attack, score 0–100, confidence, reasons[], evidence_flow_ids[],
    │        reflection_modes?, stored_reflection?}
    │       xss | sqli | open_redirect | ssrf | webhook_abuse | oauth_redirect |
    │       hpp | header_injection | path_traversal | mass_assignment
    │       XSS: stored/cross-page evidence satisfies reflection gate (+12 stored)
    │       URL sink: value-first ssrf/open_redirect (catalog categories +
    │         url_features + observed.url_sink); no Findings from scoring
    │     Cross-flow merge: load_and_merge_cross_flow after _fill_reflection
    │       (synthesize) and on list_candidates / get_param_intelligence
    │     Stable consumer API (attack modules — no probe-table parsing):
    │       get_param_intelligence(db, param_id|uuid)
    │       list_candidates(db, attack=…, min_score=…, host=…)
    │     synthesize writes capabilities + candidates onto param profiles
    │     CLI show/export/candidates/reflections; scores ≠ confirmed vulns
    │
    ├── Operator experience (Module 12 — CLI / control panel / docs truth):
    │     CLI: run --budget, config --probe-strategy|--budget, status
    │       (requests_used, confidence buckets, pending plan actions),
    │       candidates [--attack|--min-score|--host|--capability], synthesize,
    │       reflections (raw cross-flow links), show (dual reflection modes),
    │       export parameter|host [--format markdown|json]
    │       with schema_version / engine_version / capabilities / candidates
    │     Config: parameter_intel.cross_flow.enabled (default false) via
    │       talos config set … --project
    │     Control panel: /api/input-validation/status (full), /profiles,
    │       /profiles/{uuid}, /candidates; Input Validation page surfaces
    │       budget, confidence, candidates + stored sinks, profiles (read-level)
    │     Docs: architecture, about-talos, cli-cheat-sheet, updates.md
    │     Migration note: pre-revamp probes → synthesize; stale → clear-cache
    │     Canaries: multiprobe prefix TL + high-entropy hex (not weak __TL__)
    │     value_reflection hooks: FlowWorker + insert_replayed_flow
    │
    ├── Phase 1: Baseline     — capture normal endpoint behaviour
    ├── Phase 1b: Multiprobe  — one multi-signal request (canary + taxonomy samples)
    │     talos.input_validation.multiprobe — canaries, payload builder, analyzer
    │     Job type iv_multiprobe; flow_meta.multiprobe structure; one flow per job
    │     probe_strategy / budget: quick|standard|deep|exhaustive
    │     standard: multiprobe first; planner skips full matrix when confident
    │     exhaustive: progressive waves approximate legacy full matrix
    ├── Phase 2: Identifier   — high-entropy canaries (legacy weak list: exhaustive only)
    ├── Phase 3: Characters   — class representatives / drill-down (M6);
    │     skipped under standard/quick when multiprobe on; full list: exhaustive
    ├── Phase 4: Length       — binary/log length search (M6); matrix: exhaustive
    ├── Phase 5: Types        — type_confirm (pruned) or full matrix (exhaustive)
    ├── Phase 6: Transformations — detect trim/lowercase/normalization etc.
    ├── Phase 7: Reflection   — endpoint-specific reflection analysis (not globally cached)
    ├── Phase 8: Validation   — semantic_rules + core validation; edge deep+ only
    ├── Phase 8b: Parser      — normalization pipeline + parser fingerprint (M8)
    │
    ├── Cache strategy:
    │     param-level analyses cached by (host, location, param_name) → shared across endpoints
    │     reflection cached by (endpoint_id, param_name, location) → per-endpoint
    │     resume: planner continues from completed evidence
    │     clear-cache / run --ignore-cache: reset probes + profiles + cache
    │     so the next planner run starts at baseline (phase --ignore-cache
    │     only re-enqueues that phase)
    │     (CLI-019: --ignore-cache on run + phase shortcuts; --force = confirm only)
    │
    └── Enriches Endpoint Intelligence after completion
    │
    ▼
[ACCESS MODEL]
    (manual input)
    - client_allowed
    - server_expected
    │
    ▼
[REPLAY ENTRY POINT]
    CLI:
        talos flow list                   ← discover flow UUIDs
        talos replay flow / endpoint
        talos auth test
    │
    ├── DEFAULT → enqueue job
    └── --right-now → immediate execution
    │
    ▼
[SCHEDULER]
    - priority queue
    - annotation checks (logout/dangerous)
    │
    ▼
[REPLAY ENGINE]
    - exact request reconstruction
    - no mutation (type 1)
    │
    OR
    - auth stripped replay (type 2)
    │
    ▼
[HTTP EXECUTION]
    httpx async request
    │
    ▼
[REPLAY RESULT STORAGE]
    - new flow inserted
    - linked to original_flow_id
    │
    ▼
[DIFF ENGINE]
    compare:
        - status
        - length
        - structure
    → verdict: SAME / DIFFERENT / ERROR
    │
    ▼
[AUTH VERDICT (if auth test)]
    SECURE / BYPASS / UNKNOWN
    │
    ▼
[ANALYSIS LAYER]
    CLI:
        talos access coverage
        talos access signals
    │
    ▼
[FINDINGS]
    Attack modules with trigger verdicts create findings (PRIMARY/LINKED)
    CLI: talos finding list|show|confirm|reject|reopen|note|group|report
    │
    ▼
[OUTPUT]
    - CLI output
    - Markdown reports (finding report, exports)
```

---


## Session Health (authoritative model)

Implementation: `talos.projects.session_health` (three layers).

| Layer | Name | Behavior | CLI |
|-------|------|----------|-----|
| **1** | TTL | Proactive refresh when auth age exceeds `(ttl - refresh_before)` | `talos auth-config set-ttl` |
| **2** | Expiry signals | Body / header / status patterns increment suspicion | `add-expiry-signal`, `clear-expiry-signals`, `reset-health` |
| **3** | Validation flows | Replay control flows with current `role_auth_state` injected; compare HTTP status to baseline | `add-control-flow`, `remove-control-flow`, `list-control-flows` |

There is **no** live CLI for URL-based validation. Schema columns `validation_endpoint_*` on `session_health_config` are legacy residue and are not exposed as commands.

Providers:

- **AUTO** — replay auth flows + extractors → `role_auth_state`
- **MANUAL** — tester-supplied session file → `manual_session_config` → `role_auth_state`

Session recovery (CLI-021; no SQLite edits):

- `talos auth-config clear-session <role>` — delete `manual_session_config` (`clear_manual_session_config`)
- `talos auth-config reset-health <role>` — zero Layer 2 suspicion (`reset_suspicion`)

---


### Scheduler job execution

The `ReplayScheduler` daemon (started with the proxy) executes pending jobs with jitter from `scheduler_config`. Job types include replay, `auth_test`, all BAC types, `unauth_attack`, and Input Validation `iv_*` jobs. Annotation and endpoint-policy pre-checks may skip jobs. Pause moves pending jobs to `paused`; resume restores them after any required MANUAL session validation for BAC attacker roles.

Job inventory and operations (CLI-016):

| Command | Behavior |
|---------|----------|
| `talos scheduler jobs list` | Inventory of jobs; filters `--status`, `--type` (exact or family prefix like `replay`/`bac`/`iv`), `--limit` (default 50); `--format json` |
| `talos scheduler jobs show <id>` | Full job detail (endpoint, flow, type, timestamps, failure reason, meta parameters); UUID or unique prefix |
| `talos scheduler cancel <id>` | Marks one **pending** or **paused** job `cancelled` (not mid-run) |
| `talos scheduler prune --status <s>` | Deletes terminal history for `done` / `failed` / `skipped` / `cancelled` (confirm / `--force`) |
| `talos scheduler clear` | Still bulk-deletes **pending** only (destructive; prefer cancel/prune when possible) |

Statuses: `pending` · `running` · `paused` · `done` · `failed` · `skipped` · `cancelled`.

## Findings Subsystem

The Findings subsystem is the central vulnerability management layer introduced
in schema v31. It sits between attack execution and reporting.

### Architecture position

```
Attack Modules
    ↓
Verdicts
    ↓
Finding Creation (talos.findings.creator)
    ↓
Finding Management (talos.findings.db)
    ↓
Evidence Collection (finding_evidence table)
    ↓
Reporting (talos.findings.report)
```

Attack modules produce verdicts and evidence. The Findings subsystem owns everything after.

### Verdict trigger map

| Attack Module | Verdict | Finding created? | Display label |
|--------------|---------|-----------------|---------------|
| BAC          | `POSSIBLE_BAC` | YES — status `TRIAGING` | Broken Access Control |
| BAC          | `SECURE` / `UNKNOWN` | No | — |
| Auth-bypass (`auth_test`, from `talos auth test`) | `BYPASS` | YES — status `TRIAGING` | Authentication Bypass |
| Auth-bypass  | `SECURE` / `UNKNOWN` | No | — |
| Unauthenticated Execution (`unauth`, from `talos attack unauth`) | `BYPASS` | YES — status `TRIAGING` | Unauthenticated Execution |
| Unauthenticated Execution | `SECURE` / `UNKNOWN` | No | — |
| CORS (`cors`, from `talos attack cors`) | `CORS_MISCONFIG` | YES — status `TRIAGING`; cluster `CORS:<origin>` | CORS Misconfiguration |
| CORS | `SECURE` / `UNKNOWN` | No (`ACAO:*` / ACAC-only are not findings) | — |

`talos.findings.model.VERDICT_TRIGGERS` and `ATTACK_DISPLAY` are keyed by
attack module (`bac` / `auth_test` / `unauth`) — every module that creates
findings must have entries in both maps, otherwise `create_finding_from_verdict`
silently produces nothing (this bit `unauth` once: it called the shared creator
with `attack_module="unauth"` before either map had an entry for it, so BYPASS
verdicts were dropped and never became findings; both maps now include it).

### Finding lifecycle

```
TRIAGING
    ├── confirm  → CONFIRMED
    ├── reject   → REJECTED
    └── duplicate --of <uuid> → DUPLICATE

CONFIRMED / REJECTED / DUPLICATE
    └── reopen   → TRIAGING
```

Lifecycle status is independent of finding **relationships** (PRIMARY / LINKED).
A LINKED finding may also have status DUPLICATE — the two concepts are separate.

### Finding relationships (PRIMARY / LINKED)

Every successful attack result still creates its own finding. Related findings
are grouped into a flat cluster so the main list stays readable.

```
F001 PRIMARY  (first successful technique for the cluster)
|
+-- F002 LINKED
+-- F003 LINKED
+-- F004 LINKED
```

| Field | Meaning |
|-------|---------|
| `relation_type` | `PRIMARY` or `LINKED` |
| `parent_finding_id` | Set only on LINKED; always points at a PRIMARY |
| `cluster_key` | Deterministic cluster identity (internal) |

**Rules:**
- PRIMARY findings have `parent_finding_id = NULL`
- LINKED findings must reference a PRIMARY parent
- Linked-to-linked (deeper trees) is not allowed — structure is always flat
- At most one PRIMARY per `cluster_key` (partial unique index
  `idx_findings_primary_cluster`)

**Cluster identity (attack-specific):**

| Module | Cluster key |
|--------|-------------|
| Unauth | `UNAUTH:<endpoint_id>` |
| Auth-bypass | `AUTH_TEST:<endpoint_id>` |
| BAC | `BAC:<endpoint_id>:<attacker_role_id>:<target_role_id>` |

For Unauth, auth mutations and request mutations are **not** part of the cluster
key. Multiple bypass techniques on the same endpoint form one cluster.

**Creation flow** (`talos.findings.creator` → `findings_db.create_finding`):

1. Build `cluster_key` for the attack module.
2. If no PRIMARY exists for that key → create PRIMARY.
3. If PRIMARY exists → create LINKED with `parent_finding_id = PRIMARY`.
4. On concurrent race (unique index violation) → re-fetch PRIMARY, create LINKED.

Attack execution is unchanged: every technique still runs, every `BYPASS` is
stored, every result may create a finding. Relationships only organise display.

**Status behaviour:**
- Default status changes affect **one finding only** (no inheritance).
- `talos finding reject|confirm|reopen <primary> --linked` is a one-time bulk
  op on the PRIMARY and currently linked children (PRIMARY only; errors if used
  on a LINKED finding). Future linked findings always start as `TRIAGING`.
- Bulk ops prompt when mixed statuses would be overwritten; `--force` skips the prompt.
- Every affected finding gets its own timeline event.

**CLI list defaults:**

```
talos finding list           # PRIMARY only (shows linked count)
talos finding list --linked  # LINKED only
talos finding list --all     # PRIMARY + LINKED
```

`talos finding show` on a PRIMARY lists linked children; on a LINKED finding it
shows the parent PRIMARY.

### Analyst notes

Free-form notes live on `findings.notes` and appear in `talos finding show` and
Markdown reports. Write them from the CLI:

```
echo "Confirmed with customer." | talos finding note set <uuid>
talos finding note clear <uuid>
```

`note set` / `note clear` also append a timeline event (`Analyst notes updated`
/ `Analyst notes cleared`). Endpoint-level notes and arbitrary tags (not safety
`logout`/`dangerous` marks) use `talos endpoint notes …` and `talos endpoint tags …`
against `endpoint_policy.notes` / `endpoint_policy.tags`.

### Finding groups

Groups are user-defined named collections — not tied to a vulnerability type.
A finding can belong to multiple groups. Groups are used for report organisation.

```
talos finding group create "Client Report"
talos finding group add "Client Report" <finding_uuid>
talos finding report --group "Client Report"
```

Group reports with more than one member finding include an **Index** section
at the top — a numbered `# | Title | Attack | Verdict | Finding ID` table —
before the individual finding reports (`talos.findings.report.generate_group_report`).
A single-finding group skips the index.

### Evidence model

Evidence is not stored inside the finding. The finding references evidence objects.
Each evidence item records:

| Field | Meaning |
|-------|---------|
| `evidence_type` | `original_flow` / `replay_flow` / `diff` / `scheduler_job` / `endpoint` / `module` / `role` / `attacker_role` / `target_role` / `bac_result` / `auth_test_result` / `unauth_result` / `analyst_note` |
| `reference_id` | Full UUID of the referenced DB object (never truncated in `finding show` or reports) |
| `label` | Human-readable description |
| `data` | JSON blob for structured metadata |

Evidence attached automatically by attack type:

**BAC:**
original_flow · replay_flow · diff · scheduler_job · endpoint · module · role · attacker_role · target_role · bac_result

**Auth-bypass (`auth_test`):**
original_flow · replay_flow · diff · endpoint · module · role · auth_test_result

**Unauthenticated Execution (`unauth`):**
original_flow · replay_flow · diff · endpoint · module · role · unauth_result

`module` and `role` are resolved from the original flow's `role_id`/`module_id`
columns (falling back to the BAC attacker role/module when supplied) so every
finding shows which application area and identity it was found under, in both
`talos finding show` and generated reports. Control Panel finding detail
(`GET /api/findings/{id}` → `flow_comparison`) surfaces the same Original vs
Attack/Testcase Flow comparison as first-class cards (method/URL/status/body
length + delta), not only buried evidence badges.

### Timeline

Every finding maintains an immutable ordered event log. Rather than writing a
single batch of "now" events at finding-creation time, `talos.findings.creator`
reconstructs the timeline from the real historical timestamps already recorded
elsewhere in the DB, in chronological order:

1. Baseline flow first appeared — `flows.captured_at` of the original flow.
2. Test case scheduled — `scheduler_jobs.created_at`.
3. Test case run started — `scheduler_jobs.started_at` (falls back to the
   replay flow's `captured_at` if the job has no explicit start time).
4. Attack replay executed against target — replay flow's `captured_at`.
5. Replay diff computed — same timestamp, labelled with the diff verdict.
6. Verdict determined — `scheduler_jobs.finished_at` (falls back to the diff
   timestamp).
7. Finding created — real "now", when the finding row was inserted.
8. Evidence attached — real "now", immediately after.

Any stage whose timestamp is unavailable is simply skipped — the timeline never
invents a time. Events are also appended manually by the analyst (status
changes). The timeline is never modified after being written — only appended.

### DB tables (v31, relationships v34)

| Table | Purpose |
|-------|---------|
| `findings` | One row per vulnerability instance; v34 adds `relation_type`, `parent_finding_id`, `cluster_key` |
| `finding_evidence` | Evidence references per finding |
| `finding_timeline` | Immutable event log per finding |
| `finding_groups` | Named finding collections |
| `finding_group_members` | Many-to-many findings ↔ groups |

Partial unique index: `idx_findings_primary_cluster` on `cluster_key` where
`relation_type = 'PRIMARY' AND cluster_key IS NOT NULL`.

---

## Passive Source Intelligence / Secret Exposure Engine

Passive, zero-HTTP subsystem that scans captured client-delivered response
bodies (HTML/JS/JSON/XML/text/CSS/source maps) for secrets and sensitive
exposure, then creates high-confidence Findings without drowning the UI in
noise. Package: `talos.passive` (Phases 0–12 + 14–16 landed in core CLI:
types/config/redaction + schema v39/v40 CRUD + candidate/classify/normalize +
queue/worker + detector pipeline + findings bridge + CLI + source-map + HTML
extractors + infrastructure disclosures + soft scan budget + docs). Control
Panel UX is Phase 13 (**Done** — Secret Detection workspace).

### Decision log (Phase 0 — design freeze)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Scan placement | Separate `PassiveScanQueue` + `SourceScanWorker` daemon | Proxy and FlowWorker stay capture-only; no heavy scan on response path or in `_persist_db` |
| Job execution | Own worker thread — **not** `ReplayScheduler` | Scheduler semantics = HTTP job execution; passive is pure local analysis |
| Source of truth | `flows.response_body` (BLOB) after commit | Job carries `flow_id`; worker reloads body from DB (no multi-MB bodies in two queues) |
| Archive | Never scan archive JSONL | Archive uses `_b64` serialization → false positives + recursive noise |
| Active validation | None in v1 | No outbound provider checks; engine remains passive |
| Intelligence vs findings | Observation → detection → finding | Passive tables store intelligence only; Findings subsystem owns lifecycle |
| Clustering | `PASSIVE_SECRET` | One cluster per project: first leak PRIMARY, later leaks LINKED |
| Source grouping | UI/query only (`logical_source_name`, URL) | Does **not** change PRIMARY/LINKED or manual `finding_groups` |
| Base64 / encodings | Decoder Pipeline only; not findings | Pure encoded blobs create no findings; decoded text is rescanned |
| Determinism | Rule + score + suppress first | No AI in v1 |
| Content scope | Source-like content, not JS-only | HTML, JS, JSON, XML, text, CSS, source maps; wasm skipped by default |
| Auto findings | CONFIRMED_PATTERN + HIGH only | MEDIUM / OBSERVATION_ONLY stay intelligence-only |
| Infrastructure | Observation-first | No auto-findings for private IPs/routes in v1 (config exceptions later) |
| Raw secret in evidence | Allowed on local workstation | Always redact in list UIs/CLI normal output |
| Enabled defaults | Scan from Phase 4; auto-findings from Phase 8 | Avoid findings spam before scoring/suppression/bridge are green |
| Body storage | Hashes + metadata in `source_documents`; bodies stay on `flows` | Dedup by `body_hash`; no second body copy |

### Locked invariants

1. Separate passive queue/worker (never block capture).
2. Observation → detection → finding (findings only when eligible).
3. Cluster by secret fingerprint (PRIMARY/LINKED), not by source file.
4. Base64 alone ≠ finding.
5. No archive JSONL scan.
6. No active (outbound) secret validation in v1.
7. Source-like content broadly; not JS-only.
8. Manual `finding_groups` unchanged.
9. No heavy work in `TalosAddon.response()` or expensive scan inside `FlowWorker._persist_db()`.
10. Never claim decryption — engine name is **Decoder Pipeline**.

### Target pipeline (not fully wired until later phases)

```
TalosAddon.response()
    → FlowQueue → FlowWorker
         → persist flow + endpoint
         → Parameter / Reflection Intelligence
         → is_source_candidate()?   # cheap gate only
              YES → PassiveScanQueue.enqueue(PassiveScanJob)
         → priority / qualification / archive (unchanged)

SourceScanWorker
    → classify → normalize → document registry (body_hash dedup)
    → extractors → detector pipeline → score + suppress
    → store passive_detections
    → create findings when eligible (Phase 8+)
```

### Phase status

| Phase | Scope | Status |
|-------|--------|--------|
| 0 | Design freeze + this decision log | **Done** |
| 1 | Package skeleton: constants, models, config defaults, redaction | **Done** |
| 2 | Schema v39 + passive DB CRUD (`talos.passive.db`) | **Done** |
| 3 | Candidate gate + classifier + normalizer | **Done** |
| 4 | Queue + worker skeleton + FlowWorker enqueue | **Done** |
| 5 | Detector framework + YAML rules + Stage 1 specific | **Done** |
| 6 | Contextual generic + suppress + scoring | **Done** |
| 7 | Decoder pipeline + entropy + rescan | **Done** |
| 8 | Finding bridge + PRIMARY/LINKED | **Done** |
| 9 | CLI (`talos passive …`) | **Done** |
| 10 | Source map `sourcesContent` extractor | **Done** |
| 11 | HTML inline `<script>` + bootstrap JSON extractors | **Done** |
| 12 | Infrastructure / disclosure detectors (observation-first) | **Done** |
| 13 | Control Panel detections API + Findings UX grouping | **Done** (Secret Detection workspace) |
| 14 | Soft scan budget + performance hardening | **Done** (core) |
| 15 | Rescan productization + scanner versioning | **Done** |
| 16 | Documentation + Talos Helper sync | **Done** |

### Schema (v39 + v40)

| Table | Role |
|-------|------|
| `source_documents` | Unique body identity: `UNIQUE(project_id, body_hash)`; scan lifecycle; v40 adds `parent_document_id` + `logical_source_name` for virtual docs |
| `source_occurrences` | Each flow/URL sighting of a document |
| `passive_detections` | Scored observations; optional unique on `(document_id, detector_id, value_fingerprint, match_start)`; `finding_id` link |
| `passive_scan_config` | Single-row defaults (`id='default'`); seeded on init/migrate |

Bodies remain on `flows.response_body`. Findings lifecycle lives in `findings`; `passive_detections.finding_id` links after Phase 8.

### Phase 3 — Candidate / classify / normalize

| Module | Role |
|--------|------|
| `talos.passive.candidate` | `is_source_candidate(content_type, path, …)` — cheap CT/path gate (+ optional empty/magic body checks). Used by FlowWorker after commit. |
| `talos.passive.classifier` | `classify_source(…) → SourceKind` — CT, extension/hints, then short magic/text sniff. |
| `talos.passive.normalize` | `normalize_body(bytes) → NormalizeResult` — charset → utf-8 → latin-1; records truncation. |

**Reject at gate:** empty body; `image/*` / media / PDF / WASM; path `.png`/`.jpg`/`.pdf`/…; magic PNG/JPEG/GIF/PDF/ZIP/WASM even if CT lies.  
**Allow:** HTML/JS/JSON/XML/text/CSS/source maps; `text/plain` + `application/octet-stream` when path or sniff says source-like.

### Phase 4 — Queue + worker + FlowWorker enqueue

| Module | Role |
|--------|------|
| `talos.passive.queue` | `PassiveScanQueue` — bounded, drop-on-full + WARNING + `dropped_job_count` (mirrors `FlowQueue`). |
| `talos.passive.worker` | `SourceScanWorker` — load body by `flow_id`, candidate → classify → normalize → upsert document + occurrence; skip re-scan when `scanner_version == SCANNER_VERSION`; `maybe_enqueue_passive_scan()` for FlowWorker. |
| `talos.proxy.addon` | Starts `SourceScanWorker` after `FlowWorker`; stops passive worker after FlowWorker on `done()`. |
| `talos.worker.FlowWorker` | After successful DB commit: if config `enabled` + `is_source_candidate(…)`, enqueue `PassiveScanJob` (never raises; never blocks capture). |

**Phase 4 behaviour:** document registry + occurrence only; documents marked `scan_status=scanned`. Same `body_hash` twice → second occurrence only.

### Phases 5–7 — Detector pipeline

| Module | Role |
|--------|------|
| `talos.passive.rules_loader` | Load `rules/*.yaml`, compile regex once, keyword index; fail closed on bad packs |
| `talos.passive.rules/` | Packs: cloud, source_control, payment, auth, crypto (PEM doc), generic keys |
| `talos.passive.detectors.specific` | Stage 1: keyword prefilter → provider regex |
| `talos.passive.detectors.pem` | Stage 1: multi-line PEM / OpenSSH private key blocks |
| `talos.passive.detectors.contextual` | Stage 2: sensitive-key assignment (`password=`, `apiKey:`, …) |
| `talos.passive.detectors.entropy` | Stage 3: high-entropy candidates gated by keyword/assignment |
| `talos.passive.decoder.pipeline` | Stages 4–5: base64/url/hex/html/unicode decode → rescan 1–2 only |
| `talos.passive.scoring` | Additive score → CONFIRMED/HIGH/MEDIUM/OBSERVATION |
| `talos.passive.suppress` | Placeholders, env refs, public test tokens, low-entropy generics |
| `talos.passive.detectors.orchestrator` | Full stage pipeline → `list[Detection]` |
| `SourceScanWorker` | Runs orchestrator before `mark_document_scanned`; persists detections |

**Phases 5–7 behaviour:** detections stored in `passive_detections` (suppressed omitted unless `store_suppressed_detections`). Encodings alone never create detections.

### Phase 8 — Finding bridge

| Module | Role |
|--------|------|
| `talos.findings.model` | `EVIDENCE_TYPE_SOURCE_*` / `PASSIVE_DETECTION`; `ATTACK_DISPLAY["passive_secret"]` |
| `talos.passive.finding_bridge` | `create_passive_secret_finding()` — cluster `PASSIVE_SECRET`; first PRIMARY, later LINKED |
| `SourceScanWorker` | After persist detections → auto-create findings when confidence ≥ threshold |

**Clustering:** all eligible leaks share `PASSIVE_SECRET`. First finding is PRIMARY ("Client-Side Secret Exposure"); later leaks are LINKED under it. Threshold default HIGH (CONFIRMED_PATTERN + HIGH). `auto_finding_threshold=OFF` disables. Secret detection is on by default (`passive_scan_config.enabled`). Finding detail / `talos finding show` highlight every redacted leak in source context.

### Phase 9 — CLI

```text
talos passive status | config show|set | rules list
talos passive documents list|show | detections list|show
talos passive rescan --all | --document ID | --flow ID
```

Secrets redacted in list/show. Rescan reloads body from occurrence `flow_id`.

### Phase 10 — Source map extractor

| Module | Role |
|--------|------|
| `talos.passive.extractors.sourcemap` | Parse JSON; emit virtual docs from `sourcesContent` |
| Schema v40 | `source_documents.parent_document_id` + `logical_source_name` |
| Worker | After parent scan, extract + scan virtual JS; findings titled “… in Source Map” when applicable |

Map without `sourcesContent` → parent occurrence/scan only, no crash. Caps: max 50 sources, size limits.

### Phase 11 — HTML inline extractors

| Module | Role |
|--------|------|
| `talos.passive.extractors.html` | Inline `<script>` **without** `src` → virtual JS docs; JSON script types + `__NEXT_DATA__` / bootstrap ids → virtual JSON; optional `window.__CONFIG__` islands |
| Worker / CLI rescan | After parent HTML scan (or rescan), register children under `parent_document_id` and run detectors |

Never fetches external scripts. Caps: max 40 scripts, 20 bootstrap islands, size totals. Findings from children may be titled “… (Inline HTML)”.

### Phase 12 — Infrastructure / disclosure detectors

| Module | Role |
|--------|------|
| `talos.passive.detectors.infrastructure` | INTERNAL_IP, INTERNAL_HOSTNAME, SENSITIVE_ROUTE (aggregated), DEBUG_PATH, EMAIL |
| Category | `infrastructure_disclosure` / `sensitive_info` — **never** auto-finding (bridge requires `category=secret`) |
| Aggregation | Up to 40 unique routes → **one** detection row with `routes[]` metadata (not 500 findings) |
| CLI | `talos passive detections list --category infrastructure_disclosure` |

Future hook: `endpoint_extraction_candidate` metadata on route aggregates for JS endpoint extraction (not implemented).

### Phases 14–15 — Performance + rescan

| Concern | Behaviour |
|---------|-----------|
| Size cap | `max_document_size` (default 2 MiB) → `too_large` status, no detectors |
| Soft time budget | `PassiveScanConfig.max_scan_time_ms` (default 0 = off); partial stage results kept |
| Keyword prefilter | YAML rules still keyword-gated before regex |
| Rescan | `talos passive rescan --all` targets `scanner_version != SCANNER_VERSION` (or `--force`); reloads body by occurrence `flow_id`; re-runs HTML/source-map extractors |
| Identity | `SCANNER_VERSION = 1.3.0` |

### Detector catalogue (v1 core)

| Family | Implementation |
|--------|----------------|
| Provider / structured | YAML packs: cloud, source_control, payment, auth, communication, database + `specific.py` |
| PEM / OpenSSH | `detectors/pem.py` |
| JWT compact | `detectors/jwt.py` |
| Connection strings | `detectors/connection_string.py` + database.yaml |
| Contextual generic | `detectors/contextual.py` + generic.yaml keys |
| Entropy | `detectors/entropy.py` (assignment/keyword gated) |
| Decoder | `decoder/pipeline.py` (not findings) |
| Infrastructure | `detectors/infrastructure.py` (observation-first) |

---

## Error Intelligence

Passive, zero-HTTP subsystem that captures **what an error contains**
(exception types, stack frames, DB vendors, path/host/version leaks),
fingerprints identical errors across the whole project, and links them to
flows / endpoints / parameters / attacks.

Package: **`talos.error_intel`**. UI label: **Error Intelligence**. Optional
product synonym **Improper Error Management** only if/when a Findings bridge
exists later — **not** a Finding subtype in v1.

### Why this is not Input Validation

| Layer | Job |
|-------|-----|
| **Input Validation** | How did the app treat a mutation? (`accepted` / `rejected` / …) |
| **Error Intelligence** | What did the rejection *contain*? (`SQLSyntaxErrorException`, path leak, …) |

IV keeps a thin `ResponseFingerprint.error_signature` (status + error JSON keys
+ HTML hints) for outcome classification. Error Intelligence **owns** rich error
parsing so IV does not become a second secret/stack-trace scanner.

Reuse (do not fork):

- Body volatility stripping ideas from `talos.input_validation.fingerprint.normalize_body_for_hash` (Phase 4)
- Passive Source Intelligence pipeline shape (`talos.passive`: gate → queue → worker → detectors → score → store)
- Cross-flow hook style from `talos.projects.value_reflection.on_flow_committed`
- Infrastructure detector path/traceback concepts — **lift, do not bolt** Error Intelligence onto secret scanning (secrets run on source-like bodies; errors run on **error-like** HTTP responses)

### Architectural placement

```
Traffic / Replay / Attacks
        │
        ▼
   Flow committed (body on flows table)
        │
        ├── Parameter Intelligence
        ├── Reflection Intelligence (value_reflection)
        ├── Passive Source Intelligence (source-like only)
        └── Error Intelligence  ← error-like responses
```

Sibling of `talos.passive` and `talos.input_validation`, not a submodule of either.

### Decision log (Phase 0 — design freeze)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Package name | `talos.error_intel` | Clear product/UI name; avoids vague `talos.errors` |
| Worker | Dedicated `ErrorIntelWorker` (Phase 6) | Different candidate gate and all-response scope from `SourceScanWorker` |
| Job execution | Own queue/worker — **not** `ReplayScheduler` | Same rationale as passive: local analysis only |
| Source of truth | `flows.response_body` after commit | Job carries `flow_id`; worker reloads body (no multi-MB bodies twice) |
| Generic 4xx storage | Default **off** (`store_generic_http_errors=false`) | Avoid flood of boring 400/404 chrome; gate may still enqueue |
| 404 default pages | Only stored if `store_generic_http_errors=true` | Low-value noise by default |
| Scanner versioning | `ERROR_INTEL_VERSION` | Rescan invalidation like `SCANNER_VERSION` |
| Intelligence vs findings | Clusters + observations only in v1 | No auto Findings; optional “Improper Error Management” bridge is a later product decision |
| Status scope | Not status≥400 alone | Stack / exception JSON on 200 is in scope |
| Attack modules | Never parse errors | Call `observe_error(...)` or rely on post-flow enqueue |
| IV coupling | Independent write path | Optional later: link `error_id` on rejected IV profiles by `flow_id` |
| Determinism | Rules + extractors + scoring | No LLM in v1 |
| Fingerprint inputs | Status **bucket** + category + language + exception + frames/message hashes | Endpoint / param / attack_type live on **observations** only |
| Secrets in stacks | Cap snippets; redact in list UIs | Source-like error bodies may still feed passive secret scan separately |

### Locked invariants

1. **Passive only** — no extra HTTP; only observe stored responses.
2. **Intelligence first** — tables store errors + sightings; **no auto Findings in v1**.
3. **Capture-safe** — cheap gate in FlowWorker; heavy parse on a dedicated queue/worker. Never block `TalosAddon.response()` or expensive work inside `_persist_db`.
4. **Body source of truth** — job carries `flow_id`; worker reloads `flows.response_body`.
5. **Not status≥400 alone** — stack traces / exception classes on 200 are in scope.
6. **Attack modules never parse errors** — they call `observe_error(...)` (or automatic post-flow hook).
7. **IV remains independent** — optional later link; IV does not reimplement classifiers.
8. **Deterministic** — rules + extractors + scoring; no LLM in v1.

### Target pipeline

```
Response (flow)
      │
      ▼
┌─────────────────┐
│  Cheap Gate     │  is_error_candidate?
│  (status / CT / │  empty body? image? pure static asset?
│   body sniff)   │
└────────┬────────┘
         │ no → ignore
         ▼
┌─────────────────┐
│  Error Detector │  multi-stage pattern + structure match
│  Orchestrator   │  (Phase 2+)
└────────┬────────┘
         │ no hits → ignore (or generic http if configured)
         ▼
┌─────────────────┐
│  Extractors     │  exception type, frames, paths, hosts, versions
└────────┬────────┘
         ▼
┌─────────────────┐
│  Normalize      │  strip UUIDs, timestamps, line numbers, req IDs
└────────┬────────┘
         ▼
┌─────────────────┐
│  Fingerprint    │  → error_id (cluster identity)
└────────┬────────┘
         ▼
┌─────────────────┐
│  Classify       │  category + language + tech + severity
└────────┬────────┘
         ▼
┌─────────────────┐
│  Store          │  error_clusters + error_observations
└─────────────────┘
```

### Phase status

| Phase | Scope | Status |
|-------|--------|--------|
| 0 | Design freeze + this decision log + package skeleton | **Done** |
| 1 | `is_error_candidate` gate | **Done** |
| 2 | Detector stages A–G + `ErrorDetectorOrchestrator` | **Done** |
| 3 | Classification model (category + severity scoring) | **Done** |
| 4 | Normalize + fingerprint | **Done** |
| 5 | Schema v43 + `error_clusters` / `error_observations` / config CRUD | **Done** |
| 6 | Queue + `ErrorIntelWorker` + FlowWorker / replay hooks | **Done** |
| 7 | Parameter / attack context enrich + rollups | **Done** |
| 8 | CLI (`talos error-intel …`) | **Done** |
| 9 | Control Panel (Passive workspace + Flow Errors tab) | **Done** (UI under Testing hub `/testing/errors`; API `/api/error-intel/*`; intelligence only) |
| 10 | Docs + golden fixtures expansion | In progress (partial with 0–9) |

### Public entrypoint

```python
observe_error(
    *,
    project_id: str,
    flow_id: str,
    response_status: int | None = None,
    response_headers: dict | str | None = None,
    response_body: str | bytes | None = None,  # or load from DB
    endpoint_id: str | None = None,
    parameter_uuid: str | None = None,
    parameter_name: str | None = None,
    attack_type: str | None = None,   # proxy | replay | iv | bac | unauth | …
    payload: str | None = None,       # redacted/truncated in storage
    duration_ms: float | None = None,
) -> list[ErrorObservation]
```

Production path prefers **enqueue-by-flow_id** (Phase 6) so callers never pass
multi-MB bodies twice. Contextual enrich:

```python
attach_error_context(project_id=…, flow_id=…, parameter_uuid=…, attack_type=…, payload=…)
```

### Phase 1 — Candidate gate

| Module | Role |
|--------|------|
| `talos.error_intel.candidate` | `is_error_candidate(...)` — cheap pure gate for FlowWorker / observe |
| `talos.error_intel.observe` | `observe_error` / `attach_error_context` public API (Phase 0–2: gate only, returns `[]`) |

**Positive signals (any may pass):**

| Signal | Examples |
|--------|----------|
| Status 4xx/5xx | 400, 401, 403, 404, 422, 500, 502, 503 with scannable body |
| Error-shaped JSON on 2xx | keys `error`, `exception`, `fault`, `trace`, `stack` (+ variants) |
| Stack / exception markers | `Traceback`, `SQLException`, `at com.`, `System.*Exception`, `panic:`, `SQLSTATE` |
| Framework error chrome | Whitelabel Error Page, Werkzeug Debugger, ASP.NET, Laravel whoops |
| Server error headers | `X-Exception`, `X-Error-Message`, … (config list) |

**Hard reject:** empty body without error headers; `image/*` / media / PDF / WASM
(CT or magic); pure static asset path when body is deferred and CT empty.

**Not required:** source-like Content-Type (JSON APIs and plain-text 500s are primary).

**Store policy is not the gate:** a generic nginx 404 HTML may pass the gate;
`store_generic_http_errors` (default false) decides later whether Stage G
clusters are persisted.

### Phase 2 — Detector stages (landed)

Pure multi-stage pipeline: decoded text (+ status/headers) → `ErrorDetectResult`.

| Stage | Module | Family | Notes |
|-------|--------|--------|-------|
| A | `detectors/stack_trace.py` | `stack_trace` | Java, .NET, Python, JS, PHP, Ruby, Go, Rust |
| B | `detectors/database.py` | `database` | SQLSTATE, ORA, MySQL, PG, SQLite, JDBC, Mongo/Redis, Hibernate |
| C | `detectors/framework.py` | `framework` | Spring Whitelabel, Werkzeug, Django, Laravel, Rails, ASP.NET, Tomcat/Jetty, Next/Express |
| D | `detectors/infrastructure.py` | `infrastructure` | Cloudflare, AWS, Azure, GCP, Envoy, k8s, nginx, Apache, IIS |
| E | `detectors/security.py` | `security` | JWT, OAuth, CSRF, CORS, AuthN/Z (+ `WWW-Authenticate`) |
| F | `detectors/disclosure.py` | `disclosure` | Paths / private IPs / internal hosts / versions as **artifacts** (+ optional matches); runs on 5xx or after strong hit |
| G | `detectors/http_generic.py` | `http_generic` | JSON/problem+json/HTML title/plain status — only if **no strong hit** and (`store_generic_http_errors` **or** 5xx) |

**Public API:**

```python
from talos.error_intel import detect_errors, ErrorDetectorOrchestrator

result = detect_errors(body, status_code=500, content_type="text/plain")
result.primary          # highest-specificity RawErrorMatch
result.matches          # all stage hits
result.artifacts        # ErrorArtifact list (path/host/version/…)
result.strong_hit       # True when stack/db/framework/security/infra fired
result.detectors_fired  # ordered unique detector_id list
```

`ERROR_INTEL_VERSION = 0.3.0` (Phases 3–5: classify + normalize/fingerprint + schema v43).

### Phase 3 — Classification (landed)

| Module | Role |
|--------|------|
| `talos.error_intel.classify` | `classify_error` / `classify_from_detect` → `ClassifiedError` |

Maps primary `RawErrorMatch` + sibling matches + disclosure artifacts to:

- **category** (closed set below)
- **severity** via additive score → bands (`SCORE_*_MIN` in constants)
- **language / framework / database / server / technologies[]**
- **flags**: `has_stack_trace`, `has_path_leak`, `has_internal_host`, `has_version_leak`
- **confidence** 0–100 from detector seed (+ multi-family agree boost)
- **message_norm**, **evidence_snippet**, **fingerprint** (via Phase 4)

Severity rubric (deterministic):

| Severity | Examples |
|----------|----------|
| **Low** | Generic 400 validation; nginx default 404 |
| **Medium** | Structured validation codes; 5xx without stack; auth text |
| **High** | Stack trace; SQL exception; path leak; framework debug page |
| **Critical** | Stack + SQL/query fragment; credentials/connection string; private key / cloud keys |

### Phase 4 — Normalize + fingerprint (landed)

| Module | Role |
|--------|------|
| `talos.error_intel.normalize` | Strip UUIDs, timestamps, line numbers, req IDs, path user segments |
| `talos.error_intel.fingerprint` | Identity tuple → SHA-256 fingerprint |

```text
fingerprint = SHA256(
  status_bucket | category | language | exception_type |
  framework | database | normalized_stack_hash |
  normalized_message_hash | server_bucket
)
```

**Not** in fingerprint: `endpoint_id`, `parameter_*`, `attack_type` (observations only).

Stack example:

```
at com.example.UserService.load(UserService.java:142)
→ at com.example.UserService.load(UserService.java:<LINE>)
```

Same Hibernate / SQL exception with different line numbers or request IDs → **one** fingerprint.

### Category taxonomy (v1 closed set)

| category | Meaning |
|----------|---------|
| `stack_trace` | Language stack / exception dump |
| `database` | SQL / NoSQL engine error |
| `framework` | Framework-branded error page / handler |
| `infrastructure` | Proxy / CDN / ingress / web server |
| `security` | AuthN/Z, JWT, CSRF, CORS, policy |
| `validation` | App validation / 4xx business error |
| `http` | Generic status-only / empty-ish error |
| `disclosure` | Paths/hosts/versions without full stack |
| `unknown` | Matched gate but weak classification |

### Schema v43 — Phase 5 (landed)

| Table | Role |
|-------|------|
| `error_clusters` | Unique fingerprint per project; category, severity, tech flags, evidence snippet |
| `error_observations` | Sightings: flow / endpoint / parameter / attack_type / artifacts |
| `error_intel_config` | Single-row defaults (`enabled`, `store_generic_http_errors`, scan caps) |

No `finding_id` column in v1.

**CRUD:** `talos.error_intel.db` — `upsert_error_cluster`, `insert_error_observation`,
`store_classified_error`, `get_config` / `update_config`, list helpers.

```python
from talos.error_intel import classify_error
from talos.error_intel.db import store_classified_error

classified = classify_error(body, status_code=500)
cluster, obs, created = store_classified_error(
    db_path, project_id, classified,
    flow_id=…, attack_type="iv", parameter_uuid=…,
)
```

`observe_error(...)` (Phase 6+) enqueues or processes inline when `db_path`
is provided; returns stored `ErrorObservation` list. Prefer enqueue-by-flow_id
on the capture path (`maybe_enqueue_error_scan`).

### Phase 6 — Queue, worker, hooks (landed)

| Module | Role |
|--------|------|
| `talos.error_intel.queue` | Bounded `ErrorIntelQueue` — drop-on-full, never blocks capture |
| `talos.error_intel.worker` | `ErrorIntelWorker` + `maybe_enqueue_error_scan` + `process_error_scan_sync` |
| FlowWorker | Post-commit cheap gate → enqueue (`inline_if_no_queue=False`) |
| Proxy addon | Starts `ErrorIntelWorker` after FlowWorker (mirrors passive) |
| `insert_replayed_flow` | Post-commit inline scan (scheduler / IV / BAC / unauth; no daemon queue) |
| `observe_error` | Public API: enqueue or process + store |
| `attach_error_context` | Parameter / attack enrich without re-parse |

**Attack context** is inferred from `flows.source` + `flow_meta` automatically:

| Signal | `attack_type` |
|--------|----------------|
| `source=proxy_capture` | `proxy` |
| `flow_meta.generated_by=input_validation` | `iv` |
| `flow_meta.attack_module=bac` | `bac` |
| `flow_meta.attack_module=unauth` | `unauth` |
| other `auto_replay` / `manual_replay` / `manual_send` / `ai_send` | `replay` |

IV `parameter_uuid` / `parameter_name` / `payload` come from `flow_meta` on the
replay row. `attach_error_context` fills empty observation fields after the fact.

**Dedup:** one observation set per `flow_id` unless `force` / CLI `--force`.
Same fingerprint across proxy + IV + BAC → one cluster, many observations.

### Phase 7 — Parameter / endpoint rollups (landed)

| Helper | Role |
|--------|------|
| `parameter_error_rollup` | Clusters linked to parameters (counts per param×error) |
| `endpoint_error_rollup` | Top clusters per endpoint |

Schema already carried `parameter_uuid` on observations (Phase 5); no new tables.

### Phase 8 — CLI (landed)

```text
talos error-intel status
talos error-intel config show|set
talos error-intel errors list|show
talos error-intel observations list [--endpoint|--parameter|--attack|--flow]
talos error-intel rescan --all|--flow ID [--force]
talos error-intel rollup parameter|endpoint
```

Aliases: `error_intel`, `errors`. Scanner version: `ERROR_INTEL_VERSION = 0.4.0`.

### Package layout (current)

```text
talos/error_intel/
  __init__.py           # public exports
  constants.py          # categories, severities, ERROR_INTEL_VERSION
  models.py             # ErrorCluster, ErrorObservation, RawErrorMatch, job
  config.py             # ErrorIntelConfig
  candidate.py          # is_error_candidate (Phase 1)
  observe.py            # observe_error / attach_error_context
  normalize.py          # Phase 4 — error-specific normalization
  fingerprint.py        # Phase 4 — identity tuple → fingerprint
  classify.py           # Phase 3 — category + severity + ClassifiedError
  db.py                 # Phase 5–7 — cluster / observation / config / rollups
  queue.py              # Phase 6 — ErrorIntelQueue
  worker.py             # Phase 6 — ErrorIntelWorker + maybe_enqueue_error_scan
  cli.py                # Phase 8 — talos error-intel …
  detectors/
    base.py             # decode, snippet, build_raw_error_match
    stack_trace.py      # Stage A
    database.py         # Stage B
    framework.py        # Stage C
    infrastructure.py   # Stage D
    security.py         # Stage E
    disclosure.py       # Stage F
    http_generic.py     # Stage G
    orchestrator.py     # detect_errors / ErrorDetectResult
```

### Relationship to existing code

| Existing | Relationship |
|----------|----------------|
| IV `error_signature` | Keep for IV outcomes; optional `extras["error_ids"]` later |
| `classify_outcome` → `rejected` | Unchanged; does not store stack content |
| `talos.passive` InfrastructureDetector | Owns source-like bodies; Error Intel owns error-shaped HTTP responses. Share pure regex helpers if useful; clear ownership: error *event* vs secret *material* |
| Findings | v1: none |

### Success criteria (detection quality — target)

1. Same Java `SQLSyntaxErrorException` from proxy + IV + BAC → one `error_id`, three observations with distinct `attack_type`.
2. `400 Invalid email` is not high-severity (and may not store by default).
3. Line numbers / request IDs alone do not fork clusters.
4. Stack on HTTP 200 JSON still detected.
5. IV `rejected` works with Error Intelligence disabled.
6. Capture path never fails if error worker crashes (non-fatal enqueue).

---

## Access Model (Two-Layer)

Talos separates **observed client behaviour** from **intended server enforcement**.
Both must be set explicitly — nothing is auto-inferred.

```
role + module
    │
    ├── client_allowed   — what the client exposes for this pair
    │       Derived from: visible navigation, enabled buttons, accessible pages
    │       Set via: talos access client set <role> <module> <allow|deny|unknown>
    │
    └── server_expected  — what the backend SHOULD enforce
            Your explicit assertion of intended security
            Used to drive BAC test generation
            Set via: talos access server set <role> <module> <allow|deny|unknown>
```

### Tri-State Values

| Value | Meaning |
|-------|---------|
| `ALLOW` | Permitted |
| `DENY` | Blocked |
| `UNKNOWN` | Not yet assessed — prevents incorrect test generation |

`NULL` means the field has not been set at all (distinct from `UNKNOWN`).

### Detection Logic (access matrix signals vs BAC)

| client | server_expected | actual (replay) | Verdict |
|--------|-----------------|-----------------|--------|
| ALLOW  | DENY            | DENY            | Correct restriction |
| DENY   | DENY            | ALLOW           | **BAC vulnerability** |
| DENY   | UNKNOWN         | ALLOW           | Likely client-side-only control |
| ALLOW  | ALLOW           | DENY            | Logic inconsistency / bug |

### Access Map Commands

```
talos role create <name>                                  create role (add = alias)
talos role list                                           list roles (UUID, name, active)
talos role show <name|uuid>                               role details + auth summary
talos role rename <name|uuid> <new_name>                  rename (UUID stable)
talos role delete <name|uuid> [--force]                   delete (cascade config; reassign flows)
talos role set <name>                                     activate for flow tagging
talos role unset                                          reset to global

talos module create <name>                                create module (add = alias)
talos module list                                         list modules (UUID, name, active)
talos module show <name|uuid>                             module details + access-map roles
talos module rename <name|uuid> <new_name>                rename (UUID stable)
talos module delete <name|uuid> [--force]                 delete (cascade config; reassign flows)
talos module set <name>                                   activate for flow tagging
talos module unset                                        reset to global

talos access client set   <role> <module> <allow|deny|unknown>
talos access client unset <role> <module>                 set client_allowed = NULL
talos access server set   <role> <module> <allow|deny|unknown>
talos access server unset <role> <module>                 set server_expected = NULL
talos access delete       <role> <module> [--force]       remove entire row
talos access show                                         display matrix
talos access coverage                                     compare expected vs observed traffic
talos access signals                                      show immediate BAC signal candidates

talos endpoint list                                       inventory (UUID, method, host, path, priority, qualified, excluded)
talos endpoint list --format json                         resolved policy JSON for Control Panel / scripts
talos endpoint list --qualified                           only qualified endpoints
talos endpoint list --host api.example.com                filter by host or canonical origin
talos endpoint list --method GET --priority HIGH          combine filters
talos endpoint list --role admin --search /api/orders     role + path/host search
talos endpoint mark   <id> [<id> ...] --logout | --dangerous | --safe
talos endpoint unmark <id> [<id> ...] --logout | --dangerous
talos endpoint show   <id> [--format table|json]
talos endpoint policy <id> [--format table|json]          why effective policy exists
talos endpoint export <id> | --endpoints <id>...

talos endpoint priority set endpoint <id> [<id> ...] <CRITICAL|HIGH|NORMAL|LOW>
talos endpoint priority set path "<pattern>" <level>
talos endpoint priority clear endpoint <id> [<id> ...]
talos endpoint priority clear path "<pattern>"

talos endpoint exclude endpoint <id> [<id> ...]
talos endpoint exclude path "<pattern>"
talos endpoint include endpoint <id> [<id> ...]
talos endpoint include path "<pattern>"

# Canonical path-rule resource (legacy priority/exclude path still work)
talos endpoint rule add "<pattern>" [--priority LEVEL] [--exclude]
talos endpoint rule update <rule_id> [--priority LEVEL|--clear-priority] [--exclude|--include]
talos endpoint rule delete <rule_id>
talos endpoint rule list|show <rule_id>
talos endpoint rule preview "<pattern>" [--priority LEVEL] [--exclude]
talos endpoint rules                                      alias for rule list
```

`talos endpoint list` is the primary discovery command for endpoint UUIDs.
It returns the full inventory (including unqualified and excluded rows) with
effective priority resolved via Endpoint Policy. Attack modules continue to
use `get_testable_endpoints()` (qualified + not excluded only); the list CLI
uses `list_endpoints()` so operators can see everything.

Bulk mutations validate **all** IDs before writing, reject the whole operation
if any ID is invalid, run in one DB transaction, dedupe IDs, and report
affected vs unchanged counts (table or `--format json`). Path-rule preview
and list/show/policy JSON all use the **same** matcher and effective-policy
resolver as candidate generation. Endpoint identity is method + **canonical
origin** (`endpoints.host`) + normalized path.

---

## Endpoint Policy System

The Endpoint Policy system is the single authority that decides:

- **What is the effective priority of an endpoint?**
- **Is this endpoint excluded from candidate generation?**
- **Which rule produced that decision?**

Every attack module, BAC engine, scheduler, and future automation calls
`get_testable_endpoints(db_path, project_id)` instead of querying the endpoints
table directly.  The policy engine handles filtering and ordering centrally.

**BAC candidate generation** (`talos.projects.bac.candidates.scan_candidates`)
resolves testable endpoints via `get_testable_endpoints()` first (optionally
scoped with `endpoint_id=` or `module_id=` so large projects do not load the
full inventory for a single-endpoint run), then selects access-matrix flows only
for those endpoint IDs.  Baseline flow selection uses the same qualification
criterion as the rest of Talos: `source = 'proxy_capture' AND status_code
BETWEEN 200 AND 299`.  Excluded endpoints never produce BAC candidates,
scheduler jobs, or findings.

As defence-in-depth, `execute_bac_job` re-resolves full effective policy
immediately before execution and skips when any of the following became true
after the job was queued:

| Policy field | Skip reason |
|--------------|-------------|
| `excluded` | `endpoint_excluded` |
| `logout` | `endpoint_annotated_logout` |
| `dangerous` | `endpoint_annotated_dangerous` |
| `!qualified` | `endpoint_not_qualified` |

**Execution scopes** on every `talos attack bac <module>` command are mutually
exclusive (project **or** module **or** endpoint):

| Flag | Effect on candidate generation |
|------|--------------------------------|
| *(none)* | Project scope — all testable endpoints |
| `--module NAME\|UUID` | Module scope only (xor `--endpoint`); resolved via `resolve_module()` |
| `--endpoint UUID` | Endpoint scope only (xor `--module`) |
| `--role NAME\|UUID` | Only that attacker role (orthogonal filter); via `resolve_role()` |

Downstream attack logic (variants, replay, decision filter, findings) is
unchanged — only candidate selection is scoped.

### Policy Types

| Policy | Storage | Purpose |
|--------|---------|---------|
| Auto Priority | `endpoint_policy.auto_priority` | Computed by scoring heuristics; updated on every flow |
| Manual Priority | `endpoint_policy.manual_priority` | Tester override; always supersedes auto |
| Exclusion (endpoint) | `endpoint_policy.excluded` | This specific endpoint is never a candidate |
| Exclusion (path rule) | `policy_rules.excluded` | All endpoints matching the pattern are excluded |
| Path Priority Rule | `policy_rules.priority` | Override priority for all matching endpoints |
| Qualification | `endpoint_policy.qualified` | 1 = endpoint has a 2xx proxy_capture flow; eligible for all attack modules |
| Baseline Flow | `endpoint_policy.baseline_flow_id` | Pre-computed best 2xx proxy_capture flow (cached lookup) |
| Notes | `endpoint_policy.notes` | Free-form tester notes; CLI: `talos endpoint notes set\|clear` |
| Tags | `endpoint_policy.tags` | Arbitrary labels for filtering/reporting; CLI: `talos endpoint tags add\|remove\|set\|clear` |

### Endpoint Qualification System

Qualification determines whether an endpoint is **eligible for any automated
testing** — Input Validation, auth bypass, BAC, and all other attack modules
only ever operate on qualified endpoints.

**Qualification criterion:**

```
qualified = True  when:
    - at least one proxy_capture flow exists with status_code BETWEEN 200 AND 299
    - AND endpoint_policy.logout = 0
    - AND endpoint_policy.dangerous = 0
```

**qualification_reason values:**

| Reason | Meaning |
|--------|---------|
| `no_flows` | No proxy_capture flows captured yet |
| `no_2xx_response` | Flows exist but all returned 4xx/5xx |
| `only_redirects` | All observed flows returned 3xx |
| `is_logout` | Endpoint is marked as a logout endpoint |
| `is_dangerous` | Endpoint is marked as dangerous |
| `flow_2xx` | At least one qualifying 2xx flow exists — endpoint is testable |

**Qualification is updated incrementally** by the FlowWorker on every
`proxy_capture` flow. No batch recomputation is needed.

**Baseline flow caching:**

`baseline_flow_id` stores the UUID of the most recently captured 2xx
proxy_capture flow. Attack modules and the replay engine read this field
directly (O(1) lookup) instead of running `SELECT … ORDER BY captured_at DESC
LIMIT 1` on every test. This eliminates the per-attack DB scan.

**Existing databases (migration v29→v30):**

The migration backfills `qualified`, `qualification_reason`, `baseline_flow_id`,
and `baseline_status` for all existing endpoint_policy rows by scanning flows
once.

**Impact on all attack surfaces:**

`get_testable_endpoints()` — the single entry point for every attack module —
now filters `WHERE ep.qualified = 1` at the SQL layer. Unqualified endpoints
never reach the scheduler, the replay engine, or any attack generator.

Applies to: Input Validation, auth bypass, BAC, parameter tampering,
method fuzzing, header injection, host fuzzing — every deterministic attack.

### Effective Priority Resolution

```
For each endpoint:

  1. Does endpoint_policy.manual_priority exist?
     → YES: use it  (source: manual)

  2. Does any policy_rules row match the normalized_path?
     → YES: use rule priority  (source: rule; pattern recorded)

  3. Use endpoint_policy.auto_priority  (source: auto)
```

### Exclusion Resolution (independent of priority)

```
endpoint_policy.excluded = 1 for this endpoint_id?
  → YES: excluded

Any policy_rules row with excluded=1 matches normalized_path?
  → YES: excluded

→ else: included → generate candidates
```

### Auto-Priority Scoring

Computed by `talos.projects.policy_score.compute_auto_priority()` after each
endpoint upsert in the FlowWorker pipeline.

Signals (additive weighted scoring):

| Signal Category | Example contributions |
|-----------------|-----------------------|
| HTTP method | DELETE +60, POST +35, GET +15 |
| Sensitive path keywords | /admin +50, /transfer +60, /permission +45 |
| Endpoint action verbs | grant +50, revoke +50, approve +40 |
| Business keywords | refund +55, payroll +60, checkout +50 |
| Path parameter types | UUID +15, sequential int +15 |
| Authentication present | +15 |
| Role visibility | seen by multiple roles +15 |
| Response content-type | JSON +10, CSV/ZIP/PDF +30-40 |
| Request body type | multipart +30, JSON +15, XML +20 |
| Sensitive parameter names | secret +50, api_key +40, tenant_id +35 |
| Low-priority signals | /static -70, /health -80, .css -80 |

Score thresholds → priority level (per-project configurable in `policy_score.json`):

```
score >= 100  →  CRITICAL
score >= 70   →  HIGH
score >= 40   →  NORMAL
score <  40   →  LOW
```

Every score is fully explainable — the contributors dict is stored in
`endpoint_policy.auto_breakdown` and displayed by `talos endpoint show`.

### Pattern Matching Rules

`/prefix/*` — matches any path starting with `/prefix/`.
`/exact`    — matches only `/exact` or paths directly under it.
Comparison is case-insensitive.

Most specific rule wins: exact endpoint > path rule > auto.

---

## CLI Output Conventions

All user-facing CLI messages go through `talos.cli_output` so commands share one
style (CLI-011). New CLI code must not invent its own `Error:` / `ERROR:` /
`Aborted.` variants.

| Helper | Stream | Format |
|--------|--------|--------|
| `cli_success(message, fields=None)` | stdout | Summary line; optional blank line then `Label:` / value pairs |
| `cli_info(message)` | stdout | Neutral informational text |
| `cli_warning(message)` | stderr | `Warning:` then blank line then body |
| `cli_error(message, exit_code=EXIT_FAILURE)` | stderr | `Error:` then blank line then body; exits unless `exit_code=None` |
| `cli_usage_error(message)` | stderr | Same as `cli_error`; exits **2** |
| `cli_precondition_error(message)` | stderr | Same as `cli_error`; exits **3** |
| `cli_cancelled(exit=False)` | stdout | `Cancelled.`; if `exit=True`, exits **130** |
| `is_interactive()` | — | True when stdin is a TTY (safe to prompt) |
| `add_force_argument(parser)` | — | Adds shared `--force` flag for destructive commands (CLI-015) |
| `confirm_or_force(prompt, force=False)` | stdin/stdout | See **Confirmation policy (CLI-015)** below |
| `confirm_or_exit(prompt, force=False)` | stdin/stdout | Same as `confirm_or_force`; on decline exits **130** |
| `add_format_argument(parser)` | — | Adds `--format {table,json}` (default `table`) to list/show/status parsers |
| `wants_json(args)` / `get_output_format(args)` | — | Resolve CLI-014 output mode |
| `cli_json(data)` | stdout | Single JSON document (`indent=2`) after `json_ready` |

Standard shapes:

```text
Error:

Endpoint not found.

Warning:

Queue is at capacity (10/10 active jobs).

Enqueued.

Job:
<uuid>

Cancelled.
```

### Confirmation policy (CLI-015)

Destructive and capacity-sensitive actions share one rule via
`confirm_or_force` / `confirm_or_exit` and `add_force_argument`:

| Context | Behavior |
|---------|----------|
| Interactive TTY | Prompt with `[y/N]`; decline → print `Cancelled.` (exit **130** via `confirm_or_exit`) |
| Non-interactive (CI, pipes, redirected stdin) | Require `--force`; otherwise exit **2** with `Error:` / `Operation requires --force in non-interactive mode.` |
| `--force` | Always skip the prompt (interactive or not) |

Never call bare `input()` for confirmations — that hangs automation. Commands
covered include: `project delete` / `project delete --purge` (purge uses a
second interactive confirmation unless `--force`), `role|module delete`,
`mutation delete`, `access delete`, `auth clear`,
`auth-config clear-expiry-signals`, `scheduler clear` / overflow enqueue,
`scheduler prune`, `input-validation clear-cache`, `finding` bulk status
(`--linked`), and `finding group remove` (group delete).

Cancellation is always the single word `Cancelled.` on stdout.

### Machine-readable output (CLI-014)

List, show, and status commands accept:

```bash
talos <command> … --format table   # default — human tables / labeled blocks
talos <command> … --format json    # automation — one JSON document on stdout
```

Contract:

| Mode | Successful data | Empty list | Errors / warnings |
|------|-----------------|------------|-------------------|
| `table` | Human tables / blocks | Human empty-state message | stderr CLI-011 shapes |
| `json` | `cli_json(...)` document | `[]` | stderr CLI-011 shapes (unchanged) |

Implement new list/show/status handlers by calling `add_format_argument` on the
subcommand parser, then:

```python
if wants_json(args):
    cli_json(payload)
    return
# existing table path
```

Do not mix banner prose with JSON on stdout. Keep mutation success messages
human-readable unless a future ticket extends JSON to write commands.

### Exit code policy (CLI-012)

Process exit status is the automation interface. All commands use the same codes:

| Code | Constant | Meaning | Typical causes |
|------|----------|---------|----------------|
| **0** | `EXIT_OK` | Success | Work done, or intentional no-op (already complete / already queued) |
| **1** | `EXIT_FAILURE` | General failure | Resource not found, operation failed, attack produced no jobs (non-auth) |
| **2** | `EXIT_USAGE` | Invalid arguments | Unknown subcommand, bad flags, missing required operands, missing `--force` in non-interactive mode (CLI-015) |
| **3** | `EXIT_PRECONDITION` | Preconditions failed | No project bound (open / `--project` / `TALOS_PROJECT`), auth not ready, endpoint excluded/logout/dangerous |
| **130** | `EXIT_CANCELLED` | User cancelled | Declined `[y/N]` confirmation (not a hard error) |

Examples:

| Situation | Exit |
|-----------|------|
| Mutation / outscope / endpoint not found | 1 |
| BAC / unauth: no jobs (candidates empty) | 1 |
| BAC: no jobs because auth prereqs failed | 3 |
| IV run: nothing new to enqueue | 0 |
| Scheduler enqueue: duplicate already pending | 0 |
| User answers `n` to delete/clear prompt | 130 |
| `talos foo` unknown top-level command | 2 |
| Command needs project but none bound | 3 |
| Unknown `--project` / `TALOS_PROJECT` id | 1 |

Scripts should treat only `0` as success. Use `130` to distinguish interactive abort from failures when needed.

---

## Component Responsibilities

| Component | Responsibility | Does NOT do |
|-----------|---------------|-------------|
| `talos.__main__` | Parse global `--project` + top-level command; wire config → manager → CLI handler; export `TALOS_PROJECT` for children | Business logic |
| `talos.cli_output` | Shared CLI success/warning/error/cancel/confirm formatting, EXIT_* codes (CLI-011/012), confirmation policy + `--force` (CLI-015), and `--format json` helpers (CLI-014) | Business logic |
| `talos.config.TalosConfig` | Resolve storage root from env or default (paths only; not app settings) | Create directories; project selection |
| `talos.configuration` | Layered config manager, EffectiveConfig, HTTPManipulationEngine, `talos config` + `talos config http` CLI (CLI-022); sections include `burp` | Application settings for proxy/capture/scheduler/attack/http/burp |
| `talos.burp` | Burp metadata header contract (`X-Talos-*`), process-cached `burp.*` knobs, IV `flow_meta["burp"]` trace | Burp UI (lives in `burp-extension/`); never talks to Burp itself |
| `talos.projects.model.Project` | Data shape + serialization only | I/O, side effects |
| `talos.projects.model.ScopeConstraints` | Capture constraint values + serialization | Enforcement |
| `talos.projects.db` | Schema init for one project's SQLite DB | Hold connections, run queries |
| `talos.projects.manager.ProjectManager` | Full project lifecycle (create/open/close/delete/rename/description; optional purge); registry single-ACTIVE; process override via `--project` / `TALOS_PROJECT` | Formatting |
| `talos.projects.access` | Full role/module lifecycle (create, resolve name\|uuid, rename UUID-stable, delete with cascade/reassign-to-global); access map (client + server tri-state); coverage and BAC signal queries | Enforcement, inference |
| `talos.projects.access_cli` | Argument parsing + output for role/module (incl. show/rename/delete) and access commands | State management |
| `talos.projects.cli` | Argument parsing + output formatting for project commands | State management |
| `talos.projects.endpoints` | Canonicalize raw paths/queries into stable endpoint identities | DB writes, access inference |
| `talos.projects.parameters` | Extract request surfaces + Phase 2 structure discovery (encoded JSON, JWT claims, value-first headers) and response HTML/JS inventory; upsert with type inference, dedupe, and passive `url_features` | DB schema changes beyond inventory; IV mutation |
| `talos.url_sink` | URL Sink Discovery (Phases 1–2): value/name classifiers, `url_features` compose, encoded-JSON decode, JWT claim extract, HTML/JS inventory helpers | IV probes, Findings, candidate scoring (later phases) |

| `talos.url_identity` | Shared URL identity: scheme, hostname, ports, canonical authority/origin, path normalization | Scope policy, I/O |
| `talos.projects.scope_io` | Atomic scope file/bulk-text parse (one prefix per line; `#` comments) | Storage, matching |
| `talos.projects.scope_cli` | `project scope add\|remove\|list\|clear\|import` | Registry writes (via manager) |
| `talos.projects.outscope` | CRUD for out-of-scope **Basic Scope prefixes** (stored in `out_of_scope_domains.domain`); `load_prefix_set()` for proxy/worker | Enforcement |
| `talos.projects.outscope_cli` | `project outscope add\|remove\|list\|clear\|import` (legacy `add domain` accepted) | State management |

| `talos.projects.mutation_cli` | Argument parsing + output for `mutation add/list/delete/enable/disable/edit` commands | State management |
| `talos.proxy.scope` | Basic Scope URL-prefix matching; shared `evaluate_scope` / `is_url_in_scope` (out-of-scope overrides in-scope) | Configuration, logging |
| `talos.proxy.queue.FlowQueue` | Bounded thread-safe queue; drop-on-full | Processing, persistence |
| `talos.passive.queue.PassiveScanQueue` | Bounded queue for `PassiveScanJob`; drop-on-full + WARNING | Detectors, findings, capture path |
| `talos.passive.worker.SourceScanWorker` | Drain passive queue; load body by flow_id; classify/normalize; upsert document + occurrence; extract source maps + HTML inline scripts; run detector orchestrator (incl. JWT/conn/infra); persist detections; auto-create secret findings; skip rescan at `SCANNER_VERSION` | Outbound HTTP |
| `talos.proxy.addon.TalosAddon` | mitmproxy hook; **request hook** applies mutations; **shared Basic Scope evaluator** on full request URL → extract (canonical origin on `host`) → stamp role/module → enqueue; starts/stops FlowWorker + SourceScanWorker | DB writes, normalization, session detection |
| `talos.proxy.launcher.build_mitmdump_command` | Single shared function building the mitmdump argv; adds `--mode upstream:<url>` only when a resolved URL is supplied — never hardcodes host/port; `--set http2=false` when HTTP/1.1 is configured | Process spawning, DB access |
| `talos.proxy.ntlm` / `talos.proxy.platform_auth` | NTLMv2 Type 1/3 + host-scoped platform auth (raw NTLM scheme; strip Negotiate; drop browser Authorization; hide leftover 401 WWW-Authenticate from the browser) | Network I/O |
| `talos.proxy.http_client.create_async_client` | Shared outbound httpx factory (upstream, HTTP/1.1, NTLM). Platform-auth hosts mount a direct transport so NTLM does not traverse an intercepting upstream | Network I/O |
| `talos.proxy.runtime.ProcessOps` | Platform process control for managed children (mitmdump, scheduler). **POSIX:** `start_new_session`, SIGTERM/SIGKILL, `/proc` starttime, non-blocking `waitpid`+`WNOHANG` only when available. **Windows:** `CREATE_NEW_PROCESS_GROUP`, `CTRL_BREAK` / `TerminateProcess`, FILETIME identity, `GetExitCodeProcess` for exit codes — never `os.WNOHANG` (not defined on Windows). Exit-code probes never raise | Freeform shell, SIGKILL-first stop |
| `talos.proxy.runtime.ProxyRuntimeManager` | Sole mitmdump lifecycle owner: start/stop/restart/status, readiness wait (20s on Windows / 5s elsewhere), drain, port reclaim. Readiness-timeout cleanup is fail-soft so probe bugs cannot mask `ProxyStartError` | Direct subprocess outside ProcessOps |
| `talos.projects.proxy_config` | Upstream URL helpers plus origin transport (`http2`, `keep_alive`, platform-auth rows). `resolve_upstream_url` / `load_proxy_transport`. Dual-writes project.yaml; consumed by proxy CLI/launcher and outbound engines | Process spawning |
| `talos.proxy.cli` | Argument parsing; active-project gate; `start` calls `resolve_upstream_url` (optional `--upstream` / `--no-upstream` one-shot) then the shared launcher; `config` persists mode | Proxy logic |
| `talos.worker.FlowWorker` | Drain queue; validate; out-of-scope backstop drop; attach project_id; normalize flows into stable endpoints; persist to DB + archive; update endpoint_roles and parameter inventory transactionally; update endpoint qualification and baseline_flow_id cache; after commit, cheap `is_source_candidate` + enqueue `PassiveScanJob` when passive enabled | Proxy logic, access inference, heavy passive scan |
| `talos.projects.auth` | CRUD for per-project auth config (cookie/header names); additive set, clear | Enforcement, inference, credential storage |
| `talos.projects.auth_cli` | Argument parsing + output for auth set/show/clear/test commands; `auth test` default path enqueues scheduler job; `--right-now` executes immediately | State management, HTTP I/O |
| `talos.projects.annotations` | CRUD for endpoint safety tags (logout, dangerous); read-only guard consumed by replay engine and auth-strip | Enforcement, inference |
| `talos.projects.endpoint_cli` | Argument parsing + output for endpoint list/mark/unmark/show/priority/exclude/include/rules/export/notes/tags commands | Policy engine (`list_endpoints`), annotations, notes/tags, replay.db |
| `talos.projects.policy_score` | Pure weighted scoring engine: compute_auto_priority() → (score, level, contributors); load per-project config from policy_score.json | DB access, I/O, side effects |
| `talos.projects.policy` | Endpoint Policy engine: upsert_auto_priority(), update_endpoint_qualification(), set_manual_priority(), set_excluded(), path rule CRUD, get_effective_policy(), list_endpoints() (full inventory + filters for CLI), get_testable_endpoints(endpoint_id=/module_id=), is_endpoint_testable(), set_notes/set_tags/add_tags/remove_tags/get_notes_and_tags — single authority for priority/exclusion/qualification/notes/tags decisions | Scoring logic, proxy, replay, endpoint CLI |
| `talos.replay.db` | Read flow/endpoint records for replay input; insert replayed flows, diff rows, and auth test results; calls `migrate_project_db` on every entry | Business logic, HTTP I/O |
| `talos.replay.diff` | Pure diff computation between original and replay flow; produces DiffResult (verdict, status_diff, length_diff) | DB access, I/O |
| `talos.replay.engine` | Async exact (Type 1) replay via httpx; uses `get_upstream_url` for optional outbound proxy; reconstruct request; store result linked to original | Mutation, auth stripping |
| `talos.replay.auth_strip` | Type 2 replay: strip auth fields, send via same upstream resolution, compute auth-bypass verdict (SECURE/BYPASS/UNKNOWN) | Auth config management, endpoint selection |
| `talos.replay.cli` | Argument parsing; active-project gate; dispatch `replay flow` / `replay endpoint`; default path enqueues scheduler job; `--right-now` executes immediately; print outcome or job ID | HTTP I/O, DB writes |
| `talos.send.draft` | Build request draft from any flow; structured patches (method/url/header/query/body/cookie/path/host/json-set) and raw-message apply | HTTP I/O, DB writes |
| `talos.send.raw_http` | Parse/serialize HTTP/1.1 request messages for file-based editing and export | Network, DB |
| `talos.send.normalize` | Content-Length policy (default ON; `--no-update-content-length` disables) | Network, DB |
| `talos.send.request_diff` | Pure request-side comparison (method/url/headers/cookies/body); richer response payload helpers | DB, network |
| `talos.send.engine` | Async send-once / repeat / parallel / redo via same httpx/proxy/timeout stack as replay; INSERT new flow (`manual_send`/`ai_send`); lineage + session/note/profile in `flow_meta`; diff vs root capture | Exact-replay semantics, capture mutation |
| `talos.send.db` | History filters (root/session/parent/source); note UPDATE on send rows only; export HTTP files; tree lines | Schema migration beyond flows |
| `talos.send.cli` | Full Repeater CLI (from/edit/once/redo/dup/show/export/history/tree/diff/note); immediate send (no scheduler); `--format json` for AI | — |
| Control Panel Repeater | `/repeater` + `/api/send/*` workbench; mutations call `talos.send.engine` in-process (CLI exception); drafts in browser localStorage | Redesign of send semantics |
| `talos.intruder` | High-volume mutation engine (Phase 1–5): template + generators (wordlist/numbers/static/uuid/csv/json/example_values/pool/dates/bruteforce/random/pattern) + single/sniper/pitchfork/zip/cluster_bomb; timing fixed/unlimited/token_bucket/adaptive; storage modes; host concurrency caps; session clone; grep extract → `intruder_pools`; param-intel `from-params`; offline `suggest`; optional findings promote (default off, max_findings cap, `finding_id` lineage); time-sliced `intruder_session` jobs; metrics table | Control Panel UI, state_machine (later) |
| `talos.scheduler.scheduler.ReplayScheduler` | Daemon thread: consume pending jobs from scheduler_jobs; annotation pre-check (logout/dangerous); per-cycle config reload; configurable jitter; mark job done/failed/skipped (`endpoint_excluded` / `endpoint_not_qualified` → skipped); trigger `create_finding_from_verdict` after BAC and auth outcomes | Direct execution (delegates to replay/auth engines), CLI parsing |
| `talos.projects.bac.candidates` | BAC candidate generation from access matrix × testable endpoints (2xx flows); mutually exclusive endpoint/module scope + attacker role filter | Write path, attack execution |
| `talos.projects.bac.engine` | BAC attack execution; re-checks Endpoint Policy before HTTP; outbound httpx uses project upstream via `get_upstream_url` | Candidate generation, CLI |
| `talos.scheduler.db` | CRUD for scheduler_jobs (enqueue, next pending, mark running/done/failed/skipped/cancelled, list_jobs/get_job, cancel_job, prune_jobs, clear, dedup, status counts); read/write scheduler_config; compute queue metrics | HTTP I/O, replay execution |
| `talos.scheduler.cli` | Argument parsing + output for scheduler status/config/enqueue/jobs list\|show/cancel/prune/clear/pause/resume; `resume` flips paused jobs to pending and does not preflight BAC/role sessions (session health is enforced at job execution); warns when Intruder sessions remain paused | Scheduling logic, HTTP I/O |
| `talos.findings.model` | Constants: FINDING_STATUS_*, RELATION_TYPE_* (PRIMARY/LINKED), EVIDENCE_TYPE_* (incl. `module`, `role`, `unauth_result`), TIMELINE_ACTOR_*, VERDICT_TRIGGERS map (`bac`/`auth_test`/`unauth`), ATTACK_DISPLAY labels | DB access, I/O, side effects |
| `talos.findings.db` | CRUD for findings, finding_evidence, finding_timeline, finding_groups, finding_group_members; `build_cluster_key` / PRIMARY-or-LINKED `create_finding` with race retry; list filters by relation_type + linked_count; `list_linked_findings` / `count_linked_findings`; `update_finding_notes`; `add_timeline_event` optional `occurred_at` | HTTP I/O, business logic |
| `talos.findings.creator` | Determine whether a verdict triggers a finding; build cluster_key; create PRIMARY or LINKED finding + attach evidence (incl. module/role, unauth_result) + reconstruct the timeline from real historical timestamps; integration point between attack engines and findings | DB schema changes, HTTP I/O |
| `talos.findings.report` | Generate Markdown vulnerability reports for individual findings or groups (incl. relation/cluster/linked refs, module/role, Unauthenticated Execution result section); group reports with >1 finding get a numbered Index table at the top; fetches supporting data (flows, diffs, endpoints, roles) from DB | DB writes, HTTP I/O |
| `talos.findings.cli` | Argument parsing + output for all finding subcommands (list/show/confirm/reject/reopen/duplicate/note/group/report); list defaults to PRIMARY with `--linked`/`--all`; bulk status via `--linked`/`--force`; `note set\|clear` writes analyst notes + timeline; `show` prints relation, linked children or parent PRIMARY, full evidence UUIDs, module/role, Original vs Attack flow comparison | Finding creation, report generation logic |
| `talos.projects.auth_config_cli` | CLI for auth-config, session health, and session recovery (`clear-session`, `reset-health`) | Auth execution |
| `talos.projects.auth_provider` | AUTO/MANUAL provider + manual session files | Proxy capture |
| `talos.projects.session_health` | L1–L3 session health engine | CLI parsing |
| `talos.projects.unauth.*` | Unauth recipes, engine, filter, CLI | BAC |
| `talos.projects.attack_cli` | Top-level attack dispatcher | Attack execution |
| `talos.projects.attack_config` | attack_config keys including unauth_auto_run | CLI |
| `talos.projects.flow_cli` | Universal flow list/show/export; `list_flows()` discovery query | HTTP I/O |
| `talos.input_validation.*` | Input Validation config, engine, phases, CLI; fingerprint + outcomes (M1); profile model (M2); offline synthesis (M3); multiprobe canaries (M4); event-driven planner (M5); character taxonomy + binary length (M6); type/semantic validation + negative evidence (M7); parser/normalization fingerprint (M8); surface completeness path/header/cookie/multipart/GraphQL/XML (M9); multi-level learning endpoint/app inheritance (M10); capabilities + attack candidates + consumer API (M11) | Findings creation; exploit chains (out of IV); M12 operator UX polish |
| `talos.proxy.launcher` | Shared mitmdump argv builder | DB writes |

Empty package: `talos/attack_runtime/` is not an active subsystem.

---

## Data Lifecycle

### Project Creation
```
CLI: talos project create <name>
  → make_project_id(name) → slug
  → check registry for collision
  → mkdir <projects_root>/<id>/
  → mkdir <projects_root>/<id>/archive/
  → init_project_db(<id>/talos.db)   ← schema created here
  → copy default_headers_drop.txt → <id>/headers_drop.txt
  → write to registry.json
     (includes scope: [], constraints: {defaults})
```

### Project Activation (interactive)
```
CLI: talos project open <id>
  → load registry
  → set any current ACTIVE → INACTIVE
  → set target → ACTIVE
  → save registry
  → init_project_db (idempotent schema migration)
```
Single-active **registry** invariant is enforced here. No two projects can be
ACTIVE in the registry simultaneously.

### Process-scoped project override (CLI-013 / automation)
```
CLI: talos --project <id> <command> …
  or: TALOS_PROJECT=<id> talos <command> …
  → ProjectManager binds <id> for this process only
  → registry ACTIVE status is NOT rewritten
  → init_project_db on first active() resolve (idempotent)
  → when --project is used, TALOS_PROJECT is exported so child
    processes (mitmdump / TalosAddon) inherit the same bind
```
Resolution order for `manager.active()`:
  1. constructor / `--project` / `TALOS_PROJECT`
  2. registry entry with status=ACTIVE
  3. None → CLI exit 3 (precondition)

Parallel scripts may each pass a different `--project` without interfering.

### Scope + Constraints Configuration
```
CLI: talos project scope add example.com
     talos project scope add http://api.example.com:8000
  → appends Basic Scope URL prefixes to project.scope in registry
  → each entry is one complete prefix (never comma-split)

CLI: talos project scope import scope.txt
  → atomic file import (UTF-8, one prefix per line, # comments)

CLI: talos project scope <id> [PREFIX…]   # legacy replace-all / list

CLI: talos project constraints <id> --store-bodies true --max-body-size 2097152
  → replaces project.constraints in registry
```

### Project Rename (CLI-017)
```
CLI: talos project rename <id> <new_name>
  → make_project_id(new_name) → new_id
  → if new_id already registered (and ≠ old) → ProjectAlreadyExists
  → if new_id == old id:
       update display name only in registry
  → else:
       rename <projects_root>/<old_id> → <new_id> (when present)
       rewrite project_id columns inside talos.db
       re-key registry entry; update data_dir
  → status / scope / description / constraints preserved
```

### Project Description (CLI-017)
```
CLI: talos project description <id>
  → print current description

CLI: talos project description <id> Production July Assessment
  → set registry description text
```

### Project Delete / Purge (CLI-017)
```
CLI: talos project delete <id> [--force]
  → confirm (CLI-015)
  → remove registry entry only
  → data_dir preserved on disk

CLI: talos project delete <id> --purge [--force]
  → confirm (strong wording)
  → interactive without --force: second confirmation
  → remove registry entry
  → shutil.rmtree(data_dir) when present
  → database, archive, reports, sessions, filters gone
```

### Proxy Startup
```
CLI: talos [--project <id>] proxy start [--port 8080] [--listen-host 127.0.0.1] [--quiet]
  → manager.active() → None → exit 3 (precondition)
  → project.scope empty → WARNING printed to stderr (proxy still starts)
  → seed_default_context(project.db) ensures global role/module exist
  → resolve active role_id + module_id once at proxy startup
  → prints startup summary (scope entries, store_bodies, max_body_size, listen addr)
  → launch: mitmdump --listen-host 127.0.0.1 --listen-port 8080
                     --ssl-insecure -s addon.py
      POSIX   → os.execvp (replaces current process)
      Windows → subprocess.run (blocks; KeyboardInterrupt swallowed on Ctrl+C)
```

### Capture Flow Path
```
browser → mitmdump (TLS intercept)
       → TalosAddon.response(flow)
           → is_url_in_scope(pretty_url, project.scope, out_of_scope_prefixes)
               # out-of-scope overrides in-scope; full URL identity
               → False → SKIP → return
               → True  → _extract_flow(flow, constraints, drop_headers)
                         # host field = canonical origin for endpoint identity
                           → assign flow_id (UUID4)
                           → strip URL fragment
                           → _capture_body(request, constraints)
                               → store_bodies=False → body=None
                               → len > max_body_size → truncate, truncated=True
                           → _capture_body(response, constraints)
                           → _filter_headers(headers, drop_headers)
                           → flow dict:
                               flow_id, request_start, response_end,
                               method, url, host, path, query,
                               request_headers, request_cookies,
                               request_body, request_body_truncated,
                               status_code, response_headers,
                               response_body, response_body_truncated,
                               role_id, module_id
                             (project_id NOT included — attached at worker layer)
                       → flow_queue.put(flow_dict)
                           → queue full → drop + WARNING log
                             → queue ok  → enqueued for worker
               → _cprint(CAPTURE line with flow_id prefix + status)
```

### Worker Pipeline
```
FlowQueue → FlowWorker._run() (daemon thread)
    poll get(timeout=0.2s)
        → None (empty) → loop, check stop_event
        → flow dict
            → _validate_flow()
                method missing   → drop + WARNING
                url missing      → drop + WARNING
                status_code None → drop + WARNING
                bad timestamp    → drop + WARNING
                missing role_id  → drop + WARNING
                missing module_id → drop + WARNING
            → attach project_id
            → _persist_db(flow, db_path)
                normalize_flow_url(path, query)
                  remove utm_*, fbclid, gclid, known cache-busters
                  sort remaining params
                  collapse duplicate slashes and strip trailing slash
                  keep host + method unchanged
                endpoint identity = (method, host, normalized_path)
                upsert endpoint first_seen/last_seen/auth signal/roles_seen
                  INSERT INTO flows (
                      id, project_id, captured_at, response_end,
                      method, url, host, path, query,
                      request_headers (JSON), request_cookies (JSON),
                      request_body (BLOB), request_body_truncated,
                      status_code,
                      response_headers (JSON), response_body (BLOB),
                  response_body_truncated,
                  content_type, session_id, endpoint_id,
                  role_id, module_id, tags,
                  source,             -- 'proxy_capture' for all worker-written flows
                  original_flow_id,   -- NULL for proxy_capture flows
                  replay_error        -- NULL for proxy_capture flows
                  )
                  per-operation connection
                  on normalization failure → NULL endpoint_id, flow still stored
                  on endpoint upsert failure → rollback, NULL endpoint_id, flow stored
                  COMMIT (flow + endpoint + endpoint_roles)
                  upsert endpoint_roles(endpoint_id, role_id, first_seen, last_seen)
                  extract parameters (query params, JSON body, form body)
                  upsert parameters per endpoint (type inference, dedup, 5-sample cap)
                  COMMIT parameters
                  on parameter failure → rollback param writes only; flow unaffected
                  compute auto-priority score (policy_score heuristics)
                    → upsert endpoint_policy (INSERT OR IGNORE + UPDATE auto fields)
                  COMMIT auto-priority
                  on score failure → rollback; log; flow unaffected
            → _persist_archive(flow)
                  file: <data_dir>/archive/flows-YYYY-MM-DD.jsonl
                  bytes → {"_b64": "..."}  (base64, lossless)
                  append + flush per write
                  rotate file handle at UTC midnight

Shutdown:
    TalosAddon.done() called by mitmproxy on exit
    → stop_event.set()
    → drain remaining queue items (no flows lost on clean exit)
    → close archive file handle
```

### Per-Project Storage
```
~/.talos/                         (or $TALOS_DATA_DIR)
  registry.json                   index of all projects + active state + constraints
  projects/
    <id>/
      talos.db                    structured data (SCHEMA_VERSION 54)
      archive/
        flows-YYYY-MM-DD.jsonl    raw capture archive
      headers_drop.txt            capture header filter template copy
      policy_score.json           auto-priority thresholds (optional/user-tuned)
      auth_sessions/
        <role_id>.txt             MANUAL provider session files
      BAC-decision-filter.yaml    optional BAC decision filter
      unauth-decision-filter.yaml optional unauth decision filter
      exports/                    Markdown/CSV exports from CLI (when written)
```

`talos project delete` removes the registry entry only; the project directory on disk is preserved.
`talos project delete --purge` also permanently deletes the project directory (DB, archive, reports, sessions, filters). Interactive purge requires a second confirmation unless `--force` is set.


### DB vs Archive
| Store | Role | Format |
|-------|------|--------|
| `talos.db` `flows` table | Structured truth — queryable, indexed | SQLite rows |
| `archive/flows-*.jsonl` | Ground truth — exact capture, audit, replay source | JSONL; bytes as `{"_b64": "..."}` |

### Data Isolation
- No table is shared across projects.
- Each project has its own SQLite database and archive directory.
- `project_id` is stored on top-level traffic/domain tables such as `flows`, `endpoints`, and `sessions`.
- Context and relation tables such as `roles`, `modules`, `access_map`, `parameters`, and `endpoint_roles` are isolated by database, not by a row-level `project_id` column.
- The registry is the only cross-project file; it stores metadata only (no traffic data).

---

## Basic Scope Matching Rules (URL-prefix model)

Talos uses **Basic Scope** aligned with Burp normal scope control. One entry is
one complete URL/host prefix. Wildcards are not part of the model (rejected at
parse time with an actionable message).

| Prefix | Matches | Does NOT match |
|--------|---------|----------------|
| `example.com` | `http(s)://example.com` any port, any path | `api.example.com` (subdomains not implied) |
| `http://example.com` | HTTP only, any port | HTTPS |
| `https://example.com` | HTTPS only, any port | HTTP |
| `example.com:8000` | Port 8000 only (both schemes) | Port 9000 or default 80/443 |
| `http://example.com:8000` | HTTP + port 8000 | HTTPS :8000 or HTTP :9000 |
| `example.com/api/` | Paths under `/api/` on that host | `/login`, `/apix` |
| `https://host/sap/` | `/sap/bc/...` **and** SAP session form `/sap(<sid>)/bc/...` | `/login`, `/sapphire/` |
| `10.10.10.25:8000` | That IPv4 + port | Same IP on another port |

**Port identity:** `http://h` ≡ `http://h:80`; `https://h` ≡ `https://h:443`.
Non-default ports remain part of canonical origin.

**Parenthetical path parameters (matching only):** Before path-prefix comparison,
Talos strips `(...)` groups from the request path and the rule path
(`talos.url_identity.strip_url_path_parameters`). This makes Basic Scope work for
SAP WebGUI session URLs (`/sap(<session>)/bc/...`) and ASP.NET cookieless forms
(`/(S(...))/app/...`) when the operator scopes the directory form
(`https://host/sap/`). Captured endpoint paths are **not** rewritten — only the
scope evaluator treats parentheses as transparent.

**Precedence:**

1. Parse full request URL identity (`talos.url_identity`).
2. If any **out-of-scope** prefix matches → OUT_OF_SCOPE.
3. Else if any **in-scope** prefix matches → IN_SCOPE.
4. Else → OUT_OF_SCOPE.

Implementation: `talos.proxy.scope.evaluate_scope` / `is_url_in_scope` — pure
functions shared by capture (addon) and the worker out-of-scope backstop.
Empty in-scope list → nothing captured (strict opt-in).

**Endpoint identity:** `method + canonical_origin + normalized_path` stored with
`endpoints.host` = canonical origin (e.g. `http://test.com:8000`), so ports
8000 and 9000 never collapse.

---

## Capture Constraints

| Field | Default | Effect |
|-------|---------|--------|
| `capture_in_scope_only` | `True` | Always enforced; not user-configurable |
| `store_bodies` | `True` | Set False to skip body storage entirely |
| `max_body_size` | `1 048 576` (1 MB) | Bodies exceeding this are truncated; `*_body_truncated=True` in flow dict |

---

## Database Schema (per project)

`SCHEMA_VERSION = 54` (`talos.projects.db`). WAL mode and foreign keys are enabled.
Intruder tables: `intruder_sessions`, `intruder_results` (v46; `finding_id` v48); `intruder_pools` (v47).
AI Layer Phase A (v49): `ai_sessions`, `ai_audit_events`, `ai_project_prefs`.
AI Layer Phase B (v50–v51): `ai_app_notes`, `ai_app_note_revisions`; immutable
`ai_suggestions`, `ai_execution_plans`, `ai_observations`, `ai_task_nodes`.
AI Layer Phase E (v52): `ai_draft_findings`. Markdown KB is filesystem-only
(`~/.talos/ai/kb/*.md` — not SQLite).
URL Sink Discovery Phase 1 (v53): `parameters.url_features` JSON (passive value +
name classification via `talos.url_sink`).
URL Sink Discovery Phase 2 (still v53): structure discovery expands inventory —
encoded JSON dotted paths, JWT virtual claims, expanded/value-first headers,
HTML/JS response params (`location=response`); no schema bump.
Auth-session engine (v54): `auth_session_bindings`,
`auth_session_candidates`, `auth_session_results` for the Authentication &
Session Testing package (`talos.auth_session` — attack engine; distinct from
`data_dir/auth_sessions/` manual role session files). Phase 1: schema + JWT
library. Phase 2: bind/generate/approve/reject CLI. Phase 3: engine +
`auth_session_attack` scheduler jobs + `run` / `results` (one job per test_id).
Phase 4: `auth-session-decision-filter.yaml` (filter-then-heuristic) +
`WEAK_VALIDATION` findings (`AUTH_SESSION:<auth_type>`; first PRIMARY, later LINKED).
Phase 5: full JWT algorithm-degradation matrix (same-family downgrades +
cross-family RS/ES/PS/HS edges; core owns pure `alg=none`); CLI polish
(`status`, `--format json` on action paths, results verdict tallies); docs.
Passive Source Intelligence tables arrive at v39; v40 adds virtual-document
parent/logical columns for source maps and HTML extractors; v42 adds
cross-flow / stored reflection (`value_index`, `cross_flow_reflections`,
`parameters.cross_flow_*`); v43 adds Error Intelligence (`error_clusters`,
`error_observations`, `error_intel_config`).

### Tables (current)

| Table | Purpose |
|-------|---------|
| `schema_version` | Single version integer (54) |
| `flows` | Captured and replayed HTTP exchanges |
| `endpoints` | Deduplicated method + **canonical origin** (`host` column) + normalized_path |
| `parameters` | Endpoint Intelligence parameter inventory (v42: `cross_flow_*`; v53: `url_features`) |
| `value_index` | Distinctive request values for cross-flow matching (v42) |
| `cross_flow_reflections` | Source→sink stored-reflection links (v42) |
| `sessions` | Session identity placeholders |
| `roles` / `modules` | Access-model identities and feature areas |
| `access_map` | client_allowed + server_expected per role×module |
| `endpoint_roles` | Observed role→endpoint pairs |
| `replay_diffs` | Diff results for replays |
| `auth_config` | Required auth artifact names (cookie/header) |
| `auth_test_results` | Authentication Bypass verdicts |
| `endpoint_annotations` | Legacy annotation tags table (logout/dangerous also on policy) |
| `scheduler_jobs` | Job queue |
| `scheduler_config` | min_delay / max_delay / max_queue_size |
| `scheduler_state` | running / paused / waiting_for_session |
| `out_of_scope_domains` | Out-of-scope Basic Scope prefixes (`domain` column stores prefix text) |
| `ai_sessions` | AI agent sessions (pin, mode, budgets, usage) — schema v49 |
| `ai_audit_events` | Append-only AI audit log — schema v49 |
| `ai_project_prefs` | Per-project AI prefs (auto-aggressive ack) — schema v49 |
| `ai_app_notes` / `ai_app_note_revisions` | Structured AI app notes — v50 |
| `ai_suggestions` / `ai_execution_plans` / `ai_observations` / `ai_task_nodes` | Suggest/approve loop + PTT — v51 |
| `ai_draft_findings` | AI draft findings before operator promote — v52 |

| `attack_config` | Key/value attack settings (e.g. `unauth_auto_run`) |
| `attack_host_exclusions` | **Legacy** — not used by current exclusion path |
| `role_auth` | **Legacy** single login/checkpoint assignment |
| `role_session_tokens` | **Legacy** token store |
| `auth_flow_config` | Current multi-flow + extractor config |
| `role_auth_state` | Live auth key/value state for injection |
| `role_auth_provider` | auto \| manual per role |
| `manual_session_config` | MANUAL provider session payload |
| `session_health_config` | TTL + expiry signals (+ legacy URL columns) |
| `session_health_control_flows` | Layer 3 validation flow IDs |
| `session_suspicion_state` | Runtime suspicion counters |
| `endpoint_policy` | Priority, exclusion, qualification, baseline cache |
| `policy_rules` | Path pattern priority/exclusion rules |
| `bac_results` | BAC attack outcomes |
| `unauth_results` | Unauthenticated Execution outcomes |
| `auth_session_bindings` | Auth-session: map `auth_config` field → auth type (JWT, …) (v54) |
| `auth_session_candidates` | Auth-session: pending/approved/… mutation candidates (v54) |
| `auth_session_results` | Auth-session: one verdict row per mutated replay flow (v54) |
| `cors_results` | CORS: one verdict row per unique Origin-probe replay flow (v55) |
| `proxy_config` | Direct vs upstream URL |
| `input_validation_config` | IV enablement and phase toggles |
| `iv_param_cache` | Parameter-level IV phase cache (resume) |
| `iv_reflection_cache` | Per-endpoint reflection cache |
| `iv_probe_results` | Per-probe IV results |
| `iv_param_profiles` | Versioned parameter intelligence profiles (Module 2) |
| `iv_endpoint_profiles` | Endpoint-level intelligence stubs (Module 2) |
| `iv_app_profiles` | Application/host intelligence stubs (Module 2) |
| `findings` | Vulnerability instances (PRIMARY/LINKED) |
| `finding_evidence` | Evidence references |
| `finding_timeline` | Immutable event log |
| `finding_groups` / `finding_group_members` | User groups |
| `source_documents` / `source_occurrences` / `passive_detections` | Passive Source Intelligence |
| `passive_scan_config` | Passive scan defaults |
| `value_index` / `cross_flow_reflections` | Cross-flow / stored reflection (v42) |
| `error_clusters` | Error Intelligence unique fingerprints (v43) |
| `error_observations` | Error sightings: flow / param / attack_type (v43) |
| `error_intel_config` | Error Intelligence defaults (v43) |

### Scheduler job types

From `talos.scheduler.job`:

| Category | job_type values |
|----------|-----------------|
| Replay | `replay_flow`, `replay_endpoint` |
| Authentication Bypass | `auth_test` |
| BAC | `bac_session_swap`, `bac_method_fuzz`, `bac_content_type`, `bac_url_fuzz`, `bac_header_inject`, `bac_host_fuzz`, `bac_role_inject`, `bac_parser_confuse` |
| Unauthenticated Execution | `unauth_attack` |
| Auth-session (Phase 4) | `auth_session_attack` (one job per approved test_id; settle marks candidate done/failed + WEAK_VALIDATION findings) |
| CORS | `cors_attack` (one unique replay flow per Origin technique) |
| Input Validation | `iv_baseline`, `iv_multiprobe`, `iv_identifier`, `iv_characters`, `iv_length`, `iv_types`, `iv_transformations`, `iv_reflection`, `iv_validation`, `iv_parser` |

Statuses: `pending`, `running`, `done`, `failed`, `skipped`, `paused`, `cancelled`.

Priorities: `PRIORITY_MANUAL=100`, `PRIORITY_AUTO=10`.

### Flows: source and identity

- `source`: `proxy_capture` | `manual_replay` | `auto_replay` | `iv_scan` | `manual_send` | `ai_send`
- `original_flow_id`: parent capture for replays
- `replay_reason`: examples include `testing`, `auth_test`, `unauth_attack`, `input_validation`, BAC attack type strings, `session_validation`, `session_refresh`, `scheduler`
- `flow_meta` (JSON): module-specific metadata (e.g. `generated_by`)

### Endpoint qualification (policy)

`qualified = 1` when at least one `proxy_capture` flow has status **200–299**, and the endpoint is not marked logout/dangerous. Baseline flow id is cached on `endpoint_policy`.

`get_testable_endpoints()` is the single candidate filter for attack modules
(qualified + not excluded). `list_endpoints()` is the full inventory used by
`talos endpoint list` (includes unqualified/excluded; optional CLI filters).

`list_flows()` is the full flow inventory used by `talos flow list`
(proxy captures and replays; optional filters for endpoint, status, role,
source, and limit). Ordered by `captured_at` DESC for chronological discovery.

### Migrations

`migrate_project_db(db_path)` upgrades older databases in place up to `SCHEMA_VERSION` (54). Called automatically on project DB use. For the full step list, see migration branches in `talos/projects/db.py` (`_migrate_schema` / `migrate_project_db`).

Notable milestones:

| Range | Highlights |
|-------|------------|
| v6–v13 | Replay columns, diffs, auth_config, annotations, scheduler |
| v14–v18 | Mutations, attack_config, host exclusions (later legacy) |
| v19–v23 | Auth flows, session health, BAC results, endpoint policy |
| v24–v30 | IV tables, qualification, providers, manual session, scheduler_state |
| v31–v34 | Findings, unauth_results, proxy_config, finding relationships (PRIMARY/LINKED) |
| v35 | IV multi-level profiles: `iv_param_profiles`, `iv_endpoint_profiles`, `iv_app_profiles` |
| v39–v41 | Passive Source Intelligence tables + source-map columns + scan budget |
| v42 | Cross-flow reflection: `value_index`, `cross_flow_reflections` |
| v43 | Error Intelligence: `error_clusters`, `error_observations`, `error_intel_config` |
| v44–v48 | Repeater tabs; Intruder sessions/results/pools; findings promote lineage |
| v49 | AI Layer Phase A: `ai_sessions`, `ai_audit_events`, `ai_project_prefs` |
| v50 | AI Layer Phase B: `ai_app_notes`, `ai_app_note_revisions` |
| v51 | AI Layer Phase B: `ai_suggestions`, `ai_execution_plans`, `ai_observations`, `ai_task_nodes` |
| v52 | AI Layer Phase E: `ai_draft_findings` (markdown KB is filesystem `~/.talos/ai/kb`) |
| v53 | URL Sink Discovery Phase 1: `parameters.url_features` (passive value + name classification) |
| v54 | Auth-session engine: `auth_session_bindings`, `auth_session_candidates`, `auth_session_results` |
| v55 | CORS engine: `cors_results` (one unique replay flow per Origin technique) |

---

## Failure Points

| Failure | Location | Behavior |
|---------|----------|----------|
| Registry file corrupted (bad JSON) | `_load_registry()` | Raises `ProjectError` with clear message; no silent fallback |
| Duplicate project name | `create()` | Raises `ProjectAlreadyExists` before any disk write |
| DB init fails mid-create | `create()` | Directory may exist; registry is NOT written → registry stays clean |
| No project bound at proxy start | `TalosAddon.__init__` | Raises `NoActiveProject` if neither registry ACTIVE nor `TALOS_PROJECT` / `--project`; mitmproxy logs it and aborts |
| Unknown `--project` / `TALOS_PROJECT` id | `__main__._make_manager` | `cli_error` exit 1 before subcommand runs |
| Scope list empty at proxy start | `proxy.cli.cmd_start` | WARNING printed to stderr; proxy starts but captures nothing |
| `headers_drop.txt` missing from project dir | `_load_drop_headers()` | WARNING log; all headers pass through (non-fatal) |
| `default_headers_drop.txt` template missing from install | `_copy_headers_drop_template()` | WARNING log; project created without filter file |
| `TALOS_DATA_DIR` points to unwritable path | `ProjectManager.__init__` | `mkdir` raises `PermissionError` immediately |
| Active role/module missing in DB | `seed_default_context()` | Global role/module are inserted and activated before capture starts |
| Worker DB insert fails | `FlowWorker._process()` | Logs ERROR; archive write skipped for that flow; both stores stay consistent |
| Worker archive write fails | `FlowWorker._process()` | Logs ERROR; DB row already committed; archive line missing for that flow |
| URL normalization raises unexpectedly | `_persist_db()` | Logs ERROR; endpoint_id set to NULL; flow stored with raw query |
| Endpoint upsert fails during DB write | `_persist_db()` | Logs ERROR; transaction rolled back for endpoint work; flow stored with NULL endpoint_id |
| Parameter extraction fails | `_persist_db()` | Logs ERROR; parameter writes rolled back; flow and endpoint already committed and unaffected |
| Flow missing `role_id` or `module_id` | `_validate_flow()` | Logs WARNING; flow dropped before persistence |
| Queue full at shutdown | `FlowWorker.stop()` | Drain loop consumes remaining items before thread exits; flows not silently lost |
| Replay: flow_id not found | `replay_flow()` | Returns `ReplayOutcome(failure_reason='flow_not_found')`; CLI exits 1 |
| Replay: endpoint has no qualifying 2xx proxy_capture flow | `replay_endpoint()` | Returns `ReplayOutcome(failure_reason='no_qualifying_flow')`; CLI exits 1 |
| Replay: connection refused / unreachable | `_execute_replay()` | Stores flow with `replay_error='connection_error'`, `status_code=NULL`; outcome marked failed |
| Replay: request times out (>30 s) | `_execute_replay()` | Stores flow with `replay_error='timeout'`, `status_code=NULL`; outcome marked failed |
| Replay: HTTP protocol error | `_execute_replay()` | Stores flow with `replay_error='http_error'`, `status_code=NULL`; outcome marked failed |
| Replay: unexpected exception | `_execute_replay()` | Stores flow with `replay_error='unexpected_error'`; never silently discarded |
| Diff storage fails after replay | `_execute_replay()` / `_execute_stripped_replay()` | Logs ERROR; replay flow already committed and unaffected; diff row missing for that replay |
| Auth test: auth_config empty | `run_auth_bypass_test()` | Returns `auth_verdict='UNKNOWN'`, `failure_reason='auth_config_empty'`; CLI exits 1 |
| Auth test: no qualifying flow | `run_auth_bypass_test()` | Returns `auth_verdict='UNKNOWN'`, `failure_reason='no_qualifying_flow'`; CLI exits 1 |
| Auth test result storage fails | `_execute_stripped_replay()` | Logs ERROR; replay flow and diff already committed and unaffected |
| Replay/auth test: endpoint tagged logout | `replay_flow()` / `replay_endpoint()` / `run_auth_bypass_test()` | Returns `failure_reason='endpoint_annotated_logout'`; CLI exits 1; no request sent |
| Replay: endpoint tagged dangerous (auto mode) | `replay_endpoint()` | Returns `failure_reason='endpoint_annotated_dangerous'`; CLI exits 1; no request sent |
| Auth test: endpoint tagged dangerous | `run_auth_bypass_test()` | Returns `failure_reason='endpoint_annotated_dangerous'`; CLI exits 1; no request sent |
| Scheduler: job endpoint tagged logout | `ReplayScheduler._annotation_pre_check()` | Job marked skipped; logged; no request sent |
| Scheduler: job endpoint tagged dangerous (auto priority) | `ReplayScheduler._annotation_pre_check()` | Job marked skipped; logged; no request sent |
| Scheduler: underlying replay/auth engine fails | `ReplayScheduler._execute_job()` | Job marked failed; error logged; scheduler continues to next cycle |
| Scheduler: unknown job type | `ReplayScheduler._run()` | Job marked skipped; scheduler continues |

---

## Configuration

### Layered configuration (CLI-022)

Application settings converge on **`talos.configuration`**:

```text
Built-in defaults
        ↓
Global  ~/.talos/config.yaml   (or $TALOS_DATA_DIR/config.yaml)
        ↓
Legacy project stores (SQLite proxy/scheduler/attack tables,
                       headers_drop.txt, registry constraints)
        ↓
Project project.yaml   (overrides only)
        ↓
CLI one-shot overrides
        ↓
EffectiveConfig  (immutable snapshot)
```

| Layer | Path / store | Written by |
|-------|--------------|------------|
| Defaults | `talos.configuration.defaults.BUILTIN_DEFAULTS` | code |
| Global | `$TALOS_DATA_DIR/config.yaml` | `talos config set --global` / `edit --global` |
| Project | `<project>/project.yaml` | `talos config set` / `edit`; dual-write from legacy CLIs |
| Legacy | SQLite + `headers_drop.txt` + constraints | bridged on load; dual-written on set |

**CLI:** `talos config show|effective|get|set|unset|edit` and section resources
`talos config proxy|capture|scheduler|attack|http|parameter_intel|url_sink|burp`.
HTTP rules use the dedicated resource `talos config http`
(list/create/match/actions/export/…). `burp.enabled` / `burp.header_prefix`
control `X-Talos-*` grouping headers on outbound attack requests (Input
Validation first). Headers attach only when enabled and an upstream proxy
is set. See `docs/burp-extension.md`.

**Runtime:** Proxy addon loads `EffectiveConfig` once at startup. The
**HTTP Manipulation Engine** (`http.enabled` + concatenated `http.rules` from
all layers) runs on every request and response when enabled. Rules are sorted by
priority; match conditions scope by host/path/method/status/endpoint/context.
Default: engine on with **empty rules** (no traffic modification). Helpers
`get_upstream_url` / `get_scheduler_config` / `get_unauth_auto_run` resolve via
the same manager so global inheritance applies.

**Still outside the layered model** (operational or specialized config):

- Auth sessions / providers / extractors (`auth-config`)
- BAC / unauth decision filters (YAML)
- Policy score weights (`policy_score.json`)
- Input Validation enable/workers/phases (SQLite + own CLI)
- Endpoint policy, roles, modules, findings

Compatibility wrappers: `talos proxy config`, `talos scheduler config`,
`talos attack unauth config` remain and dual-write YAML + SQLite.

### Path and process environment

| Source | Key | Default | Purpose |
|--------|-----|---------|---------|
| Environment | `TALOS_DATA_DIR` | `~/.talos` | Override storage root (test isolation, custom path) |
| Environment | `TALOS_PROJECT` | (unset) | Process-scoped project id (CLI-013); same as `talos --project <id>` |
| CLI (root) | `--project <id>` | (unset) | Per-invocation project bind; does not rewrite registry ACTIVE |

---

## Implemented Subsystems

- [x] Project management (`talos.projects`)
- [x] Proxy layer — scope enforcement, header filtering, flow extraction (`talos.proxy`)
- [x] Flow queue — in-memory, bounded, drop-on-full (`talos.proxy.queue`)
- [x] Worker pipeline — validate, persist to DB + archive (`talos.worker`)
- [x] Access model — roles, modules, two-layer client/server tri-state map (`talos.projects.access`)
- [x] Access analysis — coverage and signal reporting from captured flows (`talos.projects.access`, `talos.projects.access_cli`)
- [x] Flow normalization — endpoint deduplication, parameter extraction (`talos.projects.endpoints`, `talos.projects.parameters`)
- [x] Replay engine — exact (Type 1) replay; endpoint and flow entry points; `auto_replay` flow storage (`talos.replay`)
- [x] Diff engine — structural comparison of original vs replay; verdict SAME/DIFFERENT/ERROR; stored in `replay_diffs` (`talos.replay.diff`)
- [x] Auth bypass testing — Type 2 replay (auth stripped); SECURE/BYPASS/UNKNOWN verdict; stored in `auth_test_results` (`talos.replay.auth_strip`, `talos.projects.auth`)
- [x] Endpoint safety annotations — manual tagging (logout/dangerous); guard layer in replay engine and auth-strip blocks unsafe execution (`talos.projects.annotations`, `talos.projects.endpoint_cli`)
- [x] Replay scheduler — daemon thread started alongside proxy; priority queue with dedup and overflow guards; annotation pre-checks; configurable jitter; `talos scheduler` CLI for status/config/enqueue/clear (`talos.scheduler`)
- [x] Out-of-scope domain list — per-project block list that overrides the scope allow-list; enforced at proxy capture and worker persist; CLI via `talos project outscope` (`talos.projects.outscope`, `talos.projects.outscope_cli`)
- [x] HTTP Manipulation Engine — single declarative rule engine for request **and** response modification; replaces former `capture.header_rules` + `request_mutations` / `talos mutation`; rules in layered `http.rules` (global + project concatenated, priority-sorted); match conditions (host/path/method/status/headers/endpoint/context); actions (headers, cookies, query, URL/method, body, status, delay/drop/abort); master switch `http.enabled`; CLI `talos config http` (list/show/create/delete/enable/disable/set-priority/set-match/add-action/export/import/…); proxy `request()` + `response()` hooks (`talos.configuration.http_engine`, `talos.configuration.http_rules`, `talos.configuration.http_cli`)
- [x] CORS misconfiguration — `talos attack cors run` enqueues `cors_attack` jobs (one unique replay flow per Origin technique); in-scope 200 OK POST/PATCH/PUT then GET; findings only on attacker-origin reflection (`CORS:<origin>` PRIMARY + LINKED techniques); Control Panel `/testing/cors`
- [x] Unauthenticated Execution — `talos attack unauth run` enqueues `unauth_attack` jobs (technique + optional request mutation recipes in `UNAUTH_RECIPES`); results in `unauth_results`; verdicts SECURE/BYPASS/UNKNOWN; BYPASS creates findings; decision filter via `talos attack unauth filter`; offline **filter apply** re-evaluates stored results and auto-rejects TRIAGING findings that flip BYPASS→SECURE (`talos attack unauth filter apply [--dry-run] [--force]`, `talos.projects.unauth.reclassify`); exclusions via Endpoint Policy (`talos endpoint exclude`). Distinct from Authentication Bypass (`talos auth test` → `auth_test` / `auth_test_results`). Auto-run via `talos attack unauth config [show] [--auto-run on|off]` (default off) makes the scheduler enqueue classic `auth_test` jobs for untested qualified endpoints (`talos.projects.unauth`, `talos.projects.attack_config`)
- [x] Auth-session foundation (Phase 1) — package `talos.auth_session` (naming: not `Project.auth_session_path` / `auth_sessions/` files); schema v54 tables; stdlib JWT codec/mutators; suite catalog with algorithm degradation (no `*_to_none`); `AuthTypeAnalyzer` + JWT registry (`docs/design-auth-session-testing-engine.md`)
- [x] Auth-session bindings & candidates (Phase 2) — `talos attack auth-session bind|unbind|show-bindings|generate|candidates|approve|reject|suite list`; insert-if-absent generate; operator approve lifecycle
- [x] Auth-session engine & scheduler (Phase 3) — heuristic verdict; `execute_auth_session_job` (one mutation / one flow); `auth_session_attack` job type + settle; `run` / `results` CLI; meta-aware dedupe
- [x] Auth-session filter & findings (Phase 4) — `auth-session-decision-filter.yaml` (filter init|show|validate); score filter-then-heuristic; `WEAK_VALIDATION` → TRIAGING findings from settle/`--right-now` via findings_bridge; cluster `AUTH_SESSION:<auth_type>`
- [x] Auth-session docs & suite polish (Phase 5) — full alg-degradation matrix (RS/ES/PS same-family downgrades + cross-family); `status` CLI; `--format json` on generate/approve/run/results; cheat sheet + architecture + updates + Talos Helper; Control Panel still out of scope
- [x] Broken Access Control (BAC) — access-matrix candidate generation, eight attack modules + parser-confuse, decision filter, scoped `--endpoint`/`--module NAME|UUID`/`--role NAME|UUID`, results in `bac_results`, findings on `POSSIBLE_BAC`; offline **filter apply** re-evaluates stored results and auto-rejects TRIAGING findings that flip POSSIBLE_BAC→SECURE (`talos attack bac filter apply [--dry-run] [--force]`, `talos.projects.bac.reclassify`) (`talos.projects.bac`)
- [x] Input Validation Engine — eight analysis phases via scheduler job types `iv_*`; disabled by default; parameter cache tables; CLI `talos input-validation` (`talos.input_validation`)
- [x] IV Evidence Foundations (Module 1) — `ResponseFingerprint` + `compare_fingerprints` + `classify_outcome` + `IV_PROFILE_SCHEMA_VERSION` / `profile_envelope`; pure helpers only (no change to default probe matrix / request volume); tests in `tests/test_iv_fingerprint.py` (`talos.input_validation.fingerprint`, `talos.input_validation.outcomes`)
- [x] IV Profile Data Model (Module 2) — versioned parameter/endpoint/app profiles (`observed`/`inferred`, confidence, `tested`, `attempts`, capabilities, candidates placeholders); tables `iv_param_profiles` / `iv_endpoint_profiles` / `iv_app_profiles` (schema v35); CRUD in `talos.input_validation.db`; pure shape helpers in `talos.input_validation.profile`; no probe-volume change; tests in `tests/test_iv_profile.py`
- [x] IV Synthesis from Existing Probes (Module 3) — offline `synthesize_param_profile` / `synthesize_many` from `iv_probe_results` + flows using M1 fingerprints/outcomes into M2 profiles; `talos input-validation synthesize`; show/export intelligence sections; transform/reflection race guard + auto-synthesis; multiprobe extension hooks; no probe-volume change; tests in `tests/test_iv_synthesize.py` (`talos.input_validation.synthesize`)
- [x] IV Canaries & Multiprobe (Module 4) — high-entropy `TL…` canaries; multiplexed payload embeds taxonomy class samples; `iv_multiprobe` job (one HTTP → reflection + multi-class outcomes); `probe_strategy` quick|standard|deep|exhaustive; standard skips weak identifiers + per-char matrix when multiprobe on; exhaustive keeps legacy list; flow_meta.multiprobe evidence; synthesis consumes analyzer results; tests in `tests/test_iv_multiprobe.py` (`talos.input_validation.multiprobe`)
- [x] IV Event-Driven Planner (Module 5) — deterministic adaptive DAG (`planner.py`); budget tiers + `max_requests_per_param`; `run` enqueues next wave only (not ~70 jobs); post-job `continue_param_plan`; high-confidence early stop; reflection-unknown multiprobe retry; no analysis-before-evidence; status shows budget/requests/plan; tests in `tests/test_iv_planner.py`
- [x] IV Character Taxonomy & Length (Module 6) — class-tier charset probes (`taxonomy.py`); binary/log length search with truncation vs reject (`length_search.py`); planner `char_drilldown` / `length_binary` executors; standard representatives not full 30-char list; length seed under 10; exhaustive keeps extended matrix; tests in `tests/test_iv_taxonomy_length.py`
- [x] IV Types, Semantic Validation & Negative Evidence (Module 7) — passive-first type pruning + semantic rules + type-family catalogs (boolean polarity, email shapes, array wrap, numeric edges) + JSON native inject (`type_intel.py` / `surface.inject_json_param`); planner `type_confirm` / `semantic_rules`; systematic `tested{}`; tests in `tests/test_iv_type_semantic.py` + `tests/test_iv_surface.py`
- [x] IV Normalization & Parser Fingerprinting (Module 8) — norm pipeline + parser fingerprint (`parser_intel.py`); `iv_parser` jobs; structural inject; tests in `tests/test_iv_parser_norm.py`
- [x] IV Surface Completeness (Module 9) — path/header/cookie/multipart/GraphQL/XML first-class inject (`surface.py`); auth-artifact skip default; `include_auth_artifacts` config/CLI; transport-legal header/cookie gates + location-aware multiprobe/norm/validation; schema v38; tests in `tests/test_iv_surface.py`
- [x] IV Multi-Level Learning (Module 10) — endpoint/app profile aggregation + inheritance priors (`learning.py`); confidence decay cap 75; local observed wins; standard skips control/parser when parent known; CLI `show --endpoint` / `show --host`; tests in `tests/test_iv_learning.py`
- [x] IV Capabilities, Attack Candidates & Consumer API (Module 11) — centralized capability derivation (`capabilities.py`); attack candidate scores with reasons (`candidates.py`); `get_param_intelligence` / `list_candidates` stable API; synthesize + CLI show/export; prioritization only (not confirmed vulns); tests in `tests/test_iv_candidates.py`
- [x] Findings subsystem — PRIMARY/LINKED clusters, groups, reports (`talos.findings`)
- [x] Passive Source Intelligence (Phases 0–12, 14–16 core CLI + Phase 13 Control Panel) — design freeze + package skeleton + schema v39/v40 CRUD + candidate/classify/normalize + queue/worker + detector pipeline (provider/YAML, PEM, JWT, connection strings, contextual, entropy, decoder, infrastructure) + findings bridge (`PASSIVE_SECRET` one PRIMARY, later leaks LINKED) + CLI (`talos passive …`) + source-map + HTML inline extractors + rescan + docs/Helper; Control Panel Secret Detection workspace (`/secret-detection`, `/api/passive/*`, Console tree, dashboard/flow/finding deep links); `SCANNER_VERSION=1.3.0`; tests in `tests/test_passive_*.py` + `talos-control-panel/backend/tests/test_passive_routes.py`.
- [x] Flow inspector — `talos flow list|show|export` (`talos.projects.flow_cli`)
- [x] Flow inventory (CLI-003) — `talos flow list` prints UUID, endpoint (`host`+`path`), method, status, role, source, created; filters `--endpoint`, `--status-code`, `--role` (name or UUID), `--source`, `--limit`; primary discovery path for flow UUIDs used by show/export/replay/auth-config (`talos.projects.flow_cli`)

- [x] Authentication Provider architecture — per-role provider selection (AUTO | MANUAL) stored in `role_auth_provider`; MANUAL sessions store arbitrary headers/cookies/expiry in `manual_session_config` and are applied to `role_auth_state` without replaying any flows; AUTO provider retains the existing extractor-based refresh path; `session_health.should_refresh`, `refresh_auth_state`, and `ensure_healthy` are provider-aware; scheduler detects MANUAL session expiry, pauses itself (`WAITING_FOR_SESSION`), and marks pending jobs `paused` instead of failing them; `talos auth-config set-provider`, `set-session`, `show-provider`, `clear-session`, `reset-health`; `talos scheduler pause|resume` (`talos.projects.auth_provider`, `talos.projects.session_health`, `talos.scheduler`)
  - **Authentication lifecycle enforcement:** `talos auth-config set-session` automatically runs validate + refresh + status after saving; if validation fails the role_auth_state is cleared so the session is not used until explicitly fixed. `talos auth-config validate` and `refresh` for MANUAL require: auth artifact names configured, session values not expired, a validation flow configured, and successful validation; they exit 1 and do not mark the session ready unless all checks pass. Validation flows are mandatory for every role: `validate_session()` returns False when no control flows are configured.
  - **Validation flow mechanism:** `validate_session()` injects the current `role_auth_state` into the validation flow's request (replacing all configured auth headers and cookies), replays it, and compares the replay response HTTP status to the original baseline status of that flow. A matching status confirms the session is alive; a mismatch (401, 403, redirect, etc.) means the session is dead. Session validation uses control flows only (Session Health Layer 3). There is no `set-validation` / `clear-validation` CLI. Legacy `validation_endpoint_*` columns may exist in schema but are not the user path.
  - **IV auth injection:** Input Validation scan jobs (scheduler `_execute_iv_job`) inject the current `role_auth_state` into the base flow before every probe mutation. This replaces the original captured credentials with the live session, ensuring probes always use the latest authenticated values. If auth is configured but `role_auth_state` is empty, the job fails with `no_active_auth_state` instead of replaying with stale captured credentials.
  - **Cookie header deduplication:** `_inject_auth_state` in the BAC engine removes all Cookie header variants (any capitalisation) before rebuilding the single canonical `Cookie` header from the updated cookies dict. This prevents duplicate Cookie headers that would be joined with commas by intermediate proxies.
  - **Input Validation auth pre-check:** `talos input-validation run` (and all phase shorthand commands) call `verify_auth_for_iv_scan()` before scheduling any jobs. This collects all role_ids from flows for the scoped endpoints and verifies each role has: auth artifact names configured, provider set, session values / login flows present, validation method configured, and validation passes. If any role fails the check, the scan does not start.
  - **File-based `set-session` (no launched editor):** `talos auth-config set-session <role> path` prints (creating from a template if absent) a persistent session file at `<project_data_dir>/auth_sessions/<role_uuid>.txt` — Talos never launches notepad/sublime/`$EDITOR` for this file; the tester edits it with whatever tool they prefer. `talos auth-config set-session <role>` (no `path` arg) then parses that file, verifies the role's provider is already `manual` and that the project has at least one auth artifact defined (`talos auth set --header/--cookie`), and only then applies + validates + refreshes — exactly as the old apply/validate flow did. `<role>` is a role name or UUID. `Project.auth_session_path(role_id)` (in `talos.projects.model`) computes the path from the resolved UUID.
  - **Role UUID discoverability (CLI-001):** `talos role list` prints UUID, name, and active marker; `talos role show <name|uuid>` prints name, UUID, status, access-map modules, auth provider, and auth-flow count. All `auth-config` role arguments accept a role **name or UUID** (resolved via `resolve_role()` in `talos.projects.access` — name first, then UUID). BAC `--role` uses the same resolver.
  - **Module name/UUID discoverability (CLI-004):** `talos module list` prints UUID, name, and active marker; `talos module show <name|uuid>` prints name, UUID, status, description, and access-map roles. BAC `--module` accepts a module **name or UUID** via shared `resolve_module()` (name first, then UUID) — same identification rule as roles.
  - **Role & module lifecycle (CLI-006):** `talos role|module rename <name|uuid> <new_name>` updates the display name only (UUID stable; no FK rewrite). `talos role|module delete <name|uuid> [--force]` shows dependency counts (access matrix, flows, auth config, BAC results, findings evidence), prompts unless `--force`, cascades config rows, reassigns tagged flows to the built-in `global` role/module, and refuses deletion/rename of `global`. Manual session file for a deleted role is removed when present.
  - **Unauth auto-run config (CLI-005):** `talos attack unauth config show` and `talos attack unauth config --auto-run on|off` expose `attack_config.unauth_auto_run`. When enabled, the scheduler auto-enqueues classic `auth_test` jobs for untested qualified endpoints. Distinct from `talos attack unauth run` (`unauth_attack` recipes).
  - **`scheduler resume` no session preflight:** `cmd_resume` used to validate MANUAL sessions (first every role, then only roles referenced by pending/paused BAC jobs). That preflight was removed — resume always returns paused jobs to pending and sets the scheduler RUNNING. Session health is enforced when a job runs (`ReplayScheduler._execute_bac_job` / `_execute_iv_job` call `ensure_healthy`; expired MANUAL sessions pause the scheduler as `WAITING_FOR_SESSION`). Paused Intruder sessions are listed as a warning and are not auto-resumed (`talos.scheduler.cli`).
- [x] Configurable proxy startup mode — Direct (default, no upstream) vs Upstream Proxy (`--mode upstream:<url>`). Shared resolution in `talos.projects.proxy_config` (`resolve_upstream_url` / `get_upstream_url` / validate); mitmdump argv built only by `talos.proxy.launcher.build_mitmdump_command` (no hardcoded host/port). Persist with `talos proxy config --upstream <url>` / `--no-upstream`; one-shot override on `talos proxy start --upstream|--no-upstream`. Replay, BAC, and unauth engines use the same project upstream for httpx (or direct when unset). Config is re-read on every start/resolve so changes apply after restart.
- [x] Origin HTTP/1.1 + keep-alive + platform NTLMv2 (`talos proxy config --http1`, `talos proxy auth add`). Required for IIS Negotiate/NTLM + Persistent-Auth through a MITM (same as Burp platform authentication with HTTP/2 off). Addon short-circuits matching hosts through a persistent NTLM client that talks **directly to the origin** (httpx mounts bypass an intercepting upstream such as Burp with platform auth off — NTLM cannot survive a second hop that does not own the origin socket). Other hosts still use the configured upstream. Strips `WWW-Authenticate: Negotiate` so browsers fall back to NTLM; a leftover 401 does not forward `WWW-Authenticate` (prevents the browser prompt loop).

- [x] Findings quality-of-life pass — `talos finding show` prints full (untruncated) evidence reference UUIDs, the target's application module and role, and an Original Flow vs. Attack Replay Flow comparison (method/URL/status/body-length delta); `talos.findings.creator` reconstructs the timeline from real historical timestamps (flow capture time, scheduler job start/finish time) instead of a single batch of "now" events; `unauth` attacks were added to `VERDICT_TRIGGERS`/`ATTACK_DISPLAY` (previously missing, so BYPASS verdicts from `talos attack unauth` silently produced no finding) with the correct "Unauthenticated Execution" label; `talos finding list` and generated reports show module/role too; group reports with more than one finding get a numbered Index at the top (`talos.findings.cli`, `talos.findings.creator`, `talos.findings.report`, `talos.findings.model`).
- [x] Finding relationships (PRIMARY / LINKED) — schema v34 adds `relation_type`, `parent_finding_id`, `cluster_key` with partial unique index one-PRIMARY-per-cluster; Unauth clusters as `UNAUTH:<endpoint_id>` (mutations excluded); creator owns PRIMARY/LINKED decision with concurrent-race retry; default `talos finding list` shows PRIMARY only with linked count; `--linked` / `--all` list filters; bulk `confirm|reject|reopen --linked [--force]` (PRIMARY only, one-time, no status inheritance); statuses remain independently triageable; LINKED ≠ DUPLICATE lifecycle (`talos.findings.db`, `talos.findings.creator`, `talos.findings.cli`, `talos.findings.model`, `talos.findings.report`).
- [x] Role UUID discoverability (CLI-001) — `talos role list` shows UUID/Name/Active; `talos role show <name|uuid>` dossier; `auth-config` and BAC `--role` accept role name or UUID via shared `resolve_role()` (no schema change) (`talos.projects.access`, `talos.projects.access_cli`, `talos.projects.auth_config_cli`, `talos.projects.bac.cli`).
- [x] Module name/UUID discoverability (CLI-004) — `talos module list` shows UUID/Name/Active; `talos module show <name|uuid>` dossier; BAC `--module` accepts module name or UUID via shared `resolve_module()` (no schema change) (`talos.projects.access`, `talos.projects.access_cli`, `talos.projects.bac.cli`).
- [x] Role & module lifecycle (CLI-006) — `rename` / `delete [--force]` for roles and modules; dependency summary; cascade access/auth/BAC config; reassign flows to `global`; protect built-in `global` (`talos.projects.access`, `talos.projects.access_cli`).
- [x] Unauth auto-run config (CLI-005) — `talos attack unauth config [show] [--auto-run on|off]` surfaces `unauth_auto_run` for scheduler `auth_test` auto-enqueue; default off; distinct from `unauth run` (`talos.projects.unauth.cli`, `talos.projects.attack_config`).
- [x] Endpoint & finding notes/tags (CLI-008) — `talos endpoint notes set|clear`, `talos endpoint tags add|remove|set|clear`, `talos finding note set|clear` write existing `endpoint_policy.notes`/`tags` and `findings.notes`; finding notes append timeline events and appear in show/report; export dossier includes notes/tags (`talos.projects.endpoint_cli`, `talos.projects.policy`, `talos.findings.cli`, `talos.findings.db`).
- [x] Confirmation prompt consistency (CLI-015) — shared policy in `talos.cli_output`: interactive TTY → `[y/N]`; non-interactive → require `--force` or exit **2** (`Operation requires --force in non-interactive mode.`); `add_force_argument` / `is_interactive` / `confirm_or_*`; applied to project/role/module/HTTP-rule/access delete, auth clear, auth-config clear-expiry-signals, scheduler clear/overflow/prune, IV clear-cache, finding bulk status and group remove (`talos.cli_output` + CLI modules).
- [x] Scheduler job management (CLI-016) — per-job inventory and operations without bulk-clearing the queue: `talos scheduler jobs list [--status] [--type] [--limit] [--format]`, `jobs show <id>` (UUID or unique prefix; endpoint/flow/type/timestamps/failure reason/meta), `talos scheduler cancel <id>` (pending/paused → `cancelled`), `talos scheduler prune --status done|failed|skipped|cancelled [--force]`; DB helpers `list_jobs` / `get_job` / `cancel_job` / `prune_jobs` / `count_jobs_by_status`; `STATUS_CANCELLED` surfaced in status counts (`talos.scheduler.db`, `talos.scheduler.cli`).
- [x] Project lifecycle management (CLI-017) — `talos project rename <id> <new_name>` (display name + slug re-key, directory move, DB `project_id` rewrite); `talos project description <id> [TEXT…]` show/set; `talos project delete [--purge] [--force]` (default preserves disk; `--purge` rmtree data_dir with double interactive confirm) (`talos.projects.manager`, `talos.projects.cli`).
- [x] Input Validation flag consistency (CLI-019) — phase shortcuts use `--ignore-cache` (not `--force`) to re-run completed analyses; `--force` on phase cmds kept only as a deprecated alias for `--ignore-cache`; `--force` reserved for confirmation bypass elsewhere (e.g. `clear-cache`); `run` already used `--ignore-cache` only (`talos.input_validation.cli`).
- [x] Session recovery commands (CLI-021) — operators recover stuck sessions and degraded health confidence without SQLite edits: `talos auth-config clear-session <role>` wires `clear_manual_session_config()` (prints `Session cleared.`); `talos auth-config reset-health <role>` wires `reset_suspicion()` (prints `Health suspicion reset.`); role name or UUID (`talos.projects.auth_config_cli`, `talos.projects.auth_provider`, `talos.projects.auth`).
- [x] Layered configuration system (CLI-022) — single `EffectiveConfig` from defaults → global `config.yaml` → legacy project stores → `project.yaml` → CLI; `talos config show|effective|get|set|unset|edit|schema` and section resources (`proxy`/`capture`/`scheduler`/`attack`/`http`/`parameter_intel`/`url_sink`/`burp`); HTTP Manipulation Engine for declarative `http.rules`; dual-write keeps legacy SQLite CLIs working; proxy addon and proxy/scheduler/attack helpers consume the manager (`talos.configuration`); Control Panel `/talos-config` + `/mutations` (HTTP Rules) + `/api/configuration` for effective values, sources, global/project scope.
- [x] Burp Suite integration — `burp.enabled` / `burp.header_prefix` layered knobs; IV jobs stamp `flow_meta["burp"]`; when the extension is loaded Talos posts traces to `127.0.0.1:17384` so proxied requests carry no `X-Talos-*` (HTTP history cannot be rewritten); header fallback if ingest is down; Java Montoya extension (`burp-extension/`) trees Engine → Endpoints (`talos.burp`, `docs/burp-extension.md`).
- [x] **AI Layer Phase A** — policy-gated agent foundation (`talos.ai`): Workflow Engine (session lifecycle, frozen project pin, one-active-per-project, BudgetCounters, audit); capability-based mode grants (`suggest-only` default / `step` GA / experimental `auto-*`); Talos Tool Protocol (`ToolSpec` / `ToolPolicy` / `ToolHandler`, registry list/get only — **no** `call()`); `PolicyValidator` → sealed `ExecutionPlan` + single-use capability token; `Executor` sole invoke path; READ inventory/intel/context tools + `role.set_active` / `module.set_active` (exists-only); schema v49 (`ai_sessions`, `ai_audit_events`, `ai_project_prefs`); CLI `talos ai start|stop|resume|reset-budget|status|mode|tools list|audit list`. Design: `docs/design-talos-ai-layer.md`. Tests: `tests/test_ai_phase_a.py`.
- [x] **AI Layer Phase B** — offline agent loop: structured app notes (v50) with optimistic revision concurrency; immutable `ActionSuggestion` + `ExecutionPlan` + observations + PTT (v51); `HeuristicPlanner` (`provider=none`); CLI `suggest [--auto-reads]`, `approve`, `deny`, `pending`, `plans show`, `notes show|edit|export`; tools `notes.app.get|patch`, `task_tree.list|upsert`; suggest-only hard-rejects execute/approve. **No AI client-data redaction** (authorized BB/pentest product). Tests: `tests/test_ai_phase_b.py`.
- [x] **AI Layer Phase C** — stdio MCP (`talos ai mcp serve`) over WorkflowEngine → PolicyValidator → Executor; LLM providers `none` / `ollama` / `openai-compatible` / `anthropic` + `LLMPlanner` with heuristic fallback; operator config `~/.talos/ai/config.yaml` + `TALOS_AI_API_KEY` via `talos ai config show|set|unset|edit` (never a tool); `llm_tokens` budget accounting. **Still no** `talos/ai/redaction.py` (Key Decision 9). Tests: `tests/test_ai_phase_c.py`.
- [x] **AI Layer Phase D** — active pentest tools: `send.once` (`ai_send`, ≤20 edits) + `replay.flow` (enqueue-only); live Basic Scope + outscope + snapshot fail-closed shrink; annotation matrix (`logout` always reject; `dangerous` human-approve → `PRIORITY_AI_MANUAL` + `ai_force_dangerous`); engine enqueue `iv.run` / `iv.synthesize` / `passive.rescan` / `attack.unauth.run` / `attack.bac.run` / `intruder.session.run` (pre-created session); `PRIORITY_AI_AUTO=15` / `PRIORITY_AI_MANUAL=100`. Tests: `tests/test_ai_phase_d.py`.
- [x] **AI Layer Phase E (core CLI)** — minimal markdown KB (`~/.talos/ai/kb/*.md`, tool `kb.search`, CLI `talos ai kb list|show|search`); draft findings (`ai_draft_findings` v52) + tools `draft_finding.*` + operator `talos ai finding promote` → `create_finding` with `verdict=AI_DRAFT_PROMOTED`, `attack_type=ai_draft` (never confirm); `talos ai session export` JSON bundle. **Not in this ship:** Control Panel AI page, network MCP, structured dual-scope KB promote pipeline. Design: `docs/design-talos-ai-layer.md`. Tests: `tests/test_ai_phase_e.py`.

---

## History / Deprecated CLI

The following are **not** part of the current CLI. Do not document them as live commands.

| Former surface | Replacement |
|----------------|-------------|
| `talos ui` | Removed; CLI-only |
| `talos auth mark-login` | `talos auth-config add-flow` |
| `talos mutation *` | `talos config http *` (HTTP Manipulation Engine) |
| `capture.header_rules.*` | `http.rules` actions (`header.remove` / `replace` / `add` / `rename`) |
| `mutation.enabled` | `http.enabled` |
| `talos auth mark-checkpoint` | `talos auth-config add-control-flow` |
| `talos auth generate` | `talos auth-config refresh` |
| `talos auth-config set-validation` / `clear-validation` | Layer 3 control flows (`add-control-flow`) |
| `talos attack unauth exclude` | `talos endpoint exclude` |
| `talos attack unauth run --max-priority` / `--auth-mutation` | `talos attack unauth run --technique` |
| `talos attack run` (generic) | `talos attack unauth` / `talos attack bac` |

Legacy tables retained for compatibility (not primary workflows): `role_auth`, `role_session_tokens`, `attack_host_exclusions`, and unused URL validation columns on `session_health_config`.
