# Talos: Release Updates

All notable changes to Talos are documented here, organized by version.

## Passive Source Intelligence — Phases 11–12 + 14–16 (HTML, infra, polish)

### Problem

Secrets embedded only in HTML inline scripts / SPA bootstrap JSON were
invisible to the scanner. Infrastructure leakage (internal IPs, route tables)
had no observation path. Operator docs and Talos Helper still described
Phases 0–10 only.

### Decision

| Piece | Role |
|-------|------|
| `extractors/html.py` | Inline `<script>` without `src`; JSON/`__NEXT_DATA__` bootstrap islands; caps |
| Worker + CLI rescan | Virtual child docs under `parent_document_id`; never fetch external scripts |
| `detectors/jwt.py` / `connection_string.py` | Compact JWT + credential-bearing DB URIs |
| `detectors/infrastructure.py` | Observation-first IPs/hosts/routes/emails; routes aggregated (max 40) |
| Rules | `communication.yaml`, `database.yaml`, `infrastructure.yaml`, `sensitive_info.yaml` |
| Bridge | Still secrets-only; infra never auto-findings even if mis-scored |
| CLI | `detections list --category …` |
| Perf | Soft `max_scan_time_ms` budget (default off); large-body smoke test |
| Identity | `SCANNER_VERSION` → `1.3.0` |

**Not in this release:** Control Panel Source Intelligence UI (Phase 13).

### Operator happy path

Browse an HTML shell with an inline AWS key → PRIMARY `passive_secret`
finding (title may include “Inline HTML”). List disclosures with
`talos passive detections list --category infrastructure_disclosure`.
After rule upgrades: `talos passive rescan --all`.

### Tests

- `tests/test_passive_html_extract.py`
- `tests/test_passive_detectors_infra.py`
- `tests/test_passive_detectors_jwt_conn.py`
- `tests/test_passive_perf_rescan.py`

---

## Passive Source Intelligence — Phases 8–10 (findings + CLI + source maps)

### Problem

High-confidence detections stayed in `passive_detections` only. Operators
could not triage secrets as Findings, control the scanner from the CLI, or
see secrets embedded in source-map `sourcesContent`.

### Decision

| Piece | Role |
|-------|------|
| `talos.findings.model` | Evidence types `source_document` / `source_occurrence` / `passive_detection`; `ATTACK_DISPLAY["passive_secret"]` |
| `talos.passive.finding_bridge` | `create_passive_secret_finding()` — cluster `PASSIVE_SECRET:<value_fingerprint>`; PRIMARY then LINKED |
| `SourceScanWorker` | After detection persist → auto-findings when confidence ≥ `auto_finding_threshold` |
| `talos.passive.cli` | `status`, `config`, `rules`, `documents`, `detections`, `rescan` |
| Schema v40 | `source_documents.parent_document_id` + `logical_source_name` |
| `extractors/sourcemap` | Virtual JS docs from `sourcesContent`; caps on count/size |

**Superseded for extractors/disclosures:** Phases 11–12 landed later (see above).
Control Panel UI remains Phase 13. Historical note: this release set
`SCANNER_VERSION` to `1.2.0` (now `1.3.0`).

### Operator happy path

Browsing an app that ships a hardcoded AWS key in JS creates a PRIMARY finding
(`attack_type=passive_secret`, verdict `EXPOSED`). The same key in a second
bundle creates LINKED. Source maps with `sourcesContent` are scanned as child
documents. Use `talos passive detections list` / `talos finding list` and
`talos passive rescan --all` after rule upgrades.

### Tests

- `tests/test_passive_finding_bridge.py` — PRIMARY/LINKED, threshold, worker e2e
- `tests/test_passive_cli.py` — status/config/rules/list (redacted)
- `tests/test_passive_sourcemap.py` — extract + worker map fixture

---

## Passive Source Intelligence — Phases 5–7 (detectors + suppress + decoder)

### Problem

Phase 4 registered source documents but never ran detectors. There was no
provider rule pack, generic assignment detection, suppression, scoring, or
decode/rescan path — so secrets in JS/JSON never became `passive_detections`.

### Decision

| Piece | Role |
|-------|------|
| `rules_loader` + `rules/*.yaml` | Provider patterns (AWS, GitHub, Stripe, Google, Bearer); generic key lists |
| `detectors/specific` + `pem` | Stage 1 structured secrets |
| `detectors/contextual` | Stage 2 assignment-context generics |
| `detectors/entropy` | Stage 3 high-entropy with keyword/assignment gate |
| `decoder/pipeline` | Stages 4–5 depth-limited decode → rescan 1–2 only |
| `scoring` + `suppress` | Deterministic confidence; drop placeholders / public test tokens |
| `detectors/orchestrator` | Wire stages; produce `Detection` rows |
| `SourceScanWorker` | Run orchestrator before `mark_document_scanned`; `insert_detection` |

**Still no auto-findings** (Phase 8). Encodings alone never create detections.
`SCANNER_VERSION` bumped to `1.1.0`. Synthetic fixtures only under
`tests/fixtures/passive/`.

### Operator happy path

Browsing an app that ships a hardcoded AWS/GitHub/Stripe key in a captured JS
body creates a `passive_detections` row (redacted value + fingerprint). No
Findings UI entry until Phase 8.

### Tests

- `tests/test_passive_detectors_specific.py` — rules + AWS/GitHub/Stripe/PEM
- `tests/test_passive_detectors_contextual.py` — assignment true/false positives
- `tests/test_passive_suppress.py` / `test_passive_scoring.py`
- `tests/test_passive_decoder.py` — base64 secret rescan, depth/size limits
- `tests/test_passive_worker.py` — worker persists AWS detection

---

## Passive Source Intelligence — Phase 4 (queue + worker + FlowWorker enqueue)

### Problem

Phase 3 could decide *what* is source-like and how to normalize it, but nothing
ran asynchronously after capture. There was no bounded queue, no scan daemon,
and FlowWorker never enqueued work.

### Decision

| Piece | Role |
|-------|------|
| `talos.passive.queue` | `PassiveScanQueue` — bounded, drop-on-full + WARNING + counter (mirrors `FlowQueue`) |
| `talos.passive.worker` | `SourceScanWorker` — load body by `flow_id` → candidate → classify → normalize → upsert document + occurrence; skip if already scanned at `SCANNER_VERSION` |
| `maybe_enqueue_passive_scan` | Safe post-commit hook used by FlowWorker (never raises / never blocks) |
| `TalosAddon` | Starts/stops `SourceScanWorker` next to `FlowWorker` |
| `FlowWorker` | After DB commit: if config enabled + `is_source_candidate(…)`, enqueue job |

**Phase 4 stores registry only:** documents marked `scanned` with empty
detections (placeholder until Phase 5). Same body hash → occurrence only, no
second scan. Capture continues if passive worker fails.

**Not in this release:** detectors, findings bridge, CLI, UI (Phases 5–16).
Fingerprint formula unchanged.

### Operator happy path

Proxy start now runs FlowWorker + SourceScanWorker. Browsing source-like
responses (JS/HTML/JSON/…) registers `source_documents` / `source_occurrences`
when `passive_scan_config.enabled` is true (default). No findings yet.

### Tests

- `tests/test_passive_worker.py` — queue drop-on-full; fake flow → document +
  occurrence; same body twice → no second scan; FlowWorker end-to-end enqueue

---

## Passive Source Intelligence — Phase 3 (candidate + classifier + normalizer)

### Problem

Phase 2 persisted documents/detections but had no pure logic to decide which
responses are source-like, what `SourceKind` they are, or how to turn body
bytes into scan text.

### Decision

| Piece | Role |
|-------|------|
| `talos.passive.candidate` | `is_source_candidate()` — cheap Content-Type/path gate (optional empty body + magic sniff) |
| `talos.passive.classifier` | `classify_source() → SourceKind` (CT → extension/hints → sniff) |
| `talos.passive.normalize` | `normalize_body()` — charset / utf-8 / latin-1 → `NormalizeResult` |

**Reject:** PNG/JPEG/GIF/PDF/ZIP/WASM (CT, extension, or magic); empty bodies;
media/font CTs. **Allow:** HTML/JS/JSON/XML/text/CSS/maps; mislabeled
`octet-stream` when path/sniff says JS/JSON.

**Not in this release:** FlowWorker enqueue, queue/worker, detectors, findings
(Phases 4–8). Fingerprint formula unchanged.

### Operator happy path

None user-facing yet — pure library used by Phase 4 worker.

### Tests

- `tests/test_passive_candidate.py` — CT/path matrix + magic rejects
- `tests/test_passive_classifier.py` — SourceKind golden cases
- `tests/test_passive_normalize.py` — charset / fallback / truncation

---

## Passive Source Intelligence — Phase 2 (schema v39 + DB CRUD)

### Problem

Phase 1 delivered pure types and redaction, but there was no project-DB
persistence for source documents, occurrences, detections, or scan config.

### Decision

| Piece | Role |
|-------|------|
| `SCHEMA_VERSION` **39** | `source_documents`, `source_occurrences`, `passive_detections`, `passive_scan_config` |
| `talos.passive.db` | CRUD: ensure/get/update config; upsert document; insert occurrence/detection; mark scanned/error; list + link finding |
| Fingerprint / cluster | Unchanged: `SHA256(family + "\\0" + canonical)` → later `PASSIVE_SECRET:<fp>` |

**Not in this release:** detectors, FlowWorker enqueue, findings bridge, CLI,
or UI (Phases 3–16). Capture path untouched.

### Operator happy path

None user-facing yet. New projects get the tables on `init_project_db`;
existing DBs upgrade via `migrate_project_db` (38 → 39) with a seeded
`passive_scan_config` default row.

### Tests

- `tests/test_passive_db.py` — schema migrate, config, document/occurrence/detection CRUD + dedup
- Existing: `tests/test_passive_redaction.py`, `tests/test_passive_models.py`

---

## Passive Source Intelligence — Phase 0–1 (package skeleton)

### Problem

Talos captures response bodies but has no passive, zero-HTTP path to surface
hardcoded secrets and sensitive exposure from client-delivered sources
(HTML/JS/JSON/…) without blocking the proxy capture path or flooding findings.

### Decision

| Piece | Role |
|-------|------|
| `docs/architecture.md` | Phase 0 design freeze: decision log + locked invariants |
| `talos.passive` | Package skeleton (Phase 1): constants, models, config defaults, redaction |
| `fingerprint_secret` / `redact_secret` | Stable cluster fingerprint + UI-safe display |

**Not in this release:** schema tables, FlowWorker enqueue, detectors, findings
bridge, CLI, or Control Panel UI (Phases 2–16).

### Operator happy path

None yet — library-only. `import talos.passive` exposes types and helpers for
upcoming phases.

### Tests

- `tests/test_passive_redaction.py` — fingerprint contract + redaction
- `tests/test_passive_models.py` — models, config merge, finding eligibility

---

## Control Panel — Flow HTTP / table polish + IV transport-safe headers

### Problem

1. Flow Pretty still showed a low-signal header eye toggle, a Wrap checkbox, and
   a “Pretty · no body” status line that added noise without helping inspection.
2. Flows list **Actions** ⋮ menu often failed to open (DaisyUI dropdown not marked
   open; panel overflow clipped the menu).
3. DataTable help text did not put “click to sort” in the visible toolbar line.
4. IV header/cookie probes failed with `http_error: Illegal header value` when
   multiprobe/null/norm:trim payloads hit h11/httpx client validation — never
   reaching the application, yet counted as failed probes.

### Decision

| Piece | Role |
|-------|------|
| `HttpInspector` / `HttpPrettyView` / `HttpRawView` | Wrap always on; no Wrap control; all headers always shown; no Pretty status toolbar |
| `DataTable` + `Flows` Actions | Help line includes sort; `dropdown-open` + overflow-visible for ⋮ menus |
| `surface` transport gates | `is_http_header_value_legal`, `transport_skip_for_payload` / `_headers` |
| Multiprobe / taxonomy / parser_intel / type_intel | Location-aware payloads (header/cookie omit null/CTL; header trim = internal pad) |
| Scheduler IV job | Pre/post-inject skip with `transport_invalid_header` \| `transport_invalid_cookie`; Illegal header value → skipped not failed |

### Operator happy path

1. Flow HTTP: Pretty request | response with wrap; full headers; Raw still available.
2. Flows list: click header to sort; ⋮ Actions menu opens and stays usable.
3. IV on header/cookie params: transport-illegal probes are skipped cleanly instead of flooding failed jobs.

### Tests

- Frontend: Vitest (parseHttp, etc.) + `tsc` / vite build
- Core: `test_iv_surface` transport suite, multiprobe location filters, parser norm header trim

---

## Control Panel — Burp-style HTTP Pretty

### Problem

Flow Pretty was a flat monochrome dump (start-line + headers + body) with only
basic JSON indent — nothing like Burp’s message editor Pretty tab.

### Decision

Match [Burp Pretty](https://portswigger.net/burp/documentation/desktop/tools/message-editor):
same message as Raw, plus standardized indentation (JSON / XML / HTML / CSS /
JavaScript; form fields one-per-line), syntax colorization, line numbers, and
wrap. (Low-signal hide toggle and Wrap checkbox were later removed — see above.)

| Piece | Role |
|-------|------|
| `prettyBody` / `buildPrettyMessage` | Format detection + indent helpers |
| `HttpPrettyView` | Gutter + tokenized rendering |
| CSS `.http-pretty` / `.hp-*` | Light/dark token palette |

### Tests

`parseHttp.test.ts` — pretty JSON/HTML/XML/CSS/form + `buildPrettyMessage`

---

## Control Panel — Flow detail polish + boxed resizable tables

### Problem

Flow HTTP still exposed Inspector / Headers / Cookies / Body tabs operators did
not need day-to-day; the sticky right rail stole horizontal space from request
and response; list tables lacked visible column edges and resize controls; the
Flows **Actions** column header was blank.

### Decision

| Piece | Role |
|-------|------|
| `HttpInspector` | Pretty (default) + Raw for request and response; request Params / JWT only |
| `HttpPrettyView` | Start-line + headers + pretty-printed body |
| `FlowDetail` layout | Full-width tabs; Actions / Session / Attack / Related **below** HTTP |
| `DataTable` | Boxed cells, drag-edge column resize, persist widths with order/hidden |
| Action headers | Visible “Actions” / “Select” labels on Flows, Endpoints, Scheduler |

### Operator happy path

1. Filter Flows → open a row (filters preserved for ←/→ navigation).
2. HTTP tab: Pretty request | Pretty response side by side; Raw when needed.
3. Scroll below for Actions (Replay now, Enqueue, Export, copy helpers), Session, Attack, Related.
4. On list tables: drag column edges to resize; Columns menu; Reset widths.

### Tests

- Frontend: Vitest suite (parseHttp, flowFlags, PathField) + `tsc` / vite build
- Backend: existing `test_flow_routes.py` unchanged (presentation-only UI)

---

## Control Panel — Flow inspection workspace

### Problem

Flow list/detail treated captures as dense table rows plus a Pretty/Raw HTTP
dump. Cookies and JWTs were expanded under Headers and again in dedicated
blocks; `flow_meta`, truncation, replay chains, evidence, and session context
were under-used compared with `talos flow show` / related Core tables.

### Decision

| Piece | Role |
|-------|------|
| `HttpInspector` + `parseHttp` | Request/response Pretty + Raw (later simplified; parsers remain) |
| `FlowDetail` workspace | Overview / HTTP / Replay / Timeline / Debug + operator panels |
| Shared `FlowActions` | Same actions on list ⋮ and detail (replay, enqueue, export, login/control, copy raw/curl/UUID) |
| Backend enrichments | `derived` + `results`, `/related`, `/intelligence`, list `include=flags`, filter-aware adjacent |
| Docs | pages / routing / frontend / backend / database CP docs |

Thin UI only: no re-derived BAC/unauth verdicts or browser session scores.
“Replay modified / different role” remains disabled until Core CLI exists.

### Operator happy path

1. Filter Flows → open a row (filters preserved for ←/→ navigation).
2. HTTP tab: Pretty / Raw request and response.
3. Actions panel: Replay now, Enqueue, Export Markdown, copy curl.
4. Overview shows `flow_meta` and truncation; Replay tab shows children + original.

### Tests

- Frontend: `parseHttp.test.ts`, `flowFlags.test.ts` (Vitest)
- Backend: `test_flow_routes.py` (detail, related, intelligence, flags, adjacent, export)

---

## Input Validation — Operator Experience (Module 12) — Revamp complete

### Problem

M1–M11 intelligence was usable by code (profiles, candidates API) but operators
still needed SQL for confidence/plan state, had no dedicated `candidates` CLI
list, Markdown-only export without version fields, and a Control Panel that
showed only raw cache counts / probes. Docs partially drifted from live
canaries (`TL`+hex multiprobe) and budget CLI surface.

### Decision

| Piece | Role |
|-------|------|
| CLI `run --budget` / `config --budget` | Alias for planner `probe_strategy` tiers |
| CLI `status` | + confidence buckets, candidate readiness, plan actions |
| CLI `candidates` | Filter list (`--attack`, `--min-score`, `--host`, `--capability`) |
| CLI `export … --format json` | schema_version / engine_version / capabilities / candidates |
| Control panel | Full status, `/profiles`, `/candidates`, richer IV page |
| Docs / Talos Helper | architecture, about-talos, cheat sheet, root `--help` |
| Migration notes | synthesize from probes; clear-cache for stale matrix |

**Operator happy path**

```bash
talos input-validation config --enable
talos input-validation run --budget standard
talos input-validation status
talos input-validation show <parameter_uuid>
talos input-validation candidates --min-score 60
```

Candidate scores remain **prioritization only**, not confirmed vulnerabilities.

### Tests

`tests/test_iv_cli_operator.py` — help surface, status confidence keys,
candidates dispatch, export format args. Control panel route smoke for
status/candidates/profiles.

### Revamp status

Modules **M1–M12** of the Input Validation / Parameter / Endpoint intelligence
revamp are complete. Future work (hidden param discovery, OAST SSRF confirm,
attack module wiring to candidates) is out of scope for this plan.

### Handoff from Module 11 — done

See **Capabilities, Attack Candidates & Consumer API (Module 11)** below.

---

## Input Validation — Capabilities, Attack Candidates & Consumer API (Module 11)

### Problem

Attack modules (XSS, SQLi, SSRF, open redirect, HPP, …) would otherwise re-read
raw `iv_probe_results` and re-interpret acceptance/reflection. Profiles had
capability placeholders and an empty `candidates[]` with no scorer or stable
import path.

### Decision

| Piece | Role |
|-------|------|
| `talos.input_validation.capabilities` | Central capability derivation from observed/inferred (reflection, types, surface, parser, length) |
| `talos.input_validation.candidates` | Attack candidate scorer + stable consumer API |
| `score_candidates(profile)` | Pure: `{attack, score 0–100, confidence, reasons[], evidence_flow_ids[]}` |
| `get_param_intelligence(db, param_id\|uuid)` | Single import for attack modules (no probe-table parsing) |
| `list_candidates(db, filters)` | Project-wide prioritization (`attack`, `min_score`, `host`, …) |
| Synthesize | After aggregation, writes capabilities + candidates onto param profiles |
| CLI | `show` / `export parameter` / `export host` display candidates; scores are prioritization only |

**Candidate attacks (prioritization, not confirmed vulns)**

`xss` · `sqli` · `open_redirect` · `ssrf` · `hpp` · `header_injection` ·
`path_traversal` · `mass_assignment`

**Scoring highlights**

- Reflected HTML + markup (`<>`) accepted → high XSS score with reasons
- `redirect*` name + URL type accepted → open_redirect / SSRF candidates
- Rejected quotes → SQLi score reduced; reasons cite negative evidence
- Parser duplicate behavior → HPP candidate

### Tests

`tests/test_iv_candidates.py` — pure scoring fixtures, negative evidence,
consumer API, list filters, shape contract.

### Handoff (Module 12) — done

See **Operator Experience (Module 12)** above. UI/CLI copy states scores are
**prioritization only**. Control panel surfaces `candidates` via read APIs.

### Handoff from Module 10 — done

See **Multi-Level Learning (Module 10)** below.

---

## Input Validation — Multi-Level Learning (Module 10)

### Problem

APIs share middleware. Re-learning “rejects null bytes / control chars” on
every parameter wastes budget. Parameter profiles were isolated; endpoint and
application tables existed as empty stubs with no aggregation or planner
inheritance.

### Decision

| Piece | Role |
|-------|------|
| `talos.input_validation.learning` | Aggregate param → endpoint → app; inheritance priors; confidence decay (cap 75); probe filters |
| `PlanContext` inheritance fields | `inherited_tested`, rejected classes, `suppress_control_probes`, `suppress_parser_probes` |
| Planner (standard/quick) | Skip semantic wave when core families inherited; skip parser when parent fingerprinted; shrink char estimates |
| Engine probe expand | Merge inherited class outcomes; filter validation probes; skip parser jobs when parent known |
| Synthesize | After each param upsert, refresh endpoint + app profiles |
| CLI | `show --endpoint <id>`, `show --host <host>`; param show lists inheritance priors; status shows multi-level counts |
| DB | `list_param_profiles_for_endpoint`, `list_endpoint_profiles`, `list_app_profiles`, `get_endpoint_meta` |

**Inheritance rules**

- Local **observed** / `tested` always wins; inherited facts stay in
  `inferred.inheritance` / planner priors only (not rewritten into observed).
- Inherited confidence capped at **75** until local confirm.
- Host-level rejected control/null suppresses those probes under
  **quick/standard**; **deep/exhaustive** re-confirm.
- Second parameter on the same endpoint plans fewer standard HTTP requests
  when inheritance covers validation + parser.

### Tests

`tests/test_iv_learning.py` — aggregation, confidence decay, local-wins merge,
planner request savings, control suppress by tier, DB refresh.

### Handoff (Module 11) — done

See **Capabilities, Attack Candidates & Consumer API (Module 11)** above.
Endpoint/app profiles expose capabilities and shared parser/reflection defaults;
parameter-level candidate scoring consumes those flags without re-deriving from
every probe row.

### Handoff from Module 9 — done

See **Surface Completeness (Module 9)** below.

---

## Input Validation — Surface Completeness (Module 9)

### Problem

Passive Parameter Intelligence already extracted path, header, cookie,
multipart, GraphQL variables, and XML leaves, but IV injection was still
query/JSON-form-centric: path params returned the base request unchanged,
multipart filenames and XML leaves were not mutated, and auth session
cookies / Authorization were probed the same as ordinary inputs.

### Decision

| Piece | Role |
|-------|------|
| `talos.input_validation.surface` | Path segment rewrite via `{name}`; hardened header/cookie inject; multipart field + filename; GraphQL variables; XML leaf; auth/hop-by-hop skip policy; surface kinds |
| `prepare_iv_probe` | Passes `normalized_path` + `semantic_type`; all locations inject via `surface.inject_value` |
| Flow lookup | `find_best_flow_for_param` joins `endpoints.normalized_path` + `parameters.semantic_type` |
| Config / CLI | `include_auth_artifacts` (default off); `config --include-auth-artifacts` / `--skip-auth-artifacts`; `run --include-auth-artifacts` one-shot |
| Engine | Skips auth artifacts & hop-by-hop headers with `iv_param_cache` phase=`surface` status=`skipped` + clear reason |
| Synthesis | `observed.surface` (location + kind); capabilities `path_parameter`, `header_injection_surface`, `multipart_filename`, `graphql_variable`, `xml_body` |
| Schema | **38** — `include_auth_artifacts` on `input_validation_config` |

**Supported surfaces**

| Location | Inject behaviour |
|----------|------------------|
| `path` | Segment matching `normalized_path` `{name}` placeholder |
| `query` | Query string value replace/append |
| `body` JSON | Dotted path (incl. nested) |
| `body` form | URL-encoded field |
| `body` multipart | Field body **or** `filename=` when semantic_type=filename |
| `body` GraphQL | `variables.*` / bare variable / operationName |
| `body` XML | First leaf element with matching local tag |
| `header` | Case-insensitive replace/add; hop-by-hop never mutated; header-safe payloads only |
| `cookie` | Multi-cookie Cookie header; append if missing; cookie-safe payloads only |

**Auth skip (default):** session-like cookies, Authorization / x-auth-token /
configured `talos auth set` artifacts. Opt in with `--include-auth-artifacts`.

**Transport skip (follow-up):** payloads illegal for h11/httpx
(`Illegal header value` — NUL/CTL, leading/trailing SP on header values) are
skipped with `transport_invalid_header` / `transport_invalid_cookie`, not
counted as application failures. Multiprobe/char/validation/norm probes are
location-aware for header/cookie.

### Tests

`tests/test_iv_surface.py` — path rewrite, header/cookie, transport legality,
multipart/GraphQL/XML, auth skip, prepare_iv_probe, synthesis capabilities,
engine skip cache.

### Handoff (Module 10) — done

See **Multi-Level Learning (Module 10)** above.

### Handoff from Module 8 — done

Parser probes remain location-aware; value inject now works on path/header/
cookie/multipart/XML so norm probes can run when those surfaces are inventoryed.

---

## Input Validation — Normalization & Parser Fingerprinting (Module 8)

### Problem

Stacks differ on duplicate query keys, JSON null vs empty vs omitted fields,
and array syntax. Normalization stages (URL-decode → trim → case → reflect)
decide which payloads can ever work. IV only lightly detected trim/case when
reflected, with no structured parser fingerprint or ordered pipeline.

### Decision

| Piece | Role |
|-------|------|
| `talos.input_validation.parser_intel` | Norm + parser probe selection; structural inject helpers; pipeline + fingerprint synthesis; `tested{}` keys |
| Planner `parser_probes` | Real executor (no longer M8 stub); quick skips; standard ~5; deep ~10 (+ unicode/double-encode) |
| Job type `iv_parser` | Analysis `parser`; meta `injection_mode` for dup/JSON/array mutations |
| `prepare_iv_probe` | Structural inject: `dup_query`, `json_null`/`empty`/`omit`/`dup_key`, array styles |
| Synthesis | `observed.parser`, `normalization_pipeline`, `inferred.parser_family`, capabilities, tested negatives |

**Standard:** cost-controlled dup-query (or JSON null/empty on body) + light
trim/case/url_decode when reflected. **Deep:** unicode compatibility + double
encoding + more array/JSON variants. **Quick:** skips most parser probes.
Fingerprint only — no HPP exploitation.

Negative evidence: rejected duplicates land under `tested.parser:duplicate`
(and related keys) with confidence.

### Tests

`tests/test_iv_parser_norm.py` — detection, selection by tier, structural
inject, synthesis, planner/engine expansion.

### Handoff (Module 9) — done

See **Surface Completeness (Module 9)** above.

---

## Input Validation — Types, Semantic Validation & Negative Evidence (Module 7)

### Problem

Type characterization always paid the full ~12-type matrix even when passive
`semantic_type` already said “integer”. Validation mixed characterization with
exploit-shaped SQLi/XSS strings. Negative evidence (rejected families) was
inconsistent, so attack modules could not reliably skip hopeless surfaces.

### Decision

| Piece | Role |
|-------|------|
| `talos.input_validation.type_intel` | Passive-first type pruning; semantic probes; core vs edge validation; type conflict synthesis; `tested{}` helpers |
| Planner `type_confirm` / `semantic_rules` | Real executors (no longer M7 stubs); estimates ~4 / ~5 under standard |
| Engine | Expands probes from passive `semantic_type` + examples + length bounds |
| Synthesis | `observed.types` + `_summary` (confidence/conflict); `observed.semantic`; systematic `tested` |
| Validation core | empty, whitespace, null_byte, very_long, negative_int, float |
| Validation edge | special_chars, html_injection, crlf — **deep/exhaustive only** |

**Standard:** integer-like params get ≤4 type confirms (not 12); URL/name-hint
params prioritize URL probes; `very_long` skipped when `max_accepted` known;
no SQLi/XSS strings required. **Exhaustive:** full type + validation matrices.

### Tests

`tests/test_iv_type_semantic.py` — pruning, semantic selection, conflict
detection, negative evidence merge, planner/engine expansion.

### Handoff (Module 8) — done

See **Normalization & Parser Fingerprinting (Module 8)** above.

---

## Input Validation — Character Taxonomy & Length (Module 6)

### Problem

Character acceptance used a fixed ~30-char matrix; length used 10 fixed sizes.
Attack modules care about **classes** (quote, delimiter, operator…), not that
character #17 was tested. Length bounds can be found with logarithmic seed +
binary midpoints, and truncation should be distinguishable from hard reject
when reflection is available.

### Decision

| Piece | Role |
|-------|------|
| `talos.input_validation.taxonomy` | Class → representatives + drill-down; tier selection |
| `talos.input_validation.length_search` | Log seed + binary refine; truncate vs reject |
| Planner `char_drilldown` / `length_binary` | Real executors (no longer M6 stubs) |
| Engine | Expands class probes; length index = payload length for multi-wave |
| Synthesis | `observed.acceptance.classes` + `observed.length` (max_accepted, min_rejected, truncation_at) |

**Standard:** multiprobe taxonomy first; when length is still uncertain,
≤5 seed length probes (not 10). Char phase remains skipped when multiprobe is
on; class representatives (~11) when multiprobe is off. **Deep:** class
drill-down + structure classes + binary length. **Exhaustive:** extended char
list + full length matrix.

Negative evidence: rejected classes still land in `tested{}`.

### Tests

`tests/test_iv_taxonomy_length.py` — taxonomy aggregation, length decision
logic, planner estimates, engine expansion.

### Handoff (Module 7) — done

See **Types, Semantic Validation & Negative Evidence (Module 7)** above.

---

## Input Validation — Event-Driven Planner (Module 5)

### Problem

Even with multiprobe, `run` still enqueued length/types/validation (and on
deep/exhaustive the full matrix) **up front** for every parameter. Analysis
jobs could race ahead of evidence, and high-confidence parameters still paid
for probes they did not need.

### Decision

| Piece | Role |
|-------|------|
| `talos.input_validation.planner` | Pure state machine: next actions from budget + observations |
| Budget tiers | Same names as `probe_strategy`: quick / standard / deep / exhaustive |
| `max_requests_per_param` | Optional hard HTTP cap (0 = tier default) |
| Engine `plan_and_enqueue_for_param` | First wave only on `run` (typically baseline) |
| Scheduler hook | After each IV job settles → `continue_param_plan()` |
| Action tokens | `char_drilldown`, `length_binary` (M6); `type_confirm`, `semantic_rules` (M7); `parser_probes` (M8) |

**Default path (`standard`):** ENSURE_BASELINE → MULTIPROBE → EVALUATE
(conditional follow-ups only if uncertainty high) → FINALIZE → SYNTHESIZE → DONE.

- High-confidence after multiprobe → early stop (no length/types/validation matrix).
- Reflection unknown → at most one extra multiprobe.
- Budget hard stop → finalize only (0 HTTP analysis).
- Never schedules transformations/reflection before required evidence.
- **Exhaustive** still approximates the legacy matrix via progressive waves
  (not a single 70-job enqueue).

Schema: `SCHEMA_VERSION` **37** (`max_requests_per_param` on
`input_validation_config`).

### Tests

`tests/test_iv_planner.py` — pure planner decisions (early stop, multiprobe
retry, budget stop, no analysis-before-evidence) + schedule integration.

### Handoff (Module 6) — done

See **Character Taxonomy & Length (Module 6)** above.

---

## Input Validation — Canaries & Multiprobe (Module 4)

### Problem

The fixed IV matrix spent ~9 identifier + ~30 character requests per parameter
with weak, collision-prone markers (`123456`, `abcdef`). Industry multi-signal
practice shows one carefully structured request can answer reflection, encoding,
and several character-class questions.

### Decision

| Piece | Role |
|-------|------|
| `talos.input_validation.multiprobe` | Canary generator, multiprobe payload builder, response analyzer |
| Job type `iv_multiprobe` | One HTTP probe; plan stored in job meta + `flow_meta.multiprobe` |
| `probe_strategy` config | `quick` \| `standard` \| `deep` \| `exhaustive` |
| Identifier probes | High-entropy canaries by default; legacy weak list only on `exhaustive` |
| Characters | Skipped under `standard`/`quick` when multiprobe is enabled |
| Synthesis (M3) | Re-analyzes multiprobe payloads offline into acceptance.classes + reflection |

**Default (`standard`):** baseline + multiprobe first; no weak fixed identifiers;
no full character matrix. **Exhaustive:** multiprobe + legacy 9 identifiers +
full character list (escape hatch). Evidence remains one flow per multiprobe job.

Schema: `SCHEMA_VERSION` **36** (`analyses_multiprobe`, `probe_strategy`).

### Tests

`tests/test_iv_multiprobe.py` — canaries, payload parse, analyzer (synthetic
bodies), strategy scheduling, offline synthesis.

### Handoff (Module 5)

**Done.** Planner chooses multiprobe as the default first active step after
baseline. Budget tiers map to `probe_strategy` names already stored on config.

---

## Input Validation — Synthesis from Existing Probes (Module 3)

### Problem

Probe evidence lived as raw `iv_probe_results` rows while operators and later
modules need aggregated intelligence profiles. Analysis jobs (transformations /
reflection) could race ahead of unfinished scan probes and store empty results.

### Decision

Offline synthesizer (no new HTTP, default probe matrix unchanged):

| Piece | Role |
|-------|------|
| `talos.input_validation.synthesize` | `synthesize_param_profile`, `synthesize_many`, readiness helpers |
| Fingerprint + `classify_outcome` (M1) | Per-probe outcomes vs baseline |
| `upsert_param_profile` (M2) | Persist versioned documents |
| CLI `input-validation synthesize` | Project / `--host` / `--param-uuid` (+ `--dry-run`) |
| `show` / `export parameter` | Display acceptance, reflection, capabilities from profile |
| Scheduler race guard | Skip transform/reflection while scan jobs pending; synthesize when ready |

Profiles include `inferred.synthesis.partial`, negative evidence in `tested`,
bounded `attempts`, taxonomy acceptance classes, and simple capability flags.
Multiprobe rows (M4) can attach `multiprobe_classes` without changing the
aggregator contract.

### Tests

`tests/test_iv_synthesize.py` — offline fixtures, conflict reflection, partial,
race readiness, multiprobe hook, show attachment.

### Handoff (Module 4)

Multiprobe writes fewer rows with compound payload classes; synthesizer already
folds `multiprobe_classes` into `observed.acceptance.classes`.

---

## Input Validation — Profile Data Model (Module 2)

### Problem

IV stored raw probes and partial phase caches without a single consumer-facing
intelligence document. Later modules (synthesis, planner, attack candidates)
need a **versioned, layered** shape: observed vs inferred, confidence,
negative evidence, mutation history, capabilities, and multi-level keys.

### Decision

Add the profile data model and persistence (no planner / no new HTTP probes):

| Piece | Module / table | Role |
|-------|----------------|------|
| Canonical JSON shape | `talos.input_validation.profile` | `empty_*_profile`, `ensure_profile_shape`, serialize/deserialize |
| Parameter profiles | `iv_param_profiles` | Keyed by `param_uuid`; full observed/inferred document |
| Endpoint stubs | `iv_endpoint_profiles` | Keyed by `endpoint_id` |
| App/host stubs | `iv_app_profiles` | Keyed by `host` |
| CRUD | `talos.input_validation.db` | `upsert/get/list/delete_*_profile` |

**Why new tables (not `iv_param_cache` phase `profile`):** phase cache is for
analysis resume by `(host, location, name, phase)`; intelligence profiles are
versioned multi-level documents with different keys and lifecycle.

Schema: `SCHEMA_VERSION` **35**. Default IV request matrix still unchanged.

### Tests

`tests/test_iv_profile.py` — shape, round-trip, migration, CRUD.

### Handoff (Module 3)

Populate profiles offline from `iv_probe_results` + flows using Module 1
`fingerprint_from_flow` / `classify_outcome`; write via `upsert_param_profile`.

---

## Input Validation — Evidence Foundations (Module 1)

### Problem

Adaptive probing, multi-level profiles, and attack-candidate scoring need a
stable way to describe **application behaviour** from responses.  Without a
shared fingerprint and outcome vocabulary, synthesis and planners guess from
raw status/body presence only.

### Decision

Add pure evidence helpers (no scheduler / probe-volume change):

| Piece | Module | Role |
|-------|--------|------|
| `ResponseFingerprint` | `talos.input_validation.fingerprint` | Status, CT class, lengths, normalized body/header hashes, JSON schema sketch, redirect, error signature, `duration_ms` |
| `fingerprint_from_flow` / `compare_fingerprints` | same | Build + differential delta |
| Outcome vocabulary + `classify_outcome` | `talos.input_validation.outcomes` | `accepted\|modified\|encoded\|normalized\|truncated\|rejected\|ignored\|unknown` with confidence + reasons |
| `IV_PROFILE_SCHEMA_VERSION` / `profile_envelope` | same | Versioning contract for Module 2+ stored profiles |

Default IV request matrix is unchanged (~70 probes/param).  Module 2 will embed
fingerprints and outcomes in versioned parameter profiles.

### Tests

`tests/test_iv_fingerprint.py` — stability, deltas, classifier, schema envelope.

---

## HTTP Manipulation Engine (core)

### Problem

Talos had two overlapping systems for modifying outbound HTTP:

- Declarative `capture.header_rules` (YAML, `HeaderMutationEngine`)
- Per-project DB `request_mutations` (`talos mutation`)

Both were request-only, used different storage models, and could not express
response manipulation or scoped match conditions.

### Decision

Replace both with a single **HTTP Manipulation Engine**:

| Piece | Detail |
|-------|--------|
| Config | `http.enabled` + `http.rules` in layered config |
| Layers | Global + project rules **concatenate** (priority-sorted) |
| Direction | `request` \| `response` \| `both` |
| Match | host, path, method, status, headers, endpoint_id, role/module, context flags |
| Actions | header/cookie/query/URL/method/body/status/delay/drop/abort |
| Default | Engine **on**, **zero rules** — traffic unmodified |
| CLI | `talos config http …` |
| Proxy | `request()` + `response()` hooks via `HTTPManipulationEngine` |

Removed: `talos mutation`, `request_mutations` table (fresh DBs),
`capture.header_rules`, `mutation.enabled`, `HeaderMutationEngine`.

### Operator migration (beta — no auto-migration)

```bash
# Old
talos mutation add header X-Research tester
talos config set capture.header_rules.remove '["If-None-Match"]'

# New
talos config http create --name "Research" \
  --action 'header.replace:X-Research=tester'
talos config http create --name "Strip validators" \
  --action 'header.remove:If-None-Match' \
  --action 'header.remove:If-Modified-Since'
```

Control Panel: **Mutations** workspace rebranded to **HTTP Rules** (`/mutations`);
Talos Config Header Rules tab removed (use HTTP Rules + `http.enabled` setting).

---

## Control Panel: Endpoint Workspace (`/endpoints`)

### Problem

`/endpoints` was a browse/filter table over SQLite policy flags. Endpoint detail
owned the only mutations, while core already supported resolved policy, bulk
multi-ID mutations, policy explanation, first-class path rules, and rule
preview. The panel did not expose that contract and could not multi-select
endpoints into a single atomic CLI mutation.

### Decision

Treat `/endpoints` as the **Endpoint Workspace** with four tabs:

| Tab | Role |
|-----|------|
| Inventory | Endpoint operations (browse, filter, bulk mutate, test) |
| Policy | Talos decisions (TESTABLE/SKIPPED + explain) |
| Rules | Path policy configuration + live preview |
| Coverage | Read-only model quality (qualification, baseline, roles observed, parameters) |

Architecture unchanged: thin UI; resolved reads via core policy engine;
**every** mark/priority/exclusion/tag/rule mutation through Talos CLI (multi-ID
in one argv — never N sequential commands). No separate Tags/Dangerous/Logout
top-level tabs (those remain inventory dimensions).

Endpoint detail becomes an inspector: Overview \| Policy \| Parameters \| Flows \|
Activity (Activity only when core persists audit events — not faked).

### Surface

| Area | Change |
|------|--------|
| Frontend | `Endpoints.tsx` + `pages/endpoints/*`; `PolicyExplain`, `SideDrawer` |
| Backend | Expanded `routers/endpoints.py`; `endpoint_reads.py` resolver helper |
| Bulk API | `POST /api/endpoints/bulk/{mark,unmark,priority,exclude,include,tags,test}` |
| Rules API | `GET/POST /api/endpoints/rules`, preview, update, delete |
| Reads | `/summary`, `/policy-summary`, `/coverage`, list filters, `ids_only` for select-all-matching |
| Console catalog | `command_tree.py` endpoint group aligned with list/policy/rule/tags |
| Docs | `pages.md`, `routing.md`, `frontend.md`, `backend.md` |
| Tests | `talos-control-panel/backend/tests/test_endpoints_workspace.py` |

### Operator notes

- Priority displays as **effective level + source** (`HIGH` `AUTO` / `RULE` / `MANUAL`).
- Bulk bar reports **affected / unchanged / total** from CLI JSON.
- Rule preview and Policy explain use the same core matcher/resolver as live policy.
- Coverage role table is **observed traffic**, not the Access Model.

---

## Endpoint core updates (pre–Control Panel Endpoints revamp)

### Problem

Endpoint CLI mutations were single-ID only; list/show JSON was incomplete for
the Control Panel (raw-ish rows rather than a resolved-policy contract); path
rules were managed through fragmented `priority set path` / `exclude path`
commands; and there was no explicit “why is this the effective policy?” view
or rule impact preview.

### Decision

Keep Endpoint Policy as the single resolver. Extend core CLI + `policy.py` so
the Control Panel can drive inventory and mutations without parsing Rich tables
or translating one rule edit into unrelated commands.

### Surface

| Area | Change |
|------|--------|
| Bulk mutations | `mark` / `unmark` / `priority set\|clear endpoint` / `exclude\|include endpoint` / `tags` accept multiple IDs |
| Bulk contract | Validate all IDs first; reject whole op if any invalid; one transaction; dedupe; affected vs unchanged; `--format json` |
| JSON inventory | `endpoint list\|show\|rules --format json` returns **resolved** state (`origin`, priority source, tags, baseline, …) |
| Policy explain | `talos endpoint policy <id> [--format json]` |
| Rule resource | `talos endpoint rule add\|update\|delete\|list\|show\|preview` (canonical); legacy path priority/exclude kept |
| Preview | Same path matcher + effective-policy resolver as live rules |
| Identity audit | List/show/export/policy expose canonical origin from `endpoints.host` |

### Breaking note (scripts)

`talos endpoint list --format json` is now an object:

```json
{ "endpoints": [ ... ], "count": N }
```

not a bare array. Prefer:

```bash
talos endpoint list --format json | jq '.endpoints[].id'
```

### Docs / Helper

Root `talos --help` (Talos Helper), `docs/cli-cheat-sheet.md`, and
`docs/architecture.md` updated. Tests:
`tests/test_endpoint_policy_core.py`, `tests/test_endpoint_list.py`.

---

## Basic Scope redesign (Burp-inspired URL-prefix model)

### Problem (root cause)

Scope treated application identity as a **hostname** (and optional wildcard
subdomain / path) while **discarding ports**. Capture, endpoint clustering, and
out-of-scope exclusions could collapse distinct origins such as
`http://test.com:8000` and `http://test.com:9000`. Out-of-scope was domain-only
and implicitly included subdomains — a different mental model from the allow
list.

### Decision

**Basic Scope** is the canonical Talos scope model (aligned with Burp normal
scope control):

- One entry = one complete URL/host prefix (never comma-separated).
- Protocol optional → HTTP and HTTPS; present → that scheme only.
- Port omitted → any port; present → that port only.
- Path is a prefix; query is not part of identity.
- Subdomains are never implied.
- Wildcards rejected with an actionable message (no dual matching engines).
- Out-of-scope uses the **same** parser/matcher and **overrides** in-scope.

### Surface

| Area | Change |
|------|--------|
| Core | `talos.url_identity`, rewritten `talos.proxy.scope`, `scope_io` import |
| CLI | `project scope add\|remove\|list\|clear\|import`; same for `outscope` |
| Legacy | `project scope <id> [PREFIX…]` and `outscope add domain` still work |
| Capture | Shared evaluator on full URL; endpoints store **canonical origin** |
| Control Panel | In scope / Out of scope: add, bulk paste, file import via CLI temp files |

See `docs/architecture.md` (Basic Scope Matching Rules) and `docs/cli-cheat-sheet.md`.

---

## Control Panel: Talos Configuration workspace

The Control Panel now exposes layered configuration (CLI-022) as a first-class
workspace rather than only via fragmented Proxy / Scheduler / Projects forms.

### Control Panel

| Piece | Detail |
|-------|--------|
| Route | `/talos-config` — **Talos Configuration** |
| Tabs | Overview · Settings · Header Rules · Files |
| Scope | **Project** vs **Global** (maps to CLI with/without `--global`) |
| Backend | `talos_ui/routers/configuration.py` → `/api/configuration/*` |
| Console | Full `talos config` command tree in `command_tree.py` |
| Cross-links | Proxy (source badge), Scheduler (read-only rates + Configure), Mutations (`mutation.enabled`), Attack unauth auto-run, Projects capture → Capture section |

Reads use `talos [--project id] config show|effective|get|schema --format json`.  
Project writes use `run_scoped` + `config set|unset`. Global writes use `cli.run` + `--global` (no project open).

### Core addition

| Command | Purpose |
|---------|---------|
| `talos config schema [--format json]` | Machine-readable sections, types, defaults, known keys for UIs |

Talos Helper (`talos --help`) and `docs/cli-cheat-sheet.md` document `schema`.

### Semantics preserved in the UI

- **Remove override** / **Inherit** (not “reset to default”) — may fall back to global
- Source badges: DEFAULT · GLOBAL · LEGACY · PROJECT · CLI
- Header-rule lists/maps are full-leaf replacements (no UI-side item merge)
- No direct YAML or SQLite mutation from the Control Panel

Tests: `tests/test_layered_config.py` (schema),  
`talos-control-panel/backend/tests/test_configuration_routes.py`.

---

## CLI-022: Layered configuration system

Configuration was scattered across the project registry, SQLite tables,
`headers_drop.txt`, `policy_score.json`, decision-filter YAML files, auth
session files, and environment variables. Operators had no single place to
see what applied or why.

### Design

Mature CLIs use **precedence**, not a single file:

```text
Built-in defaults
        ↓
Global configuration   (~/.talos/config.yaml)
        ↓
Project configuration  (project.yaml + legacy bridges)
        ↓
CLI one-shot overrides
```

Exactly one **`EffectiveConfig`** is produced per load. Runtime components
(proxy addon, scheduler helpers, attack auto-run, upstream resolution)
consume that object (or helpers that load it) instead of each opening their
own files.

### New CLI: `talos config`

| Command | Purpose |
|---------|---------|
| `talos config show` | Paths to global / project files + layer summary |
| `talos config effective` | Full merged tree with value sources |
| `talos config get <key>` | One value + inheritance source |
| `talos config set <key> <value> [--global]` | Project override (or global) |
| `talos config unset <key> [--global]` | Remove override → inherit lower layer |
| `talos config edit [--global]` | Open YAML in `$EDITOR` / `$VISUAL` |
| `talos config schema` | Machine-readable types/defaults (UI / automation) |
| `talos config proxy\|capture\|scheduler\|attack\|mutation` | Section resources (`show` / `set` / `unset` / `edit`) |

Examples:

```bash
talos config set proxy.upstream.url http://127.0.0.1:8081
talos config set scheduler.max_delay 15
talos config get scheduler.max_delay
# → Project override / 15

talos config unset scheduler.max_delay
# → inherits global or default

talos config effective
talos config scheduler show
talos config set attack.unauth_auto_run true --global
```

### Sections in the model

| Section | Keys (representative) |
|---------|------------------------|
| `proxy` | `upstream.enabled`, `upstream.url` |
| `capture` | `store_bodies`, `max_body_size`, `drop_headers`, `header_rules.*` |
| `scheduler` | `min_delay`, `max_delay`, `max_queue_size` |
| `attack` | `unauth_auto_run` |
| `mutation` | `enabled` |

### Declarative header rules

`capture.header_rules` drives a **`HeaderMutationEngine`** pipeline on every
outbound proxy request:

```text
remove → replace → add → rename
```

Built-in defaults remove `If-None-Match` and `If-Modified-Since` (replacing
hardcoded `pop` calls in the addon). DB mutations (`talos mutation`) still
apply afterward when `mutation.enabled` is true.

### Backward compatibility

- Existing `talos proxy config`, `talos scheduler config`, and
  `talos attack unauth config` remain and **dual-write** project.yaml + SQLite.
- Legacy stores (`proxy_config`, `scheduler_config`, `attack_config`,
  `headers_drop.txt`, registry constraints) are bridged into the project layer
  under `project.yaml`.
- Unset re-syncs SQLite from the YAML merge so sticky dual-write values cannot
  defeat inheritance.
- Global config applies only to projects under `$TALOS_DATA_DIR/projects`
  (isolated test trees do not inherit `~/.talos/config.yaml`).

### Implementation

- Package: `talos.configuration` (`manager`, `model`, `merge`, `io`, `legacy`,
  `header_engine`, `cli`)
- Proxy addon loads `EffectiveConfig` once at startup
- Tests: `tests/test_layered_config.py`

### Why

One source of truth, inheritance that operators can inspect, and a CRUD surface
that is useful for both humans (`effective`, section resources) and automation
(`get` / `set` / `unset` with stable dotted keys).

---

## CLI-021: Session recovery commands

Internal recovery APIs already existed (`clear_manual_session_config`,
`reset_suspicion`) but no CLI exposed them. Operators recovering from a
stuck `WAITING_FOR_USER` session or permanently degraded Layer 2 health
confidence had to edit SQLite and restart.

### Problem (fixed)

```text
problem → SQLite edits → restart → retry
```

That path leaked implementation details and blocked fully CLI-controlled
session lifecycle management.

### Changes

- **`talos auth-config clear-session <role>`** — clears the role's
  `manual_session_config` via `clear_manual_session_config()`. Output:
  `Session cleared.`
- **`talos auth-config reset-health <role>`** — resets the Layer 2
  `session_suspicion_state` counter via `reset_suspicion()`. Output:
  `Health suspicion reset.`
- Both accept a role **name or UUID** (same resolver as other auth-config
  commands). Missing role exits **1**.
- **Talos Helper** (`talos --help`), architecture, cheat sheet, and README
  document the recovery path.
- **Tests**: `tests/test_session_recovery.py` covers clear/reset effects,
  idempotency, missing role, and Talos Helper discoverability.

### Support path (after)

```bash
talos auth-config clear-session admin
talos auth-config set-session admin path   # re-edit if needed
talos auth-config set-session admin

talos auth-config reset-health admin
talos auth-config status admin
```

### Why

If sessions can be created through the CLI, they should also be recoverable
through the CLI. Support docs become "run reset-health" instead of
"open SQLite."

---

## Dynamic upstream proxy (no hardcoded host/port)

Upstream proxy handling is fully configuration-driven. Talos never hardcodes
an upstream host, port, URL, or credentials in runtime paths.

### Problem (fixed)

- `talos.proxy.launcher.build_mitmdump_command` always appended
  `--mode upstream:http://127.0.0.1:8081`, ignoring the resolved URL and
  breaking Direct mode.
- Replay, BAC, and unauth engines passed a hardcoded
  `proxy="http://127.0.0.1:8081"` to httpx, so attacks always required a
  local proxy on 8081 even when the project was in Direct mode.

### Changes

- **`talos.projects.proxy_config`**: single authority for upstream URL —
  `validate_upstream_url`, `get_upstream_url` / `set_upstream_url` /
  `clear_upstream_url`, and `resolve_upstream_url` (CLI one-shot → project
  config → Direct). Invalid URLs raise `InvalidUpstreamUrl` (CLI exit **2**).
- **`talos.proxy.launcher`**: adds `--mode upstream:<url>` only when a
  non-empty resolved URL is supplied; otherwise Direct (no `--mode`).
- **`talos.proxy.cli`**: `proxy start` accepts one-shot `--upstream URL` /
  `--no-upstream` (do not persist); `proxy config` still persists mode.
  Both use shared resolution/validation.
- **Replay / BAC / unauth engines**: `httpx.AsyncClient(proxy=get_upstream_url(db_path))`
  so outbound traffic follows the same project setting (or goes direct).
- **Talos Helper / cheat sheet / architecture**: document one-shot start
  flags and dynamic resolution.
- **Tests**: `tests/test_upstream_proxy.py` covers no-upstream, project
  config, CLI override, CLI over config, invalid URL, launcher Direct vs
  Upstream, and source-level no-hardcode guards.

### Behavior

| Source | Effect |
|--------|--------|
| No config, no CLI flag | Direct — no upstream |
| `talos proxy config --upstream <url>` | Persist Upstream for project |
| `talos proxy config --no-upstream` | Persist Direct |
| `talos proxy start --upstream <url>` | One-shot Upstream (config unchanged) |
| `talos proxy start --no-upstream` | One-shot Direct (config unchanged) |

Config is re-read on every start/resolve; restart the proxy after
`proxy config` changes. Replay and attack jobs pick up the current project
setting on each request.

### Example

```bash
# Direct (default)
talos proxy start --port 8080

# Persist Burp as upstream
talos proxy config --upstream http://127.0.0.1:8081
talos proxy start --port 8080

# One-shot override without changing project config
talos proxy start --no-upstream
talos proxy start --upstream http://corp-proxy.example:3128
```

---

## CLI-020: Help output and command hierarchy

Root help (Talos Helper), documentation, and a few module comments described
command paths that did not match the live argparse tree. Operators who copy
from `talos --help` or the cheat sheet then hit parser rejections.

### Verified mismatch (fixed)

| Documented / help | Actual parser | Result of documented form |
|-------------------|---------------|---------------------------|
| `talos endpoint rules list` | `talos endpoint rules` | `unrecognized arguments: list` (exit 2) |

There is **no** nested `list` under `endpoint rules`. Listing path-based
policy rules is the `rules` leaf command itself (optional `--format table|json`).

### Changes

- **Talos Helper** (`talos --help` / `_print_usage`): `rules list` → `rules`.
- **`talos.projects.endpoint_cli`**: module docstring and comments match the
  parser (`talos endpoint rules`).
- **Docs**: `docs/cli-cheat-sheet.md` (tree + examples), `docs/architecture.md`,
  and historical examples in this file corrected.
- **Cheat sheet scheduler tree**: added `jobs list|show`, `cancel`, and
  `prune` so the hierarchy matches root help (CLI-016).
- **Tests**: `tests/test_command_hierarchy.py` locks Talos Helper and the
  live `endpoint rules` parser together so this class of drift fails CI.

### Why

Help must be authoritative. When help and the parser diverge:

```
User copies command → CLI rejects it → confidence drops
```

One canonical hierarchy: live argparse is source of truth; root help and the
cheat sheet must mirror it.

### Example

```bash
# Correct
talos endpoint rules
talos endpoint rules --format json

# Wrong (was shown in help/docs; rejected by parser)
talos endpoint rules list
```

---

## CLI-019: Input Validation flag consistency

Input Validation mixed two meanings of `--force`: phase shortcuts used it to
**re-run analysis** (ignore cache), while almost every other Talos command —
including `input-validation clear-cache` — uses `--force` only to **skip
confirmation**. That mismatch breaks the mental model operators build across
the CLI and causes mistakes in automation.

### Changes

- **Phase shortcuts** (`baseline`, `identifier`, `characters`, `length`,
  `types`, `transformations`, `reflection`, `validation`) now take
  **`--ignore-cache`** as the primary flag to ignore completed cache and
  re-schedule the phase.
- **`--force` on phase shortcuts** remains a **deprecated alias** for
  `--ignore-cache` so existing scripts keep working. Prefer `--ignore-cache`.
- **`talos input-validation run`** already used `--ignore-cache` only (unchanged).
- **`talos input-validation clear-cache --force`** still means confirmation
  bypass only (CLI-015) — not re-analysis.
- Zero-jobs hint text now says `Use --ignore-cache to re-run.`
- Talos Helper (root `--help`), architecture, cheat sheet, about-talos, and
  tests updated (`tests/test_iv_flag_consistency.py`).

### Why

One meaning per flag:

| Flag | Meaning |
|------|---------|
| `--force` | Override safety / skip confirmation (destructive ops) |
| `--ignore-cache` | Reprocess / ignore completed IV cache |

### Example

```bash
# Preferred
talos input-validation baseline --ignore-cache
talos input-validation reflection --endpoint <id> --ignore-cache
talos input-validation run --ignore-cache

# Deprecated alias (still works on phase shortcuts only)
talos input-validation baseline --force

# --force still means confirm bypass here
talos input-validation clear-cache --force
```

---

## CLI-017: Project lifecycle management

Projects supported create / open / close / delete, but **delete only
unregistered** the project — multi-GB capture directories stayed on disk.
There was also no rename or description update, so long-lived assessments
could not be retitled and stale storage piled up.

### Changes

- **`talos project rename <id> <new_name>`** — updates the display name and,
  when `make_project_id(new_name)` differs, re-keys the registry, moves
  `<projects_root>/<old_id>` → `<new_id>`, and rewrites `project_id` columns
  inside `talos.db`. Status, scope, description, and constraints are preserved.
  Collision with an existing slug is rejected.
- **`talos project description <id> [TEXT…]`** — show current description
  when TEXT is omitted; set (or clear with empty text) when provided.
- **`talos project delete <id> [--purge] [--force]`**
  - Default (unchanged): remove registry entry only; data preserved on disk.
  - **`--purge`**: also `rmtree` the project directory (DB, archive, reports,
    auth sessions, filters — everything). Irreversible.
  - Interactive purge requires a **second** confirmation unless `--force`.
  - Non-interactive still requires `--force` (CLI-015).
- Default delete success output hints at `--purge` for full cleanup.
- Manager API: `rename`, `set_description`, `delete(..., purge=)`.
- Root help (Talos Helper), architecture, cheat sheet, README, and tests
  updated (`tests/test_project_lifecycle.py`).

### Why

```text
Create → use for months → need a better name → rename
Delete → storage fills with captures → delete --purge
```

Consultancies keep hundreds of historical projects; lifecycle management is
essential for operations and disk hygiene.

Example:

```bash
talos project rename old-client "Acme Q3 Assessment"
talos project description acme-q3-assessment "Production July Assessment"
# Unregister only (data kept):
talos project delete stale-lab --force
# Full wipe (registry + disk):
talos project delete stale-lab --purge --force
```

**Not in this release (future):** `project export` / `project import` for
moving assessments between systems; clone / archive as first-class commands.

---

## CLI-016: Scheduler job management

The scheduler previously exposed only aggregate operations (`status`, `clear`,
`pause`, `resume`). Large engagements produce thousands of jobs; operators
could not list failures, inspect one job, cancel a single attack, or prune
history without wiping the entire pending queue.

### Changes

- **`talos scheduler jobs list`** — inventory with filters:
  - `--status pending|running|paused|done|failed|skipped|cancelled`
  - `--type` exact job type or family prefix (`replay`, `bac`, `iv`, …)
  - `--limit N` (default 50, max 1000)
  - `--format table|json` (CLI-014)
- **`talos scheduler jobs show <job_id>`** — detail block (or JSON): endpoint,
  flow, type, priority, timestamps, failure reason, verdict, meta parameters.
  Accepts a full UUID or a unique prefix.
- **`talos scheduler cancel <job_id>`** — mark one **pending** or **paused** job
  `cancelled` (running jobs refuse; terminal jobs need prune).
- **`talos scheduler prune --status <done|failed|skipped|cancelled>`** — delete
  terminal history only; confirmation / `--force` (CLI-015). Leaves active
  queue intact.
- DB helpers: `list_jobs`, `get_job`, `cancel_job`, `prune_jobs`,
  `count_jobs_by_status`; `list_jobs_by_status` delegates to `list_jobs`.
- `STATUS_CANCELLED` included in `scheduler status` counts.
- Root help (Talos Helper), architecture, cheat sheet, README, and tests
  updated.

### Why

Support and operators need:

```text
List failed jobs → inspect one → fix issue → cancel or prune
```

instead of `pause` → `clear` → start over.

Example:

```bash
talos scheduler jobs list --status failed
talos scheduler jobs show 8d41a2c1
talos scheduler cancel a921ff03
talos scheduler prune --status done --force
```

---

## CLI-015: Confirmation prompt consistency

Destructive commands previously mixed three behaviors: confirm + `--force`,
confirm only, or immediate delete. Non-interactive runs (CI, pipes) could also
block forever on `input()` when a prompt was present.

### Changes

- **Shared policy** in `talos.cli_output` (`confirm_or_force` / `confirm_or_exit`):
  - Interactive TTY → prompt `[y/N]`; decline → `Cancelled.` (exit **130**)
  - Non-interactive → require `--force` or exit **2** with  
    `Error:` / `Operation requires --force in non-interactive mode.`
  - `--force` always skips the prompt
- Helpers: `is_interactive()`, `add_force_argument(parser)`,
  `NONINTERACTIVE_FORCE_REQUIRED` message constant
- Destructive surfaces aligned to the policy (confirm + `--force` where missing):
  - `talos mutation delete`
  - `talos access delete`
  - `talos auth clear`
  - `talos auth-config clear-expiry-signals`
  - `talos input-validation clear-cache`
  - `talos finding group remove` (group delete; `--remove-findings` retained)
  - Existing: `project delete`, `role|module delete`, `scheduler clear` /
    overflow enqueue, `finding confirm|reject|reopen --linked`
- Root help (Talos Helper), architecture, cheat sheet, coding guide, and tests
  updated (`tests/test_cli_output.py`, `tests/test_confirmation_policy.py`).

### Why

Operators must predict which commands are destructive. Automation must never
hang waiting for a keyboard. One helper keeps future delete/clear commands
consistent.

Example:

```bash
# Interactive
talos mutation delete <id>          # prompts [y/N]

# CI / scripts
talos mutation delete <id> --force
talos project delete qa-smoke --force
```

---

## CLI-014: Machine-readable output (`--format json`)

List, show, and status commands previously printed only human-readable tables
and labeled blocks. Automation had to scrape text with grep/awk/sed.

### Changes

- Shared helpers in `talos.cli_output` (CLI-014):
  - `add_format_argument(parser)` — attaches `--format {table,json}` (default `table`)
  - `wants_json(args)` / `get_output_format(args)`
  - `cli_json(data)` / `json_ready(value)` — stable JSON on stdout (indent=2)
- Applied to inventory and status surfaces, including:
  - `project list|status`, `project outscope list`
  - `role|module list|show`, `access show`
  - `endpoint list|show|rules`, `flow list|show`
  - `mutation list`, `auth show`
  - `auth-config list-flows|show|status|show-provider|show-extractor|list-control-flows`
  - `scheduler status`, `scheduler jobs list|show`, `finding list|show`,
    `finding group list`
  - `input-validation status|show`
- Empty lists emit `[]` in JSON mode (no human empty-state prose on stdout).
- Errors and warnings remain human-shaped on stderr (CLI-011); exit codes unchanged (CLI-012).
- Root help, architecture, cheat sheet, coding guide, and tests updated.

### Why

Scripts, dashboards, and bridges need a stable structured contract. Table
column tweaks must not break automation. Pipe into `jq` and language clients
directly.

Example:

```bash
talos endpoint list --format json | jq '.endpoints[].id'
talos project status --format json
talos finding list --format json
```

---

## CLI-013: Process-scoped project context

Commands previously required a globally mutable active project
(`talos project open <id>`). Concurrent scripts and CI jobs that opened
different projects interfered with each other.

### Changes

- **Root flag:** `talos --project <id> <command> …` (also `--project=<id>`).
- **Environment:** `TALOS_PROJECT=<id> talos <command> …`.
- **Resolution order** for the effective project:
  1. `--project` (exported into `TALOS_PROJECT` for child processes such as the proxy addon)
  2. existing `TALOS_PROJECT` in the environment
  3. registry entry with status `ACTIVE` (`project open`)
- Override **does not rewrite** registry ACTIVE status — safe for parallel automation.
- `talos project open` remains the interactive session model.
- `talos project status` reports process override when one is set.
- Unknown override id → exit **1** (not found); no project bound → exit **3**.
- Precondition messages mention `--project` / `TALOS_PROJECT`.
- Root help, architecture, cheat sheet, README updated; tests in
  `tests/test_project_context_override.py`.

### Why

Automation and multi-project shells need self-contained commands. Global
mutable context is fine for interactive use, not for concurrent scripts.

---

## CLI-012: Exit code consistency

Commands previously mixed exit statuses for the same class of outcome
(e.g. not found sometimes `0`, cancel always `0`, usage errors same as
hard failures). Automation and CI could not rely on `$?`.

### Changes

- Documented exit policy in `talos.cli_output` (CLI-012):

  | Code | Constant | Meaning |
  |------|----------|---------|
  | 0 | `EXIT_OK` | Success / intentional no-op |
  | 1 | `EXIT_FAILURE` | General failure (not found, op failed) |
  | 2 | `EXIT_USAGE` | Invalid arguments / unknown command |
  | 3 | `EXIT_PRECONDITION` | Setup/policy gate failed |
  | 130 | `EXIT_CANCELLED` | User declined confirmation |

- Helpers: `cli_usage_error`, `cli_precondition_error`, `confirm_or_exit`,
  `cli_exit`; `cli_error` defaults to `EXIT_FAILURE`.
- Applied across CLI modules: not found → 1; bad args → 2; no active project
  / auth prereqs / policy blocks → 3; cancel prompts → 130; IV “nothing new”
  and “already queued” → 0.
- Root help, architecture, cheat sheet, and tests updated.

### Why

Exit codes are the primary interface for shell scripts, CI, and language
integrations. One table of meanings makes automation predictable.

---

## CLI-011: Output consistency & error handling

CLI modules previously mixed labels (`Error:` / `ERROR:` / `Not found:`),
cancellation wording (`Aborted.` / `Cancelled.`), and job-enqueue formats.

### Changes

- **`talos.cli_output`** shared helpers: `cli_success`, `cli_info`,
  `cli_warning`, `cli_error`, `cli_cancelled`, `confirm_or_force`.
- **Standard formats** across commands:
  - Errors → `Error:` + blank line + body on stderr (exit 1 by default)
  - Warnings → `Warning:` + blank line + body on stderr
  - Cancellation → `Cancelled.` on stdout
  - Job enqueue → `Enqueued.` with a `Job:` field (and optional Type/Target/Priority)
- **Confirmations** for delete/clear/capacity overflow use `confirm_or_force`
  (or `--force`); declining always prints `Cancelled.`
- CLI modules under project/proxy/replay/scheduler/findings/input-validation
  call the helpers instead of ad-hoc `print(..., file=sys.stderr)`.
- Docs and root help updated; unit tests in `tests/test_cli_output.py`.

### Why

A CLI is an API for humans and scripts. One failure/success vocabulary
makes automation reliable and the product feel consistent.

---

## CLI-008: Endpoint & finding notes / tags

The product already stored free-form notes and tags on endpoints
(`endpoint_policy.notes` / `endpoint_policy.tags`) and notes on findings
(`findings.notes`). `endpoint show` and finding reports could display them,
but the CLI had no way to write them.

### Changes

- **`talos endpoint notes set <uuid>`** reads multi-line notes from stdin
  (pipe or interactive Ctrl-D) and stores them on the endpoint policy row.
- **`talos endpoint notes clear <uuid>`** clears endpoint notes.
- **`talos endpoint tags add|remove|set|clear <uuid> …`** manages arbitrary
  labels (merge / drop / replace / empty). Distinct from safety annotations
  (`mark --logout` / `--dangerous`).
- **`talos finding note set <uuid>`** / **`clear`** updates analyst notes and
  records a timeline event. Notes appear in `finding show` and Markdown reports.
- **Endpoint export** includes policy notes and tags in the dossier when set.
- **Policy helpers:** `get_notes_and_tags`, `add_tags`, `remove_tags` on
  `talos.projects.policy` (reuse existing `set_notes` / `set_tags`).
- **Docs / root help** updated for discoverability.

### Why

Without CLI write paths, analysts keep context in spreadsheets and external
markdown, fragmenting collaborative triage. Exposing the existing fields keeps
investigation knowledge inside Talos.

---

## CLI-006: Complete role & module lifecycle

Roles and modules already supported create, list, show, and set/unset active —
but typos and experiments could not be fixed from the CLI without editing SQLite.

### Changes

- **`talos role rename <name|uuid> <new_name>`** / **`talos module rename …`**
  update the display name only. The UUID is stable, so access map, flows, and
  auth-config references keep working with no rewrite.
- **`talos role delete <name|uuid> [--force]`** / **`talos module delete …`**
  print a dependency summary (access matrix, flows, auth config, BAC results,
  findings evidence), confirm unless `--force`, then cascade config rows and
  reassign tagged flows to the built-in **`global`** role/module.
- **Protected `global`:** rename and delete refuse the seed role/module.
- **Manual session file** for a deleted role is removed from
  `<project>/auth_sessions/<role_uuid>.txt` when present.
- **Docs / root help** updated for full CRUD discoverability.

### Why

Without rename/delete, projects accumulate junk roles and modules, the access
matrix becomes harder to read, and operators fall back to manual SQLite edits.
Complete lifecycle keeps long-running engagement projects maintainable.

---

## CLI-005: Unauth auto-run config

The engine already supported `unauth_auto_run` (scheduler auto-enqueues classic
`auth_test` jobs for untested qualified endpoints), but the CLI did not expose it.

### Changes

- **`talos attack unauth config show`** prints `Auto Run : Enabled|Disabled`
  (default Disabled).
- **`talos attack unauth config --auto-run on|off`** persists the flag via
  `set_unauth_auto_run()` / `attack_config` and reprints the current state.
- **Distinct from `talos attack unauth run`:** auto-run enqueues classic
  Authentication Bypass (`auth_test`) jobs; `unauth run` enqueues
  `unauth_attack` recipe jobs.
- **Docs / root help** updated so the capability is discoverable.

### Why

Hidden engine features reduce trust and block unattended enterprise workflows.
Exposing config completes the product surface without additional engine work.

---

## CLI-004: Module name/UUID discoverability

Modules are the same conceptual resource as roles, but BAC required `--module UUID`
while roles accepted names. Operators had to memorise UUIDs from create output
because `module list` only printed names.

### Changes

- **`talos module list`** prints a table: `UUID`, `Name`, `Active` (`*` for the
  active module).
- **`talos module show <name|uuid>`** prints name, UUID, status, description, and
  access-map roles.
- **Shared `resolve_module()`** (name first, then UUID) in `talos.projects.access`,
  mirroring `resolve_role()` (CLI-001).
- **BAC `--module`** accepts a module **name or UUID** (resolved before candidate
  scan). Example: `talos attack bac session-swap --module payments`.
- **Docs / root help** updated so roles and modules share one identification rule.

### Why

One rule for user resources — name or UUID — cuts special cases, documentation,
and user errors such as “invalid module UUID”.

---

## CLI-003: Flow inventory (`talos flow list`)

Flows are created during capture and by replay / attack modules. Commands such
as `talos flow show`, `talos flow export`, `talos replay flow`, and
`talos auth-config add-flow` all require a flow UUID — but there was no list
command to discover those UUIDs without inspecting SQLite.

### Changes

- **`talos flow list`** prints the project flow inventory:
  `UUID`, `Endpoint` (`host` + `path`), `Method`, `Status`, `Role`,
  `Source`, `Created` (`captured_at`). Newest first.
- **Filters** (AND): `--endpoint` (endpoint UUID), `--status-code`,
  `--role` (name or UUID via `resolve_role()`), `--source`
  (`proxy_capture` | `manual_replay` | `auto_replay` | `iv_scan`),
  `--limit N`.
- **Docs / root help** updated so the discovery path is
  `flow list` → copy UUID → `flow show` / `replay` / auth-config.

### Why

Without list, replay and auth setup required guessing UUIDs or opening the DB.
List makes the CLI the source of truth for flow discovery, chronological
incident review, and finding requests such as a login capture.

---

## CLI-002: Endpoint inventory (`talos endpoint list`)

Endpoints are created automatically during capture, and almost every downstream
command requires an endpoint UUID — but there was no list command. Error
messages and docs already told operators to run `talos endpoint list`, which
did not exist.

### Changes

- **`talos endpoint list`** prints the full project inventory:
  `UUID`, `Method`, `Host`, `Path`, `Priority` (effective), `Qualified`,
  `Excluded`.
- **Filters** (AND): `--method`, `--host`, `--qualified`, `--excluded`,
  `--search`, `--role` (name or UUID), `--priority`.
- **Policy resolution:** uses `list_endpoints()` in the Endpoint Policy
  engine so effective priority and path-rule exclusions match
  `talos endpoint show`. Unlike `get_testable_endpoints()` (attack modules),
  the list includes unqualified and excluded rows for discovery and debugging.
- **Docs / root help** updated; the previous “no endpoint list” note is
  removed. BAC / unauth error text that references `talos endpoint list` is
  now accurate.

### Why

Without list, the workflow was capture → endpoint exists → cannot see UUID →
cannot replay / attack. Operators had to inspect SQLite. List makes the CLI
the source of truth for endpoint discovery.

---

## CLI-001: Role UUID discoverability

Roles and auth-config no longer force operators to retain UUIDs from create
output alone.

### Changes

- **`talos role list`** prints a table: `UUID`, `Name`, `Active` (`*` for the
  active role).
- **`talos role show <name|uuid>`** prints name, UUID, status, access-map
  modules, configured auth provider, and auth-flow / extractor counts.
- **`auth-config` role arguments** accept a **role name or UUID**. Resolution
  uses `resolve_role()` (name first, then UUID) with no schema changes.
  Example: `talos auth-config add-flow admin <flow_id>`.
- **BAC `--role`** uses the same shared resolver.
- **Docs / root help** updated so workflows prefer role names; UUIDs remain
  fully supported for scripts and copy-paste.

### Why

Previously create printed a UUID that later commands required, but
`role list` only showed names — a classic discoverability gap. Operators can
now list/show roles or pass the name directly into auth-config.

---

## Embedded UI Removed

Talos is now **CLI-only**. The built-in web interface and all related code
have been removed.

### Breaking changes

- **`talos ui` removed.** The command no longer exists.
- **Package `talos.ui` removed** (app, API routes, templates, proxy manager).
- **UI-only dependencies removed** from install: FastAPI, Jinja2, uvicorn.

### Preserved CLI behaviour

Access coverage and BAC signal queries used by `talos access coverage` and
`talos access signals` were moved from `talos.ui.db` into
`talos.projects.access`. No CLI command other than `talos ui` was removed.

---

## BAC Endpoint Policy + Scoped Testing

### Bug fix: endpoint exclusions ignored during BAC candidate generation

Previously, `scan_candidates()` selected proxy_capture flows directly from the
`flows` table with **no** Endpoint Policy check. Excluded endpoints still
produced BAC candidates, scheduler jobs, HTTP attacks, and findings.

**Fix:** candidate generation now calls `get_testable_endpoints()` first and
only selects flows whose `endpoint_id` is in that set (qualified, not
excluded by endpoint or path rule). An excluded endpoint is treated as if it
does not exist for BAC attack generation.

### Bug fix: BAC required `status_code = 200` instead of 2xx

Endpoint Qualification uses `status_code BETWEEN 200 AND 299`. BAC candidate
generation incorrectly required `status_code = 200`, so endpoints whose only
successful captures were `201` / `202` / `204` / `206` were qualified by policy
but never produced BAC candidates. Flow selection now matches qualification.

### Defence-in-depth: full policy re-check at execution

`execute_bac_job` re-resolves full effective policy before sending any request.
If policy changed after the job was queued, the job is skipped (no HTTP, no
finding):

| Condition | Skip reason |
|-----------|-------------|
| `excluded` | `endpoint_excluded` |
| `logout` | `endpoint_annotated_logout` |
| `dangerous` | `endpoint_annotated_dangerous` |
| `!qualified` | `endpoint_not_qualified` |

### New: endpoint- and module-scoped BAC testing

All `talos attack bac <module>` commands accept a mutually exclusive execution
scope. Only candidate selection changes — the BAC engine, variants, decision
filter, scheduler, and findings path are unchanged.

```bash
# Project scope (default) — all testable endpoints
talos attack bac session-swap

# Module scope — one application feature (name or UUID; see CLI-004)
talos attack bac session-swap --module payments
talos attack bac session-swap --module <uuid>

# Endpoint scope — targeted validation / regression
talos attack bac session-swap --endpoint <uuid>
talos attack bac session-swap --endpoint <uuid> --role customer --auto-generate
```

`--endpoint` and `--module` cannot be combined. Invalid or excluded
`--endpoint` / missing `--module` values fail fast with a clear error.

### Policy API: scoped `get_testable_endpoints`

```python
get_testable_endpoints(db_path, project_id)                       # project
get_testable_endpoints(db_path, project_id, endpoint_id=...)      # O(1)
get_testable_endpoints(db_path, project_id, module_id=...)        # module
is_endpoint_testable(db_path, project_id, endpoint_id)            # bool
```

BAC (and other attack modules) request scoped policy results instead of loading
every testable endpoint and filtering in application code.

### Files touched

- `talos/projects/policy.py` — scoped `get_testable_endpoints` + `is_endpoint_testable`
- `talos/projects/bac/candidates.py` — 2xx flows + scoped policy lookup
- `talos/projects/bac/cli.py` — mutually exclusive `--endpoint` / `--module`
- `talos/projects/bac/engine.py` — full policy pre-check
- `talos/scheduler/scheduler.py` — skip reasons for policy guards
- `talos/projects/attack_cli.py` — help text

---

## Finding Relationships (PRIMARY / LINKED) — schema v34

### Summary

Successful attack techniques on the same vulnerability cluster no longer flood
the main findings list as independent noise. Every successful result still
creates a real finding; related findings are grouped as **PRIMARY** + **LINKED**.

Example (Unauth on `GET /api/profile`):

```
F001 PRIMARY  remove_all_auth
|
+-- F002 LINKED  authorization_null
+-- F003 LINKED  authorization_whitespace
+-- F004 LINKED  malformed_bearer
```

### Behaviour

- **Cluster identity (Unauth):** `UNAUTH:<endpoint_id>` — mutations are excluded.
- **Auth-bypass:** `AUTH_TEST:<endpoint_id>`
- **BAC:** `BAC:<endpoint_id>:<attacker_role_id>:<target_role_id>`
- First finding in a cluster is PRIMARY; later ones are LINKED to that PRIMARY.
- Flat relationships only (no linked-to-linked trees).
- Partial unique index guarantees one PRIMARY per `cluster_key` (race-safe).
- Attack results, replay flows, and scheduler jobs are **not** deduplicated.
- Status remains independent per finding by default.
- `LINKED` relationship ≠ `DUPLICATE` lifecycle status.

### CLI

```bash
talos finding list                 # PRIMARY only (default); shows linked count
talos finding list --linked        # LINKED only
talos finding list --all           # PRIMARY + LINKED
talos finding show <uuid>          # shows linked children or parent PRIMARY
talos finding reject <uuid>        # one finding only
talos finding reject <primary> --linked           # bulk (PRIMARY only)
talos finding confirm <primary> --linked --force  # skip mixed-status prompt
```

Bulk `--linked` is a one-time operation on currently existing linked findings.
Future linked findings always start as `TRIAGING` (no status inheritance).

### DB (v33 → v34)

- `findings.relation_type` — `PRIMARY` | `LINKED` (default PRIMARY)
- `findings.parent_finding_id` — set for LINKED only
- `findings.cluster_key` — internal grouping identity
- Unique index `idx_findings_primary_cluster` on `cluster_key` where
  `relation_type = 'PRIMARY' AND cluster_key IS NOT NULL`
- Existing multi-finding Unauth/Auth clusters are backfilled on migrate

### Modules touched

`talos.findings.model`, `talos.findings.db`, `talos.findings.creator`,
`talos.findings.cli`, `talos.findings.report`, `talos.projects.db`,
`talos.__main__` (help text)

---

## v0.8.0: Unauth Mutation Engine, BAC Parser-Confusion, Mutation Naming

### Summary

This release replaces the old `talos attack unauth exclude` command with a
comprehensive mutation composition engine.  Both the Unauth and BAC attack
modules now generate combinations of auth mutations × request mutations, expose
richer reporting fields (`mutation_family`, `mutation`), and gain the new
`parser-confusion` technique family.

---

### Breaking Changes

- **`talos attack unauth exclude` removed.** Use `talos endpoint exclude` instead.
  The Endpoint Policy system now owns all inclusion/exclusion.  No per-attack
  exclusion logic exists.
- `attack_config.py`: removed `add_unauth_exclusion`, `remove_unauth_exclusion`,
  `list_unauth_excluded_hosts`.  `get_untested_endpoint_ids` now filters by
  endpoint_policy (qualified=1, logout=0, dangerous=0, excluded=0) instead of
  the legacy `attack_host_exclusions` table.

---

### New: `talos attack unauth run`

The unauth attack command is completely redesigned.  Instead of simple auth
stripping, it now generates jobs via a **mutation composition engine**:

```
baseline flow
      ↓
auth mutation  (remove, empty, malformed, null, whitespace, duplicate)
      ↓
request mutation  (method-fuzz, url-fuzz, header-inject, host-fuzz,
                   content-type, role-inject, parser-confusion)
      ↓
replay  →  decision filter  →  BYPASS | SECURE | UNKNOWN
```

**Auth mutations (11):**
- `remove-auth` family: remove_authorization_header, remove_authorization_cookie, remove_all_auth
- `empty-auth` family: empty_authorization_header, empty_authorization_cookie
- `malformed-auth` family: malformed_bearer, malformed_basic
- `authorization_null`: set auth fields to literal "null"
- `authorization_whitespace`: set auth fields to whitespace " "
- `duplicate-auth` family: duplicate_empty_header, duplicate_malformed_header

**Request mutations:** same families as BAC (method-fuzz, url-fuzz, header-inject,
host-fuzz, content-type, role-inject, parser-confusion).

**Predefined composition recipes (42 total, three priority tiers):**
- Priority 1: baseline auth-only jobs + high-value two-mutation combos
- Priority 2: additional two-mutation compositions
- Priority 3: three-mutation combinations

```bash
talos attack unauth run                            # priority ≤ 2 (default)
talos attack unauth run                         # all recipes
talos attack unauth run --technique baseline    # restrict by technique name
```

**New decision filter for unauth:** `unauth-decision-filter.yaml`

Default SECURE patterns: 401, 403, 407, WWW-Authenticate header, and body
keywords (Access Denied, Unauthorized, Forbidden, Login required, etc.)

Default BYPASS patterns: 2xx status, "Welcome" in body.

```bash
talos attack unauth filter init
talos attack unauth filter show
talos attack unauth filter validate
```

---

### New: BAC `parser-confuse` attack module

```bash
talos attack bac parser-confuse [--role NAME] [--auto-generate]
```

Techniques:
- `duplicate_id_param` — duplicate first query parameter (first vs last wins)
- `hpp_id_param` — HTTP Parameter Pollution: inject id=0 alongside existing value
- `duplicate_accept` — inject duplicate Accept header
- `duplicate_content_type` — inject second Content-Type: text/plain
- `te_cl_conflict` — conflicting Transfer-Encoding: chunked + Content-Length

---

### New: BAC `session-swap` sub-techniques

Two new session_swap variants for BAC:
- `authorization_null` — set all auth fields to literal "null"
- `authorization_whitespace` — set all auth fields to single space " "

```bash
# These run automatically when you run:
talos attack bac session-swap
```

---

### Mutation naming: `mutation_family` + `mutation` fields

All variant definitions now carry:
- `mutation_family` — high-level family (e.g. `method-fuzz`, `host-fuzz`)
- `mutation` — specific mutation label (e.g. `GET→POST`, `X-Original-URL`)

Both fields are stored in the `bac_results` table for richer reporting.
New `unauth_results` table stores the same fields for unauth attacks.

---

### DB changes (v31 → v32)

- `bac_results`: added `mutation_family TEXT` and `mutation TEXT` columns.
- New `unauth_results` table with `auth_mutation_family`, `auth_mutation`,
  `request_mutation_family`, `request_mutation`, `verdict`, and decision
  filter evidence fields.
- New `UNAUTH_ATTACK = "unauth_attack"` and `BAC_PARSER_CONFUSE = "bac_parser_confuse"`
  scheduler job type constants.

---

## v0.7.0: Endpoint Qualification System & Baseline Flow Caching

### Summary

This release introduces the Endpoint Qualification System — a pre-computed
triage layer that prevents unqualified endpoints from ever reaching the
scheduler, attack generator, or Input Validation engine.

Every attack module and IV engine now operates exclusively on endpoints that
have at least one successful (2xx) proxy_capture flow. Endpoints that only
returned errors, redirects, or no response are filtered out before any
scheduling or candidate generation begins.

### Problem

With large captures (e.g. 20,000 endpoints) only a fraction return 200 OK.
Previously all endpoints entered the scheduler pipeline. The scheduler spent
cycles examining endpoints that could never yield a valid test baseline,
wasting scheduler cycles, DB queries, rate-limit budget, and attack
generation time.

### Endpoint Qualification

**New columns on `endpoint_policy`:**

| Column | Type | Purpose |
|--------|------|---------|
| `qualified` | `INTEGER` (bool) | 1 = endpoint has at least one 2xx proxy_capture flow |
| `qualification_reason` | `TEXT` | Explains why qualified or not |
| `baseline_flow_id` | `TEXT` | Pre-computed UUID of the best 2xx proxy_capture flow |
| `baseline_status` | `INTEGER` | HTTP status of the baseline flow |

**qualification_reason values:**

| Value | Meaning |
|-------|---------|
| `no_flows` | No proxy_capture flows captured yet |
| `no_2xx_response` | Flows exist but none returned 2xx |
| `only_redirects` | All observed flows returned 3xx |
| `is_logout` | Endpoint is a logout endpoint |
| `is_dangerous` | Endpoint is marked dangerous |
| `flow_2xx` | At least one 2xx flow — endpoint is testable |

**Qualifying status codes:**

Any 2xx response qualifies: `200`, `201`, `202`, `204`, `206`, etc.
Single-status hardcoding (`status_code = 200`) is replaced everywhere with
`status_code BETWEEN 200 AND 299`.

**Qualification criterion:**

```
qualified = True  when:
    status_code BETWEEN 200 AND 299
    AND source = 'proxy_capture'
    AND endpoint_policy.logout = 0
    AND endpoint_policy.dangerous = 0
```

### Baseline Flow Caching

`baseline_flow_id` caches the UUID of the most recently captured 2xx
proxy_capture flow. The replay engine now reads this field first (fast path)
instead of executing `SELECT … ORDER BY captured_at DESC LIMIT 1` on every
attack. This eliminates per-attack DB scans.

The fallback to a full scan remains for edge cases (e.g. if the baseline
flow is deleted).

### Worker Integration

The `FlowWorker` calls `update_endpoint_qualification()` after each
proxy_capture flow is persisted. This runs in a separate DB transaction
after auto-priority scoring. Failure is non-fatal — the flow and endpoint
remain committed.

### Impact on all attack surfaces

`get_testable_endpoints()` — the single entry point for every attack module
— now adds `WHERE ep.qualified = 1` at the SQL layer. Unqualified endpoints
never reach the scheduler or any attack generator.

`get_untested_endpoint_ids()` (auth bypass auto-enqueue) now joins with
`endpoint_policy` and filters `qualified = 1`.

Input Validation parameter queries (`_list_*_params`) now join with
`endpoint_policy` and filter `qualified = 1` and `excluded = 0`, ensuring
IV only probes parameters from endpoints with a valid baseline.

### Database Migration

Schema version: v29 → v30.

The migration backfills `qualified`, `qualification_reason`,
`baseline_flow_id`, and `baseline_status` for all existing endpoint_policy
rows by scanning the flows table once. Endpoints with an existing 2xx
proxy_capture flow are immediately qualified.

---

## v0.6.1: Replay Engine Hardening, Canonical Endpoint Export & Flow Metadata

### Summary

This release hardens the replay pipeline, introduces a canonical endpoint export, standardizes replay metadata, and refactors Input Validation into a fully replay-driven architecture where every probe is an independent replay flow.

### Replay Engine Hardening

**Automatic `Content-Length` regeneration.**

The replay engine now removes the `Content-Length` header immediately before sending every replay request. `httpx` automatically recalculates the correct value from the final request body, making replay resilient to body mutations performed by Input Validation, BAC, and future attack modules.

This permanently eliminates replay failures caused by stale
`Content-Length` values after request mutation.

### Live Proxy Improvements

**Conditional cache headers removed automatically.**

Before forwarding live traffic upstream, Talos removes:

* `If-None-Match`
* `If-Modified-Since`

This forces origin servers to return fresh responses (`200 OK`) instead of `304 Not Modified`, ensuring Endpoint Intelligence, Parameter Intelligence, Input Validation, and future analysis modules always observe complete response bodies.

### Input Validation Architecture

Input Validation now follows the same execution model as BAC.

**Every probe = one scheduler job = one replay flow.**

Every payload sent by the engine now produces:

* One scheduler job
* One replay flow
* One unique flow ID
* One HTTP request
* One HTTP response
* One replay metadata record
* One probe result

Transformation and Reflection remain pure analysis phases that consume existing replay flows without generating additional HTTP traffic.

### Universal Replay Metadata

Replay flows now contain a standardized `flow_meta` JSON object describing why the replay exists.

Example:

```json
{
    "generated_by": "input_validation",
    "analysis": "characters",
    "parameter_uuid": "...",
    "parameter_name": "ProductId",
    "payload": "<",
    "payload_type": "character",
    "payload_index": 17,
    "baseline_flow": "...",
    "mutation": {
        "location": "body",
        "host": "myapp.local",
        "endpoint_id": "..."
    }
}
```

Future modules (BAC, SQLi, XSS, SSRF, XXE, etc.) populate the same metadata structure with module-specific information.

### Database Schema: v28

The `iv_probe_results` table has been normalized.

Removed duplicated HTTP fields:

* `status_code`
* `content_type`
* `body_length`
* `error`

Probe results now reference replay flows through `flow_id`, making the `flows` table the single source of truth for all HTTP request and response data.

### Canonical Endpoint Export

Endpoint export is now owned by the Endpoint subsystem.

```bash
talos endpoint export <endpoint_id>
```

The exported report includes:

* Endpoint Intelligence
* Parameter Intelligence
* Parameter summaries
* Original captured flows
* Replay flows
* Raw HTTP requests
* Raw HTTP responses
* Input Validation observations and evidence

Future attack modules (BAC, SQLi, XSS, SSRF, etc.) will contribute their results to the same endpoint report.

### Universal Flow CLI

A new module-independent Flow CLI has been introduced.

```bash
talos flow list
talos flow list --source proxy_capture --limit 20

talos flow show <flow_id>

talos flow export <flow_id>
talos flow export --module <module>
talos flow export --parameter <parameter_uuid>
talos flow export --endpoint <endpoint_id>
talos flow export --flows <flow_id> <flow_id> ...
```

The Flow CLI provides a unified interface for listing and inspecting capture and
replay evidence generated by the proxy, Replay, Input Validation, BAC, and
future attack modules. See **CLI-003** for the list inventory details.

### Scheduler Improvements

Scheduler jobs now expose replay metadata for Input Validation, including:

* Analysis type
* Payload
* Flow link

`talos scheduler status` and per-job metadata make individual probes traceable
from scheduling through replay execution.

### Flow inspection

Replay flows generated by Input Validation appear alongside all other replay
traffic and carry standardized replay metadata, so they can be listed,
inspected, and exported via `talos flow list` / `show` / `export` like every
other Talos flow.

---

## v0.6.0: Input Validation: Per-Request Architecture + Universal Flow Metadata

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
`session_health.ensure_healthy()`: identical to BAC.

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

- `iv_probe_results`: per-HTTP-request IV evidence, one row per probe.
- `flows.flow_meta`: universal replay metadata column (TEXT JSON).

### Reflection Phase Fixed

`iv_reflection` is now correctly included in the scheduling sequence.
Transformation and Reflection phases are pure analysis (zero HTTP) that
consume existing probe flows.

### New CLI Commands

```bash
# IV exports (Markdown/CSV under <project>/exports/ or stdout)
talos input-validation export parameter <param_uuid>
talos input-validation export host <host>
talos input-validation export csv           # per-probe CSV (all params)
# Endpoint dossiers: talos endpoint export <endpoint_id>

# Universal flow inspector
talos flow list
talos flow list --source proxy_capture --limit 20
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

### Scheduler / flow metadata for IV

Completed IV jobs record analysis type, exact payload, and the resulting flow
id so probes can be traced via `talos scheduler status` and
`talos flow list` / `show`. IV scan flows use `source=iv_scan` and are
listable and exportable like any other flow.

---

## v0.5.0: Endpoint Intelligence + Input Validation Engine

### Summary

This release expands Parameter Intelligence into a full **Endpoint Intelligence**
system and introduces the **Input Validation Engine** as an active analysis layer.

### Endpoint Intelligence (Parameter Intelligence expansion)

Parameter extraction now covers **every observable input surface**:

| Added | Previous |
|-------|---------|
| Path parameters (from normalized path pattern) |: |
| JSON body: nested (dotted path names) | Top-level only |
| JSON body: arrays |: |
| Multipart/form-data fields |: |
| XML / SOAP element names |: |
| GraphQL variables |: |
| Security-relevant headers (`Authorization`, `X-Forwarded-For`, `Origin`, `X-Tenant`, `X-CSRF-Token`, etc.) |: |
| Cookie parameters (individual names) |: |

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

### DB Schema: v25

The following changes are applied automatically via migration when an existing
project database is opened.

**parameters table**: new columns:
- `semantic_type TEXT NOT NULL DEFAULT 'unknown'`
- `seen_count INTEGER NOT NULL DEFAULT 1`
- `appears_in_roles TEXT NOT NULL DEFAULT '[]'`
- `appears_in_modules TEXT NOT NULL DEFAULT '[]'`
- `is_reflected INTEGER NOT NULL DEFAULT 0`
- `reflection_count INTEGER NOT NULL DEFAULT 0`
- `reflection_locations TEXT NOT NULL DEFAULT '[]'`
- `reflection_encoding TEXT NOT NULL DEFAULT '[]'`

**New tables:**
- `input_validation_config`: per-project IV engine configuration
- `iv_param_cache`: parameter-level analysis results, cached by `(host, location, param_name, phase)`
- `iv_reflection_cache`: endpoint-specific reflection analysis cache

### Input Validation Engine

New active analysis engine. **Disabled by default**: must be explicitly enabled.

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

**Design:** All execution goes through the Talos Scheduler: no requests are
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
talos input-validation show <param_uuid>
talos input-validation export parameter|host|csv

# Phase shortcuts (each supports --host/--endpoint/--parameter/--ignore-cache;
# --force is a deprecated alias for --ignore-cache on phase cmds only — CLI-019)
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

### Schema migration on project open / process override

`talos project open` and process-scoped override resolution (`--project` /
`TALOS_PROJECT` via `ProjectManager.active()`) call `init_project_db` on the
target database, ensuring the schema is current when a project is activated
or bound. Existing projects created with older schema versions are migrated
automatically on next open or override resolve — no manual migration step.

### Scheduler job types

Eight new job type constants added to `talos.scheduler.job`:

```python
IV_BASELINE, IV_IDENTIFIER, IV_CHARACTERS, IV_LENGTH,
IV_TYPES, IV_TRANSFORMATIONS, IV_REFLECTION, IV_VALIDATION
```

---

## v0.4.x: auth-config, session health, BAC decision filter

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

1. **TTL-based pre-refresh**: proactive refresh before expiry
2. **Expiry signal detection**: body/header/status signals increment suspicion
3. **Validation endpoint**: authoritative session check on suspicion
4. **Control flows**: replay stable authenticated flows to judge liveness

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
talos endpoint rules
```

---

## v0.3.x: BAC attack modules

Seven BAC attack modules added:

- `bac session-swap`: direct session swap
- `bac method-fuzz`: HTTP Method Manipulation
- `bac content-type`: Content-Type Confusion
- `bac url-fuzz`: URL Manipulation
- `bac header-inject`: Header Manipulation
- `bac host-fuzz`: Host Header Changes
- `bac role-inject`: Role Parameter Injection

Scheduler integration: all BAC attacks create scheduler jobs, not
immediate execution. Centralized concurrency + pause/resume.

---

## v0.2.x: Replay, diff, access model, scheduler

- ReplayScheduler daemon thread with priority queue
- Diff engine: status, length, JSON structure comparison
- Two-layer access model: client_allowed + server_expected
- `talos access signals`: BAC/IDOR signal report
- Per-project header drop file
- Request mutations (inject headers on every proxied request)

---

## v0.1.x: Initial capture pipeline

- MITM proxy (mitmproxy) integration
- FlowWorker daemon thread
- SQLite WAL storage
- Endpoint normalization and deduplication
- Role + module tagging
- JSONL raw archive
- Basic parameter extraction (query + JSON/form body)


