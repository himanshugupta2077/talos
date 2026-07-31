# URL Sink Discovery — Full QA Issues Report (CLI focus)

**Date:** 2026-07-31  
**Scope:** Phases 1–4 as shipped on `main` (through `c86da50`); Control Panel out of scope.  
**Method:** Design plan + docs review, package/engine/CLI code inspection, integration harness (extract → upsert → capabilities/candidates → list filters), unit suites, argparse help checks.  
**Policy:** Report only — **no fixes** in this pass.

**Code under test:** `talos/url_sink/*`, `talos/projects/parameters.py`, `talos/projects/db.py` (v53), `talos/worker/worker.py`, `talos/input_validation/{url_sink_probes,fingerprint,planner,engine,capabilities,candidates,synthesize,cli}.py`, CLI entrypoints.

**Unit tests re-run:** `tests/test_url_sink_*.py` + `tests/test_iv_url_sink.py` + `tests/test_iv_candidates.py` → **254 passed**.

---

## Executive summary

| Layer | Status |
|-------|--------|
| Passive classifiers + `url_features` compose | **Working** — success metric `abc=https://…` → score 95, `possible_network_resource=true` |
| Extract surfaces (query/JSON/base64/JWT/headers/HTML) | **Mostly working** — one JS island gap (`window.__NEXT_DATA__ =`) |
| Schema v53 + upsert score merge | **Working** — higher score wins on re-observe |
| IV warrant / canaries / synthesis contract | **Working** in pure/offline paths; canaries are benign `.invalid` only |
| Capabilities + value-first candidates | **Working** when evidence present (passive score and/or type accept / url_sink) |
| CLI operator visibility (Phase 5) | **Incomplete** — inventory and `url_sink` detail hard to see without JSON digging / prior param UUID |
| IV scheduling of inventory-only rows | **Bugs** — `location=response` and `jwt.*` virtuals are scheduled as if injectable |

**Bottom line:** Core URL Sink Discovery intelligence (Phases 1–4 logic) is largely correct and covered by unit tests. **End-to-end CLI usability is not complete** (acknowledged Phase 5). Separately, **IV incorrectly treats some inventory-only parameters as mutatable surfaces**, which can waste budget and invent non-representative headers.

---

## What was verified OK

### Phase 1 — Passive core

| Check | Result |
|-------|--------|
| `abc=https://cdn.example/x` → score ≥ 90, NRS, no name catalog hit | Pass (score 95) |
| Email `user@example.com` not NRS | Pass |
| `report.pdf` stays `semantic_type=filename`, not hostname/NRS | Pass |
| Protocol-relative `//host`, IPv4/IPv6, UNC, paths | Pass (unit + smoke) |
| Name-only `go` / empty `redirect_url` scores &lt; 45 | Pass |
| `HTTPSRedirect` → redirect category | Pass |
| `callback_url` multi-category webhook + remote_fetch | Pass |
| Schema v53 `parameters.url_features`; migration `ADD COLUMN` present | Pass |
| Upsert: weaker re-observation does not lower high score | Pass |
| Catalog size ~481 entries / 9 categories | Pass |

### Phase 2 — Structure discovery

| Check | Result |
|-------|--------|
| Nested JSON `user.avatar`, `config.oauth.metadata.url` | Pass |
| Base64 form `cfg` → `cfg.oauth.metadata.url` | Pass |
| JWT Bearer → `jwt.jku` / `jwt.iss` / `jwt.aud` virtual headers | Pass |
| Header allowlist: Referer, Destination, Link (angle-bracket) | Pass (Link score 99) |
| Value-first custom header `x-my-callback` | Pass |
| UA / Accept not inventoried | Pass |
| HTML hidden `redirect_url`; gate drops `next=1` | Pass |
| `window.__CONFIG__` / `__INITIAL_STATE__` / bare `apiUrl` assigns | Pass |
| `<script id="__NEXT_DATA__" type="application/json">` | Pass (unit fixture) |
| FlowWorker wires `extract_flow_params` + `extract_response_url_sink_params` | Pass (source) |

### Phase 3 — IV canaries

| Check | Result |
|-------|--------|
| Warrant for high-score / URL semantic / categories | Pass |
| Standard canaries on `talos-canary.invalid` (+ loopback, path) | Pass |
| Deep expands protocols (ftp/gopher/file/unc) | Pass (8 vs 5) |
| No collaborator/OAST domains in probe set | Pass |
| Engine references `url_sink` / `iv_url_sink` | Pass |

### Phase 4 — Capabilities & candidates

| Check | Result |
|-------|--------|
| Passive high score → `network_resource_sink` + `url_like_value` | Pass |
| Passive `abc` also emits `ssrf` ~50 (value-first) | Pass |
| Name-only `go` no URL-family candidates / no redirect_sink | Pass |
| + type accept / fetch / DNS → `ssrf` high, `fetch_sink` | Pass |
| `redirect_url` + redirect_behavior → `open_redirect` / `redirect_sink` | Pass |
| `callback_url` + fetch → `webhook_abuse` / `webhook_sink` | Pass |
| `redirect_uri` + redirect → `oauth_redirect` | Pass |
| `list_candidates --attack webhook_abuse\|oauth_redirect\|ssrf` | Pass |
| `list_candidates --capability network_resource_sink` | Pass |
| `KNOWN_ATTACKS` + AI schema enums include new attacks | Pass |
| `get_param_intelligence(parameter_row_id)` works | Pass |

---

## Issues found

Severity: **Critical** &gt; **High** &gt; **Medium** &gt; **Low**.  
IDs are stable for follow-up tickets.

---

### HIGH

#### QA-USD-01 — No CLI to browse parameter inventory / `url_features` after capture

| | |
|--|--|
| **Area** | CLI surface (Phase 5) |
| **Severity** | High |
| **Where** | `talos endpoint` has no `params` (or equivalent) subcommand; only list/show/export/… |

**Symptom:** After proxy capture + FlowWorker inventory, operators cannot list parameters with sink score / categories / NRS from CLI. `talos input-validation show` requires a **parameter row UUID** already known.

**Impact:** Main help text advertises automatic `url_features` inventory (endpoint list blurb), but there is no discoverability path. Operators cannot complete “find URL sinks from capture” without SQL or guessing UUIDs.

**Plan ref:** Phase 5 acceptance — *CLI show/export includes url_features…* still unchecked.

---

#### QA-USD-02 — `input-validation show` / table formatting never surfaces `url_features`

| | |
|--|--|
| **Area** | CLI display |
| **Severity** | High |
| **Where** | `talos/input_validation/cli.py` (zero references to `url_features`); `format_profile_summary_lines()` |

**Symptom:** Table mode prints host/location/type/examples, intelligence summary (capabilities + candidates), probes — but **not** passive score, `name_categories`, `possible_*` flags, or evidence tokens.

**JSON note:** `get_parameter_profile` **does** attach `url_features` on the parameter object, so `show --format json` can expose it under `parameter.url_features` if the caller knows to look. Table mode and summary lines do not.

**Impact:** Primary operator command for IV does not show the Phase 1 inventory document without JSON + `jq`.

---

#### QA-USD-03 — Endpoint dossier export omits `url_features`

| | |
|--|--|
| **Area** | CLI display / export |
| **Severity** | High |
| **Where** | `talos/projects/endpoint_cli.py` — parameters `SELECT` / MD table |

**Symptom:** Export MD columns are Name | Location | Type | Seen | Reflected only. `url_features` is not selected or rendered (score, NRS, categories).

**Impact:** Best “whole endpoint” CLI artifact cannot be used for URL sink triage.

---

#### QA-USD-04 — IV export parameter path also drops `url_features` from SQL

| | |
|--|--|
| **Area** | CLI export |
| **Severity** | High |
| **Where** | `talos/input_validation/cli.py` — `_cmd_export_parameter` `SELECT` from `parameters` |

**Symptom:** Export `SELECT` columns are id, name, host, method, path, location, types, seen, examples, reflection — **no `url_features`**. Markdown export has no URL Sink section. JSON export’s `parameter` object therefore lacks inventory features even when the DB column is populated.

**Impact:** `talos input-validation export parameter …` cannot archive passive sink intelligence; only nested `profile.observed.url_features` if synthesize already merged it.

---

#### QA-USD-05 — `location=response` inventory params are IV-scheduled (not inventory-only)

| | |
|--|--|
| **Area** | IV engine / surface |
| **Severity** | High |
| **Where** | `engine._list_all_params` (no location filter); `surface.should_skip_param` (does not skip `response`); `inject_value` no-ops unknown locations |

**Symptom:** HTML/JS inventory rows use `location=response` (Phase 2). Plan/QA stated response inventory is **not** a request injection surface. Engine still lists them for IV. `should_skip_param(location="response", …)` → `skip=False`. `inject_value(location="response", …)` returns URL/headers/body **unchanged**.

**Impact:**

- Wasted IV budget / status noise on non-injectable params.
- Probes that do not mutate the request can look like “accepted” / baseline-identical outcomes if not carefully gated — risk of weak or misleading `observed` / canary synthesis depending on fingerprint path.
- Contradicts Phase 2 “by design: no IV of location=response”.

**Repro sketch:** Upsert HTML `redirect_url` at `location=response` on a qualified endpoint; run `input-validation run --endpoint …`; observe jobs for `response|redirect_url`.

---

#### QA-USD-06 — JWT virtual claim params (`jwt.jku`, etc.) are IV-scheduled as real headers

| | |
|--|--|
| **Area** | IV engine / surface / structure discovery |
| **Severity** | High |
| **Where** | Virtual params from `jwt_claims` (location=header, names `jwt.*`); `is_auth_artifact` / `should_skip_param`; `inject_value` header path |

**Symptom:** Plan: *JWT claim extraction is inventory-only; do not force IV mutation of production tokens by default.* Parent `authorization` is correctly skipped as auth artifact. Child virtuals `jwt.jku` / `jwt.iss` / `jwt.aud` are **not** skipped (`skip=False`). Inject adds a **literal HTTP header** named `jwt.jku` (etc.), not a mutated JWT claim inside `Authorization`.

**Impact:**

- False characterization: app never saw a claim rewrite; it saw an exotic header.
- Canaries/capabilities/candidates on `jwt.*` names can mislead operators.
- Plan inventory-only guarantee not enforced at scheduler boundary.

**Repro sketch:** Capture `Authorization: Bearer <jwt with jku>`; confirm `jwt.jku` row; run IV; inspect probe request headers for `jwt.jku: https://talos-canary.invalid/`.

---

#### QA-USD-07 — Phase 5 operator polish still open (umbrella)

| | |
|--|--|
| **Area** | Product completeness |
| **Severity** | High (gap, not a logic regression) |
| **Where** | Plan Phase 5 acceptance boxes still `[ ]` |

**Symptom:** Docs/`updates.md` explicitly mark CLI show/export polish as out of Phase 4. Combined with QA-USD-01–04, CLI is not a full operator surface for the feature as marketed in help/cheat-sheet narratives.

**Note:** This is expected unfinished work if Phase 5 was not claimed complete; called out because the user asked whether “the full thing” works on CLI.

---

### MEDIUM

#### QA-USD-08 — `window.__NEXT_DATA__ = {…}` assignment form never extracts

| | |
|--|--|
| **Area** | `talos/url_sink/html_js_extract.py` |
| **Severity** | Medium |
| **Where** | `_WINDOW_BOOTSTRAP` regex |

**Symptom:**

| Pattern | Result |
|---------|--------|
| `<script id="__NEXT_DATA__" type="application/json">…</script>` | Works |
| `window.__CONFIG__ = {…}` | Works |
| `window.__INITIAL_STATE__ = {…}` | Works |
| `window.__NEXT_DATA__ = {…}` | **Fails** (no candidates) |

**Root cause (analysis):** Alternation includes `__NEXT_DATA__` **after** `__?` has already consumed leading underscores, so the engine looks for a second `__NEXT_DATA__` and never matches. Plan lists `__NEXT_DATA__` as a first-class JS island.

**Impact:** Apps that embed Next data via assignment (not `id=` script tag) miss nested URL inventory (e.g. `props.pageProps.apiUrl`).

---

#### QA-USD-09 — Plan `url_sink.*` config knobs not implemented

| | |
|--|--|
| **Area** | Config |
| **Severity** | Medium |
| **Where** | Plan “Config & safety”; `talos/configuration/defaults.py` has no `url_sink` |

**Missing (per plan):**

- `url_sink.passive.enabled` (default true)
- `url_sink.html_js.enabled` (default true)
- `url_sink.iv_probes.enabled`
- `url_sink.score_threshold` (default 45)

**Impact:** Cannot disable HTML/JS inventory or IV canaries via config; threshold only hardcoded. Types analysis toggle is the only practical IV gate called out in docs.

---

#### QA-USD-10 — `candidates --help` attack list is stale

| | |
|--|--|
| **Area** | CLI help vs implementation |
| **Severity** | Medium |
| **Where** | `talos/input_validation/cli.py` argparse help for `--attack` |

**Symptom:** Help lists:

`xss, sqli, open_redirect, ssrf, hpp, header_injection, path_traversal, mass_assignment`

Omits **`webhook_abuse`** and **`oauth_redirect`**, which are in `KNOWN_ATTACKS` and work when passed. `docs/cli-cheat-sheet.md` documents them correctly.

**Impact:** Operators following `--help` will not discover new attack filters; may think Phase 4 attacks are missing.

---

#### QA-USD-11 — CLI never formats `observed.url_sink` canary aggregate

| | |
|--|--|
| **Area** | CLI display |
| **Severity** | Medium |
| **Where** | `format_profile_summary_lines`, IV show/export |

**Symptom:** After Phase 3 synthesize, `observed.url_sink` holds `accepts_*`, `redirect_behavior`, `fetch_behavior`, `error_classes`, `per_probe`, etc. Table summary may mention fragments only inside **candidate reason strings**, not a dedicated block. Docs suggest `show` for `observed.url_sink`, but table mode does not present it structurally.

**Impact:** Hard to distinguish “passive score only” vs “server processed canary” without raw JSON profile.

---

#### QA-USD-12 — Help/docs advertise inventory without a list command

| | |
|--|--|
| **Area** | CLI docs consistency |
| **Severity** | Medium |
| **Where** | `talos --help` endpoint section vs `talos endpoint --help` |

**Symptom:** Top-level help mentions parameter inventory + `url_features` under `endpoint list` prose. `endpoint --help` has no params-related command. Same gap as QA-USD-01, framed as documentation/UX mismatch.

---

#### QA-USD-13 — Soft `open_redirect` on non-redirect URL-accept params (operator noise)

| | |
|--|--|
| **Area** | Candidates |
| **Severity** | Medium (product tradeoff; Phase 4 QA called “by design”) |
| **Where** | `candidates.py` open_redirect scorer |

**Symptom:** Params like `abc` or `avatar` with type URL accept (no redirect name, no Location behavior) still emit `open_redirect` at scores ~50–64. Phase 4 QA notes this as pre-Phase-4 parity.

**Impact:** `talos input-validation candidates --attack open_redirect` is noisier than operators may expect; ranking relies on score comparison with redirect-named params (which reach ~100 with behavior).

**Classification:** Keep as issue for product review — not necessarily a regression vs Phase 4 QA decision.

---

### LOW

#### QA-USD-14 — `candidates --help` capability examples omit `network_resource_sink`

| | |
|--|--|
| **Severity** | Low |
| **Where** | `--capability` help examples: reflective_input, stored_reflection, html_context |

**Impact:** Filter works; discoverability only. Cheat-sheet documents it.

---

#### QA-USD-15 — `input-validation run --help` does not mention `url_sink_probes`

| | |
|--|--|
| **Severity** | Low |
| **Where** | argparse for `run` |

**Impact:** Operators may not know canaries run under types analysis when passive features warrant.

---

#### QA-USD-16 — Primary `name_category` for `redirect_url` is `oauth`, not `redirect`

| | |
|--|--|
| **Severity** | Low |
| **Where** | `catalog._PRIMARY_PRIORITY` (oauth before redirect) |

**Symptom:** `redirect_url` matches oauth + redirect + remote_fetch; primary is **oauth**. Scoring still uses full `name_categories` (open_redirect and oauth_redirect both fire with evidence).

**Impact:** Display/filters that only show primary category may label classic open-redirect params as oauth. Multi-category list is correct.

---

#### QA-USD-17 — Parent `cfg` form field remains in inventory at score 0

| | |
|--|--|
| **Severity** | Low |
| **Where** | Encoded unwrap still keeps outer field |

**Symptom:** Base64 JSON form field invents leaf `cfg.oauth.metadata.url` (good) but also keeps `cfg` with score 0 / non-NRS.

**Impact:** Minor inventory noise; not a network resource.

---

## Explicitly not treated as bugs (by design / prior QA)

| Behavior | Why |
|----------|-----|
| Opaque schemes without `://` (e.g. `javascript:alert(1)`) not auto-URL | Plan scope |
| Short catalog names (`go`, `to`, `next`) match name-only at score ≤ 30 | Inventory gate 45; candidate spam gates after Phase 4 QA |
| Name-only sinks do not invent `redirect_sink` / `webhook_sink` / candidates without measured URL evidence | Phase 4 QA fixes |
| Soft timing-only / timeout error class as fetch soft signal | Plan |
| Multiple attack labels on one param (ssrf + open_redirect + oauth) | Prioritization families |
| No Findings / no OAST confirmation | Explicit non-goal |
| Control Panel surfaces | Out of scope this QA |
| `url_like_value` alias when NRS | Compat contract |
| Passive `ssrf` at ~50 without type accept | Current scorer allows value-first emit; type accept raises further |

---

## CLI command matrix (operator path)

| Goal | Command | Works for URL Sink? |
|------|---------|---------------------|
| See inventory after capture | *(none)* | **No** dedicated command (QA-USD-01) |
| Endpoint dossier | `talos endpoint export …` | Params listed **without** `url_features` (QA-USD-03) |
| Param profile table | `talos input-validation show <param_uuid>` | Caps/candidates yes; **no** structured `url_features` / `url_sink` (QA-USD-02/11) |
| Param profile JSON | `… show <uuid> --format json` | `parameter.url_features` present if DB v53; dig manually |
| Export param MD/JSON | `… export parameter <uuid>` | Caps/candidates if synthesized; **parameter SELECT lacks url_features** (QA-USD-04) |
| List attacks | `… candidates --attack ssrf\|webhook_abuse\|…` | **Logic works**; help text incomplete (QA-USD-10) |
| Filter NRS | `… candidates --capability network_resource_sink` | **Works** |
| Run canaries | `… run` / types path | Warrant + enqueue present; inventory-only rows wrongly included (QA-USD-05/06) |

---

## Suggested fix priorities (for later — not done here)

1. **IV surface gates:** skip `location=response`; skip virtual `jwt.*` (and similar structure-only names) unless explicit opt-in; never inject synthetic claim headers.  
2. **Phase 5 CLI:** `endpoint params` list/show with score/NRS/category; table + export sections for `url_features` and `observed.url_sink`.  
3. **Help text:** align `--attack` / `--capability` with `KNOWN_ATTACKS` and NRS.  
4. **`_WINDOW_BOOTSTRAP`:** fix `__NEXT_DATA__` assignment match.  
5. **Config knobs** from plan if operators need kill-switches.

---

## Test evidence appendix

```text
.venv/bin/pytest tests/test_url_sink_*.py tests/test_iv_url_sink.py tests/test_iv_candidates.py -q
# 254 passed

Integration harness (temp project.db):
  extract/upsert 24 params across query/body/header/response
  abc score=95 NRS; jwt.jku; Link=99; HTML gate; score merge
  list_candidates webhook_abuse/oauth_redirect/ssrf/NRS filters green
```

Harness artifacts (ephemeral): under `/tmp/url_sink_qa_*/` when re-run.

---

## Verdict

| Question | Answer |
|----------|--------|
| Is URL Sink Discovery **implemented** for Phases 1–4 logic? | **Yes** — classifiers, inventory, canaries, capabilities, candidates largely match the plan and unit tests. |
| Does it **work end-to-end on Talos CLI** for an operator? | **Partially.** Filtering candidates works once IV profiles exist. **Browsing/exporting inventory and canary detail is incomplete (Phase 5).** |
| Are there **must-fix** issues before trusting IV on real captures? | **Yes:** do not trust IV results for `location=response` or `jwt.*` virtual params until QA-USD-05/06 are fixed. |

---

*Report generated as QA-only documentation. Fixes shipped 2026-07-31 — see
`docs/updates.md` “URL Sink Discovery Phase 5 + QA fix-up”.*
