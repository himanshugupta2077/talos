# Authentication & Session Testing Engine for Talos

| Field | Value |
|-------|-------|
| **Document** | Design: Authentication & Session Testing Engine |
| **Author** | Talos Engineering |
| **Date** | 2026-07-31 |
| **Status** | Phases 1–5 complete (v1 CLI + full JWT suite; Control Panel out of scope) |
| **Audience** | Senior engineers familiar with Talos attack modules |
| **Related** | `docs/architecture.md`, `docs/cli-cheat-sheet.md`, `AGENTS.md` |

---

## Overview

Talos today can **strip authentication** (`talos auth test` / Unauth) and **swap sessions across roles** (BAC), but it cannot systematically probe whether a presented credential is *actually validated* — signature, algorithm, claims, expiry, key id, and structural integrity. Authentication is one of the highest-impact attack surfaces, yet those checks are either missing or scattered across unauth techniques and passive JWT detectors.

This design introduces a dedicated **Authentication & Session Testing** engine (`talos attack auth-session`) that:

1. Binds configured auth artifacts (header/cookie names already in `auth_config`) to an **authentication type** (JWT first).
2. Generates a **deterministic, typed test suite** of token mutations (e.g. `alg=none`, algorithm degradation, claim elevation, corrupt signature).
3. Stores mutations as **attack candidates** with an explicit **operator approve → run** lifecycle.
4. For **each** approved testcase, sends a **new independent HTTP request/flow** (mutate that test only → replay → diff against the shared baseline). Mutations are never batched into one request.
5. Scores each response with **replay + structural diff + decision filter**, creating findings through the existing findings subsystem (each finding ties to that specific mutated flow).

No AI participates in the execution path for v1. The model never invents mutations at runtime; only predefined, reviewable test cases run.

---

## Background & Motivation

### Current state

| Capability | Location | What it tests |
|------------|----------|---------------|
| Authentication Bypass (`auth_test`) | `talos/replay/auth_strip.py`, `talos auth test` | Endpoint works with auth **removed** |
| Unauthenticated Execution | `talos/projects/unauth/` | Auth removed + empty/malformed/null/duplicate auth techniques + optional BAC request mutations |
| BAC | `talos/projects/bac/` | Lower-privilege role token injected into higher-privilege flows (session swap + HTTP mutations) |
| Passive JWT detector | `talos/passive/detectors/jwt.py` | Client-side **exposure** of compact JWT strings (secret inventory) |
| JWT claim inventory | `talos/url_sink/jwt_claims.py` | Passive extraction of URL-shaped claims (`jku`, `x5u`, `iss`, `aud`) without verification |
| Session health | `talos/projects/session_health.py`, `auth-config` | Role session TTL / expiry signals / control-flow probes (operational validity, not attack) |

### Pain points

1. **No token-integrity testing.** Unauth's `malformed_auth` replaces credentials with fixed garbage (`invalid_token_xyz_talos`); it does not exercise JWT parsers, `alg=none`, claim elevation, or `kid` injection.
2. **Auth type is implicit.** `auth_config` stores only `(type, name)` pairs — cookie vs header names — with no JWT / session / API-key classification for specialized suites.
3. **Finding signal is coarse.** `auth_test` verdicts `BYPASS` on any 200 after strip. For JWT, a secure app may return 200 with an error body, or accept a mutated token with equivalent body — operators need fingerprint-aware decisions.
4. **Extensibility.** Adding OAuth refresh-token or SAML checks into Unauth would blur module boundaries; a dedicated engine keeps analyzers modular.

### Product constraints (durable)

- Authorized pentest / bug-bounty tooling only; operator owns legal scope.
- Deterministic engines first; AI remains policy-gated suggest-first and **out of the v1 execution path**.
- Reuse scheduler, replay DB, diff engine, endpoint policy, findings, and auth config.
- CLI-first v1; Control Panel later.

---

## Goals & Non-Goals

### Goals

1. **G1 — Dedicated engine** for authentication/session validation with pluggable auth-type analyzers.
2. **G2 — JWT v1 suite** covering signature, **algorithm degradation / confusion** (relative to observed `alg`), structural, claim, and `kid` mutations listed in this document.
3. **G3 — Candidate lifecycle**: generate → list/show → approve/reject → run (scheduler jobs) → results/findings.
4. **G4 — Reuse infrastructure**: `replay_db`, `compute_diff`, `scheduler_jobs`, `endpoint_policy` (qualified/baseline/excluded), `get_upstream_url` / httpx, findings creator.
5. **G5 — Clear boundaries** vs `auth_test`, Unauth, BAC, and passive JWT detectors (see [Relation to Existing Modules](#relation-to-existing-modules)).
6. **G6 — Extensible auth-type registry** so Session Cookie / API Key / OAuth can land without redesign.

### Non-Goals (v1)

- No AI-planned mutations or freeform LLM payload generation.
- No cryptographic key recovery, brute-force of secrets, or offline JWT cracking.
- No full OAuth protocol attack graph (CSRF, redirect_uri, PKCE) — only token-structure tests when type is registered later.
- No Control Panel UI (CLI only).
- No automatic run on every captured flow; operator selects scope and approves candidates.
- No replacement of Session Health Engine (that remains operational session validity).
- No modification of Unauth recipes to absorb JWT suite (keep separation).
- No client-data redaction pipeline for this engine (consistent with product AI/auth rules).
- No `jku` / `x5u` / `x5c` / header-injection JWT suite in v1 (url_sink inventories those URL sinks separately; future suite rows only—see Future Authentication Types / suite backlog).
- No historical **reclassify / filter-apply** path in v1 (unlike Unauth/BAC). Operators who change `auth-session-decision-filter.yaml` must re-run candidates to rescore; optional follow-up after Phase 5.

---

## Relation to Existing Modules

```mermaid
flowchart TB
  subgraph capture [Capture & Auth Setup]
    Proxy[Proxy flows]
    AuthCfg["auth_config names"]
    RoleState["role_auth_state tokens"]
  end

  subgraph identity_tests [Identity / Auth Surface]
    AuthTest["auth_test<br/>strip all auth"]
    Unauth["unauth<br/>strip + empty/malformed techniques"]
    AuthSession["auth-session NEW<br/>mutate token structure"]
    BAC["bac<br/>swap role tokens"]
    PassiveJWT["passive JWT<br/>secret exposure"]
  end

  Proxy --> AuthTest
  Proxy --> Unauth
  Proxy --> AuthSession
  Proxy --> BAC
  Proxy --> PassiveJWT
  AuthCfg --> AuthTest
  AuthCfg --> Unauth
  AuthCfg --> AuthSession
  RoleState --> BAC
```

| Module | Question answered | Mutation of credential | Typical finding |
|--------|-------------------|------------------------|-----------------|
| **`talos auth test`** (`AUTH_TEST`) | Does this endpoint require any auth at all? | **Remove** configured cookies/headers | Authentication Bypass (`BYPASS` on 200) |
| **Unauth** (`UNAUTH_ATTACK`) | Can access be obtained without valid auth via empty/malformed/null/duplicate auth and request tricks? | Strip then re-inject **non-original** empty/malformed values; never restore original | Unauthenticated Execution (`BYPASS`) |
| **Auth-session (new)** | Given a *present* token, does the server validate signature/alg/claims/structure? | **Surgical mutation** of JWT (or future type) while keeping location | Auth/session weakness (`WEAK_VALIDATION` / type-specific) |
| **BAC** | Can role A access role B's resources using A's valid session? | Replace auth with **another role's valid token** + HTTP mutations | Broken Access Control (`POSSIBLE_BAC`) |
| **Passive JWT** | Is a JWT string exposed in JS/HTML/responses? | None (detection only) | Client-Side Secret Exposure |

**Important:** Unauth already has `malformed_auth`. That remains a coarse unauth technique. Auth-session is **not** a superset of Unauth; it answers a different security property (token *validation* vs *presence*). Overlap is intentional and complementary — findings use distinct `attack_type` / cluster keys so triage stays clear.

---

## Key Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| **KD1** | Package at **`talos/auth_session/`** (top-level, like `input_validation/`, `intruder/`). **Naming note:** distinct from `Project.auth_session_path()` / `data_dir/auth_sessions/` (manual role session files for `auth-config`). Package = attack engine; CLI remains `talos attack auth-session`. | Substantial JWT mutation library + multi-type registry; not tightly coupled to access matrix (unlike BAC). Avoids further growth of `talos/projects/`. Docs must call out the homonym so imports are not confused with role session files. |
| **KD2** | CLI surface: **`talos attack auth-session …`** | Matches `talos attack unauth` / `talos attack bac`. Not `talos auth-session` (avoids clash with `talos auth` / `auth-config`). |
| **KD3** | Auth type stored in new **`auth_session_bindings`** table, not by overloading `auth_config` | `auth_config` is name-only and shared by strip/BAC/unauth; adding type there would force all consumers to understand types. Bindings reference `(location, name)` already in `auth_config`. See Alternatives E/F. |
| **KD4** | Candidate table with **pending / approved / rejected / running / done / failed** lifecycle | Explicit operator approval is a product requirement for this engine; unauth's "run enqueues all" is too aggressive for claim-elevation tests. |
| **KD5** | JWT mutations via **stdlib only** (`base64`, `json`) in v1 — no PyJWT/python-jose; no `hmac`/`hashlib` until optional pubkey-HMAC mutator | We never *verify* tokens; we *construct* invalid ones. Avoids crypto-library version churn. Reuse `extract_jwt_token` + `decode_jwt_payload` from `url_sink.jwt_claims`; **implement header decode + encode in `jwt_codec`** (do not expand url_sink). |
| **KD6** | Job type: single **`auth_session_attack`** with **one `test_id` per job** in `meta` | Matches unauth's single `unauth_attack` + meta pattern; each job executes exactly one mutation and one outbound request. |
| **KD7** | Verdict: **`WEAK_VALIDATION` \| `SECURE` \| `UNKNOWN`** with default rule: 2xx **and** `diff_verdict == SAME` → `WEAK_VALIDATION`; 401/403/3xx or filter-passed → `SECURE` | Stricter than `auth_test` (which BYPASS on any 200). Auth-session cares that the *same authorized resource* was returned with a broken token. See Detection semantics vs `compute_diff`. |
| **KD8** | Baseline selection: prefer **operator `--flow`**, else **endpoint_policy.baseline_flow_id**, else `get_best_flow_for_endpoint` | Aligns with unauth baseline usage and endpoint policy authority. |
| **KD9** | One candidate row per **(binding × testcase × baseline flow)**; generate is **insert-if-absent** | Enables per-mutation approve/reject and precise evidence. No silent rewrite of done/approved rows. |
| **KD10** | Finding cluster: **`AUTH_SESSION:<endpoint_id>:<auth_type>`** via extended `build_cluster_key(..., auth_type=)`. Titles via **`findings_bridge` + optional `title=` on creator** (not `variant=` alone). | Groups JWT weaknesses per endpoint; primary/linked across mutations. Each finding references the **specific mutated replay flow**. See Findings checklist item 5. |
| **KD11** | No auto-enqueue on proxy capture in v1 | Operator-driven only; optional auto later behind config flag (out of v1 scope). |
| **KD12** | Decision filter file: **`auth-session-decision-filter.yaml`** (project data dir), same schema shape as unauth/BAC filters | Operator-tunable SECURE/WEAK patterns without code changes. No reclassify in v1. |
| **KD13** | **Phased delivery** (3–5 phases, multi-PR each) sized for one AI implementation session per phase | Operator asks “implement Phase N”; each phase leaves a coherent, testable slice; phases merge in order. |
| **KD14** | **One outbound HTTP flow per testcase** — never batch mutations into one request; never reuse one mutated request across multiple tests | Clean evidence: each `auth_session_results.replay_flow_id` maps 1:1 to one `test_id` / candidate / scheduler job execution unit. |
| **KD15** | **Algorithm degradation family** expands from observed original `alg` into many deterministic `test_id`s (not a single HS↔RS swap). **Degradation never emits pure `to_none`** — core `jwt.alg_none*` owns none | Avoids double-coverage with fixed none rows; still covers HS* confusion and strength downgrades. |
| **KD16** | **Findings created in scheduler settle**, not deep inside the engine (match Unauth/BAC) | Engine returns `AuthSessionOutcome` and may persist `auth_session_results`; scheduler settles job/candidate + `_maybe_create_finding_*`. Prevents double findings. |
| **KD17** | Duplicate job detection uses a **dedicated meta-aware helper** (not `has_pending_duplicate`) | Generic helper ignores `meta.test_id`; pattern follows unauth `_has_pending_unauth_duplicate` + `json_extract`. |

---

## Proposed Design

### High-level architecture

```mermaid
flowchart LR
  CLI["talos attack auth-session"]
  Bind["auth_session_bindings"]
  Gen["generators / JWT suite"]
  Cand["auth_session_candidates"]
  Sched["scheduler_jobs<br/>auth_session_attack"]
  Eng["auth_session.engine"]
  Mut["jwt_mutate"]
  Replay["httpx + replay_db"]
  Diff["compute_diff"]
  DF["decision filter"]
  Res["auth_session_results"]
  Settle["scheduler settle"]
  Find["findings.creator"]

  CLI --> Bind
  CLI --> Gen
  Gen --> Cand
  CLI -->|approve/run| Sched
  Sched --> Eng
  Eng --> Mut
  Eng --> Replay
  Replay --> Diff
  Diff --> DF
  DF --> Res
  Eng --> Res
  Eng -->|AuthSessionOutcome| Settle
  Sched --> Settle
  Settle --> Find
```

### Package layout

```text
talos/auth_session/          # ATTACK ENGINE package — not Project.auth_session_path()
  __init__.py          # public exports; docstring notes naming vs auth_sessions/ dir
  models.py            # AuthType, Binding, Candidate, TestCase, Outcome dataclasses
  types.py             # AuthType registry (jwt, …) + interface AuthTypeAnalyzer
  db.py                # bindings / candidates / results CRUD
  config.py            # defaults, suite enable/disable, claim-elevation config
  extract.py           # locate JWT/token; preserve scheme separately from extract_jwt_token
  jwt_codec.py         # decode_jwt_header + encode + split/join (stdlib base64/json)
  jwt_mutate.py        # pure mutation functions → MutatedToken
  suite_jwt.py         # catalog + alg_degradation_tests (none-skip rule)
  candidates.py        # generate candidates for binding + baseline flow(s)
  engine.py            # execute_auth_session_job (no findings)
  decision_filter.py   # load/eval auth-session-decision-filter.yaml
  verdict.py           # combine status + diff + filter → WEAK_VALIDATION|SECURE|UNKNOWN
  findings_bridge.py   # builds title; create_finding_from_verdict(..., title=) from settle only
  cli.py               # argparse subcommands under attack auth-session
  # optional: has_pending_auth_session_duplicate in cli.py or db.py

# wiring (existing modules)
talos/projects/attack_cli.py   # register auth-session subparser
talos/scheduler/job.py         # AUTH_SESSION_ATTACK constant
talos/scheduler/scheduler.py   # dispatch branch
talos/findings/model.py        # VERDICT_TRIGGERS + ATTACK_DISPLAY + evidence type
talos/projects/db.py           # schema v54 migration
```

**Not under `talos/projects/`** for the reasons in KD1. Shared project concerns (auth names, endpoint policy, proxy upstream) are imported, not reimplemented.

### Auth-type analyzer interface

```python
# talos/auth_session/types.py (sketch)

from dataclasses import dataclass
from typing import Protocol, Any

@dataclass(frozen=True)
class TestCaseDef:
    test_id: str           # stable: "jwt.alg_none"
    title: str
    family: str            # signature | algorithm | algorithm_degrade | structure | claims | kid
    description: str
    risk_hint: str         # critical | high | medium | low
    requires_claims: tuple[str, ...] = ()  # e.g. ("role",) for elevation

@dataclass(frozen=True)
class TokenContext:
    raw_token: str         # compact JWT without scheme
    scheme: str | None     # "Bearer" | None
    header: dict[str, Any]
    payload: dict[str, Any]
    location: str          # "header" | "cookie"
    field_name: str        # "Authorization" | "session"
    original_header_value: str  # full value including scheme if any

@dataclass(frozen=True)
class MutatedToken:
    test_id: str
    new_raw_token: str
    new_header_or_cookie_value: str  # scheme re-applied if needed
    mutation_summary: str            # human + machine readable
    metadata: dict[str, Any]

class AuthTypeAnalyzer(Protocol):
    auth_type: str  # "jwt"

    def detect(self, raw_value: str) -> TokenContext | None:
        """Return context if value matches this auth type; else None."""
        ...

    def list_test_cases(self, ctx: TokenContext, config: dict) -> list[TestCaseDef]:
        """Deterministic suite filtered by config + available claims."""
        ...

    def apply(self, ctx: TokenContext, test_id: str, config: dict) -> MutatedToken:
        """Produce mutated token; raise if test_id unknown or inapplicable."""
        ...
```

Registry:

```python
ANALYZERS: dict[str, AuthTypeAnalyzer] = {
    "jwt": JwtAnalyzer(),
    # future: "session_cookie", "api_key", "oauth_access", ...
}
```

### Configuration model

#### Bindings (`auth_session_bindings`)

Operators already run `talos auth set --header Authorization` (or cookie names). Auth-session **binds** those names to a type:

```bash
talos attack auth-session bind \
  --type jwt \
  --header Authorization \
  --role admin          # optional: prefer this role's flows / claim elevation defaults

talos attack auth-session bind --type jwt --cookie access_token
talos attack auth-session unbind --header Authorization
talos attack auth-session show-bindings
```

Preconditions:

- Binding field must exist in `auth_config` (same names Unauth/BAC strip). If missing, CLI suggests `talos auth set`.
- At generate time, selected baseline flow must contain a detectable token for that binding.

Optional per-binding JSON config (stored on row):

```json
{
  "claim_elevation": {
    "role": ["user", "admin"],
    "roles": ["user", "admin"],
    "is_admin": [false, true],
    "scope": ["read", "admin"]
  },
  "enabled_families": ["signature", "algorithm", "algorithm_degrade", "structure", "claims", "kid"],
  "disabled_tests": ["jwt.huge_kid", "jwt.alg_degrade.rs256_to_ps256"],
  "scheme_preserve": true
}
```

Notes: family `algorithm` covers fixed rows (`none` casings, empty/missing/unknown); family `algorithm_degrade` covers the observed-alg expansion matrix (`jwt.alg_degrade.*`). Default claim-elevation pairs apply when claims exist in payload; if claim absent, that testcase is **skipped at generation** (not failed at run).

#### Suite defaults (`config.py`)

Project-level optional overrides via `attack_config` key or dedicated JSON file under project data dir (`auth-session-config.yaml`). v1 can keep suite constants in code + binding JSON only.

### JWT test suite (v1)

Each testcase is deterministic. Mutators operate on decoded header/payload dicts and re-encode with base64url (no padding), then reassemble `header.payload.signature`.

#### Core catalog (non-algorithm families + fixed algorithm rows)

| `test_id` | Family | Mutation |
|-----------|--------|----------|
| `jwt.alg_none` | algorithm | Set `alg` to `none`; empty or stripped signature (core owns none — not degradation) |
| `jwt.alg_None` | algorithm | `alg=None` casing variant |
| `jwt.alg_NONE` | algorithm | `alg=NONE` casing variant |
| `jwt.alg_none_empty_sig` | algorithm | `alg=none`, signature segment empty string |
| `jwt.alg_empty` | algorithm | `alg=""` (empty string) |
| `jwt.alg_missing` | algorithm | Delete `alg` header claim |
| `jwt.alg_unknown` | algorithm | `alg` set to unknown string (e.g. `TalosFakeAlg`) |
| `jwt.invalid_signature` | signature | Flip last N chars of signature |
| `jwt.missing_signature` | structure | Two-part token `h.p` (no third segment) |
| `jwt.empty_payload` | structure | Payload `{}` |
| `jwt.empty_header` | structure | Header `{}` (or minimal) |
| `jwt.corrupted_b64` | structure | Break base64url in payload segment |
| `jwt.remove_exp` | claims | Delete `exp` |
| `jwt.exp_far_future` | claims | Set `exp` to far future |
| `jwt.exp_past` | claims | Set `exp` to past (optional; often SECURE — still useful signal) |
| `jwt.remove_nbf` | claims | Delete `nbf` |
| `jwt.remove_iss` | claims | Delete `iss` |
| `jwt.remove_aud` | claims | Delete `aud` |
| `jwt.modify_sub` | claims | Change `sub` to alternate value from config or suffix `-talos` |
| `jwt.elevate_role` | claims | Apply claim_elevation map (role/user→admin etc.) |
| `jwt.duplicate_claim_role` | claims | JSON payload with duplicated key via raw segment craft (where feasible) |
| `jwt.invalid_kid` | kid | Random `kid` |
| `jwt.empty_kid` | kid | `kid=""` |
| `jwt.huge_kid` | kid | `kid` of ~8–16 KiB (size capped) |

The single historical “wrong algorithm HS↔RS” row is **superseded** by the algorithm-degradation family below (which includes cross-family swaps and more).

#### Algorithm degradation / algorithm confusion family

**Intent:** If the original JWT uses a strong (or any) algorithm, systematically try weaker, alternate, or confusing algorithms and see whether the server still accepts the mutated token.

**Behavior (non-negotiable product rules):**

1. **Detect** the original `alg` from the JWT header at generate time (`TokenContext.header["alg"]`).
2. **Generate a set** of deterministic algorithm-degradation mutations **relative to that observed `alg`** — not a single fixed swap, and not a blind full cross-product spam for every token.
3. Each algorithm variant is its **own `test_id`** and therefore its own candidate, job, outbound flow, and result row.
4. The **full matrix is documented** in code/docs as the catalog source; `list_test_cases(ctx)` **filters** to the applicable subset for the observed alg.

##### Product rule: `alg=none` ownership (no double-coverage)

**Rule (KD15):** Core fixed rows own **all pure `none` acceptance probes**. Degradation **must not** emit `to_none` targets.

| Owner | `test_id`s | Mutation focus |
|-------|------------|----------------|
| **Core (algorithm family)** | `jwt.alg_none`, `jwt.alg_None`, `jwt.alg_NONE`, `jwt.alg_none_empty_sig` | `alg` → none casings; empty-sig sibling |
| **Core (algorithm family)** | `jwt.alg_empty`, `jwt.alg_missing`, `jwt.alg_unknown` | empty / missing / garbage `alg` |
| **Degradation (`algorithm_degrade`)** | `jwt.alg_degrade.<from>_to_<to>` where `<to>` ∉ {`none`, `empty`, `missing`, `unknown`} | Cross-family and strength changes only (HS*, RS*, ES*, PS* targets) |

Encoded in `alg_degradation_tests(original_alg)`: filter out any target that normalizes to `none` / empty / missing / unknown. Unit test must assert that for `RS256`, generate includes `jwt.alg_none` (from core) and **does not** include `jwt.alg_degrade.rs256_to_none`.

**Naming convention:**

```text
jwt.alg_degrade.<from>_to_<to>
```

Examples: `jwt.alg_degrade.rs256_to_hs256`, `jwt.alg_degrade.rs512_to_rs256`, `jwt.alg_degrade.es256_to_hs256`.  
**Not emitted:** `jwt.alg_degrade.rs256_to_none` (covered by core `jwt.alg_none*`).

Normalize `from`/`to` to lowercase alnum (`rs256`, `hs256`, …).

**Catalog source matrix (by original `alg` family)** — full product matrix; Phase 1 uses the frozen subset table below:

| Observed `alg` | Degradation targets (`to_*`, each → own `test_id`) — **excludes none/empty/missing/unknown** |
|----------------|------------------------------------------------------|
| **RS256 / RS384 / RS512** | `HS256`, `HS384`, `HS512`; same-family **downgrade** when stronger (RS512→RS384, RS512→RS256, RS384→RS256); cross-family `ES256`, `PS256` (Phase 5 may add more) |
| **ES256 / ES384 / ES512** | `HS256`/`HS384`/`HS512`; same-family downgrade chain; optional RS*/PS* cross-family |
| **PS256 / PS384 / PS512** | Same pattern as RS*: HS*, same-family downgrade, optional ES*/RS* |
| **HS256 / HS384 / HS512** | Wrong HS family (e.g. HS256→HS512); **upgrade-to-asymmetric** without real key (HS→RS256 / ES256) — server **must** reject |
| **none / empty / missing / unknown / other** | Degradation: `HS256`, `RS256` only (force non-none algs). Core fixed rows still apply for none/empty/missing/unknown |

**Signing / signature policy for degradation mutators (v1) — hard rule:**

- Do **not** require real private keys or public-key material for generation.
- Degradation mutators **never change the signature segment** in v1:
  1. Rewrite header `alg` to target; re-encode header segment.
  2. Keep payload segment unchanged.
  3. **Keep original signature bytes byte-for-byte.**
- Structural suite owns signature-segment mutations: `jwt.invalid_signature`, `jwt.missing_signature`, `jwt.alg_none_empty_sig` (empty sig only for core none-empty-sig).
- No empty-sig / random-sig **siblings** under `jwt.alg_degrade.*` in v1 (removes sibling explosion).
- Classic “HMAC with public key as secret” is **out of scope** for v1 (no key harvest). Optional later: binding config public key PEM + `hmac`/`hashlib` mutator—not Phase 1–5 exit.

##### Phase 1 mandatory degradation targets (frozen for implementers)

`alg_degradation_tests(original_alg)` **must** emit exactly these `to` targets for Phase 1 (plus core fixed algorithm rows always):

| Observed `alg` (normalized) | Phase 1 required `jwt.alg_degrade.<from>_to_*` targets |
|-----------------------------|--------------------------------------------------------|
| `rs256` | `hs256`, `hs384`, `hs512` |
| `rs384` | `hs256`, `hs384`, `hs512`, `rs256` |
| `rs512` | `hs256`, `hs384`, `hs512`, `rs256` |
| `es256` | `hs256`, `hs384`, `hs512` |
| `es384` | `hs256`, `hs384`, `hs512`, `es256` |
| `es512` | `hs256`, `hs384`, `hs512`, `es256` |
| `ps256` / `ps384` / `ps512` | `hs256`, `hs384`, `hs512` (treat like RS family for Phase 1) |
| `hs256` | `hs512`, `rs256` |
| `hs384` | `hs256`, `hs512`, `rs256` |
| `hs512` | `hs256`, `rs256` |
| `none` / empty / missing / unknown / other | `hs256`, `rs256` only |

**Phase 5 completes:** same-family full downgrade chains not listed above (e.g. RS512→RS384), additional cross-family edges (`rs256_to_es256`, `rs256_to_ps256`, `es256_to_rs256`, …), PS* parity with RS*.

**Generation example (original `alg=RS256`):**

| `test_id` | Source |
|-----------|--------|
| `jwt.alg_none`, `jwt.alg_None`, `jwt.alg_NONE`, `jwt.alg_none_empty_sig` | Core |
| `jwt.alg_empty`, `jwt.alg_missing`, `jwt.alg_unknown` | Core |
| `jwt.alg_degrade.rs256_to_hs256` | Degradation Phase 1 |
| `jwt.alg_degrade.rs256_to_hs384` | Degradation Phase 1 |
| `jwt.alg_degrade.rs256_to_hs512` | Degradation Phase 1 |
| `jwt.alg_degrade.rs256_to_es256` | Degradation Phase 5 (full matrix) |
| `jwt.alg_degrade.rs256_to_ps256` | Degradation Phase 5 (full matrix) |

#### Implementation notes for mutations

- Preserve `Bearer ` (or detected scheme) prefix when rewriting `Authorization`. `extract_jwt_token` already strips `Bearer`/`Token` schemes—`jwt_codec` / `extract.py` must capture scheme separately for `scheme_preserve`.
- Cookie values: write compact JWT only (no scheme).
- Duplicate claims: standard `json.dumps` cannot emit duplicate keys; craft payload segment by string concatenation of JSON fragments for `jwt.duplicate_claim_role` only.
- Algorithm family: **one concrete token per `test_id`**; never pack multiple alg attempts into one request.
- Degradation: header `alg` rewrite only; **signature segment unchanged**.

**JWT codec reuse (precise):**

| Capability | Source |
|------------|--------|
| Strip scheme + detect compact JWT | `talos.url_sink.jwt_claims.extract_jwt_token` |
| Decode **payload** dict | `talos.url_sink.jwt_claims.decode_jwt_payload` |
| Decode **header** dict (needed for `alg`) | **`talos.auth_session.jwt_codec.decode_jwt_header`** (new; url_sink has no header decode) |
| Encode header/payload segments + reassemble | **`jwt_codec`** (new; do **not** expand url_sink responsibilities) |
| Passive JWT detector | Orthogonal (exposure only); do not use for mutations |

Helper: `suite_jwt.alg_degradation_tests(original_alg: str) -> list[TestCaseDef]` used by `JwtAnalyzer.list_test_cases` — implements the **full** product degradation matrix (Phase 5) + none-skip rule.

### Candidate lifecycle

```mermaid
stateDiagram-v2
  [*] --> pending: generate
  pending --> approved: approve
  pending --> rejected: reject
  approved --> running: scheduler job claim
  running --> done: settle success
  running --> failed: settle error
  failed --> approved: approve retry
  done --> approved: approve re-test
  rejected --> pending: force-refresh
  approved --> pending: unapprove optional
```

**Status ownership (implementer-ready):**

| Transition | Owner | When |
|------------|-------|------|
| `pending` → `approved` | CLI `approve` | From **`pending`** |
| `failed` → `approved` | CLI `approve` (or `approve --retry-failed`) | Re-run path; then operator runs `run` again |
| `done` → `approved` | CLI `approve` | Explicit re-test; new job + new flow (KD14) |
| `pending` → `rejected` | CLI `reject` | `pending` only (v1) |
| `approved` → `running` | **Scheduler** when it claims/starts the job (before engine) | Not CLI |
| `running` → `done` / `failed` | **Scheduler settle** after engine returns | Not engine |

`run` enqueues only candidates with status **`approved`**. No separate `run --retry-failed` is required: re-approve `failed`/`done`, then `run`. Optional convenience: `approve --retry-failed` expands to all `failed` in scope.

#### Generation algorithm

```text
inputs:
  project_id, binding_id | all bindings
  scope: --endpoint | --flow | --module | (default: all testable endpoints with baseline)
  optional: --role, --test-id filter

for each binding:
  analyzer = ANALYZERS[binding.auth_type]
  for each baseline flow in scope:
    if endpoint not testable (policy): skip
    token_value = extract from flow at binding location/name
    ctx = analyzer.detect(token_value)
    if ctx is None: record skip reason; continue
    for test in analyzer.list_test_cases(ctx, binding.config):
      key = (binding_id, test.test_id, flow_id)
      apply generate insert rules (below)
```

**Token values are not stored in candidate rows** beyond a short fingerprint/prefix for display. Full original token remains only in the source flow (already captured). Mutated tokens live on replay flows after execution.

##### Generate / regenerate / unbind rules (deterministic)

**Generate (default — insert-if-absent):**

| Existing row status | Default `generate` behavior |
|---------------------|-----------------------------|
| *none* | INSERT `pending` with current suite metadata |
| `pending` | **Skip** (do not overwrite) |
| `rejected` | **Skip** (preserve operator reject; use `--force-refresh` to reopen) |
| `approved` | **Skip** |
| `running` | **Skip** |
| `done` / `failed` | **Skip** (historical evidence kept; unique key blocks re-insert) |

**`--force-refresh` (optional flag on `generate`):**

- Allowed only for statuses `pending` or `rejected`.
- Resets row to `pending`, refreshes `mutation_summary` / title / risk_hint / meta from current suite catalog, clears `reject_reason`.
- **Never** touches `approved`, `running`, `done`, or `failed`.

**New suite test_ids (e.g. Phase 5 matrix completion):** insert-if-absent creates **new** pending rows for new `(binding_id, test_id, baseline_flow_id)` keys only. Existing `done` rows are not rewritten.

**Method safety on generate (default):**

- Prefer baselines with safe methods: **GET / HEAD / OPTIONS**.
- If selected baseline method is POST/PUT/PATCH/DELETE (or other non-safe), **warn on stderr** and **skip** that flow/endpoint unless `--include-unsafe-methods` is set.
- Claim-elevation tests remain operator-gated via approve; built-in elevation map is the v1 default when claims exist (Open Q #1 **decided**).

**Unbind rules:**

| Condition | Behavior |
|-----------|----------|
| Binding has candidates in `approved` or `running` | **Refuse** unbind; print counts; operator must reject/cancel first |
| Binding has only `pending` / `rejected` candidates | Optionally cascade: set those candidates to `rejected` with reason `binding_unbound`, then delete binding; or require `--force` to cascade-reject pending |
| Binding has `done` / `failed` candidates or any `auth_session_results` rows | **Refuse** hard delete of binding (`ON DELETE RESTRICT`); operator may `unbind --archive` later (v1: refuse with message that results exist) |
| No candidates/results | DELETE binding |

FK: `auth_session_candidates.binding_id` → `auth_session_bindings(id)` **`ON DELETE RESTRICT`**. Results do not FK-delete bindings.

#### Approve / run

```bash
# Review
talos attack auth-session candidates list [--status pending] [--endpoint UUID] [--test-id ID] [--family FAM]
talos attack auth-session candidates show <candidate_id>

# Approve subset (IDs and/or filters)
talos attack auth-session approve <id> [<id>...]
  # also accepts failed/done ids for re-test → approved
talos attack auth-session approve --all-pending [--endpoint UUID] [--test-id ID ...] [--family FAM]
talos attack auth-session approve --retry-failed [--endpoint UUID] [--test-id ID ...] [--family FAM]
talos attack auth-session reject <id> [<id>...] [--reason "..."]
talos attack auth-session reject --all-pending [--endpoint UUID] [--test-id ID ...] [--family FAM] [--reason "..."]

# Enqueue approved only (same filters as approve where noted)
talos attack auth-session run [--endpoint UUID] [--candidate <id> ...] [--test-id ID ...] [--family FAM]
# optional immediate path for debugging:
talos attack auth-session run --candidate <id> --right-now
```

**Filter semantics for `approve` / `reject` / `run`:**

| Flag | Effect |
|------|--------|
| positional `<id>...` | Exact candidate UUIDs |
| `--all-pending` | All `pending` (approve/reject only); ignored on run |
| `--endpoint UUID` | Restrict to endpoint |
| `--test-id ID` | Repeatable; match candidate `test_id` (e.g. `jwt.alg_none`) |
| `--family FAM` | Repeatable; match `test_family` (`algorithm`, `algorithm_degrade`, `claims`, …) |
| `--candidate ID` | Run only these approved candidate UUIDs (run only) |

When both IDs and filters are present: **union** of matches, still constrained to allowed status:

| Command | Allowed source statuses |
|---------|-------------------------|
| `approve` | `pending`, **`failed`**, **`done`** (re-test) → `approved` |
| `approve --all-pending` | `pending` only |
| `approve --retry-failed` | all `failed` in scope → `approved` |
| `reject` | `pending` only |
| `run` | `approved` only |

`run` enqueues `auth_session_attack` jobs with scheduler row:

| Job column | Value |
|------------|--------|
| `job_type` | `auth_session_attack` |
| `flow_id` | baseline flow UUID |
| `endpoint_id` | endpoint UUID (when known) |
| `priority` | `PRIORITY_MANUAL` (same as unauth run) |
| `meta` (JSON) | see below |

```json
{
  "candidate_id": "...",
  "binding_id": "...",
  "auth_type": "jwt",
  "test_id": "jwt.alg_none",
  "test_family": "algorithm",
  "baseline_flow_id": "...",
  "endpoint_id": "..."
}
```

**Duplicate suppression (KD17):** Do **not** use `sched_db.has_pending_duplicate` alone (it matches only `job_type` + optional endpoint/flow and **ignores meta**). Implement:

```python
def has_pending_auth_session_duplicate(
    db_path: Path,
    *,
    flow_id: str,
    test_id: str,
    binding_id: str,
) -> bool:
    """True if pending/running auth_session_attack exists with same
    flow_id + meta.test_id + meta.binding_id (json_extract), mirroring
    unauth _has_pending_unauth_duplicate."""
```

Skip enqueue when that returns true.

**Scheduler / job model:** `run` enqueues **one `auth_session_attack` job per approved candidate** (hence per `test_id`). There is no multi-mutation job. N approved tests ⇒ N jobs ⇒ N independent outbound requests ⇒ N result rows.

### Execution pipeline

**Critical execution model (non-negotiable):** For **each** technique/testcase, Talos sends a **new independent HTTP request/flow** via existing replay infrastructure.

- Do **not** batch mutations into one request.
- Do **not** reuse a single mutated request across multiple tests.
- Pipeline per approved candidate:

```text
shared baseline request (original_flow_id)
        │
        ▼
for each approved candidate independently:
        mutate JWT for THAT test_id only
        → send as a NEW flow (new replay_flow_id)
        → compute_diff(baseline, this_replay)
        → store auth_session_results row (1:1 with this flow)
        → optional finding tied to this replay_flow_id
```

Mirrors BAC/Unauth engines for a **single** job unit. **Responsibility split (KD16):**

| Layer | Responsibility |
|-------|----------------|
| **Engine** `execute_auth_session_job` | Load, mutate, send, insert replay flow + diff + **`auth_session_results`**, compute verdict, return `AuthSessionOutcome` (do **not** create findings; do **not** mark scheduler job terminal state) |
| **Scheduler** `_settle_auth_session_outcome` | Mark job done/failed/skipped; update candidate `running`→`done`/`failed`; call `_maybe_create_finding_auth_session` when verdict is `WEAK_VALIDATION` |

```text
# Engine
1. Load candidate + baseline flow (replay_db.get_flow_for_replay)
2. Endpoint policy re-check (qualified, not excluded/logout/dangerous)
3. Load binding; extract token; rebuild TokenContext
4. analyzer.apply(ctx, test_id) → MutatedToken   # exactly one test_id
5. Apply mutation to request headers/cookies only (no other field changes)
6. httpx send (no redirects, no retries, 30s timeout, project upstream)
   → one new outbound request; insert as new flow
7. insert_replayed_flow + insert_replay_diff     # this flow only
8. insert_auth_session_result                    # 1:1 with replay_flow_id
9. verdict via decision filter + status/diff rules (pure function)
10. return AuthSessionOutcome(verdict, ids, failure_reason, ...)

# Scheduler settle (after engine returns)
11. mark candidate done/failed; mark job terminal
12. if WEAK_VALIDATION and not failure: findings_bridge / create_finding_from_verdict
```

Hard constraints (same family as BAC/Unauth, plus auth-session specifics):

- No retries; redirects disabled.
- Do not mutate non-owned fields.
- Re-check endpoint policy at execution time.
- Original credential must **not** be used unchanged (invariant assert after mutation).
- **One outbound flow per candidate/testcase** (KD14); engine must not loop multiple `test_id`s inside one job.

### Detection / verdict

```mermaid
flowchart TD
  A[Replay response] --> B{Network error / timeout / no status?}
  B -->|yes| U[UNKNOWN]
  B -->|no| C{Filter file present?}
  C -->|yes| D{failed_detection match?}
  D -->|yes| W[WEAK_VALIDATION]
  D -->|no| E{passed_detection match?}
  E -->|yes| S[SECURE]
  E -->|no match| H[Heuristic]
  C -->|no file| H
  H --> F{Status 401/403/407 or 3xx?}
  F -->|yes| S
  F -->|no| G{Status 2xx AND diff SAME?}
  G -->|yes| W
  G -->|no| U
```

**Exact engine order (do not copy unauth blindly):**

1. If replay error / timeout / missing status → `UNKNOWN` (never open filter).
2. If `auth-session-decision-filter.yaml` **exists** and loads: evaluate `failed_detection` first → `WEAK_VALIDATION`; then `passed_detection` → `SECURE`.
3. If filter **absent**, **load error**, **or no section matched** → **fall through to heuristic** (status + `compute_diff`). This differs from unauth, which often returns UNKNOWN when a filter file exists but nothing matches—auth-session **always** applies heuristic as fallback so SAME-body accepts are not lost.

**v1 heuristic:**

| Condition | Verdict |
|-----------|---------|
| Replay error / timeout | `UNKNOWN` |
| Status ∈ {401, 403, 407} or 3xx | `SECURE` |
| Status 2xx (incl. **204**) **and** `diff_verdict == SAME` | `WEAK_VALIDATION` |
| Status 2xx **and** `diff_verdict == DIFFERENT` | `UNKNOWN` |
| Status 5xx | `UNKNOWN` |
| Other | `UNKNOWN` |

**Rationale for SAME requirement:** Accepting a broken JWT with a 200 error body is not the same as authorization success. Unauth's BYPASS-on-2xx is intentionally looser for "no auth at all" tests. Auth-session requires evidence the **authorized baseline resource** was still served.

#### Detection semantics vs real `compute_diff`

`talos.replay.diff.compute_diff` is **coarse** (by design for all attack modules). `SAME` is **not** full-body equality. It returns `DIFFERENT` only when:

- status code changed, or
- body length delta exceeds **max(500 bytes absolute, 20% of original)**, or
- both bodies are JSON and **top-level key sets** differ.

| Class | Effect on auth-session | Notes |
|-------|------------------------|-------|
| **False WEAK_VALIDATION** | Small body drift (timestamps, request ids, CSRF) within 500B/20% + same JSON keys → `SAME` → finding | Operator triage; decision filter `passed_detection` body patterns can force SECURE |
| **False UNKNOWN (miss)** | Invalid JWT returns 200 + short error envelope that changes length or top-level keys → `DIFFERENT` → UNKNOWN | Document for operators; filter `failed_detection` can force WEAK if envelope still proves access; optional v1.1 fingerprint |
| **204 / empty 2xx** | Empty vs empty → `SAME` if baseline also empty → WEAK_VALIDATION is intentional (server accepted request) | Call out in suite docs |
| **Non-JSON HTML soft-fail** | Large error page → DIFFERENT → UNKNOWN; small “Unauthorized” HTML similar length → possible WEAK FP | Prefer filter body keywords for SECURE |

**v1.1 fingerprint (optional, not Phase 1–4 exit):** inputs = `(status, content_type, length_bucket, top_level_json_keys_hash, optional body_simhash)`. Used only when status 2xx and `diff == DIFFERENT` to optionally promote near-identical bodies to WEAK. Out of flowchart for v1 heuristic.

Decision filter file name: `auth-session-decision-filter.yaml` in project data directory. Schema clone of `unauth-decision-filter.yaml` with sections:

- `failed_detection` → `WEAK_VALIDATION`
- `passed_detection` → `SECURE`

**Phase 4 default YAML** (shipped by `filter init`) should include common **SECURE** soft-fail patterns (body phrases like `invalid token`, `invalid signature`, `unauthorized`, status 401/403 groups) so operators get fewer false WEAKs without re-running when they init the filter early. **Do not** use bare tokens like `jwt` or `signature` alone — authorized success bodies often echo those words and would force false SECURE on true WEAK (2xx + SAME).

CLI: `talos attack auth-session filter init|show|validate`.  
**No `filter apply` / reclassify in v1** (non-goal; re-run required after filter edits).

### Baseline selection strategy

Priority order when generating candidates:

1. Explicit `--flow <uuid>` (repeater / send history / capture).
2. Explicit `--endpoint <uuid>` → `endpoint_policy.baseline_flow_id`, else `replay_db.get_best_flow_for_endpoint`.
3. `--module` / project-wide → all testable endpoints with baseline (same SQL pattern as unauth `_get_testable_flows`).
4. Prefer flows whose request includes the bound auth field with a detectable token; if baseline lacks JWT but another 2xx proxy_capture flow has it, **prefer the JWT-bearing 2xx flow** and record `baseline_source=jwt_bearing_flow` in candidate meta.

Role preference: if binding has `role_id` or CLI `--role`, prefer flows stamped with that `role_id`.

### Operator workflow (end-to-end)

```bash
# 1. Capture traffic, configure auth names (existing)
talos auth set --header Authorization
talos auth-config refresh admin   # ensure valid session if needed

# 2. Bind auth type
talos attack auth-session bind --type jwt --header Authorization

# 3. Generate candidates for high-value endpoint or specific flow
talos attack auth-session generate --endpoint <uuid>
# or: talos attack auth-session generate --flow <uuid>

# 4. Review
talos attack auth-session candidates list --status pending

# 5. Approve high-signal tests first (filters are part of the CLI contract)
talos attack auth-session approve --all-pending --endpoint <uuid> \
  --test-id jwt.alg_none --test-id jwt.elevate_role
# or: talos attack auth-session candidates list --format json | jq ...
#     talos attack auth-session approve <id1> <id2>

# 6. Run (scheduler must be alive with proxy, or --right-now)
talos attack auth-session run --endpoint <uuid>
# or: talos attack auth-session run --test-id jwt.alg_none --right-now

# 7. Inspect
talos attack auth-session results list --endpoint <uuid>
talos finding list --attack auth_session
```

---

## API / Interface Changes

### CLI

Under existing `talos attack` root (`talos/projects/attack_cli.py`):

```text
talos attack auth-session
  bind              Bind auth_config field → auth type
  unbind            Remove binding [--force cascade-reject pending only]
  show-bindings     List bindings
  generate          Create pending candidates [--force-refresh] [--include-unsafe-methods]
  candidates list|show
  approve           → approved from pending|failed|done  [--all-pending|--retry-failed|--test-id|--family|--endpoint]
  reject            pending → rejected  [same filters]
  unapprove         approved → pending
  run               Enqueue approved only [--candidate --endpoint --test-id --family --right-now]
                    (scheduler sets running on job claim; settle → done|failed)
  results list|show
  status            Bindings + candidate/result tallies
  filter init|show|validate
  suite list        List test_ids for an auth type (docs from code; --alg = full degrade matrix)
```

Shared flags where applicable:

| Flag | Purpose |
|------|---------|
| `--endpoint UUID` | Scope |
| `--flow UUID` | Explicit baseline |
| `--module NAME\|UUID` | Scope |
| `--role NAME\|UUID` | Prefer role-tagged flows |
| `--type jwt` | Auth type |
| `--header` / `--cookie` | Binding field |
| `--test-id` | Repeatable filter (generate suite / approve / reject / run / candidates list) |
| `--family` | Repeatable filter on `test_family` |
| `--force-refresh` | generate: refresh pending/rejected metadata only |
| `--include-unsafe-methods` | generate: allow non-GET baselines |
| `--right-now` | Bypass queue (like `auth test`) |
| `--format table\|json` | CLI-014 |

### Scheduler

`talos/scheduler/job.py`:

```python
AUTH_SESSION_ATTACK = "auth_session_attack"
AUTH_SESSION_JOB_TYPES: tuple[str, ...] = (AUTH_SESSION_ATTACK,)
```

`ReplayScheduler._execute_job`: new branch → `execute_auth_session_job(...)` then `_settle_auth_session_outcome(job, outcome)` (job terminal state + candidate status + optional finding). **Do not** create findings inside the engine.

### Findings (Phase 4 implementer checklist)

Touch points in the live stack (all required for Phase 4 exit):

| # | File / API | Change |
|---|------------|--------|
| 1 | `talos/findings/model.py` | `VERDICT_TRIGGERS["auth_session"] = frozenset({"WEAK_VALIDATION"})`; `ATTACK_DISPLAY["auth_session"] = "Authentication & Session Testing"`; `EVIDENCE_TYPE_AUTH_SESSION_RESULT = "auth_session_result"` |
| 2 | `talos/findings/db.py` — `build_cluster_key` | Extend signature with `auth_type: Optional[str] = None`. Branch: `if module == "auth_session": return f"AUTH_SESSION:{endpoint_id}:{auth_type or 'unknown'}"` (requires `endpoint_id`) |
| 3 | `talos/findings/creator.py` — `create_finding_from_verdict` | Pass `auth_type` into `build_cluster_key`; add evidence branch for `auth_session` attaching `EVIDENCE_TYPE_AUTH_SESSION_RESULT` (+ original_flow, replay_flow, diff, scheduler_job, endpoint, optional module/role). **Extend signature** with `title: Optional[str] = None` and `auth_type: Optional[str] = None`. When `title` is provided, use it as the finding title **instead of** the default `"{ATTACK_DISPLAY} — {verdict} ({variant})"` builder. |
| 4 | `talos/findings/report.py` | Resolve `auth_session_result` evidence type in show/report paths (same pattern as bac/auth_test/unauth result types) |
| 5 | Title formula (**chosen path**) | **`findings_bridge` owns the title string** and passes it via `create_finding_from_verdict(..., title=...)`. Formula: `"{ATTACK_DISPLAY} — {test_id} on {METHOD} {path}"` with `METHOD`/`path` from the baseline flow. Also pass `variant=test_id` for evidence/timeline context, but **`variant` alone is not sufficient** for the desired title (live creator would produce `… — WEAK_VALIDATION (jwt.alg_none)`). Do **not** bypass creator by calling `create_finding` raw unless a later refactor demands it. |
| 6 | Severity | Findings table has **no severity column**. Put `risk_hint` in evidence JSON and/or notes; do not invent a severity field. |
| 7 | Call site | Scheduler settle only (`_maybe_create_finding_auth_session` → `findings_bridge`); once per successful `WEAK_VALIDATION` outcome |

```python
# build_cluster_key extension (sketch)
def build_cluster_key(
    attack_module: str,
    endpoint_id: Optional[str],
    attacker_role_id: Optional[str] = None,
    target_role_id: Optional[str] = None,
    auth_type: Optional[str] = None,  # NEW — auth_session only
) -> Optional[str]:
    ...
    if module == "auth_session":
        return f"AUTH_SESSION:{endpoint_id}:{auth_type or 'unknown'}"
```

Evidence set: original_flow (shared baseline), **replay_flow** (single mutated outbound flow for this test_id), diff, scheduler_job, endpoint, auth_session_result, module/role when known. Each PRIMARY/LINKED child points at its own `replay_flow_id`.

### Engine entry point

```python
async def execute_auth_session_job(
    flow_id: str,
    meta: dict,
    db_path: Path,
    project_id: str,
) -> AuthSessionOutcome:
    """Mutate one test_id, send one new flow, persist result+diff, return outcome.
    Does not create findings or mark scheduler_jobs terminal."""
    ...
```

`AuthSessionOutcome` fields (align with Unauth/Bac for settlement): `original_flow_id`, `replayed_flow_id`, `original_status`, `replay_status`, `diff_verdict`, `auth_session_verdict`, `test_id`, `binding_id`, `candidate_id`, `auth_type`, `endpoint_id`, `failure_reason`.

---

## Data Model Changes

### Schema version

Schema target: **`SCHEMA_VERSION = 54`** in `talos/projects/db.py` (Phase 1 shipped).

### New tables

```sql
-- auth_session_bindings: map auth_config fields to auth types
CREATE TABLE IF NOT EXISTS auth_session_bindings (
    id            TEXT PRIMARY KEY,          -- UUID
    location      TEXT NOT NULL,             -- 'header' | 'cookie'
    name          TEXT NOT NULL,             -- e.g. Authorization, sessionid
    auth_type     TEXT NOT NULL,             -- 'jwt' | future types
    role_id       TEXT,                      -- optional preferred role
    config_json   TEXT NOT NULL DEFAULT '{}',
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE (location, name)
);

-- auth_session_candidates: operator-facing attack candidates
CREATE TABLE IF NOT EXISTS auth_session_candidates (
    id                 TEXT PRIMARY KEY,
    binding_id         TEXT NOT NULL
        REFERENCES auth_session_bindings(id) ON DELETE RESTRICT,
    endpoint_id        TEXT,
    baseline_flow_id   TEXT NOT NULL,
    auth_type          TEXT NOT NULL,
    test_id            TEXT NOT NULL,
    test_family        TEXT NOT NULL,
    title              TEXT NOT NULL,
    mutation_summary   TEXT NOT NULL,
    token_fingerprint  TEXT,                 -- short hash of original token
    risk_hint          TEXT,
    status             TEXT NOT NULL,        -- pending|approved|rejected|running|done|failed
    reject_reason      TEXT,
    skip_reason        TEXT,
    meta_json          TEXT NOT NULL DEFAULT '{}',
    created_at         TEXT NOT NULL,
    updated_at         TEXT NOT NULL,
    UNIQUE (binding_id, test_id, baseline_flow_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_session_cand_status
    ON auth_session_candidates (status, endpoint_id);

-- auth_session_results: one row per executed attempt
CREATE TABLE IF NOT EXISTS auth_session_results (
    replay_flow_id     TEXT PRIMARY KEY REFERENCES flows(id),
    original_flow_id   TEXT NOT NULL,
    endpoint_id        TEXT,                 -- denormalized for CLI filters (mirror unauth_results)
    candidate_id       TEXT NOT NULL,
    binding_id         TEXT NOT NULL,
    auth_type          TEXT NOT NULL,
    test_id            TEXT NOT NULL,
    test_family        TEXT,
    mutation_summary   TEXT,
    original_status    INTEGER,
    replay_status      INTEGER,
    diff_verdict       TEXT,                 -- SAME | DIFFERENT | ERROR
    verdict            TEXT NOT NULL,        -- WEAK_VALIDATION | SECURE | UNKNOWN
    matched_section    TEXT,
    matched_group      TEXT,
    matched_rules      TEXT,                 -- JSON
    failure_reason     TEXT,
    created_at         TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_session_results_endpoint_test
    ON auth_session_results (endpoint_id, test_id, verdict);

CREATE INDEX IF NOT EXISTS idx_auth_session_results_original_test
    ON auth_session_results (original_flow_id, test_id);
```

### Migrations (Phase 1.1 checklist — dual write)

Fresh projects and upgrades must stay aligned (repo pattern):

1. Bump `SCHEMA_VERSION = 54` in `talos/projects/db.py`.
2. Append the three `CREATE TABLE` + indexes to the big **`_DDL`** string used by `init_project_db` (new projects).
3. In **`migrate_project_db`**: add `if current < 54:` branch that runs the same `CREATE TABLE IF NOT EXISTS` / index statements (upgrades). Function name is `migrate_project_db` (not `_apply_migrations`).
4. Extend the migration log comment block (~line 2420): `v53 → v54: auth_session_bindings, auth_session_candidates, auth_session_results`.
5. Update `scheduler_jobs` header comment to list `auth_session_attack`.
6. Test: open/migrate project asserts tables exist; pattern `assert SCHEMA_VERSION >= 54` if used elsewhere for version gates.

### No change to `auth_config`

Bindings reference the same names; strip engines remain unaware of auth-session types.

---

## Sequence: generate → approve → run

```mermaid
sequenceDiagram
  participant Op as Operator
  participant CLI as auth_session.cli
  participant Cand as candidates/db
  participant Sched as ReplayScheduler
  participant Eng as auth_session.engine
  participant Replay as replay_db + httpx
  participant Find as findings.creator

  Op->>CLI: generate --endpoint E
  CLI->>Cand: insert pending candidates<br/>(one row per test_id)
  Op->>CLI: candidates list
  Op->>CLI: approve ids...
  CLI->>Cand: status=approved
  Op->>CLI: run
  CLI->>Sched: enqueue N jobs<br/>(one job per approved candidate)
  loop Each job / test_id independently
    Sched->>Eng: execute_auth_session_job(meta.test_id)
    Eng->>Eng: mutate JWT for this test_id only
    Eng->>Replay: NEW httpx request + store new flow/diff
    Eng->>Cand: result row (1:1 flow) via engine
    Sched->>Cand: settle candidate done/failed
    Sched->>Find: WEAK_VALIDATION → finding (settle only)
  end
```

---

## Alternatives Considered

### Alternative A — Fold JWT suite into Unauth techniques

**Approach:** Add `jwt_alg_none`, `jwt_claim_elev`, etc. to `UNAUTH_TECHNIQUES` / recipes.

| Pros | Cons |
|------|------|
| Less package surface | Unauth invariant is "original auth never survives"; JWT mutations *are* related to original token structure — different mental model |
| Faster to ship one engine | Recipe explosion; unauth decision filter not tuned for SAME-body |
| | Claim elevation is not "unauthenticated" |

**Rejected** for modularity and verdict semantics (KD7).

### Alternative B — Generic Intruder wordlist over Authorization header

**Approach:** Use Intruder sniper with JWT payloads.

| Pros | Cons |
|------|------|
| Existing engine | Not deterministic catalog; weak reporting taxonomy |
| Flexible | No binding/auth-type model; operator must craft payloads |
| | Findings bridge is match-oriented, not auth-validation oriented |

**Rejected** as primary path; Intruder remains available for ad-hoc exploration.

### Alternative C — Package under `talos/projects/auth_session/`

**Approach:** Sibling of `bac/` and `unauth/`.

| Pros | Cons |
|------|------|
| Consistent with other attack modules under projects | `projects/` already large; JWT codec is general utility |
| Slightly shorter import paths for auth.py | IV/intruder already live top-level for similar reasons |

**Accepted-adjacent:** CLI still under `talos attack`. Package location top-level (**KD1**) preferred; can relocate later without CLI change.

### Alternative D — Depend on PyJWT for mutations

| Pros | Cons |
|------|------|
| Familiar API | Dependency weight; library resists invalid constructions (`alg=none` often blocked) |
| | We need *invalid* tokens; fighting the library is counterproductive |

**Rejected** in favor of stdlib encode/mutate (**KD5**).

### Alternative E — Add `auth_type` column on `auth_config`

**Approach:** `ALTER TABLE auth_config ADD COLUMN auth_type` (or extend PK) so each cookie/header name carries `jwt` / `session` / etc.

| Pros | Cons |
|------|------|
| Single table for “what is auth” | `auth_config` is shared by strip (`auth_test`), Unauth, BAC session inject — none of those need types today |
| Fewer tables | Migration risk; forces default `unknown` for all existing projects |
| | Per-binding suite config (claim elevation, disabled tests) does not fit name-only rows cleanly |
| | Operators may configure auth names before knowing type |

**Rejected.** Keep `auth_config` as pure name registry; **bindings** (KD3) are opt-in and own type + JSON config without coupling strip engines.

### Alternative F — Detect JWT on generate only (no bindings table)

**Approach:** At `generate` time, scan baseline flows for compact JWTs in any header/cookie already listed in `auth_config`; no explicit bind.

| Pros | Cons |
|------|------|
| Zero setup beyond `talos auth set` | Ambiguous when multiple JWT-shaped values exist |
| | No stable place for per-field suite config / role preference |
| | Harder to support non-JWT types later with the same UX |
| | Silent generate on every auth cookie may surprise operators |

**Rejected for v1.** Explicit `bind` is the control plane; optional later “auto-bind if single JWT detected” can wrap bindings without removing the table.

### Alternative G — Rename package to `auth_session_test` / `auth_testing`

**Approach:** Avoid collision with `Project.auth_session_path()` / `data_dir/auth_sessions/`.

| Pros | Cons |
|------|------|
| Clearer imports | Longer names; CLI already uses `auth-session` |
| | Collision is conceptual only if docs are clear |

**Deferred.** Keep **`talos/auth_session/`** (KD1) with explicit naming note in package docstring and architecture.md; rename only if implementers still collide in practice.

---

## Security & Privacy Considerations

| Risk | Severity | Mitigation |
|------|----------|------------|
| Mutated tokens still contain PII/claims from original JWT | Medium | Tokens already in project DB via capture; findings store mutation summary + flow refs, not full token dumps in titles |
| Claim elevation tests may trigger privileged side effects | High | Endpoint policy exclude dangerous/logout; **generate defaults to safe methods** (warn/skip POST/PUT/DELETE unless `--include-unsafe-methods`); operator approve; no auto-run; built-in elevation map only when claims present |
| `huge_kid` / large tokens may DoS target or proxy | Medium | Cap payload sizes (e.g. kid ≤ 8 KiB); document risk_hint; allow disable via binding config |
| Confusion with production auth logging (failed JWT spam) | Low | Rate via scheduler delays (`scheduler_config` min/max delay); manual enqueue only |
| Accidental out-of-scope testing | High | Existing Basic Scope + project constraints + endpoint policy; engine does not bypass scope |
| AI misuse | N/A v1 | No AI in execution path; future AI tools must use policy-gated suggest-first only |

**Authorization context:** This is authorized security testing product engineering. Operators are responsible for legal authorization against targets; product enforces project scope and operator approval gates.

**Threat model (engine itself):** Malicious project DB content could craft oversized mutation config — validate and cap at generate/apply time.

---

## Observability

| Signal | Mechanism |
|--------|-----------|
| Structured logs | `logging.getLogger("talos.auth_session")` — generate counts, skip reasons, job start/finish, verdict |
| Candidate status counts | `candidates list` / future `status` subcommand |
| Scheduler job rows | `talos scheduler jobs list --type auth_session_attack` (extend filter if needed) |
| Results table | `auth_session_results` queryable via CLI |
| Findings | Standard `talos finding list` with `attack_type=auth_session` |
| Metrics (optional later) | Counters: generated, approved, weak_validation rate per auth_type |

No new daemon. Failures surface as candidate `failed` + job `failed` with `failure_reason` (same pattern as BAC).

---

## Rollout Plan

### Feature availability

- Code lands behind normal release; no global feature flag required if CLI is opt-in (operator must bind/generate).
- Optional: `attack_config.auth_session_enabled` default `true` once CLI ships (or omit until stable).

### Staged delivery

See [PR Plan](#pr-plan). Phases (merge in order; implement one phase at a time):

1. **Phase 1 — Foundation:** schema, models, JWT codec/mutators (library only).
2. **Phase 2 — Operator candidate path:** bindings, generate/approve/reject CLI.
3. **Phase 3 — Execution:** engine, scheduler job, replay/diff, results.
4. **Phase 4 — Findings & filters:** decision filter + findings bridge.
5. **Phase 5 — Docs & polish:** cheat sheet, architecture, suite completeness.

### Rollback

- Drop is not needed: unused tables are inert.
- Disable by not generating/running; optional CLI hide not required.
- Findings remain for audit trail.

### Compatibility

- Existing `auth_test` / unauth / BAC behavior unchanged.
- `auth_config` schema unchanged.

---

## Open Questions

1. **Claim elevation defaults:** **Decided (v1):** ship built-in map (`role` user→admin, `roles`, `is_admin` false→true, etc.) applied only when those claims exist in the payload; binding `config_json.claim_elevation` overrides. Combined with generate’s default skip of non-safe methods unless `--include-unsafe-methods`.
2. **Multi-token requests:** **Decided:** Yes — one binding per field; independent candidate sets when both cookie and header (or multiple fields) carry JWTs.
3. **JWE / nested JWT:** **Decided (v1):** compact **JWS only**; skip non-matching values at detect (no JWE / nested JWT).
4. **Finding severity mapping:** **Decided:** findings table has **no severity column**. Store `risk_hint` on the candidate and in finding evidence JSON / notes only.
5. **Control Panel:** When to surface candidates UI?
   - **Recommendation:** After CLI stable (post Phase 4 / Phase 5). Still open for product timing only.
6. **Auto-generate on bind:** **Decided:** No — explicit `generate` only; bind never auto-generates candidates.

---

## Future Authentication Types

Each type implements `AuthTypeAnalyzer` + suite module:

| Type | Example tests |
|------|----------------|
| Session Cookie | empty, deleted, flipped bits, session fixation token from other role (careful vs BAC), path/domain attribute ignores (limited via request only) |
| API Key | empty, truncated, case flip, prefix strip, duplicate header |
| Basic Auth | empty password, user swap, malformed base64 |
| Digest | stale nonce, realm change (limited) |
| HMAC signed headers | strip signature header, zero sig, replay skew |
| OAuth2 Access Token | same as JWT if JWT-shaped; opaque token mutations like API key |
| OAuth2 Refresh Token | endpoint-specific refresh misuse (later) |
| SAML | assertion mutation (large; separate design) |
| Custom Header | generic empty/malformed/duplicate |

**JWT suite backlog (not v1):** `jwt.jku_inject`, `jwt.x5u_inject`, `jwt.x5c_inject` (header injection of URL/cert material)—url_sink already inventories `jku`/`x5u` as URL sinks; do not expand Phase 5 “suite completeness” to include these without a new product decision.

Architecture unchanged: new suite file + registry entry + optional binding config schema.

---

## Testing Strategy

| Layer | Coverage |
|-------|----------|
| Unit | `jwt_codec` round-trip; each mutator golden vectors; detect Bearer prefix; scheme preserve |
| Unit | Candidate generate skip when no JWT; unique constraint; approve transitions |
| Unit | Verdict matrix (status × diff → verdict) |
| Unit | Decision filter load/eval (copy patterns from unauth tests) |
| Integration | Engine with httpx mock: mutate Authorization, store result, finding created on WEAK_VALIDATION |
| Integration | Scheduler dispatch for `auth_session_attack` |
| Regression | Existing auth_test / unauth / BAC tests unchanged |

Test files: `tests/test_auth_session_*.py` following repo conventions.

---

## Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| High false-positive WEAK_VALIDATION when APIs always return 200 + envelope | Medium | Require `diff SAME`; decision filter; operator reject findings |
| High false-negative when app returns 200 different error body for invalid JWT | Medium | Document; optional v1.1 fingerprint / filter failed_detection on error body patterns |
| Duplicate-claim mutation not parseable by all servers | Low | Keep as optional family; may skip if construction fails |
| Operator confuses with auth test | Low | CLI naming + finding labels + docs table |
| Schema migration bugs | Medium | Idempotent CREATE IF NOT EXISTS; tests on migrate |

---

## References

| Resource | Path / note |
|----------|-------------|
| Architecture | `docs/architecture.md` |
| CLI cheat sheet | `docs/cli-cheat-sheet.md` |
| Project rules | `AGENTS.md` |
| Auth config CRUD | `talos/projects/auth.py` |
| Auth CLI / test | `talos/projects/auth_cli.py` |
| Auth-strip / auth_test | `talos/replay/auth_strip.py` |
| Unauth engine | `talos/projects/unauth/engine.py` |
| Unauth recipes | `talos/projects/unauth/recipes.py` |
| BAC engine | `talos/projects/bac/engine.py` |
| BAC candidates | `talos/projects/bac/candidates.py` |
| Decision filters | `talos/projects/unauth/decision_filter.py`, `bac/decision_filter.py` |
| Replay diff | `talos/replay/diff.py` |
| Replay DB results | `talos/replay/db.py` |
| Scheduler jobs | `talos/scheduler/job.py`, `scheduler.py` |
| Findings | `talos/findings/model.py`, `creator.py`, `db.py` |
| Attack CLI root | `talos/projects/attack_cli.py` |
| JWT passive | `talos/passive/detectors/jwt.py` |
| JWT claims inventory | `talos/url_sink/jwt_claims.py` |
| Schema / migrations | `talos/projects/db.py` (`SCHEMA_VERSION = 54`) |
| Endpoint policy | `talos/projects/policy.py` |
| Input validation candidates (pattern) | `talos/input_validation/candidates.py` |

---

## PR Plan

Implementation is **phased**. Each phase is a coherent, deliverable unit that can be implemented end-to-end in **one AI session** (or a short series). PRs within a phase may be sequential or parallel as noted; **phases are ordered and should be merged in order**.

When told **“implement Phase N”**, an AI implementer should deliver **all PRs in that phase** (tests included), leave the tree green, and not start the next phase.

---

### Phase 1: Foundation (schema, models, JWT library) — **DONE**

**Goal:** Land the `talos/auth_session/` package skeleton, project DB schema (v54), and pure JWT codec/mutation/suite catalog with unit tests. No operator-facing CLI execution path yet (optional: no CLI at all in this phase).

**Exit criteria:**
- [x] `SCHEMA_VERSION` is 54; migrations create `auth_session_bindings`, `auth_session_candidates`, `auth_session_results` idempotently.
- [x] JWT encode/decode round-trip and each core mutator covered by golden unit tests.
- [x] Core `jwt.alg_none*` rows present; algorithm-degradation helper expands observed `alg` into Phase-1 HS* (and listed) targets **without** any `*_to_none` ids (unit test asserts none-skip).
- [x] `AuthTypeAnalyzer` Protocol + JWT suite catalog (`test_id` list) importable; no network I/O, no scheduler hooks.
- [x] Existing attack modules and project open/migrate still pass.

**Depends on:** none

**AI implementer scope:** Implement PR 1.1 → 1.3 below only. Do not wire `attack_cli` or scheduler yet.

#### PR 1.1: Schema v54 + package skeleton

- **Files/components:** `talos/projects/db.py` — bump `SCHEMA_VERSION=54`, append tables to `_DDL`, `migrate_project_db` `current < 54` branch with `CREATE IF NOT EXISTS`, migration log, scheduler_jobs comment; `talos/auth_session/__init__.py` (naming note); `talos/auth_session/models.py`.
- **Dependencies:** none
- **Description:** Dual-write schema (init + migrate). Models/status enums only.

#### PR 1.2: JWT codec + mutators

- **Files/components:** `talos/auth_session/jwt_codec.py` (`decode_jwt_header`, encode, reassemble); `talos/auth_session/jwt_mutate.py`; reuse `extract_jwt_token` / `decode_jwt_payload` only; `tests/test_auth_session_jwt_mutate.py`.
- **Dependencies:** PR 1.1
- **Description:** Stdlib `base64`/`json` only. Mutators: core none casings, empty/missing/unknown alg, degradation **header-only** (sig unchanged), invalid/missing sig, claims, kid, structure. Golden vectors.

#### PR 1.3: JWT suite catalog + analyzer registry stub

- **Files/components:** `talos/auth_session/suite_jwt.py` (`alg_degradation_tests` with **none-skip** + Phase-1 target table); `types.py`; `tests/test_auth_session_suite_jwt.py` (assert no `*_to_none` degradation ids).
- **Dependencies:** PR 1.2
- **Description:** `list_test_cases` / `apply`; claim skip when absent; Phase-1 degradation set frozen per design table.

---

### Phase 2: Bindings & candidate lifecycle (CLI, no HTTP) — **DONE**

**Goal:** Operators can bind auth fields to JWT, generate pending candidates from a flow/endpoint, list/show them, and approve/reject. Still **no** replay or scheduler execution.

**Exit criteria:**
- [x] `talos attack auth-session bind|unbind|show-bindings|generate|candidates|approve|reject|suite list` work against an active project.
- [x] Candidates persisted with status lifecycle; unique on `(binding_id, test_id, baseline_flow_id)`.
- [x] Generate respects endpoint policy / baseline selection order from design; skips when token not detectable.
- [x] Unit/integration tests for generate + approve transitions; no outbound HTTP in this phase.

**Depends on:** Phase 1

**AI implementer scope:** PR 2.1 → 2.3. Wire CLI into `attack_cli` / help text. Do not implement `run` beyond a stub that errors with “not implemented” if needed—prefer omitting `run` until Phase 3.

#### PR 2.1: Bindings + auth_session DB CRUD — **DONE**

- **Files/components:** `talos/auth_session/db.py` (bindings + candidates CRUD); `talos/auth_session/config.py` (defaults, claim_elevation map); `tests/test_auth_session_db.py`.
- **Dependencies:** Phase 1
- **Description:** Read/write bindings and candidates; status transitions (`pending` → `approved`/`rejected`); fingerprint helpers (no full token storage).

#### PR 2.2: Extract + candidate generation — **DONE**

- **Files/components:** `talos/auth_session/extract.py`; `talos/auth_session/candidates.py`; `tests/test_auth_session_candidates.py`.
- **Dependencies:** PR 2.1
- **Description:** Locate JWT; **insert-if-absent** generate rules; `--force-refresh` only pending/rejected; safe-method default; baseline selection order.

#### PR 2.3: Operator CLI (bind / generate / approve) — **DONE**

- **Files/components:** `talos/auth_session/cli.py`; `attack_cli.py`; `__main__.py`; tests.
- **Dependencies:** PR 2.2
- **Description:** bind/unbind (RESTRICT rules), generate, candidates, approve/reject with `--test-id` / `--family` / `--endpoint` / `--all-pending`. No `run` yet.

---

### Phase 3: Execution engine & scheduler — **DONE**

**Goal:** Approved candidates execute end-to-end: **one job → one mutation → one new outbound flow** → store flow/diff/result → heuristic verdict. Operator can `run` (enqueue) or `--right-now`.

**Exit criteria:**
- [x] Job type `auth_session_attack` defined and dispatched in `ReplayScheduler`.
- [x] **One scheduler job / engine invocation per candidate `test_id`**; engine does not batch multiple mutations into one HTTP request.
- [x] `execute_auth_session_job` returns outcome only (persists result); **scheduler settle** updates job + candidate status (no findings yet).
- [x] `has_pending_auth_session_duplicate` meta-aware skip works.
- [x] Results include denormalized `endpoint_id`; 1:1 `replay_flow_id` ↔ candidate.
- [x] Heuristic verdict per Detection section (filter is Phase 4).
- [x] Engine tests with httpx mocked; settle path covered.

**Depends on:** Phase 2

**AI implementer scope:** PR 3.1 → 3.3. No findings; decision filter Phase 4.

#### PR 3.1: Heuristic verdict + results persistence — **DONE**

- **Files/components:** `talos/auth_session/verdict.py`; `talos/auth_session/db.py` (insert result with `endpoint_id`, update candidate); `tests/test_auth_session_verdict.py`.
- **Dependencies:** Phase 2
- **Description:** Pure verdict (status × diff); document SAME coarseness in module docstring.

#### PR 3.2: Execution engine — **DONE**

- **Files/components:** `talos/auth_session/engine.py`; `tests/test_auth_session_engine.py` (httpx mocked).
- **Dependencies:** PR 3.1
- **Description:** One test_id, one new request, persist flow/diff/result; return `AuthSessionOutcome`. **No findings.** Auth invariant on original token.

#### PR 3.3: Scheduler job type + `run` CLI — **DONE**

- **Files/components:** `talos/scheduler/job.py`; `talos/scheduler/scheduler.py` (dispatch + `_settle_auth_session_outcome` without finding yet); `has_pending_auth_session_duplicate`; CLI `run` / results; tests one-job-per-candidate + meta dedupe.
- **Dependencies:** PR 3.2
- **Description:** N candidates → N jobs; settle marks done/failed.

---

### Phase 4: Decision filter & findings — **DONE**

**Goal:** Project-tunable SECURE/WEAK patterns and automatic finding creation for `WEAK_VALIDATION`, integrated with existing findings triage.

**Exit criteria:**
- [x] `auth-session-decision-filter.yaml` load/eval (same shape as unauth/BAC filters); CLI `filter init|show|validate`.
- [x] Engine uses filter when present, else heuristic (filter miss → heuristic, not UNKNOWN-only).
- [x] `VERDICT_TRIGGERS["auth_session"] = {"WEAK_VALIDATION"}`; cluster key `AUTH_SESSION:<endpoint_id>:<auth_type>`; evidence includes `auth_session_result`.
- [x] `talos finding list` shows Authentication & Session Testing findings after a successful weak-validation run (mocked or integration).
- [x] Unit tests for filter + findings bridge.

**Depends on:** Phase 3

**AI implementer scope:** PR 4.1 → 4.2. Wire creator from **scheduler settle** (and CLI `--right-now` settle) via findings_bridge — never inside the mutation engine.

#### PR 4.1: Decision filter — **DONE**

- **Files/components:** `talos/auth_session/decision_filter.py`; CLI `filter init|show|validate`; default YAML with SECURE soft-fail body patterns; wire engine fallback order (filter miss → heuristic); `tests/test_auth_session_decision_filter.py`.
- **Dependencies:** Phase 3
- **Description:** Match sections; **heuristic fallback** when no file or no match (not unauth-style UNKNOWN-only).

#### PR 4.2: Findings model + bridge — **DONE**

- **Files/components:** full Findings checklist (model, `build_cluster_key(auth_type=)`, creator evidence branch, report.py, bridge title formula, scheduler settle call site); `tests/test_auth_session_findings.py`.
- **Dependencies:** PR 4.1
- **Description:** `WEAK_VALIDATION` → TRIAGING finding from **scheduler settle / --right-now** via findings_bridge; extend creator with `title=` + `auth_type=`; title formula Appendix B.

---

### Phase 5: Docs, suite completeness & polish — **DONE**

**Goal:** Full operator documentation and remaining suite/UX polish so the feature is release-ready.

**Exit criteria:**
- [x] `docs/cli-cheat-sheet.md` and `docs/architecture.md` document `talos attack auth-session`.
- [x] `docs/updates.md` entry for the feature.
- [x] JWT suite catalog complete per design table, including **full algorithm-degradation matrix edges** deferred from Phase 1 (same-family downgrade chains, PS*/ES* coverage as specified).
- [x] `--format json` on list/show/status paths; discoverability/hierarchy tests green if present.
- [x] No new architecture; regression suite for auth_test/unauth/BAC still green.

**Depends on:** Phase 4

**AI implementer scope:** PR 5.1 → 5.2. Documentation and completeness only unless a small bugfix is required for exit criteria.

#### PR 5.1: Full JWT suite + CLI polish — **DONE**

- **Files/components:** remaining mutators/test_ids in `suite_jwt.py` / `jwt_mutate.py` (complete **algorithm-degradation** matrix edges); `results` UX; `--format json`; `status` overview; any CLI consistency with unauth/bac flags.
- **Dependencies:** Phase 4
- **Description:** Close suite gaps including alg degradation completeness; operator ergonomics.

#### PR 5.2: Documentation & discoverability — **DONE**

- **Files/components:** `docs/cli-cheat-sheet.md`; `docs/architecture.md`; `docs/updates.md`; `test_module_discoverability.py` / `test_command_hierarchy.py` updates if required; `__main__.py` help polish.
- **Dependencies:** PR 5.1 (or parallel if docs-only after Phase 4 CLI is stable)
- **Description:** Authoritative CLI/architecture docs match live argparse.

---

### Optional follow-ups (not blocking v1; new phases later)

| Follow-up | Scope |
|-----------|--------|
| Phase 6+ | Session cookie / API key analyzers |
| Later | Control Panel candidates + results pages |
| Later | AI tool: suggest auth-session generate/approve (policy-gated, suggest-first only) |
| Later | Body fingerprint enhancement for 2xx-different soft failures |
| Later | `filter apply` / reclassify (patterned on unauth/BAC) after operators tune decision filter |
| Later | `jwt.jku_inject` / `x5u` / `x5c` suite |
| Later | Optional HMAC-with-pubkey mutator (`hmac`/`hashlib`) when operator supplies PEM |

---

## Appendix A — Example mutation (alg=none)

```text
Original Authorization:
  Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1MSIsInJvbGUiOiJ1c2VyIn0.SflKxw...

Header after mutation:
  {"alg":"none","typ":"JWT"}

Payload unchanged:
  {"sub":"u1","role":"user"}

Compact token:
  eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1MSIsInJvbGUiOiJ1c2VyIn0.

Request:
  Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1MSIsInJvbGUiOiJ1c2VyIn0.
```

If server returns **200** with **SAME** body as baseline → `WEAK_VALIDATION` finding.

---

## Appendix B — Finding title formula (deterministic)

**Implementation path (required):** extend `create_finding_from_verdict` with optional `title: Optional[str] = None`. When set, that string is stored as the finding title; when omitted, keep today’s default `"{ATTACK_DISPLAY} — {verdict} ({variant})"`.

```python
# findings_bridge (called from scheduler settle only)
method = baseline_flow.get("method") or "?"
path = baseline_flow.get("path") or baseline_flow.get("url") or "?"
title = f"{ATTACK_DISPLAY['auth_session']} — {test_id} on {method} {path}"
create_finding_from_verdict(
    ...,
    attack_module="auth_session",
    verdict="WEAK_VALIDATION",
    variant=test_id,       # context only — NOT the full title
    title=title,           # required for Appendix B formula
    auth_type=auth_type,
    ...
)
```

Template:

```text
{ATTACK_DISPLAY} — {test_id} on {METHOD} {path}
```

Examples:

- `Authentication & Session Testing — jwt.alg_none on GET /api/v1/me`
- `Authentication & Session Testing — jwt.elevate_role on GET /api/admin/users`
- `Authentication & Session Testing — jwt.alg_degrade.rs256_to_hs256 on GET /api/v1/me`
- `Authentication & Session Testing — jwt.invalid_signature on POST /api/orders`

Details in evidence (`mutation_summary`, `risk_hint`) and linked flows—not free-form titles.

---

*End of design document.*
