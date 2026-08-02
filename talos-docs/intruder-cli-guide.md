# Talos Intruder CLI — Complete Operator & AI Guide

**Audience:** Operators, automation scripts, and AI agents that configure or drive Intruder.  
**Scope:** CLI-first engine under `talos/intruder/` (Phases 1–5).  
**Design SSOT (internals):** [`design-intruder-cli.md`](design-intruder-cli.md)  
**Control Panel SSOT:** [`design-control-panel-intruder.md`](design-control-panel-intruder.md)

This document is the **practical handbook**: every command, plugin, default, safety gate, and end-to-end recipe. Prefer this over reading source when you only need to *use* Intruder.

---

## 1. What Intruder is (and is not)

| Engine | Role | Volume |
|--------|------|--------|
| **`talos intruder`** | High-volume **mutation** of a baseline request (template + payload sets + strategy) | Thousands of attempts, time-sliced jobs |
| **`talos send`** | Mutable one-off replay (Repeater) | Hard cap ~50 |
| **`talos replay`** | Exact identity-preserving re-send | Low |
| **`talos input-validation`** | Parameter intelligence with a **fixed** probe taxonomy | Medium, structured |

Intruder is **Burp Intruder–class**: pick injection points, feed payloads, choose how sets combine, rate-limit, match/grep responses, export metrics, optionally promote findings.

It is **not** automatic vulnerability scanning. You (or an agent) must choose variables, payloads, and match criteria.

---

## 2. Mental model (read this once)

```
Baseline flow (captured HTTP)
        │
        ▼
  Session (draft) ── config_json ──► template + payload_sets + strategy
        │                              + timing + match + grep + storage
        │                              + findings + safety
        ▼
  validate ──► estimate attempt count
        │
        ▼
  run ──► scheduler job segments (default)  OR  --right-now (foreground)
        │
        ▼
  Engine loop: strategy.next() → render → HTTP → metrics → match/grep → store
        │
        ▼
  pause / resume / stop via control_flag + checkpoints
        │
        ▼
  results list/export  ·  pools  ·  optional findings promote
```

### Core objects

| Object | Meaning |
|--------|---------|
| **Session** | One logical attack. Owns config, progress, checkpoint, status. |
| **Baseline** | Snapshot of method/url/headers/body from a flow (`--from FLOW_ID`). Immutable source of truth for the template. |
| **Template variable** | Named injection point (`user_id` in path/query/body/header/cookie, or raw `{{user_id}}`). |
| **Payload set** | Named generator (+ processors) that produces strings. Usually keyed by variable name. |
| **Strategy** | How payload sets map onto variables over time (single, sniper, pitchfork, cluster_bomb, …). |
| **Attempt** | One rendered HTTP request + one result row. |
| **Match rule** | Online classifier → tags + `interesting=true`. |
| **Grep rule** | Online regex extract → `grepped_json` + optional **pool**. |
| **Pool** | Project-level bag of extracted strings for chaining into later sessions. |
| **Segment** | One scheduler time-slice (default: ≤100 attempts or ≤60s wall, then continue job). |

### Session status lifecycle

```
draft → configured → queued → running ⇄ paused
                         │         │
                         ▼         ▼
                    completed / failed / cancelled
```

| Status | Meaning |
|--------|---------|
| `draft` | Created or mid-edit; may not pass validate. |
| `configured` | Last validate/configure succeeded. |
| `queued` | Scheduler job pending. |
| `running` | Engine actively sending. |
| `paused` | Cooperative pause; checkpoint saved; use `session resume`. |
| `completed` | All attempts done (or hit intentional caps cleanly). |
| `failed` | Hard failure (see `failure_reason`). |
| `cancelled` | Operator stop / cancel. |

### Two execution modes

| Mode | How | When to use |
|------|-----|-------------|
| **Scheduler** (default) | `session run` enqueues `job_type=intruder_session` | Production / long runs; share project scheduler |
| **Foreground** | `session run … --right-now` | Debug, short runs, no daemon; Ctrl-C → pause |

**Critical:** Global scheduler pause does **not** auto-resume Intruder sessions. After global pause, resume each session with:

```bash
talos intruder session resume <session_id>
```

---

## 3. Prerequisites

```bash
# Active project required (or pass --project every time)
talos project open <project_id>
# or
talos --project <project_id> intruder …

# You need a baseline flow id (from proxy capture, send, etc.)
talos flow list --format json   # or Control Panel Flows UI
```

For **scheduled** runs, the project scheduler must be running (proxy-started or `python -m talos.scheduler.runner`). Foreground `--right-now` does not need the scheduler.

Always prefer **`--format json`** for agents (stable machine-readable output).

---

## 4. Command map (complete tree)

```
talos intruder
├── session
│   ├── create --from FLOW_ID [--name]
│   ├── list [--status] [--limit]
│   ├── show SESSION_ID
│   ├── configure SESSION_ID --file PATH [--force]
│   ├── validate SESSION_ID [--force]
│   ├── run SESSION_ID [--right-now] [--force]
│   ├── pause | resume | stop | status SESSION_ID
│   ├── delete SESSION_ID [--force]
│   └── clone SESSION_ID [--name]
├── template
│   ├── show | set-var | clear-var | from-params
├── payload
│   ├── set | list | clear
├── strategy set
├── timing set
├── storage set | show
├── match add | list | clear
├── grep add | list | clear
├── pool list | show | export | clear | delete
├── findings set | show | promote
├── results list | show | export
├── generators list
└── suggest SESSION_ID [--apply] …

Aliases:
  talos intruder run …     →  session run …
  talos intruder status …  →  session status …
```

Global patterns on most commands:

| Flag | Meaning |
|------|---------|
| `--format json` | Machine output (AI contract) |
| `--force` | Skip interactive confirms; open oversized generators; override some busy states |

---

## 5. Minimal happy path (copy-paste)

Enumerate numeric `user_id` on a captured GET:

```bash
export P=demo
export FLOW=<captured_flow_uuid>

# 1. Create session from baseline
SID=$(talos --project $P --format json intruder session create --from $FLOW --name enum-users \
  | python -c "import sys,json; print(json.load(sys.stdin)['session_id'])")

# 2. Injection point
talos --project $P intruder template set-var $SID \
  --name user_id --location query --path user_id

# 3. Payloads
talos --project $P intruder payload set $SID \
  --var user_id --generator numbers --start 1 --end 200

# 4. Strategy + timing (defaults are safe: single, rps=2, concurrency=1)
talos --project $P intruder strategy set $SID --type single --primary user_id
talos --project $P intruder timing set $SID --mode fixed --rps 2 --concurrency 1

# 5. What is “interesting”?
talos --project $P intruder match add $SID --tag ok --status 200 --length-delta-gt 50

# 6. Validate + run (scheduler)
talos --project $P --format json intruder session validate $SID
talos --project $P --format json intruder session run $SID

# 7. Poll
talos --project $P --format json intruder session status $SID

# 8. Results
talos --project $P --format json intruder results list $SID --interesting --limit 50
talos --project $P intruder results export $SID --out ./enum-users --jsonl --csv --interesting
```

**Foreground variant** (no scheduler):

```bash
talos --project $P intruder session run $SID --right-now --force
```

---

## 6. Session lifecycle — commands in detail

### 6.1 Create

```bash
talos intruder session create --from <flow_id> [--name NAME] [--format json]
```

- Copies method, URL, headers, body into `config.template`.
- Links `base_flow_id`, `endpoint_id` when present.
- Auto-discovers any `{{placeholders}}` already in the baseline as **raw** variables.
- Status: `draft`.

**JSON (typical):**

```json
{
  "session_id": "…",
  "name": "enum-users",
  "status": "draft",
  "base_flow_id": "…",
  "endpoint_id": "…"
}
```

### 6.2 List / show

```bash
talos intruder session list [--status running] [--limit 50]
talos intruder session show <session_id>   # full config + progress
```

### 6.3 Configure from file

Replace config from JSON or YAML (template identity fields preserved):

```bash
talos intruder session configure <session_id> --file ./attack.json [--force]
```

Validates generators while applying. Use for complex multi-set configs written by agents.

### 6.4 Validate

```bash
talos intruder session validate <session_id> [--force]
```

Opens generators, checks strategy binding, path inject gates, estimate. On success → status `configured`.  
Oversized wordlists/bruteforce may require `--force`.

### 6.5 Run

```bash
talos intruder session run <session_id> [--right-now] [--force]
```

Before enqueue:

1. Full validate.
2. Safety: logout annotation → hard block; dangerous → confirm; out-of-scope URL → hard block (if project has scope).
3. Estimate > **1000** → confirm (or `--force`).
4. Storage `all_flows` → confirm (or `--force`).
5. Busy session (`running`/`queued`) → error unless `--force` (force cancels then re-runs).

**Default path:** enqueue job, return `job_id`, status `queued`.  
**`--right-now`:** run engine in this process until segment/session ends; Ctrl-C sets pause.

### 6.6 Pause / resume / stop / status

```bash
talos intruder session pause  <session_id>
talos intruder session resume <session_id>   # new job segment from checkpoint
talos intruder session stop   <session_id>   # control_flag=cancel
talos intruder session status <session_id>
```

| Action | Behavior |
|--------|----------|
| **pause** | If job still pending → cancel job, status `paused`. If running → set `control_flag=pause`; engine exits cooperatively. |
| **resume** | Only from `paused`. Enqueues new segment; restores checkpoint. |
| **stop** | `control_flag=cancel`; pending jobs cancelled; running engine observes flag. Terminal `cancelled`. |
| **status** | Progress: sent, matched, errors, estimate, segment, rps_ema, results_count, … |

### 6.7 Clone / delete

```bash
talos intruder session clone <session_id> [--name NAME]
# New draft; copies config only (no results, checkpoint, job).

talos intruder session delete <session_id> [--force]
# Deletes session + results. Active sessions need stop or --force.
```

---

## 7. Template (injection points)

### 7.1 Locations

| Location | How value is applied |
|----------|----------------------|
| `path` | Path segment inject via surface API; requires normalized path `{name}` brace |
| `query` | Query parameter (`path` = param name, default = variable name) |
| `body` | Body field inject (JSON/form-aware via surface) |
| `header` | Request header |
| `cookie` | Cookie name |
| `raw` | Literal replace of `{{name}}` in URL/headers/body after named injects |

**Render order (normative):** named injects `path → query → header → cookie → body`, then raw `{{…}}` replace. `Content-Length` is stripped after mutation.

### 7.2 set-var / clear-var / show

```bash
talos intruder template set-var <sid> \
  --name user_id \
  --location query \
  [--path user_id] \
  [--fixed-value admin] \
  [--original-value 42] \
  [--semantic-type integer]

talos intruder template clear-var <sid> --name user_id
talos intruder template show <sid>
```

| Flag | Purpose |
|------|---------|
| `--path` | Inject name if different from `--name` |
| `--fixed-value` | Always bind this value (not strategy-driven unless overwritten) |
| `--original-value` | Baseline documentation / suggest heuristics |
| `--semantic-type` | Hint for `suggest` and operators (`integer`, `uuid`, `email`, …) |

### 7.3 Path inject gate

For `location=path`, the endpoint’s **normalized_path** must contain `{name}` (e.g. `/users/{user_id}`).  
Otherwise validate fails with `path_inject_unavailable`.

### 7.4 from-params (Parameter Intelligence)

Auto-build variables from the endpoint’s learned parameters:

```bash
talos intruder template from-params <sid> \
  [--locations path,query,body] \
  [--set-payloads] \
  [--replace]
```

| Flag | Effect |
|------|--------|
| `--locations` | Comma filter |
| `--set-payloads` | Also set `example_values` generator per param that has examples |
| `--replace` | Replace all variables instead of merge-by-name |

Requires `endpoint_id` on the session.

### 7.5 Raw placeholders in baseline

If the captured request already contains `{{token}}` in URL/headers/body, create auto-registers them as raw variables. You still need a payload set bound to that name for strategy.

---

## 8. Payload sets & generators

### 8.1 Commands

```bash
talos intruder payload set <sid> --var NAME --generator TYPE [options] [--processor …]
talos intruder payload list <sid>
talos intruder payload clear <sid> [--var NAME]   # one set or all
talos intruder generators list                    # inventory of plugins
```

Payload set key (`--var`) is almost always the **same name** as the template variable. Multi-set strategies bind set name → variable of that name.

Processors are a chain applied **after** generation (order = CLI order / list order).

---

### 8.2 Generator catalog

#### `wordlist` — lines from a file

```bash
talos intruder payload set $SID --var user --generator wordlist --file /path/users.txt
```

| Option | Default / note |
|--------|----------------|
| path (`--file`) | Required |
| Size guards | 64 MiB / 1_000_000 lines unless `--force` on validate/run |
| Empty / missing file | Error |

**File must remain at that path** for later validate/run (paths are re-opened).

#### `numbers` — inclusive integer range

```bash
talos intruder payload set $SID --var id --generator numbers --start 1 --end 500 --step 1
```

Supports negative step (countdown). Yields `str(n)`.

#### `static` — fixed list

```bash
talos intruder payload set $SID --var role --generator static \
  --value admin --value user --value guest
```

#### `uuid` — finite UUID v4 strings

```bash
talos intruder payload set $SID --var id --generator uuid --count 50
```

Default count: 10. Very large counts need force.

#### `csv` — one column from CSV

```bash
talos intruder payload set $SID --var email --generator csv \
  --file ./emails.csv --column email --delimiter ,
# column can be header name or 0-based index
```

#### `json` — values from JSON file

```bash
talos intruder payload set $SID --var id --generator json \
  --file ./data.json --json-path 'users[].id'
```

`json_path` examples: `""` (root array), `ids`, `users[].id`, `data.items[].value`.

#### `example_values` — Parameter Intelligence store

```bash
talos intruder payload set $SID --var user_id --generator example_values \
  --param-id <parameters.id>
```

Usually set via `template from-params --set-payloads`.

#### `pool` — values extracted by earlier grep

```bash
talos intruder payload set $SID --var token --generator pool --pool session_tokens
```

Pools are **project-scoped** (`intruder_pools`).

#### `dates` — calendar range

```bash
talos intruder payload set $SID --var day --generator dates \
  --start-date 2024-01-01 --end-date 2024-01-31 \
  --step-days 1 --date-format '%Y-%m-%d'
```

#### `bruteforce` — charset product (Burp-style)

```bash
talos intruder payload set $SID --var pin --generator bruteforce \
  --charset '0123456789' --min-len 4 --max-len 4
```

| Guard | Value |
|-------|-------|
| Default charset | `a-z` + `0-9` |
| Default lengths | 1..3 |
| Soft cap | 100_000 combos without force |
| Hard max length | 12 (even with force) |

#### `random` — random strings

```bash
talos intruder payload set $SID --var tok --generator random \
  --count 100 --length 16 --charset 'abcdef0123456789' --seed 42
```

Use `--seed` for deterministic resume-friendly sequences.

#### `pattern` — template expansion

```bash
talos intruder payload set $SID --var name --generator pattern \
  --pattern 'user{n:04d}' --start 1 --end 100

talos intruder payload set $SID --var mail --generator pattern \
  --pattern 'user{n}@test.local' --start 1 --end 50
```

| Placeholder | Meaning |
|-------------|---------|
| `{n}` / `{i}` | Integer counter start..end |
| `{n:04d}` | Printf-padded counter |
| `{hex}` / `{h}` / `{HEX}` | Hex counter |
| `{a}` / `{alpha}` | a, b, … z, aa, … |
| `{rand:N}` | N random alnum chars (seeded) |
| no placeholders | Single static string |

---

### 8.3 Processors (post-generation chain)

```bash
talos intruder payload set $SID --var q --generator static --value 'a b' \
  --processor strip --processor url_encode

talos intruder payload set $SID --var h --generator static --value secret \
  --processor md5 --processor prefix:token=
```

| Processor | Effect |
|-----------|--------|
| `url_encode` / `url_decode` | Percent-encoding |
| `base64_encode` / `base64_decode` | Base64 |
| `to_lower` / `to_upper` | Case |
| `html_encode` / `html_decode` | HTML entities |
| `md5` / `sha1` / `sha256` | Hex digests |
| `strip` | Trim whitespace |
| `prefix:<text>` | Prepend (case-preserving text after colon) |
| `suffix:<text>` | Append |

Chain is sequential: each processor sees the previous output.

---

## 9. Strategies

```bash
talos intruder strategy set <sid> --type TYPE \
  [--primary VAR] \          # single
  [--set VAR]…               # multi-set order (repeatable)
```

| Type | Behavior | Attempt count (est.) |
|------|----------|----------------------|
| **`single`** | One payload set drives one primary variable; others fixed/baseline | `len(primary_set)` |
| **`sniper`** | Same payload list applied to **each** target variable in turn (one var mutated per attempt) | `len(targets) × len(payloads)` |
| **`pitchfork`** | N sets advance **in lockstep** (zip by position); stops at shortest | `min(len(sets))` |
| **`zip`** | Alias of pitchfork | same |
| **`cluster_bomb`** | Full **cartesian product** of sets | product of lengths |
| **`cartesian`** | Config alias of `cluster_bomb` | same |

### Examples

**Single (IDOR enum):**

```bash
talos intruder strategy set $SID --type single --primary user_id
```

**Sniper (same wordlist against id, then email, then role):**

```bash
# Template has three vars; one shared payload set named "probe"
talos intruder payload set $SID --var probe --generator wordlist --file ./probes.txt
talos intruder strategy set $SID --type sniper
# Engine targets all non-fixed template variables unless configured otherwise
```

**Pitchfork (paired credentials):**

```bash
talos intruder payload set $SID --var user --generator wordlist --file users.txt
talos intruder payload set $SID --var pass --generator wordlist --file passes.txt
talos intruder strategy set $SID --type pitchfork --set user --set pass
# attempt i: user=users[i], pass=passes[i]
```

**Cluster bomb (product — can explode):**

```bash
talos intruder strategy set $SID --type cluster_bomb --set user --set pass
# attempts = |users| × |passes|  → confirm if >1000
```

---

## 10. Timing & concurrency

```bash
talos intruder timing set <sid> \
  --mode fixed|unlimited|token_bucket|adaptive \
  [--rps 2] \
  [--concurrency 1] \
  [--concurrency-per-host N] \
  [--jitter-ms 0] \
  [--timeout-s 30] \
  [--burst-size 1] \
  [--min-rps 0.25] [--max-rps 10] [--slow-ms 2000]
```

| Mode | Behavior |
|------|----------|
| **`fixed`** (default) | Target RPS spacing + optional jitter |
| **`unlimited`** | No rate sleep; concurrency still limits in-flight |
| **`token_bucket`** | Burst up to `burst_size`, refill at `rps` |
| **`adaptive`** | Raises/lowers effective RPS from latency/errors (429/5xx, slow_ms window) |

**Defaults (safety-first):**

| Knob | Default |
|------|---------|
| rps | 2.0 |
| max_concurrency | 1 |
| timeout_s | 30 |
| max_concurrency_per_host | unset (no extra host limit) |

Scheduler also slices work: default **100 attempts** or **60s wall** per segment, then another job continues (checkpointed).

---

## 11. Storage modes

```bash
talos intruder storage set <sid> --mode metrics_only|sample_flows|all_flows \
  [--sample-rate 0.01] \
  [--store-interesting / --no-store-interesting] \
  [--max-body-bytes 65536]

talos intruder storage show <sid>
```

| Mode | What is written |
|------|-----------------|
| **`metrics_only`** (default) | `intruder_results` metrics only; optional store of interesting bodies |
| **`sample_flows`** | Bernoulli sample of full flow rows + interesting |
| **`all_flows`** | Full flow row per attempt — **requires confirm** on run |

Intruder-sourced flows **skip** passive / error_intel hooks on insert (by design) to avoid noise.

---

## 12. Match rules (interesting results)

```bash
talos intruder match add <sid> \
  [--tag LABEL] \
  [--status 200] \
  [--body-contains TEXT] \
  [--regex PATTERN] \
  [--length-delta-gt N] \
  [--time-gt-ms N]

talos intruder match list <sid>
talos intruder match clear <sid>
```

All specified criteria on a rule are **AND**ed. Multiple rules are independent (any match → tags).

| Criterion | Meaning |
|-----------|---------|
| `status` | Exact status code |
| `body_contains` | Substring in response body text |
| `regex` | Regex search on body |
| `length_delta_gt` | `|cur_len - baseline_len| > N` |
| `time_gt_ms` | Response duration above threshold |

Matched attempts get `match_tags` and `interesting=true`.

```bash
# Classic “different length than baseline”
talos intruder match add $SID --tag delta --status 200 --length-delta-gt 40

# Timing oracle
talos intruder match add $SID --tag slow --time-gt-ms 1500

# Error surface
talos intruder match add $SID --tag err --regex 'Exception|SQL|stack trace' 
```

---

## 13. Grep extract & pools (chaining)

### 13.1 Grep rules

```bash
talos intruder grep add <sid> \
  --name session_tokens \
  --regex 'token":"([^"]+)"' \
  [--group 1] \
  [--source body|headers|header:Set-Cookie] \
  [--ignore-case] \
  [--max-matches 50] \
  [--no-pool] \
  [--tag-interesting]

talos intruder grep list <sid>
talos intruder grep clear <sid>
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--name` | required | Extract key + default pool name |
| `--regex` | required | Must compile; use a capture group |
| `--group` | 1 | 0 = full match |
| `--source` | body | Or all headers / one header |
| `--max-matches` | 50 | Cap unique captures per response (max 1000) |
| `--no-pool` | off | Only store on the result row |
| `--tag-interesting` | off | Mark attempt interesting when this rule hits |

Captures land in `intruder_results.grepped_json` and, unless `--no-pool`, accumulate into project pools (cap ~50_000 values).

### 13.2 Pool commands

```bash
talos intruder pool list
talos intruder pool show session_tokens --limit 100
talos intruder pool export session_tokens --out ./tokens.txt
talos intruder pool clear session_tokens     # empty values, keep row
talos intruder pool delete session_tokens [--force]
```

### 13.3 Chain recipe

**Session A** — login/list endpoint, extract IDs:

```bash
talos intruder grep add $SID_A --name object_ids --regex '"id"\s*:\s*(\d+)' --group 1
talos intruder session run $SID_A
```

**Session B** — attack detail endpoint using pool:

```bash
talos intruder payload set $SID_B --var object_id --generator pool --pool object_ids
talos intruder strategy set $SID_B --type single --primary object_id
talos intruder session run $SID_B
```

---

## 14. Results

```bash
talos intruder results list <sid> \
  [--interesting] [--limit 100] [--offset 0] [--status-code 200]

talos intruder results show <sid> <attempt_index>

talos intruder results export <sid> --out ./dir_or_stem \
  [--jsonl] [--csv] [--interesting]
```

Each result typically includes: attempt index, variables, status_code, duration_ms, body_length, fingerprint hashes, match_tags, grepped map, interesting flag, optional flow_id / finding_id.

---

## 15. Findings promote (Phase 5, **off by default**)

```bash
talos intruder findings set <sid> \
  --promote on \
  [--max 25] \
  [--on interesting|matched] \
  [--cluster-by session|endpoint] \
  [--only-success on|off] \
  [--force]

talos intruder findings show <sid>

# Offline promote after a run (does not require promote=on if --enable)
talos intruder findings promote <sid> [--enable] [--force]
```

| Setting | Default | Note |
|---------|---------|------|
| promote | **false** | Must opt in |
| max_findings | 25 | Hard cap per session |
| on | interesting | `matched` is alias |
| only_success | true | Skip transport failures |
| cluster_by | session | Cluster key `INTRUDER:<session_id>` |

Idempotent via `intruder_results.finding_id`. Engine promote is fail-soft (errors logged, run continues).

---

## 16. Suggest (offline heuristics — not an external LLM)

```bash
talos intruder suggest <sid> [--format json]
talos intruder suggest <sid> --apply \
  [--replace-payloads] [--no-match] [--no-grep] [--force]
```

`suggest` inspects template variables (names, semantic_types), existing payloads, and project pools, then proposes:

- Generators per variable (numbers for `*_id`, uuid, pattern emails, dates, PIN bruteforce, …)
- Strategy (single vs sniper)
- Timing hints
- Starter match/grep rules

`--apply` writes suggestions into config (fills missing payloads by default; `--replace-payloads` overwrites).

**Schema name:** `intruder_suggest/v1` in JSON output. Safe for agents: **deterministic, no network**.

---

## 17. Safety caps & error codes

### 17.1 Hard defaults (`models.py`)

| Cap | Default |
|-----|---------|
| max_attempts | 10_000 |
| max_results | 10_000 |
| max_duration_s (active) | 3600 |
| auth_fail_threshold | 20 consecutive auth-ish failures |
| confirm threshold (estimate) | 1_000 |
| wordlist max | 1e6 lines / 64 MiB |
| slice max attempts / wall | 100 / 60s |
| pool max values | 50_000 |
| findings max | 25 |

### 17.2 Run-time safety checks

| Check | Behavior |
|-------|----------|
| Endpoint annotated **logout** | Hard block (`endpoint_annotated_logout`) |
| Endpoint annotated **dangerous** | Confirm unless `--force` |
| URL **out of project scope** | Hard block if project has scope |
| estimate > 1000 | Confirm unless `--force` |
| storage `all_flows` | Confirm unless `--force` |
| session busy | Error; `--force` cancels and re-runs |

### 17.3 Stable error codes (AI contract)

| Code | Typical cause |
|------|----------------|
| `missing_baseline` | Empty template URL/method |
| `no_variables` | No template variables |
| `unbound_variable` | Payload/strategy not bound |
| `empty_generator` | No values / missing file |
| `invalid_numbers` / `invalid_dates` / `invalid_pattern` / `invalid_random` | Bad generator options |
| `sniper_no_targets` | Sniper with no variables |
| `multiset_unbound` / `cluster_bomb_empty` | Multi-set misconfigured |
| `unknown_plugin` | Bad generator/strategy/processor name |
| `wordlist_too_large` / `bruteforce_too_large` | Need `--force` or shrink |
| `path_inject_unavailable` | Path var without `{name}` in normalized path |
| `confirm_required` | Estimate/storage needs confirmation |
| `endpoint_annotated_logout` / `_dangerous` | Safety annotations |
| `out_of_scope` | Scope policy |
| `session_busy` | Already running/queued |
| `invalid_grep` / `pool_not_found` / `param_not_found` | Grep/pool/param issues |
| `invalid_findings` / `findings_no_match` | Findings config / nothing to promote |
| `invalid_status` | Wrong lifecycle action (e.g. resume non-paused) |

JSON errors typically include `"code"` and `"error"` / message on stderr with non-zero exit.

---

## 18. Config document shape (schema_version 1)

Logical structure of `config_json` (defaults merged on validate):

```json
{
  "schema_version": 1,
  "session": {
    "base_flow_id": "…",
    "endpoint_id": "…",
    "project_id": "…",
    "name": "…"
  },
  "template": {
    "method": "GET",
    "url": "https://…",
    "headers": {},
    "body": null,
    "variables": [
      {
        "name": "user_id",
        "location": "query",
        "path": "user_id",
        "original_value": "1",
        "fixed_value": null,
        "semantic_type": "integer"
      }
    ],
    "normalized_path": "/api/users/{user_id}"
  },
  "payload_sets": {
    "user_id": {
      "generator": "numbers",
      "options": { "start": 1, "end": 200, "step": 1 },
      "processors": []
    }
  },
  "strategy": { "type": "single", "options": { "primary": "user_id" } },
  "timing": {
    "mode": "fixed",
    "rps": 2.0,
    "max_concurrency": 1,
    "max_concurrency_per_host": null,
    "jitter_ms": 0,
    "timeout_s": 30,
    "burst_size": 1,
    "min_rps": 0.25,
    "max_rps": 10.0,
    "slow_ms": 2000
  },
  "slice": { "max_attempts": 100, "max_wall_s": 60.0 },
  "storage": {
    "mode": "metrics_only",
    "sample_rate": 0.0,
    "store_interesting_bodies": true,
    "max_body_bytes": 65536,
    "max_results": 10000
  },
  "match": [],
  "grep": [],
  "findings": {
    "promote": false,
    "on": "interesting",
    "max_findings": 25,
    "only_success": true,
    "cluster_by": "session"
  },
  "safety": {
    "respect_logout": true,
    "respect_dangerous": true,
    "require_in_scope": true,
    "skip_auth_artifacts": false,
    "max_attempts": 10000,
    "max_duration_s": 3600,
    "auth_fail_threshold": 20
  }
}
```

Agents may build this offline and apply with `session configure --file`.

---

## 19. Worked recipes

### 19.1 Query IDOR (numbers + length delta)

```bash
SID=$(… create …)
talos intruder template set-var $SID --name id --location query
talos intruder payload set $SID --var id --generator numbers --start 1 --end 500
talos intruder strategy set $SID --type single --primary id
talos intruder match add $SID --tag hit --status 200 --length-delta-gt 30
talos intruder session run $SID --force
```

### 19.2 Header auth fuzz (static + processor)

```bash
talos intruder template set-var $SID --name auth --location header --path Authorization
talos intruder payload set $SID --var auth --generator wordlist --file ./tokens.txt \
  --processor prefix:'Bearer '
talos intruder strategy set $SID --type single --primary auth
talos intruder match add $SID --tag ok --status 200
```

### 19.3 Path parameter (brace required)

```bash
# endpoint normalized_path must be like /api/orders/{order_id}
talos intruder template set-var $SID --name order_id --location path --path order_id
talos intruder payload set $SID --var order_id --generator numbers --start 1000 --end 1100
```

### 19.4 Sniper — find which param reflects payload

```bash
talos intruder template from-params $SID --locations query,body
talos intruder payload set $SID --var probe --generator static \
  --value 'talos-canary-9f3a' --value '<script>x</script>'
# Ensure strategy sniper targets each param; often pair with from-params variables
talos intruder strategy set $SID --type sniper
talos intruder match add $SID --tag reflect --body-contains 'talos-canary-9f3a'
```

### 19.5 Pitchfork login spray

```bash
talos intruder template set-var $SID --name username --location body
talos intruder template set-var $SID --name password --location body
talos intruder payload set $SID --var username --generator wordlist --file users.txt
talos intruder payload set $SID --var password --generator wordlist --file passes.txt
talos intruder strategy set $SID --type pitchfork --set username --set password
talos intruder timing set $SID --mode fixed --rps 1 --concurrency 1
talos intruder match add $SID --tag success --status 200 --body-contains '"token"'
```

### 19.6 Cluster bomb (small product only)

```bash
talos intruder payload set $SID --var a --generator static --value x --value y
talos intruder payload set $SID --var b --generator static --value 1 --value 2 --value 3
talos intruder strategy set $SID --type cluster_bomb --set a --set b
# 6 attempts
```

### 19.7 PIN / OTP bruteforce with adaptive rate

```bash
talos intruder payload set $SID --var otp --generator bruteforce \
  --charset '0123456789' --min-len 4 --max-len 4
talos intruder strategy set $SID --type single --primary otp
talos intruder timing set $SID --mode adaptive --rps 1 --min-rps 0.2 --max-rps 3 --slow-ms 800
talos intruder session run $SID --force   # 10000 attempts → force
```

### 19.8 Date parameter

```bash
talos intruder payload set $SID --var day --generator dates \
  --start-date 2023-01-01 --end-date 2023-12-31 --step-days 7 \
  --date-format '%Y-%m-%d'
```

### 19.9 Pattern-generated emails

```bash
talos intruder payload set $SID --var email --generator pattern \
  --pattern 'user{n}@example.com' --start 1 --end 200
```

### 19.10 Grep → pool → second attack

```bash
# Pass 1
talos intruder grep add $SID1 --name api_keys --regex 'key=([A-Za-z0-9]+)' --group 1
talos intruder session run $SID1 --force
talos intruder pool show api_keys

# Pass 2
talos intruder session create --from $FLOW2 --name use-keys
talos intruder template set-var $SID2 --name key --location query
talos intruder payload set $SID2 --var key --generator pool --pool api_keys
talos intruder session run $SID2 --force
```

### 19.11 Agent auto-config via suggest

```bash
talos --format json intruder suggest $SID
talos --format json intruder suggest $SID --apply --force
talos --format json intruder session validate $SID --force
# Review estimate, then run
talos --format json intruder session run $SID --force
```

### 19.12 Full config file for agents

```bash
# Write attack.json (see §18), then:
talos intruder session create --from $FLOW --name agent-run
talos intruder session configure $SID --file attack.json --force
talos intruder session run $SID --force
```

### 19.13 Promote findings after review

```bash
talos intruder results list $SID --interesting --format json
talos intruder findings set $SID --promote on --max 10 --cluster-by session
talos intruder findings promote $SID --enable --force
talos findings list   # project findings UI / CLI
```

---

## 20. AI / automation playbook

### Recommended agent loop

1. **Pick baseline** — flow with real cookies/auth if needed (Intruder reuses baseline headers unless you mutate them).
2. **Create session** — capture `session_id` from JSON.
3. **Define variables** — `template set-var` or `from-params` or raw `{{…}}`.
4. **Payloads** — prefer small generators first; estimate before huge wordlists.
5. **Strategy** — start with `single`; use `cluster_bomb` only when product is small.
6. **Match/grep** — without match rules, “interesting” is sparse (grep `--tag-interesting` helps).
7. **`validate --format json`** — read `estimate_attempts`.
8. **`run --force`** if non-interactive and estimate accepted.
9. **Poll `status`** until terminal; handle `paused` with `resume` after global scheduler pauses.
10. **`results list --interesting`** / export; optional findings.

### Non-interactive flags

Always pass for CI/agents:

```text
--format json
--force          # when confirms would block and risk is accepted
```

### Do / Don’t

| Do | Don’t |
|----|-------|
| Keep default RPS=2, concurrency=1 until proven safe | Fire cluster_bomb on two large wordlists |
| Use durable file paths for wordlist/csv/json | Delete temp wordlists after configure |
| Resume sessions after global scheduler pause | Assume `scheduler resume` resumes Intruder |
| Filter `--interesting` on high-volume runs | Enable `all_flows` without disk budget |
| Opt-in findings only after reviewing tags | Leave promote on with weak match rules |
| Clone session to iterate config | Mutate a running session’s payload mid-flight |

### Distinct from Control Panel

CLI is the engine SSOT. Control Panel wraps the same CLI for create/configure/run and stores wordlists under:

```text
{project_data_dir}/intruder/artifacts/{session_id}/
```

Agents scripting against a project DB can use pure CLI without the UI.

---

## 21. Persistence (where state lives)

| Store | Contents |
|-------|----------|
| `intruder_sessions` | Config, status, progress, checkpoint, control_flag, job_id |
| `intruder_results` | Per-attempt metrics, tags, grepped, finding_id |
| `intruder_pools` | Project-wide extracted value sets |
| `scheduler_jobs` | `job_type=intruder_session`, meta.session_id |
| Optional `flows` | When storage mode stores bodies (`source=intruder`) |

Config `schema_version` is **independent** of project DDL schema version.

---

## 22. Package map (for code navigators)

```
talos/intruder/
  cli.py              # all CLI surface
  session.py          # create/run/pause/resume/stop/clone/enqueue
  engine.py           # run_session_segment (HTTP loop)
  config_schema.py    # defaults + validate + estimate
  models.py           # statuses, caps, constants, dataclasses
  template.py         # {{vars}} + inject render
  timing.py           # fixed / unlimited / token_bucket / adaptive
  match.py            # interesting rules
  grep.py             # extract rules
  results.py          # metrics + export
  suggest.py          # offline heuristics
  findings_bridge.py  # optional promote
  db.py               # SQLite access
  generators/         # wordlist, numbers, static, uuid, csv, json, …
  strategies/         # single, sniper, pitchfork, cluster_bomb
  processors/         # encode/hash/case/prefix/suffix
```

Tests: `tests/test_intruder_phase{1..5}.py`.

---

## 23. Quick reference card

```bash
# Create → configure → run → export
talos --project P intruder session create --from FLOW --name NAME
talos --project P intruder template set-var SID --name V --location query
talos --project P intruder payload set SID --var V --generator numbers --start 1 --end 100
talos --project P intruder strategy set SID --type single --primary V
talos --project P intruder timing set SID --mode fixed --rps 2 --concurrency 1
talos --project P intruder match add SID --status 200 --length-delta-gt 50
talos --project P intruder session validate SID --format json
talos --project P intruder session run SID --format json
talos --project P intruder session status SID --format json
talos --project P intruder results list SID --interesting --format json
talos --project P intruder results export SID --out ./out --jsonl --interesting

# Control
talos --project P intruder session pause|resume|stop SID

# Power tools
talos --project P intruder suggest SID --apply --format json
talos --project P intruder template from-params SID --set-payloads
talos --project P intruder grep add SID --name POOL --regex '…' --group 1
talos --project P intruder payload set SID --var X --generator pool --pool POOL
talos --project P intruder findings set SID --promote on --max 25
```

---

## 24. Version / phase summary

| Phase | Capabilities |
|-------|----------------|
| **1** | Session lifecycle, single/sniper, wordlist/numbers/static, match, fixed timing, metrics, scheduler slices, CLI/export |
| **2** | pitchfork/zip/cluster_bomb, storage modes, clone, host concurrency, expanded processors |
| **3** | grep + pools, uuid/csv/json/example_values/pool generators, from-params |
| **4** | token_bucket/adaptive timing, dates/bruteforce/random/pattern, suggest |
| **5** | Optional findings promote, finding_id lineage, hardening |

---

*Generated from implementation under `talos/intruder/` (Phases 1–5). When CLI flags and this guide disagree, trust `--help` and the code; please update this file.*
