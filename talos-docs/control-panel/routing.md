# Backend routing

Complete inventory of HTTP routes exposed by `talos_ui`. Unless noted, mutation responses are `{ "steps": [ CommandResult, ... ] }` when using `run_scoped`, or a single `CommandResult` dict for bare `cli.run`.

**Convention:** most domain routes take `project_id` as a **query parameter**. Path parameters are used for resource ids (project, endpoint, flow, finding, role, mutation, etc.).

**CommandResult fields:** `cmd`, `cmd_str`, `stdout`, `stderr`, `exit_code`, `duration_ms`, `ok`, `timed_out`.

---

## Health

| Method | URL | Purpose | Request | Response | CLI | DB |
|--------|-----|---------|---------|----------|-----|-----|
| GET | `/api/health` | Health / config probe | — | `{ ok, talos_home, projects_root, talos_bin, registry_exists }` | — | Checks registry path exists |

---

## Projects (`/api/projects`)

| Method | URL | Purpose | Request | Response | CLI | DB / files |
|--------|-----|---------|---------|----------|-----|------------|
| GET | `/api/projects` | List projects | — | `{ projects, active_project_id }` | — | `registry.json` |
| GET | `/api/projects/active` | Active project | — | `{ active_project_id, project }` | — | registry |
| GET | `/api/projects/status` | CLI project status | — | `CommandResult` | `project status` | — |
| POST | `/api/projects/close` | Close active | — | `CommandResult` | `project close` | — |
| POST | `/api/projects` | Create project | body: `name`, `description?`, `scope[]` | `CommandResult` | `project create …` | — |
| GET | `/api/projects/{project_id}` | Project detail | path | `{ project, active_project_id }` | — | registry |
| GET | `/api/projects/{project_id}/summary` | Dashboard counters | path | counts object | — | `flows`, `endpoints`, `findings`, `scheduler_jobs`, `roles`, `modules` |
| POST | `/api/projects/{project_id}/open` | Activate project | path | `CommandResult` | `project open` | — |
| DELETE | `/api/projects/{project_id}` | Delete / purge | query `force?`, `purge?` | `CommandResult` | `project delete [--purge] [--force]` | — |
| POST | `/api/projects/{project_id}/rename` | Rename (may re-slug) | body: `new_name` | `CommandResult` | `project rename` | — |
| POST | `/api/projects/{project_id}/description` | Set description note | body: `description` | `CommandResult` | `project description` | — |
| POST | `/api/projects/{project_id}/scope` | Replace scope (legacy) | body: `patterns[]` | result/steps | `project scope <id> …` or `scope clear` | — |
| POST | `/api/projects/{project_id}/scope/add` | Add one Basic Scope prefix | body: `prefix` | steps | scoped `project scope add` | — |
| DELETE | `/api/projects/{project_id}/scope/entry?prefix=` | Remove one prefix | query `prefix` | steps | scoped `project scope remove` | — |
| POST | `/api/projects/{project_id}/scope/bulk` | Bulk paste (one prefix per line) | body: `text`, `replace?` | steps | temp file → `project scope import` | — |
| POST | `/api/projects/{project_id}/scope/import` | Import `.txt` upload | multipart `file`, `replace?` | steps | temp file → `project scope import` | — |
| POST | `/api/projects/{project_id}/constraints` | Capture constraints | body: `store_bodies?`, `max_body_size?` | `CommandResult` | `project constraints …` | — |
| POST | `/api/projects/{project_id}/open-directory` | Open project directory in OS file explorer | body: `target` (`data_dir` \| `database_dir`) | `{ ok, project_id, target, path, message }` | — (OS UI helper) | registry path resolution only |
| GET | `/api/projects/{project_id}/outscope` | List out-of-scope prefixes | path | `{ prefixes, domains }` | — | `out_of_scope_domains` |
| POST | `/api/projects/{project_id}/outscope` | Add prefix | body: `prefix` or `domain` | steps | scoped `project outscope add` | — |
| DELETE | `/api/projects/{project_id}/outscope/{prefix}` | Remove prefix | path | steps | scoped `project outscope remove` | — |
| POST | `/api/projects/{project_id}/outscope/bulk` | Bulk paste | body: `text`, `replace?` | steps | temp file → `project outscope import` | — |
| POST | `/api/projects/{project_id}/outscope/import` | Import `.txt` upload | multipart `file` | steps | temp file → `project outscope import` | — |

**Augmented project shape** (list + detail): `id`, `name`, `description`, `scope`, `created_at`, `status`, `constraints` (`capture_in_scope_only`, `store_bodies`, `max_body_size`), `data_dir`, `db_path`, `db_exists`, `active`.

Notes:

- Static paths (`/active`, `/status`, `/close`) are registered before `/{project_id}` routes.
- Incremental scope/outscope mutations use `run_scoped` (open then command).
  Bulk/import write operator text to a **temp file** and call Talos core
  `import` — the panel never mutates registry/SQLite for scope and never
  accepts a client-supplied backend filesystem path.
- Legacy `POST …/scope` with `patterns[]` still replaces the full list via CLI.
- UI always passes `force=true` on delete/purge (non-interactive CLI-015).
- Scope upload size is capped (~256 KiB); files must be UTF-8 text.
- **Open directory** is a local OS integration, not a Talos mutation:
  - Browser sends **project id + predefined target only** (`data_dir` or
    `database_dir`). Arbitrary filesystem paths are rejected (enum validation).
  - Backend resolves paths via `project_data_dir` / `project_db_path` (registry
    `data_dir` overrides are respected; no hardcoded prefix check against
    `PROJECTS_ROOT`).
  - `database_dir` opens the **parent** of `talos.db` (works before the DB
    file exists if the parent directory exists).
  - Supported platforms: Linux (`xdg-open`), Windows (`os.startfile`).
  - Does not write registry or SQLite. Does not route through the Talos CLI.

---

## Proxy (`/api/proxy`)

Lifecycle ownership is **Talos core** (`ProxyRuntimeManager`). The Control Panel only invokes CLI commands and exposes runtime snapshots. There is **no** `restart-if-running` endpoint and no Control Panel restart-after-mutation coupling.

| Method | URL | Purpose | Request | Response | CLI | DB |
|--------|-----|---------|---------|----------|-----|-----|
| GET | `/api/proxy/status` | Runtime snapshot | — | Talos status JSON + `running` / `transitional` | `proxy status --format json` | — |
| GET | `/api/proxy/logs` | Tail managed log | query `tail` (default 300) | `{ lines, path }` | reads `TALOS_HOME/runtime/proxy.log` | — |
| POST | `/api/proxy/start` | Start proxy | body: `listen_host?`, `port?` | `{ steps }` | `proxy start [--listen-host] [--port]` | — |
| POST | `/api/proxy/stop` | Stop proxy | — | `{ steps }` | `proxy stop` | — |
| POST | `/api/proxy/restart` | Operator restart | body host/port optional | `{ steps }` | `proxy restart […]` | — |
| POST | `/api/proxy/kill` | Free stuck port / orphans | body: `listen_host?`, `port?`, `force?` | `{ steps }` | `proxy kill [--port] [--force]` | — |
| GET | `/api/proxy/config` | Effective proxy mode | — | `{ project_id, mode, upstream_url }` | `proxy config --format json` | — |
| POST | `/api/proxy/config` | Persist Direct/Upstream | body: `upstream_url?` or `direct: true` | `{ steps }` | `proxy config --upstream` / `--no-upstream` | — |

Defaults for listen host/port are owned by the Talos CLI when omitted (`127.0.0.1:8080`).

---

## Configuration (`/api/configuration`)

Thin surface over Talos layered configuration (`talos config …`). Never merges layers in FastAPI; never writes YAML/SQLite directly.

| Method | URL | Purpose | Request | Response | CLI |
|--------|-----|---------|---------|----------|-----|
| GET | `/api/configuration/context` | Paths + binding | query `project_id?` | talos_home, global/project paths, precedence | `--project?` `config show --format json` |
| GET | `/api/configuration/schema` | Types/defaults catalog | — | sections + settings metadata | `config schema --format json` |
| GET | `/api/configuration/effective` | Merged leaves + sources | query `project_id?`, `section?` (`proxy`\|`capture`\|`scheduler`\|`attack`\|`http`\|`parameter_intel`\|`url_sink`) | values, sources, source_counts, section_cards | `--project?` `config effective --format json` |
| GET | `/api/configuration/settings` | Normalized rows for UI table | query `project_id?`, `section?` | settings[] (key, type, effective_value, source, …) | effective + schema |
| GET | `/api/configuration/get` | One key | query `key`, `project_id?` | `{ key, value, source }` | `--project?` `config get --format json` |
| POST | `/api/configuration/value` | Set override | body `key`, `value`, `scope` (`project`\|`global`); query `project_id` when project | `{ steps }` | project: `run_scoped` `config set`; global: `cli.run` `config set --global` |
| POST | `/api/configuration/unset` | Remove override (inherit) | body `key`, `scope`; query `project_id` when project | `{ steps }` | `config unset` / `--global` |
| DELETE | `/api/configuration/value` | Same as unset | query `key`, `scope`, `project_id?` | `{ steps }` | same as POST unset |
| POST | `/api/configuration/open-directory` | OS open parent of config file | body `target` (`global_config`\|`project_config`); query `project_id?` | `{ ok, path, … }` | paths from `config show` only (not CLI mutation) |

Notes:

- Global writes **must not** call `run_scoped` (would rewrite active project).
- Project reads prefer `talos --project <id> config …` so registry ACTIVE is unchanged.
- Value tokens for set: bools `true`/`false`, numbers as decimal strings, lists/maps as JSON.

---

## Roles (`/api/roles`)

| Method | URL | Purpose | Request | Response | CLI | DB |
|--------|-----|---------|---------|----------|-----|-----|
| GET | `/api/roles` | List roles | query `project_id` | `{ roles }` | — | `roles` |
| POST | `/api/roles` | Create | query `project_id`; body `name` | steps | scoped `role create` | — |
| POST | `/api/roles/set` | Use for capture (activate) | query `project_id`; body `name` | steps | scoped `role set` | — |
| POST | `/api/roles/unset` | Reset active to `global` | query `project_id` | steps | scoped `role unset` | — |
| POST | `/api/roles/rename` | Rename (UUID stable) | query `project_id`; body `name`, `new_name` | steps | scoped `role rename` | — |
| POST | `/api/roles/delete` | Delete + cascade | query `project_id`; body `name` | steps | scoped `role delete --force` | — |

---

## Modules (`/api/modules`)

| Method | URL | Purpose | Request | Response | CLI | DB |
|--------|-----|---------|---------|----------|-----|-----|
| GET | `/api/modules` | List modules | query `project_id` | `{ modules }` | — | `modules` |
| POST | `/api/modules` | Create | query `project_id`; body `name`, `description?` | steps | scoped `module create` | — |
| POST | `/api/modules/set` | Use for capture (activate) | query `project_id`; body `name` | steps | scoped `module set` | — |
| POST | `/api/modules/unset` | Reset active to `global` | query `project_id` | steps | scoped `module unset` | — |
| POST | `/api/modules/rename` | Rename (UUID stable) | query `project_id`; body `name`, `new_name` | steps | scoped `module rename` | — |
| POST | `/api/modules/delete` | Delete + cascade | query `project_id`; body `name` | steps | scoped `module delete --force` | — |

---

## Access (`/api/access`)

| Method | URL | Purpose | Request | Response | CLI | DB |
|--------|-----|---------|---------|----------|-----|-----|
| GET | `/api/access/matrix` | Role×module matrix + traffic counts | query `project_id` | `{ cells }` with `client_allowed`, `server_expected`, `flow_count`, `endpoint_count` | — | `roles` CROSS JOIN `modules` LEFT JOIN `access_map` + optional `flows` agg |
| POST | `/api/access/client` | Set client allowed | body `role`, `module`, `value` | steps | scoped `access client set` (value lowercased) | — |
| POST | `/api/access/server` | Set server expected | same | steps | scoped `access server set` | — |
| POST | `/api/access/client/unset` | Unset client | body `role`, `module` | steps | scoped `access client unset` | — |
| POST | `/api/access/server/unset` | Unset server | body pair | steps | scoped `access server unset` | — |
| POST | `/api/access/delete` | Delete mapping | body pair | steps | scoped `access delete --force` (UI confirmed) | — |
| POST | `/api/access/bulk` | Batch mutations | body `operations[]` (`op`, `role`, `module`, `value?`); max 200 | `{ steps, ok, applied, failed }` | sequential scoped CLI per op | — |
| GET | `/api/access/coverage` | Structured coverage | query `project_id` | `{ rows }` | — | `get_access_coverage` |
| GET | `/api/access/signals` | Structured signals | query `project_id` | `{ multi_role, server_deny_endpoints, deny_with_flows, allow_without_flows }` | — | access analysis helpers |
| POST | `/api/access/coverage` | CLI coverage report | query `project_id` | steps | scoped `access coverage` | — |
| POST | `/api/access/signals` | CLI signals report | query `project_id` | steps | scoped `access signals` | — |

---

## Auth artifacts (`/api/auth`)

| Method | URL | Purpose | Request | Response | CLI | DB |
|--------|-----|---------|---------|----------|-----|-----|
| GET | `/api/auth` | List artifact names | query `project_id` | `{ artifacts }` | — | `auth_config` |
| POST | `/api/auth/set` | Add cookie/header names | body `cookies[]`, `headers[]` | steps | scoped `auth set --cookie/--header` | — |
| POST | `/api/auth/unset` | Remove names | same body shape | steps | scoped `auth unset …` | — |
| POST | `/api/auth/clear` | Clear all | query `project_id` | steps | scoped `auth clear --force` | — |
| POST | `/api/auth/test` | Auth-bypass test (not role setup) | body `endpoint_id`, `right_now?` | steps | scoped `auth test` | — |
| GET | `/api/auth/test-results` | Recent results | query `project_id`, `limit?` | `{ results }` | — | `auth_test_results` JOIN `flows` |

---

## Auth config (`/api/auth-config`)

All routes take query `project_id` unless noted. Path `role_id` is the role identifier used by the CLI.

| Method | URL | Purpose | Request | Response | CLI | DB / files |
|--------|-----|---------|---------|----------|-----|------------|
| GET | `/{role_id}/state` | Full role auth snapshot | — | provider, artifacts, session, flows (+ method/path), health (parsed signals), control_flows, suspicion, session_state, ages | — | multiple tables |
| POST | `/{role_id}/provider` | Set provider | body `provider` (`auto`\|`manual`) | steps | `auth-config set-provider` | — |
| GET | `/{role_id}/session/file` | Load session file | — | `{ path, content, steps }` | `set-session path` then read file | `<data_dir>/auth_sessions/<role>.txt` |
| POST | `/{role_id}/session/file` | Save session file | body `content` | `{ path, steps }` | path ensure + **direct write** | same file |
| POST | `/{role_id}/session/apply` | Apply session | — | steps | `set-session <role>` | — |
| POST | `/{role_id}/session/clear` | Clear manual session (recovery) | — | steps | `clear-session` | — |
| POST | `/{role_id}/flows/{flow_id}` | Attach login flow | — | steps | `add-flow` | — |
| DELETE | `/{role_id}/flows/{flow_id}` | Detach flow | — | steps | `remove-flow` | — |
| GET | `/{role_id}/flows/{flow_id}/extractor` | Show extractor source | — | `{ code, configured }` | — | `auth_flow_config` |
| POST | `/{role_id}/flows/{flow_id}/extractor` | Set extractor code | body `code` | steps | temp file + `set-extractor` | — |
| POST | `/{role_id}/flows/{flow_id}/extractor/edit` | Edit via editor shim | body `code` | steps | editor content + `edit-extractor` | — |
| DELETE | `/{role_id}/flows/{flow_id}/extractor` | Remove extractor | — | steps | `remove-extractor` | — |
| POST | `/{role_id}/test/{flow_id}` | Test flow+extractor (no store; full tokens) | — | steps | `auth-config test --format json` | — |
| POST | `/{role_id}/validate` | Validate session | — | steps | `validate` | — |
| POST | `/{role_id}/refresh` | Force refresh | — | steps | `refresh` | — |
| POST | `/{role_id}/reset-health` | Reset suspicion counter | — | steps | `reset-health` | — |
| POST | `/{role_id}/ttl` | Set TTL | body `ttl`, `refresh_before?` | steps | `set-ttl` | — |
| POST | `/{role_id}/expiry-signals` | Add signals | body `body_signals[]`, `status_codes[]`, `header_signals[{name,value}]` | steps | `add-expiry-signal` | — |
| DELETE | `/{role_id}/expiry-signals` | Clear all signals | — | steps | `clear-expiry-signals --force` | — |
| POST | `/{role_id}/control-flows/{flow_id}` | Add validation (control) flow | — | steps | `add-control-flow` | — |
| DELETE | `/{role_id}/control-flows/{flow_id}` | Remove control flow | — | steps | `remove-control-flow` | — |

Validation is control-flow based only. Legacy URL `set-validation` / `clear-validation` CLI paths are not exposed.

---

## Endpoints (`/api/endpoints`) — Endpoint Workspace API

Reads use Talos core’s policy resolver (`talos_ui/endpoint_reads.py` → `talos.projects.policy`) so the UI never infers effective priority, exclusion, or qualification. Mutations always go through multi-ID CLI in **one** argv list (atomic bulk). Static routes are registered **before** `/{endpoint_id}`.

| Method | URL | Purpose | Request | Response | CLI | DB / core |
|--------|-----|---------|---------|----------|-----|-----------|
| GET | `/api/endpoints` | Resolved inventory page | filters (search, method, role, module, priority, priority_source, qualified, excluded, dangerous, logout, qualification_reason, tag, has_parameters, has_baseline, origin, state, decision, problem); offset/limit; `ids_only=1` | `{ endpoints, total }` or `{ ids, total }` | — | policy resolver + hit/module enrich |
| GET | `/api/endpoints/filters` | Distinct filter values | `project_id` | methods, roles, modules, priorities, priority_sources, qualification_reasons, tags, origins | — | SQL distinct |
| GET | `/api/endpoints/summary` | Inventory strip counts | `project_id` | total/testable/excluded/dangerous/logout/unqualified | — | resolved inventory |
| GET | `/api/endpoints/policy-summary` | Policy tab cards | `project_id` | testable/excluded/unqualified/manual/rule/auto + by_priority | — | resolved inventory |
| GET | `/api/endpoints/coverage` | Coverage tab | `project_id` | qualification, baseline, roles, parameters | — | resolved + SQL |
| GET | `/api/endpoints/parameters/search` | Parameter picker | `project_id`, `search?`, `limit?` | `{ parameters }` | — | parameters JOIN endpoints |
| GET | `/api/endpoints/rules` | Path rules + match counts | `project_id` | `{ rules }` | — | `list_path_rules` + preview |
| GET | `/api/endpoints/policy/rules` | Legacy alias of rules list | `project_id` | `{ rules }` | — | same |
| POST | `/api/endpoints/rules` | Create rule | body pattern, priority?, exclude? | steps + bulk | `endpoint rule add` | — |
| POST | `/api/endpoints/rules/preview` | Live impact preview | body pattern, priority?, exclude? | preview object | — | `preview_path_rule_impact` |
| POST | `/api/endpoints/rules/{rule_id}` | Update rule | body priority?, clear_priority?, exclude? | steps | `endpoint rule update` | — |
| DELETE | `/api/endpoints/rules/{rule_id}` | Delete rule | — | steps | `endpoint rule delete` | — |
| POST | `/api/endpoints/bulk/mark` | Bulk safety | body `endpoint_ids`, `tag` | steps + bulk | `endpoint mark <ids…> --tag` | — |
| POST | `/api/endpoints/bulk/unmark` | Bulk unmark | body ids, tag | steps + bulk | `endpoint unmark` | — |
| POST | `/api/endpoints/bulk/priority` | Bulk priority set/clear | body ids, priority? clear? | steps + bulk | `priority set\|clear endpoint` | — |
| POST | `/api/endpoints/bulk/exclude` | Bulk exclude | body ids | steps + bulk | `exclude endpoint` | — |
| POST | `/api/endpoints/bulk/include` | Bulk include | body ids | steps + bulk | `include endpoint` | — |
| POST | `/api/endpoints/bulk/tags` | Bulk tags | body ids, action, tags | steps + bulk | `endpoint tags …` | — |
| POST | `/api/endpoints/bulk/test` | Enqueue/replay | body ids, action | steps | `scheduler enqueue` / `replay endpoint` | — |
| GET | `/api/endpoints/{id}/policy` | Policy explanation | `project_id` | structured explain | — | `explain_endpoint_policy` |
| GET | `/api/endpoints/{id}` | Detail + explanation | `project_id` | endpoint, policy, policy_explanation, parameters, roles, modules, flows, `activity_available` | — | multiple tables + resolver |
| GET | `/api/endpoints/{id}/adjacent` | Prev/next | `project_id` | prev/next ids | — | hit-ordered |
| POST | `/{id}/mark` `unmark` `priority` `exclude` `include` `tags` `export` | Single-endpoint mutations | body as needed | steps + bulk | matching CLI | — |
| POST | `/policy/path-priority` etc. | Legacy path helpers | pattern | steps | priority/exclude path | — |

Bulk mutation responses: `{ steps, bulk, ok }` where `bulk` is the CLI `--format json` payload (`affected`, `unchanged`, `count`, …).

---

## Flows (`/api/flows`)

| Method | URL | Purpose | Request | Response | CLI | DB |
|--------|-----|---------|---------|----------|-----|-----|
| GET | `/api/flows` | List | filters source/method/host/status_code/role/module/search/endpoint; offset/limit; optional `include=flags` | `{ flows, total }` (+ flag columns when requested) | — | `flows` + roles/modules; optional joins to diffs/bac/unauth/evidence |
| GET | `/api/flows/filters` | Distinct filters | `project_id` | sources, methods, hosts, statuses, roles, modules | — | flows |
| GET | `/api/flows/{flow_id}` | Detail + derived + attack side data | `project_id` | `flow`, `derived` (duration/sizes/auth/truncation), `results` {diff,bac,unauth,auth_test}, `endpoint_policy`; legacy aliases `diff`/`bac_result`/… kept | — | flows, replay_diffs, bac_results, unauth_results, auth_test_results, endpoint_policy |
| GET | `/api/flows/{flow_id}/related` | Related objects | `project_id` | original, children (+diff summary), findings evidence, scheduler jobs, param_count, optional `url_sinks` `{ nrs_count, max_score, count, endpoint_id }` | — | flows, replay_diffs, finding_evidence, findings, scheduler_jobs, parameters + url_sink by-endpoint strip |
| GET | `/api/flows/{flow_id}/intelligence` | Endpoint + session snapshot | `project_id` | endpoint policy snippet, session (provider/artifacts/TTL/suspicion) for flow’s role | — | endpoints, endpoint_policy, role_auth_*, session_health_*, session_suspicion_state |
| GET | `/api/flows/{flow_id}/adjacent` | Newer/older by captured_at | `project_id` + same filters as list (optional) | prev/next | — | window functions on filtered flows |
| POST | `/api/flows/{flow_id}/export` | Export one | `project_id` | steps | `flow export <id>` | — |
| POST | `/api/flows/export` | Export by filter | body module/parameter/endpoint/flows | steps | `flow export` with flags | — |

`derived` and list `flags` are presentation helpers only — they do not recompute Core verdicts or session health scores.

---

## Replay (`/api/replay`)

| Method | URL | Purpose | Request | Response | CLI | DB |
|--------|-----|---------|---------|----------|-----|-----|
| POST | `/api/replay/flow/{flow_id}` | Replay flow | query `project_id`; body `right_now?` | steps | scoped `replay flow` | — |
| POST | `/api/replay/endpoint/{endpoint_id}` | Replay endpoint | same | steps | scoped `replay endpoint` | — |

---

## Send / Repeater (`/api/send`)

Mode 2 mutable send surface for the Control Panel Repeater. **Architecture exception:** mutations call `talos.send.engine` / `talos.send.db` in-process (not CLI wrap). See `cli-integration.md` Exceptions. All routes take `project_id` query param.

| Method | URL | Purpose | Request | Response | Engine | DB |
|--------|-----|---------|---------|----------|--------|-----|
| GET | `/api/send/draft/{flow_id}` | Materialize editable draft | path | `SendDraftResponse` (raw dual + annotations) | `draft_from_flow` | read |
| GET | `/api/send/history` | Send history under root | query `from`, `session?`, `parent?`, `source?`, `limit?` | `{ original_flow_id, count, executions[] }` with `duration_ms` | `list_send_history` | read |
| GET | `/api/send/tree` | Structured tree + ASCII lines | query `from`, `limit?` | `{ nodes, lines, … }` | history + `build_send_tree` | read |
| GET | `/api/send/show/{flow_id}` | Request/response hydrate | query `include_bodies?` | show DTO + `duration_ms` | `get_flow_show` | read |
| GET | `/api/send/diff` | Request and/or response diff | query `a`, `b`, `side` | request/response diff | pure diffs | read |
| POST | `/api/send/once` | Once / repeat / parallel | body: `parent_flow_id`, `edit.raw_base64`\|`raw`, `profile`, … | **2xx** `{ steps, result.outcomes[] }`; precondition **409** `{ detail }` only | `send_once` / `send_repeat` / `send_parallel` | insert flow |
| POST | `/api/send/redo/{flow_id}` | Re-fire as-sent | optional note | `{ steps, result }` | `redo_send` | insert |
| POST | `/api/send/dup/{flow_id}` | Mint `session_id` branch | — | `{ steps, result.session_id }` | uuid | — |
| POST | `/api/send/note/{flow_id}` | Note on send row only | body `note` | `{ steps, result }` | `update_send_note` | update meta |
| POST | `/api/send/export/{flow_id}` | Base64 request/response.http | — | `{ steps, result.*_base64 }` | serialize | read |

**POST once rules (v1):**

- Accept `edit.raw_base64` and/or `edit.raw` only; structured-only edit → **400**.
- Profiles: `{ type: "once" }` \| `{ type: "repeat", n, delay_ms? }` \| `{ type: "parallel", n }` with `1 ≤ n ≤ 50`. Parallel concurrency = engine default `min(n, 10)`.
- Logout annotation → **409** (no flow inserted, no `steps` body).
- UI hardcodes `source: "manual_send"`.

---

## Scheduler (`/api/scheduler`)

| Method | URL | Purpose | Request | Response | CLI | DB / runtime |
|--------|-----|---------|---------|----------|-----|--------------|
| GET | `/api/scheduler/status` | Process + queue state + counts + metrics + config | `project_id` | `process`, `state`, `counts` (zero-filled), `metrics`, `config`, `active_queue`, `queue_fill_pct` | — (runtime manager + SQL) | scheduler_jobs/config/state + `SchedulerRuntimeManager` |
| GET | `/api/scheduler/filters` | Filter options | `project_id` | statuses (all 7), families, job_types, roles, modules, pruneable_statuses | — | jobs + roles + modules |
| GET | `/api/scheduler/jobs` | Job list | status (`active` sugar or exact), job_type (family/exact), role, module, limit (≤1000), offset | `{ jobs, total, limit, offset }` | — | scheduler_jobs + joins |
| GET | `/api/scheduler/jobs/{job_id}` | Job detail (UUID or unique prefix) | `project_id` | `{ job }` | — | same enrichment as list |
| POST | `/api/scheduler/start` | Start managed daemon | `project_id` | steps | `scheduler start` | runtime |
| POST | `/api/scheduler/stop` | Stop managed daemon | `project_id?` | steps | `scheduler stop` | runtime |
| POST | `/api/scheduler/cancel` | Cancel one pending/paused job | body `job_id` | steps | `scheduler cancel` | — |
| POST | `/api/scheduler/prune` | Delete terminal history | body `status`, `force` | steps | `scheduler prune --status …` | — |
| POST | `/api/scheduler/config` | Rate limits (compat) | body min/max delay, max_queue_size | steps | `scheduler config` | — |
| POST | `/api/scheduler/enqueue/flow` | Enqueue flow | body flow_id, priority?, force? | steps | `scheduler enqueue flow` | — |
| POST | `/api/scheduler/enqueue/endpoint` | Enqueue endpoint | body endpoint_id, type?, priority?, force? | steps | `scheduler enqueue endpoint` | — |
| POST | `/api/scheduler/clear` | Clear pending | query force? | steps | `scheduler clear` | — |
| POST | `/api/scheduler/pause` | Pause queue execution | `project_id` | steps | `scheduler pause` | — |
| POST | `/api/scheduler/resume` | Resume queue execution | `project_id` | steps | `scheduler resume` | — |

---

## Mutations / HTTP Rules (`/api/mutations`)

Legacy path prefix; UI label is **HTTP Rules**. All writes via `talos config http …`.

| Method | URL | Purpose | Request | Response | CLI | DB |
|--------|-----|---------|---------|----------|-----|-----|
| GET | `/api/mutations` | List effective rules + summary | `project_id` | `{ enabled, rules, mutations, summary }` | `config http list --format json` | layered `http.rules` |
| POST | `/api/mutations/engine` | Toggle master switch | body `enabled`, `global_scope?` | steps | `config http enable-engine\|disable-engine` | — |
| POST | `/api/mutations` | Create rule | body name, direction, priority, match, actions, `global_scope?` (legacy key/value still works) | steps | `config http create` | — |
| POST | `/{rule_id}/update` | Update fields / replace match & actions | body name?, match?, actions?, … | steps | `config http update` | — |
| DELETE | `/{rule_id}` | Delete | `project_id`, `global_scope?` | steps | `config http delete --force` | — |
| POST | `/{rule_id}/enable` | Enable | `global_scope?` | steps | `config http enable` | — |
| POST | `/{rule_id}/disable` | Disable | `global_scope?` | steps | `config http disable` | — |
| POST | `/{rule_id}/priority` | Set priority | body `priority` | steps | `config http set-priority` | — |
| POST | `/{rule_id}/edit` | Legacy add header.replace | body key, value | steps | `config http add-action` | — |
| POST | `/{rule_id}/duplicate` | Copy rule in same layer | `global_scope?` | steps | list + create | — |
| GET | `/export` | Export JSON | `project_id`, `layer` | `{ payload, steps }` | `config http export --format json` | — |
| POST | `/import` | Import JSON | body content, replace?, global_scope? | steps | temp file + `config http import` | — |
| POST | `/reorder` | Rewrite layer priorities 100,200,… | body `global_scope?` | steps | `config http reorder` | — |

---

## URL Sink Discovery (`/api/url-sink`)

Passive inventory of parameters with `url_features` (score, NRS, name category, looks_like). **Prioritization intelligence only** — not confirmed SSRF/open-redirect Findings. No mutations; config via `/api/configuration` (`url_sink.*` section). Default paths do **not** join `iv_param_profiles` (`include_iv=true` is page-bounded). Config flags use per-project `load_url_sink_config_for_project` — never process-level cache.

All routes require `project_id`. Implementation: `talos_ui/routers/url_sink.py` + `talos_ui/url_sink_reads.py`.

| Method | URL | Purpose | Request | Response | CLI / DB |
|--------|-----|---------|---------|----------|----------|
| GET | `/status` | Aggregates + knobs | `project_id`, `include_iv_stats?` | enabled_*, score_threshold, nrs_count, score_ge_*, by_category/looks_like/location, disclaimer | parameters parse; config project-scoped |
| GET | `/overview` | Status + top sinks + empty_state (CP Overview tab) | `project_id`, `top_n?` | `{ status, top_sinks, empty_state, disclaimer }` | DB |
| GET | `/inventory` | Filterable inventory (K13 keys) | `min_score` (45), `nrs_only` (true), `category`, `looks_like`, `location`, `host` (contains), `endpoint_id`, `has_iv_profile?`, `has_url_sink_obs?`, `search`, `sort`, `limit`, `offset`, `include_iv` | `{ items, count, total_matched, filters_applied, iv_index?, note, disclaimer }` | parameters JOIN endpoints; `has_iv_*` capped profile index |
| GET | `/params/{parameter_id}` | One sink row + IV slice | `project_id` | `{ item, disclaimer }` | DB |
| GET | `/params` | By param_uuid | `project_id`, `param_uuid` | same | DB |
| GET | `/by-endpoint/{endpoint_id}` | Endpoint strip counts (full-set aggregates) | `project_id`, `limit?` | count, nrs_count, max_score, items (top N) | all matching params, not page-truncated |
| GET | `/rollups/host` · `/endpoint` · `/category` | Aggregate rollups (full match set) | min_score, nrs_only, limit | `{ rollup, total_buckets, disclaimer }` | in-process over all matches |

**SinkRow fields:** `parameter_id`, `param_uuid` (`make_param_uuid` raw host), `url_score`, `possible_network_resource`, `name_category`, `inventory_only` (response / `jwt.*`), full `url_features`, optional `iv` when `include_iv=true`.

**`has_iv_profile` / `has_url_sink_obs`:** optional; when set, load a capped (`≤5000`) `iv_param_profiles` uuid index once per request. Default inventory path still does **not** open profiles.

---

## Error Intelligence (`/api/error-intel`)

Passive error clusters from stored HTTP responses. **Intelligence only** — no Findings bridge in v1. All routes require `project_id`. Reads use `talos.error_intel.db`; mutations shell out to `talos error-intel …`.

| Method | URL | Purpose | Request | Response | CLI / DB |
|--------|-----|---------|---------|----------|----------|
| GET | `/status` | Counts + config snapshot | `project_id` | enabled, clusters, observations, by_severity, by_category, scanner_version, … | DB |
| GET | `/overview` | Status + top clusters + empty_state | `project_id`, `top_n?` | `{ status, top_clusters, empty_state, note }` | DB (top prefers medium+) |
| GET | `/config` | Config + keys allowlist | `project_id` | `{ config, scanner_version, keys }` | DB |
| POST | `/config` | Set config key(s) | body `key`/`value` or `updates` | `{ steps }` | `error-intel config set` |
| GET | `/errors` | Filtered cluster list | `project_id`, severity (multi/csv), category?, flags?, q?, min_observations?, hide_low_noise?, limit, offset | `{ errors, total, limit, offset, count }` | `list_clusters` + `count_clusters` |
| GET | `/errors/{error_id}` | Cluster dossier | `project_id` | `{ error, observations, sibling_clusters }` | DB |
| GET | `/observations` | Observation list | filters + limit/offset | `{ observations, limit, offset, count }` | DB |
| GET | `/rollups/parameter` | Parameter rollup | `parameter_uuid?`, limit | `{ rollup }` | DB |
| GET | `/rollups/endpoint` | Endpoint rollup | `endpoint_id?`, limit | `{ rollup }` | DB |
| POST | `/rescan` | Rescan bodies | body mode=all\|flow, id?, force?, outdated?, limit? | `{ steps }` | `error-intel rescan` |
| GET | `/by-flow/{flow_id}` | Flow-scoped sightings | `project_id` | observations (max 20), clusters, scanner_enabled | DB |

---

## Attack (`/api/attack`)

### Unauth

| Method | URL | Purpose | Request | Response | CLI | DB |
|--------|-----|---------|---------|----------|-----|-----|
| GET | `/unauth/techniques` | Technique picker metadata | — | `{ techniques, items[{name,description,mutation_family,recipe_count}], total_recipes }` | — | Core recipes/variants (fallback static names) |
| GET | `/unauth/overview` | Workspace aggregate | `project_id`, top_n? | counts, testable_endpoints, total_recipes, estimated_jobs_all, jobs, auto_run, techniques, recent_bypass, empty_state | — | unauth_results, endpoints/policy, scheduler_jobs; auto-run via Core attack_config |
| GET | `/unauth/results` | Recent results | verdict?, auth_mutation?, request_mutation?, search?, limit? | `{ results }` | — | `unauth_results` JOIN flows |
| GET | `/unauth/summary` | Verdict counts | `project_id` | `{ counts }` | — | group by verdict |
| POST | `/unauth/run` | Enqueue recipes | body `technique?` | steps | `attack unauth run [--technique NAME]` | — |
| POST | `/unauth/filter/init` | Init filter | — | steps | `attack unauth filter init` | — |
| POST | `/unauth/filter/show` | Show filter | — | steps | `… filter show` | — |
| POST | `/unauth/filter/validate` | Validate filter | — | steps | `… filter validate` | — |
| POST | `/unauth/filter/apply` | Re-apply filter to stored results | body `dry_run?` `force?` | ApplySummary JSON (counts + rows) | Core `apply_unauth_decision_filter` (not CLI steps) | unauth_results, findings, finding_timeline |

Auto-run mutations use layered configuration (`POST /api/configuration/value` key `attack.unauth_auto_run`), not a dedicated attack route. Console also exposes `attack unauth config --auto-run on|off`.

### BAC

| Method | URL | Purpose | Request | Response | CLI | DB |
|--------|-----|---------|---------|----------|-----|-----|
| GET | `/bac/results` | Recent results | verdict?, limit? | `{ results }` | — | bac_results + roles/modules |
| GET | `/bac/summary` | Verdict counts | `project_id` | `{ counts }` | — | group by verdict |
| POST | `/bac/{technique}` | Run technique | body role?, auto_generate? | steps or `{ error }` | `attack bac <technique>` | — |
| POST | `/bac/filter/init\|show\|validate` | Filter ops | — | steps | matching CLI | — |

Valid techniques: `session-swap`, `method-fuzz`, `content-type`, `url-fuzz`, `header-inject`, `host-fuzz`, `role-inject`, `parser-confuse`.

---

## Input validation (`/api/input-validation`)

| Method | URL | Purpose | Request | Response | CLI | DB |
|--------|-----|---------|---------|----------|-----|-----|
| GET | `/config` | IV config + phase list | `project_id` | `{ config, phases }` | — | `input_validation_config` |
| POST | `/config` | Enable/disable/workers/budget/phases/auth | body flags | steps | `input-validation config` | — |
| GET | `/status` | Budget, jobs, confidence, profile counts | `project_id` | full status + legacy caches | — | iv_* + jobs |
| GET | `/overview` | Overview bundle | `top_n?` | status + top candidates + empty_state | — | same |
| POST | `/run` | Schedule planner jobs | scope + budget + ignore_cache | steps | `run` | — |
| POST | `/resume` | Resume | scope | steps | `resume` | — |
| POST | `/clear-cache` | Clear cache (`--force`) | scope | steps | `clear-cache` | — |
| POST | `/phase/{phase}` | Run one phase | scope | steps or error | phase cmd | — |
| POST | `/synthesize` | Offline profiles | host? / param_uuid? | steps | `synthesize` | — |
| POST | `/exclude/*` · `/include/*` | Scope exclusions | path | steps | exclude/include | — |
| GET | `/parameters` | Param cache rows | host?, limit? | `{ rows }` | — | `iv_param_cache` |
| GET | `/profiles` | Slim param profiles | host, location, capability, has_candidates, search, limit | `{ profiles, count }` | — | `iv_param_profiles` |
| GET | `/profiles/{uuid}` | Full intelligence | recompute? | intelligence + note | — | profiles |
| GET | `/candidates` | Attack candidates | attack, min_score, host, capability, search | list + note | — | profiles |
| GET | `/show/{uuid}` | Dossier: probes + intel | recompute? | probes, profile, candidates, summary_lines | — | probes + profiles |
| POST | `/show/{uuid}/cli` | CLI dossier | — | steps | `show` | — |
| GET | `/endpoints` | Endpoint profiles list | host?, limit? | `{ endpoints }` | — | `iv_endpoint_profiles` |
| GET | `/endpoints/{id}` | Endpoint dossier | — | profile, meta, parameters | — | endpoint + params |
| GET | `/hosts` | App profiles list | limit? | `{ hosts }` | — | `iv_app_profiles` |
| GET | `/hosts/{host}` | Host dossier | — | profile, endpoints, params, candidates | — | multi-level |
| POST | `/export/parameter` · `/host` · `/csv` | CLI export | body | steps | export | — |
| GET | `/export/parameter/{uuid}/json` | Downloadable param JSON | — | profile + caps + candidates | — | read helpers |
| GET | `/export/host/{host}/json` | Downloadable host JSON | — | host intel | — | read helpers |

Phases: `baseline`, `multiprobe`, `identifier`, `characters`, `length`, `types`, `transformations`, `reflection`, `validation` (parser probes are planner-driven, not a separate CLI phase).

Scope body fields: `host`, `endpoint`, `parameter`, `param_uuid`, `ignore_cache`, `force`, `budget`, `include_auth_artifacts` (only one of host/endpoint/parameter applied for run scope; host preferred).

---

## Findings (`/api/findings`)

| Method | URL | Purpose | Request | Response | CLI | DB |
|--------|-----|---------|---------|----------|-----|-----|
| GET | `/api/findings` | List | status?, view=`primary`\|`linked`\|`all` | `{ findings, view }` (+ `linked_count` on PRIMARY) | — | findings + evidence role/module |
| GET | `/api/findings/{finding_id}` | Detail | — | finding, evidence, timeline, duplicates, parent, linked, `flow_comparison` (original vs attack/testcase when evidence present) | — | findings*, evidence, timeline, flows (summary), replay_diffs |
| POST | `/{id}/confirm` | Confirm | body linked?, force? | steps | `finding confirm [--linked] [--force]` | — |
| POST | `/{id}/reject` | Reject | body linked?, force? | steps | `finding reject [--linked] [--force]` | — |
| POST | `/{id}/reopen` | Reopen | body linked?, force? | steps | `finding reopen [--linked] [--force]` | — |
| POST | `/{id}/duplicate` | Mark duplicate | body `of` | steps | `finding duplicate --of` | — |
| POST | `/{id}/notes` | Set notes | body `notes` | steps | `finding note set` (stdin) | — |
| DELETE | `/{id}/notes` | Clear notes | — | steps | `finding note clear` | — |
| GET | `/{id}/report` | Generate report | — | steps | `finding report` | — |
| GET | `/groups/list` | List groups | `project_id` | `{ groups }` | — | finding_groups + members |
| GET | `/groups/{group_id}/members` | Members | — | `{ findings }` | — | join |
| POST | `/groups` | Create group | body `name` | steps | `finding group create` | — |
| POST | `/groups/add` | Add member | body group, finding | steps | `group add` | — |
| POST | `/groups/remove-member` | Remove member | body pair | steps | `group remove` | — |
| POST | `/groups/delete` | Delete group | body group, remove_findings? | steps | `group remove [--remove-findings]` | — |
| GET | `/groups/report/{group_name}` | Group report | — | steps | `finding report --group` | — |

---

## Console (`/api/console`)

| Method | URL | Purpose | Request | Response | CLI | DB |
|--------|-----|---------|---------|----------|-----|-----|
| GET | `/api/console/tree` | Command catalog | — | `{ groups: COMMAND_TREE }` | — | — |
| POST | `/api/console/run` | Modeled command | body `command_id`, `values`, `project_id?` | steps, or background process status, or error | `build_argv` + run/run_scoped/process_manager | — |
| POST | `/api/console/raw` | Raw argv list | body `args[]`, `project_id?` | steps | run / run_scoped | — |

Background commands (from command tree `background: true`) use `process_manager.start(command_id, argv)` instead of waiting for completion.

---

## CORS

Allowed origins (hardcoded in `config.CORS_ORIGINS`):

- `http://localhost:5173`, `http://127.0.0.1:5173`
- `http://localhost:4173`, `http://127.0.0.1:4173`

Methods/headers: all (`*`), credentials allowed.
