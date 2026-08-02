# Core CLI / Product Upgrades That Greatly Help Talos AI

| Field                 | Value                                                                                                              |
| --------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **Status**            | Input notes for planning (not an implementation commit)                                                            |
| **Audience**          | Operators / engineers planning AI revamp + core CLI work                                                           |
| **Related**           | `docs/design-talos-ai-layer.md`, `docs/ai-revamp-design-notes.md`, `docs/cli-cheat-sheet.md`                       |
| **Date**              | 2026-07-30                                                                                                         |
| **Out of scope here** | Full AI redesign (see `docs/ai-revamp-design-notes.md`); `talos recon` implementation (deferred by product choice) |

---

## 1. Why this document exists

The AI layer only orchestrates existing Talos capabilities. If inventory, HTTP dump, notes, and status commands are awkward for machines (tables only, replace-only notes, no batch packs, huge bodies with no progressive fetch), the agent wastes context and proposes bad commands.

This doc lists **core CLI / product upgrades** that make a methodology-driven, micro-engagement AI high quality. Work these independently of (or slightly ahead of) the AI revamp.

**Deferred:** `talos recon` (will be designed later).

---

## 2. Priority tiers

- full talos documentation. one md file per feature in md and hosted for me in talos control panel and access to talos ai as well.

### P0 — Do early (blocks good AI)

| Upgrade                                            | Problem today                                                         | Desired behavior                                                                                                                                                                                       | Why AI needs it                                                                |
| -------------------------------------------------- | --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| **Stable `--format json` everywhere AI will call** | Some list/show/status paths are table-first or incomplete JSON        | Every read path AI uses returns one JSON document on stdout; empty → `[]` / null object                                                                                                                | Machine parsing; no table scraping                                             |
| **Batch inventory packs**                          | Full `endpoint list` / flow dumps blow context                        | Paginated, compact fields: `endpoint list --format json --limit N --offset M --fields compact`; optional “classify pack” export (id, method, host, path, role, module, annotations, param count, tags) | Phase: “go through all endpoints in batches”                                   |
| **Progressive raw HTTP access**                    | Full request/response can be huge                                     | Default: short excerpts + sizes + content-type + paths/IDs; AI can request more (`--full`, `--body request\|response`, byte ranges, or `talos http dump <flow_id> --max-bytes N`)                      | “Give AI little; if it needs more, it asks”                                    |
| **Unified HTTP dump by ID**                        | Fragmented: `send show`, flow show, export dirs                       | `talos flow dump` / `talos http dump <flow_id>` → request.http + response + meta JSON                                                                                                                  | Reliable evidence for analysis + notes                                         |
| **Append-safe notes**                              | Endpoint notes often replace entire column; no first-class append API | `endpoint notes append <id>`, app/module notes append with timestamp + author (`ai` / `analyst`)                                                                                                       | Test log: “XSS tested on field X, outcome …” without clobbering                |
| **Machine-readable command catalog**               | Help text is human prose                                              | `talos help catalog --format json` (or schema export): command, summary, when-to-use, risk class, needs-project, HTTP-producing?, dangerous-capable?                                                   | Planner proposes valid commands without stuffing entire cheat sheet every turn |
| **AI-safe command execution façade (core side)**   | Dual paths risk drift                                                 | Single internal entry used by CLI and AI: validate project pin, capture stdout/stderr/exit, optional body artifacts on disk                                                                            | Observations with raw-enough output + full path on disk                        |

### P1 — Strong helpers for checklist quality

| Upgrade | Desired behavior | Maps to |
|---------|------------------|---------|
| **Inventory interest tags** | Heuristic or operator tags: `auth-boundary`, `id-param`, `file-upload`, `graphql`, `state-change`, `admin`, `export-download` | Access control, upload, GraphQL, logic phases |
| **Role / module coverage report** | “Endpoints never seen under role B”; matrix gaps as JSON | BAC / privilege escalation |
| **Param intelligence pack export** | Semantic type, examples, reflection hints, IV candidates as one JSON pack per batch | Injection / IV / intruder targeting |
| **Engine preflight “why not runnable”** | BAC / IV / unauth / intruder return structured block reasons (annotation, missing baseline, no param profile, etc.) | Prevents AI retry loops |
| **Scheduler observe for agents** | `scheduler jobs wait <id> --timeout S --format json` or poll-friendly status with terminal states | Async engines fit micro-engagements |
| **Findings draft already exists** | Keep human promote; improve list/filter by session/phase | Checklist “possible issue” without auto-confirm |
| **Scope / project confirm snapshot** | `talos project status --format json` + scope list/outscope in one “engagement preflight” JSON | Human confirm at AI start (project, scope, budgets) |

### P2 — Operational / supervisor quality

| Upgrade | Desired behavior |
|---------|------------------|
| **Cooperative interrupt** | Long send/intruder/replay respect cancel without corrupt DB state |
| **Per-phase / larger budgets (config)** | Session budgets tunable for continuous runs (not fixed tiny defaults only) |
| **Idempotent read marking** | Document which commands are safe auto-read (for AI CommandPolicy) |
| **Export engagement bundle** | One command: checklist state + log summaries + note refs + draft findings (AI session export expansion) |
| **Flow/body size metadata always present** | Even without body: `request_bytes`, `response_bytes`, `truncated: true` |

### P3 — Later / optional

| Upgrade | Notes |
|---------|-------|
| **`talos recon`** | Deferred; native inventory + header fingerprint first; external whatweb/wappalyzer only as allowlisted subcommands later |
| **Path/rule bulk ops for AI** | Only if methodology needs automated tagging at scale |
| **Control Panel surfaces** | Out of scope for AI revamp v1 (CLI-first) |

---

## 3. Detailed specs (high level, for implementers)

### 3.1 Progressive HTTP bodies (required pattern for AI)

```text
Default observation to AI:
  flow_id, method, url, status, content_type,
  request_bytes, response_bytes,
  request_excerpt (e.g. first 2–4 KiB headers+body),
  response_excerpt (e.g. first 2–4 KiB),
  full_available: true,
  fetch_more: "talos send show <id> --body response --full"
              or "… --max-bytes 65536 --offset 4096"

Rule for prompts / runner:
  Always tell the model: excerpts may be truncated; if analysis needs more,
  propose a dump/show command for that flow_id rather than assuming full body.
```

Do **not** dump multi‑MB responses into the LLM window by default.

### 3.2 Batch endpoint classification pack

Suggested fields per endpoint row (compact):

- `endpoint_id`, `method`, `host`, `path`, `qualified`, `excluded`
- `role`, `module` (if set)
- `annotations` (`logout` / `dangerous` / safe)
- `param_count`, `has_body_params`, `content_types_seen`
- `status_codes_sample`, `last_seen`
- `tags` (if any)

API shape:

```bash
talos endpoint list --format json --limit 50 --offset 0 --pack classify
# or: talos inventory pack endpoints --limit 50 --offset 0 --format json
```

### 3.3 Append notes

```bash
talos endpoint notes append <id> --text "…"
# or stdin
# Stores: timestamp, actor (analyst|ai), text; does not wipe prior notes
```

App-level AI notes already patch-oriented; ensure **test-log entries** can append without optimistic whole-document clobber races.

### 3.4 Command catalog JSON

Minimal record:

```json
{
  "argv_prefix": ["endpoint", "list"],
  "summary": "List endpoints with filters",
  "http_producing": false,
  "mutates": false,
  "risk": "read",
  "needs_project": true,
  "ai_default_allow": true,
  "blacklisted_for_ai": false
}
```

Blacklist families (AI must never execute) live in AI policy, but catalog can mark `blacklisted_for_ai` for UX.

### 3.5 Human preflight confirm (core data for AI start)

Single JSON blob ideal for “confirm with human”:

- effective `project_id`, name, data_dir
- Basic Scope rules + outscope domains
- active role / module
- proxy status (up/down)
- inventory counts (endpoints, flows, findings)
- AI budgets remaining (if session exists)

```bash
talos project preflight --format json
# or compose from existing status + scope + inventory counts
```

---

## 4. Mapping upgrades → AI phases (from revamp notes)

| Phase intent | Core upgrades that unlock it |
|--------------|------------------------------|
| Work with partial/empty traffic | Inventory counts JSON; preflight; non-fatal empty packs |
| Endpoint batch classification | Batch packs + tags + append notes |
| Info gathering | (Later recon) + header/tech from captures + notes append |
| Checklist execution | Engine preflight, param packs, progressive HTTP, scheduler wait |
| Justification + evidence | Stable IDs, dump paths, draft findings list |
| Supervisor continuous run | Interrupt-safe long ops, budgets, catalog |

---

## 5. Explicit non-goals (core)

- Freeform OS shell for AI (`whatweb` only behind future `talos recon` allowlist)
- AI mutating global config or project registry
- AI `finding.confirm`
- Replacing deterministic engines with LLM classification as primary path
- Control Panel AI page in this track

---

## 6. Suggested implementation order (core only)

1. JSON completeness audit for endpoint/flow/send/param/findings/scheduler/access  
2. Progressive HTTP excerpts + full-on-demand dump  
3. Batch/classify inventory pack + pagination  
4. Notes append APIs  
5. Command catalog JSON  
6. Engine preflight + scheduler wait helpers  
7. Project preflight JSON  
8. (Later) `talos recon`

---

## 7. Acceptance ideas (when implementing)

- AI can classify 500 endpoints in packs of 50 without loading bodies.  
- AI can analyze a finding with 4 KiB excerpt, then request full body only for 1–2 flows.  
- Append 20 test notes to one endpoint without losing earlier notes.  
- `help catalog --format json` lists every user-facing command family.  
- Preflight JSON is enough for a human y/N before `talos ai run`.
