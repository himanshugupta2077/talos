# Talos AI — Usage Guide

| Field | Value |
|-------|-------|
| **Audience** | Operators and engineers using the AI layer on authorized bug bounty / client pentest work |
| **Status** | Shipped (Phases A–E core CLI) |
| **CLI entry** | `talos ai …` |
| **Design authority** | `docs/design-talos-ai-layer.md` |
| **Quick reference** | `docs/cli-cheat-sheet.md` § AI |

This guide explains **what the AI layer is, how it is controlled, how to configure it, and how to use it day to day**. For architecture decisions, package layout, schema, and PR history, use the design doc.

---

## 1. What the AI layer is

Talos is a **deterministic, MITM-based** web pentest platform first: proxy capture → workers → engines (replay, BAC, unauth, IV, passive, intruder, send) → findings. The AI layer sits **on top** of that stack. It does not replace engines, invent freeform shell access, or self-authorize HTTP traffic.

Product model:

```text
Planner (heuristic or LLM)   →  immutable ActionSuggestion(s) only
         │
Workflow Engine              →  sessions, task tree, approvals, budgets, audit
         │
PolicyValidator + Executor   →  sealed ExecutionPlan → ToolHandler → Talos APIs
```

| Principle | Meaning in practice |
|-----------|---------------------|
| **Suggest-first** | The model never executes tools by itself. Policy validates; you (or an experimental auto-mode) approve sealed plans. |
| **Immutable suggestions** | What the planner proposed is stored as-is. What actually runs is a separate **ExecutionPlan**. |
| **No freeform shell** | Handlers call existing Python APIs only. Preview strings are display-only. |
| **One pin per session** | An AI session is frozen to one project. Tools cannot switch/create/delete projects. |
| **Live scope gates HTTP** | Every send/replay/engine enqueue re-checks Basic Scope + outscope. Empty in-scope = deny-all. |
| **No AI client-data redaction** | Authorized BB/pentest product; operator owns target-data handling. Size limits / `tainted` flags still apply on notes. |

**Not shipped yet:** Control Panel AI page, network-exposed MCP (stdio only today), AI `finding.confirm`, role/module create via AI.

---

## 2. Prerequisites

1. **Active project** — `talos project use <id>` or `--project` / `TALOS_PROJECT`. Sessions pin to the effective project.
2. **In-scope targets** — configure Basic Scope (and outscope) for the project before approving HTTP tools.
3. **Traffic / inventory** — AI is most useful after proxy capture has populated endpoints, flows, params, and (optionally) findings.
4. **Optional LLM** — default planner is offline **heuristic** (`provider=none`). Cloud/local models are optional.

```bash
talos project use my-engagement
talos ai tools list          # verify package works
talos ai config show         # default: provider=none
```

---

## 3. Configure an LLM (optional)

Operator config lives at **`~/.talos/ai/config.yaml`**. It is **never** registered as a tool; the model cannot change it.

| Key | Purpose |
|-----|---------|
| `provider` | `none` \| `ollama` \| `openai-compatible` \| `openai` (alias) \| `anthropic` |
| `model` | Model name (e.g. `llama3.2`, `gpt-4o-mini`, `claude-sonnet-4-20250514`) |
| `base_url` | Override API base (Ollama / compatible gateways) |
| `api_key_env` | Env var name for the key (default `TALOS_AI_API_KEY`) |
| `temperature` | Default `0.2` |
| `max_tokens` | Default `2048` |
| `timeout_s` | Default `60` |
| `fallback_to_heuristic` | If LLM fails, fall back to heuristic planner (default `true`) |

**Prefer env for secrets** — do not put long-lived API keys in YAML unless you must.

### Offline heuristic (default)

```bash
talos ai config set provider none
# or: talos ai config unset provider model
```

Heuristic planner suggests inventory / READ tools from goal + project state. No network, no tokens.

### Ollama (local)

```bash
# Ollama running locally with a model pulled
talos ai config set provider ollama
talos ai config set model llama3.2
# optional if not default localhost:
# talos ai config set base_url http://127.0.0.1:11434
talos ai config show
```

### OpenAI-compatible (OpenAI, Azure-style, OpenRouter, etc.)

```bash
export TALOS_AI_API_KEY="sk-…"
talos ai config set provider openai-compatible
talos ai config set model gpt-4o-mini
# optional custom gateway:
# talos ai config set base_url https://api.example.com/v1
```

### Anthropic

```bash
export TALOS_AI_API_KEY="…"   # or ANTHROPIC_API_KEY via api_key_env
talos ai config set provider anthropic
talos ai config set model claude-sonnet-4-20250514
```

### Inspect / edit

```bash
talos ai config show
talos ai config show --format json
talos ai config set temperature 0.1
talos ai config unset model base_url
talos ai config edit --force    # opens $EDITOR on the YAML
```

---

## 4. Sessions and autonomy modes

### Start / stop / resume

One **active** AI session per project by default.

```bash
# Suggest-only: planner records ideas; approve/execute is hard-disabled
talos ai start --goal "Map auth and high-value endpoints" --mode suggest-only

# Step (GA): human approves each ExecutionPlan before tools run
talos ai start --goal "Recon inventory" --mode step --force

# Replace an existing active session
talos ai start --goal "IV campaign prep" --mode step --force-stop-existing --force

talos ai status
talos ai status --format json
talos ai stop
talos ai resume <session_id>
```

`start` creates a session row and freezes the **project pin**. It does **not** start a background agent loop. v1 is **turn-based**: each `suggest` / `approve` is one discrete CLI invocation.

### Modes and capability grants

| Mode | GA? | What it can execute |
|------|-----|---------------------|
| `suggest-only` | Yes (default) | **Nothing.** Empty capability set. Planner may still write suggestions. |
| `step` | Yes | All AI capabilities, but **every** non-auto-read tool needs operator `approve`. |
| `auto-low` | Experimental | READ + notes / task tree / context / draft findings (no HTTP). |
| `auto-budget` | Experimental | auto-low + `replay.flow` (budget-limited). |
| `auto-aggressive` | Experimental | auto-budget + `send.once` + engine enqueues. Requires one-time project ack. |

```bash
talos ai mode set step --force
talos ai mode set auto-low --force

# auto-aggressive: acknowledge once per project
talos ai mode set auto-aggressive \
  --ack "I_ACCEPT_AUTO_AGGRESSIVE=<project_id>" --force
talos ai mode clear-aggressive-ack --force
```

**Recommendation for real engagements:** stay on `suggest-only` or `step`. Treat `auto-*` as lab/experiment only.

Capabilities are the real authorization primitive (e.g. `read_endpoints`, `send_request`, `enqueue_iv`). Modes only grant capability **sets**; PolicyValidator still checks scope, annotations, budgets, and schema on every plan.

---

## 5. Core loop: suggest → pending → approve / deny → observe

```text
talos ai suggest
      │
      ▼ immutable ActionSuggestion(s) stored
      │
PolicyValidator ──► ExecutionPlan (pending_approval | rejected)
      │
talos ai pending / plans show
      │
  ┌───┴───┐
  approve   deny
      │
  Executor → ToolHandler → Observation + audit
```

### Commands

```bash
# One planner turn (heuristic or configured LLM)
talos ai suggest
talos ai suggest -n 5
talos ai suggest --auto-reads -n 5   # step only: auto-run READ tools after validate

# What is waiting on you
talos ai pending
talos ai pending --format json

# Inspect plan vs original suggestion (immutable record)
talos ai plans show <plan_id>

# Run the sealed plan (re-validates live scope / annotations / budgets)
talos ai approve <plan_id>
# also accepts suggestion_id → latest pending plan for that suggestion

talos ai deny <plan_id|suggestion_id> --reason "out of engagement window"
```

### Mental model: suggestion vs plan

| Object | Who creates it | Mutable? | Meaning |
|--------|----------------|----------|---------|
| **ActionSuggestion** | Planner only | No (append-only) | Exactly what was proposed: tool, args, reason |
| **ExecutionPlan** | PolicyValidator only | State machine only | What is allowed to run after schema/caps/scope checks |
| **Observation** | Executor | Append-only | What happened (truncated, treated as untrusted input for the next planner turn) |

Always prefer approving **`plan_id`**. Audit keeps both proposal and authorized plan for incident response.

### What “turn-based” means

There is **no AI daemon**. Continuous investigation is a **logical** multi-turn workflow you drive:

```bash
talos ai suggest --auto-reads
talos ai pending
talos ai approve <plan_id>
# … inspect results in Talos CLI / Control Panel …
talos ai suggest
# repeat until goal or budget halt
```

`talos ai stop` ends the session. It does **not** cancel scheduler jobs already enqueued by engines.

---

## 6. Scope, annotations, and engine behavior

### Scope (HTTP tools)

For every tool that sends or enqueues HTTP:

1. **Pin** — only the frozen project DB.
2. **Live Basic Scope + outscope** — same sources the proxy uses. Empty in-scope ⇒ **deny all**.
3. **Fail-closed shrink** — if scope was snapshotted at session start, both live **and** snapshot must allow the effective URL.
4. **Effective URL after edits** — for `send.once`, host/path/query mutations are applied before the check.

Historical out-of-scope flows may still be **read**. They must not be **re-sent** if live scope denies them.

### Annotations

| Annotation | AI behavior |
|------------|-------------|
| **logout** | Always reject active tools that would hit that endpoint. |
| **dangerous** | Never silent auto. Operator must **approve**; jobs use `PRIORITY_AI_MANUAL` + `ai_force_dangerous`. |

### Engines are enqueue-only

Tools like `iv.run`, `attack.bac.run`, `intruder.session.run` **queue work**. They do not wait for completion inside the AI turn. Poll with:

```bash
# via AI READ tools (after suggest/approve) or CLI
talos scheduler …          # project scheduler surfaces
# AI tools: scheduler.jobs.list / scheduler.jobs.show
```

Intruder requires a **pre-created** intruder `session_id` before `intruder.session.run`.

---

## 7. Budgets

Default hard caps per session (design defaults):

| Budget | Default |
|--------|---------|
| Max steps | 50 |
| Max tool calls | 100 |
| Max HTTP executed by AI | 100 |
| Max jobs enqueued by AI | 50 |
| Max intruder payloads per authorize | 200 |
| Max LLM tokens (estimated) | 500_000 |
| Wall clock | 7200 s (2 h) |

When a budget is hit, the session can halt (`halted_budget`). Operator may reset usage counters (does not change limits):

```bash
talos ai reset-budget --force
talos ai status    # budgets_usage / limits
```

---

## 8. Tool catalog

List live descriptors anytime:

```bash
talos ai tools list
talos ai tools list --format json
```

Registry has **no public `call()`**. Execution only via sealed `ExecutionPlan` after validate/approve (CLI or MCP).

### READ (inventory / intel)

| Tool | Purpose |
|------|---------|
| `endpoint.list` / `endpoint.show` | Endpoint inventory and policy fields |
| `flow.show` / `flow.diff` | Flow metadata (optional body excerpts) / compare two flows |
| `param.intelligence` | Parameter capability profiles |
| `iv.candidates` | Stored IV attack candidates |
| `iv.synthesize` | Synthesize IV payloads from intel (read/synth surface) |
| `finding.list` / `finding.show` | Findings + evidence |
| `passive.detections.list` | Passive detector hits |
| `error_intel.list` | Error-intel records |
| `access.coverage` | Access / role coverage view |
| `scheduler.jobs.list` / `scheduler.jobs.show` | Job queue status |
| `intruder.suggest` | Offline Intruder heuristics (no LLM) |
| `role.list` / `role.show_active` | Roles |
| `module.list` / `module.show_active` | Modules |
| `notes.app.get` | Structured app notes |
| `task_tree.list` | Pentesting task tree (PTT) |
| `kb.search` | Markdown knowledge base search |
| `draft_finding.list` / `draft_finding.show` | AI draft findings |

### WRITE / context (no HTTP)

| Tool | Purpose |
|------|---------|
| `notes.app.patch` | Patch allowlisted app-notes fields |
| `task_tree.upsert` | Create/update PTT nodes |
| `role.set_active` / `module.set_active` | Switch active role/module (**exists only** — never creates) |
| `draft_finding.create` | Write a draft finding (not a real finding until promote) |

### HTTP and engines (Phase D)

| Tool | Capability class | Notes |
|------|------------------|-------|
| `send.once` | `send_request` | One mutable send; non-retryable if interrupted mid-execute |
| `replay.flow` | `replay_flow` | Enqueue exact replay |
| `iv.run` | `enqueue_iv` | Enqueue IV job |
| `passive.rescan` | `enqueue_passive` | Enqueue passive rescan |
| `attack.unauth.run` | `enqueue_attack` | Enqueue unauth attack |
| `attack.bac.run` | `enqueue_attack` | Enqueue BAC |
| `intruder.session.run` | `enqueue_intruder` | Needs existing intruder session id |

### Explicitly not available as tools

- Project create/switch/delete
- LLM config read/write
- Freeform shell / `subprocess` / `eval`
- `finding.confirm` or auto-confirm
- Role/module create/delete/rename
- Direct `create_finding` from free-form prose (use draft + operator promote)

---

## 9. App notes (engagement memory)

AI app notes are a **separate structured store**. They never write `endpoint_policy.notes`.

Document shape (schema v1):

| Field | Role |
|-------|------|
| `tech_stack` | Observed technologies |
| `app_class` | Short app classification |
| `auth_model` | How auth works (as understood) |
| `interesting_endpoints` | Curated high-value endpoints |
| `hypotheses` | Open / supported / refuted hypotheses |
| `summary` | Free-text summary (size-capped) |
| `tainted` | Flag when content may be injection-risky for planner packing |

```bash
talos ai notes show
talos ai notes export
talos ai notes edit --force    # full JSON in $EDITOR (optimistic revision)
```

Planner turns receive a sanitized notes pack. Limits include max doc size, hypothesis count, free-text length, and allowlisted patch paths for `notes.app.patch`.

---

## 10. Knowledge base (markdown)

Operator-authored markdown under **`~/.talos/ai/kb/`** (recursive `*.md`). Add files yourself; CLI is **read-only**.

```bash
mkdir -p ~/.talos/ai/kb/techniques
# e.g. ~/.talos/ai/kb/idor-checklist.md
#      ~/.talos/ai/kb/techniques/jwt-notes.md

talos ai kb list
talos ai kb search idor
talos ai kb show idor-checklist
talos ai kb show techniques/jwt-notes
```

`doc_id` is the path relative to the KB root **without** `.md`. Hits are packed into planner context for technique recall. Rich structured promote pipelines are deferred; markdown is the Phase E surface.

---

## 11. Draft findings and promote

AI must **not** invent confirmed findings. Flow:

1. Tool `draft_finding.create` writes a row in the **draft** table.
2. Operator reviews via CLI.
3. `talos ai finding promote` creates a real finding in **`TRIAGING`** (timeline actor path as designed — never auto-confirm).
4. Or reject the draft.

```bash
talos ai finding list-drafts
talos ai finding list-drafts --status draft
talos ai finding show-draft <draft_id>
talos ai finding promote <draft_id> --force
talos ai finding promote <draft_id> --attack-type idor --force
talos ai finding reject-draft <draft_id> --force
```

Default attack type when promoting without override: **`ai_draft`** (or the draft’s stored value).

---

## 12. Audit and session export

```bash
talos ai audit list
talos ai audit list --session <session_id> --limit 100
talos ai audit list --format json

# Bug-report / handoff bundle: suggestions, plans, observations, audit, notes pointer
talos ai session export
talos ai session export <session_id> --format json
```

Audit retains proposal vs authorized plan vs execution outcomes. Use this for review, mentoring, and client evidence packages (still operator-owned).

---

## 13. MCP (stdio only)

Expose the same Tool Protocol to MCP clients (Cursor, Claude Desktop, etc.) over **stdio**. No network/SSE MCP in this ship.

```bash
talos ai start --goal "External client" --mode step --force
talos ai mcp serve
# or bind explicitly:
talos ai mcp serve --session <session_id>
```

Behavior:

- `tools/list` → ToolSpec descriptors only.
- `tools/call` → **WorkflowEngine** (PolicyValidator + Executor), never raw handlers.
- In `step` mode, calls that need approval return **needs_approval** + `plan_id` → run `talos ai approve <plan_id>` in another terminal.

Wire your client’s MCP config to run `talos ai mcp serve` with the correct project environment (`TALOS_PROJECT` or project already active).

---

## 14. End-to-end workflows

### A. First recon with heuristic planner (no LLM)

```bash
talos project use acme-bb
talos ai start --goal "Inventory high-value authenticated endpoints" --mode step --force
talos ai suggest --auto-reads -n 5
talos ai pending
# approve any remaining non-READ plans if present
talos ai approve <plan_id>
talos ai notes show
talos ai status
```

### B. LLM-assisted investigation

```bash
export TALOS_AI_API_KEY=…
talos ai config set provider ollama   # or openai-compatible / anthropic
talos ai config set model llama3.2

talos ai start --goal "Prioritize IDOR candidates on /api/v2" --mode step --force
talos ai suggest -n 5
talos ai plans show <plan_id>
talos ai approve <plan_id>
# iterate
talos ai suggest
```

### C. Safe active testing (send / engines)

```bash
# Ensure scope is correct first
talos ai mode set step --force
talos ai suggest
talos ai pending
# Read the plan carefully: tool name, args, target URL
talos ai plans show <plan_id>
talos ai approve <plan_id>
# Poll jobs outside the AI turn
talos ai suggest   # next turn can call scheduler.jobs.* via READ
```

### D. Draft finding → triage

```bash
# After agent creates drafts via tools…
talos ai finding list-drafts --status draft
talos ai finding show-draft <draft_id>
talos ai finding promote <draft_id> --force
# Continue triage with normal findings CLI / Control Panel
```

### E. Session handoff / report appendices

```bash
talos ai session export --format json > /tmp/ai-session-bundle.json
talos ai notes export --format json > /tmp/app-notes.json
talos ai audit list --format json > /tmp/ai-audit.json
```

### F. Budget exhausted mid-engagement

```bash
talos ai status
talos ai reset-budget --force
talos ai suggest
```

---

## 15. JSON / automation tips

Most commands accept `--format json` (see `talos.cli_output`). Useful for agentic operators and scripts:

```bash
talos ai status --format json
talos ai pending --format json
talos ai tools list --format json
talos ai suggest --format json
talos ai approve <plan_id> --format json
```

Mutating commands that prompt for confirmation accept **`--force`** for non-interactive use (same convention as the rest of Talos CLI).

Exit codes follow CLI conventions: precondition failures (no project, no session) vs usage vs runtime — see `cli-cheat-sheet.md` / `talos.cli_output`.

---

## 16. Safety checklist (operator)

Before approving active tools:

1. **Authorization** — engagement is in-scope for the client/BB program.
2. **Project pin** — `talos ai status` shows the expected `project_id`.
3. **Scope** — live Basic Scope matches the target; empty scope blocks HTTP.
4. **Annotations** — `logout` / `dangerous` endpoints are intentional if hit.
5. **Plan args** — read `talos ai plans show` (tool name, URL, payload bounds).
6. **Mode** — prefer `step`; avoid `auto-aggressive` on production targets.
7. **Budgets** — reset only when you intend more automated volume.
8. **Findings** — promote drafts only after human review; never treat AI prose as confirmed.

---

## 17. Troubleshooting

| Symptom | Likely cause | What to do |
|---------|--------------|------------|
| `NO_ACTIVE_PROJECT` / exit 3 | No project bound | `talos project use` or set `TALOS_PROJECT` |
| Suggest produces nothing useful | Empty inventory or heuristic with vague goal | Capture traffic first; tighten `--goal` |
| Approve rejected: scope | URL out of live scope or empty in-scope | Fix project scope; re-suggest |
| Approve rejected: logout | Endpoint annotated logout | Clear annotation only if correct |
| Dangerous endpoint needs approval | By design | Explicit `approve` in step mode |
| LLM errors / empty plans | Provider down or bad config | `talos ai config show`; check `fallback_to_heuristic` |
| Session halted | Budget exceeded | `status` → `reset-budget --force` if appropriate |
| Another session active | One active per project | `stop` or `start --force-stop-existing` |
| MCP tools need_approval | step mode | `talos ai approve <plan_id>` |
| Jobs not finished after approve | Enqueue-only engines | Poll scheduler; do not expect sync completion |

---

## 18. Package map (for developers)

```text
talos/ai/
  cli.py              # thin CLI → WorkflowEngine
  models.py           # Capability, AutonomyMode, budgets, plan types
  policy.py           # PolicyValidator → sealed ExecutionPlan
  executor.py         # sole ToolHandler invoke path
  audit.py
  workflow/           # sessions, PTT, suggestions, plans, budgets, engine
  planner/            # heuristic + LLM planner (produces suggestions only)
  tools/              # ToolSpec / ToolPolicy / handlers / registry
  llm/                # none, ollama, openai_compat, anthropic, config
  notes/              # structured app notes
  kb/                 # markdown KB store
  drafts/             # draft findings
  mcp/                # stdio MCP server
```

Tests live under `tests/` (AI-focused) and exercise policy, scope shrink, suggest/approve, and config. Handlers must not shell out to the CLI for tool bodies.

---

## 19. Related documents

| Doc | Role |
|-----|------|
| `docs/design-talos-ai-layer.md` | Full design, key decisions, schema, PR plan |
| `docs/cli-cheat-sheet.md` | Compact AI command block + rest of Talos CLI |
| `docs/architecture.md` | Core platform architecture / DB |
| `docs/about-talos.md` | Historical vision (non-authoritative; §21 MPC notes) |
| `docs/intruder-cli-guide.md` | Intruder operator guide (AI can enqueue sessions) |
| `docs/input-validation.md` | IV engine (AI enqueues; does not replace) |

---

## 20. Summary

1. **Deterministic engines first** — AI orchestrates and proposes; it does not replace BAC/IV/passive.
2. **Suggest → validate → approve → execute** — model text never runs unsealed.
3. **Default safe:** `provider=none`, mode `suggest-only`.
4. **Day-to-day active assist:** mode `step` + `suggest` / `approve` loop.
5. **Memory:** app notes + markdown KB + PTT + session export.
6. **Findings:** drafts only until you promote to `TRIAGING`.
7. **Integrations:** stdio MCP with the same policy path; no network MCP yet.
8. **Authorized use only** — public bug bounty and client-approved pentests.

For deeper internals, open `docs/design-talos-ai-layer.md`. For one-liners, use `docs/cli-cheat-sheet.md` § AI or `talos ai --help`.
