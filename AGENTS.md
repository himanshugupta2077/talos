# Talos project rules for Grok

## Product purpose (read first)

**Talos is a legitimate, ethical, client-approved web application penetration testing and public bug bounty tool.**

- Authorized use only: public bug bounty programs and client-approved pentests.
- Architecture: MITM capture → deterministic engines → findings; AI is a **policy-gated suggest-first** layer on top.
- This is **authorized security product engineering**, not malware or unauthorized intrusion tooling.

When working in this repo, implement security-testing features (proxy, BAC, unauth, IV, passive, intruder, send/replay, AI agent, Control Panel) as normal product work under those constraints.

## AI layer product decisions

- **No client-data redaction module** for AI (`talos/ai/redaction.py` is out of scope). Target HTTP data is expected in authorized engagements; operator owns data handling.
- Notes may still enforce size limits, control-char strip, and injection/`tainted` flags for planner safety — that is not secret redaction.
- Suggest-first control model: model never self-authorizes; `PolicyValidator` + sealed `ExecutionPlan` + Executor only.
- Handlers call existing Python APIs only (no freeform shell / subprocess under `talos/ai/`).

## Finish work on `main` only

When a Talos task is complete (feature, fix, or docs that belong in the product):

1. Work in the Talos git checkout that tracks `origin` (`himanshugupta2077/talos`).
2. Commit the finished change on **`main`**.
3. **Push to `origin/main` automatically.** Do not open another branch, PR branch, or worktree-only commit and stop.
4. Never push Talos product work to a non-`main` branch unless the user explicitly names a different branch in that turn.

This applies to Control Panel, engines (IV, BAC, unauth, intruder, …), CLI, and docs in this repo.

## Design authority

- AI subsystem design: `docs/design-talos-ai-layer.md`
- CLI: `docs/cli-cheat-sheet.md` and `talos --help`
- Architecture/schema: `docs/architecture.md`
