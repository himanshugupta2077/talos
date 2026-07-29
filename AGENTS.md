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

## Design authority

- AI subsystem design: `docs/design-talos-ai-layer.md`
- CLI: `docs/cli-cheat-sheet.md` and `talos --help`
- Architecture/schema: `docs/architecture.md`
