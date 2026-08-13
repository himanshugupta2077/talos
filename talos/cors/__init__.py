"""
Module: talos.cors

Purpose:
    CORS misconfiguration attack module.

    Selects in-scope 200 OK captured flows, mutates the Origin header with
    dynamically generated payloads, and records one unique replay flow per
    probe — the same scheduler-job → unique-flow contract as unauth / BAC /
    auth-session.

Pipeline per job:
    baseline captured flow
          ↓
    set Origin (app default, or synthesized from the request host)
          ↓
    apply one CORS technique payload
          ↓
    send HTTP (new flow UUID; original never mutated)
          ↓
    inspect Access-Control-Allow-Origin / -Credentials
          ↓
    CORS_MISCONFIG | SECURE | UNKNOWN

Finding policy:
    - Issue only when an attacker-controlled origin (random domain or
      attacker subdomain) is reflected in ACAO.
    - Multiple successful techniques cluster as one PRIMARY per target
      origin, with later techniques LINKED.
    - Access-Control-Allow-Credentials: true or ACAO: * are extra evidence
      on that PRIMARY, never standalone findings.

Dependencies:
    talos.replay.db
    talos.projects.annotations
    talos.projects.proxy_config
    talos.scheduler
    talos.findings
"""
