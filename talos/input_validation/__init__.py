"""
Package: talos.input_validation

Purpose:
    Active Input Validation Engine for Talos.

    This engine systematically characterizes every input accepted by the
    application by sending controlled requests.  Unlike Endpoint Intelligence
    (which passively observes captured traffic), the Input Validation Engine
    generates probes to understand how each input behaves.

    Philosophy:
        - Never viewed as an attack engine.
        - Answers: what characters are accepted? how is input transformed?
          is it reflected? what does validation look like?
        - Intentionally avoids exploit-specific payloads.
        - Disabled by default — the tester must explicitly enable it.
        - All execution goes through the Talos scheduler for centralized control.

Architecture:
    talos input-validation run
        → InputValidationEngine.schedule_project()
        → Inserts iv_* scheduler jobs
        → Scheduler picks up jobs and calls engine.run_job(job_id)
        → Phase runners execute, update iv_param_cache / iv_reflection_cache
        → Endpoint Intelligence (parameters table) is enriched with results

Sub-modules:
    config  — Read/write per-project IV configuration.
    db      — IV-specific DB operations (cache CRUD, job queries).
    engine  — Analysis orchestration and phase execution.
    phases  — Individual analysis phase implementations.
    cli     — CLI entry point for all input-validation subcommands.
"""
