"""
Package: talos.projects.bac

Purpose:
    BAC (Broken Access Control) attack modules.
    Implements seven test cases targeting role-based access enforcement:

        bac_session_swap   — Direct session swap (replay admin flow with customer token).
        bac_method_fuzz    — HTTP Method Manipulation (verb changes, override headers).
        bac_content_type   — Content-Type Confusion (change request content type).
        bac_url_fuzz       — URL Manipulation (trailing slash, dot segments, encoding).
        bac_header_inject  — Header Manipulation (X-Original-URL, X-Forwarded-For, etc.).
        bac_host_fuzz      — Host Header Changes (replace Host with external value).
        bac_role_inject    — Role Parameter Injection (isAdmin=true, role=admin, etc.).

    All attacks follow the same pipeline:
        1. Scan access matrix → identify BAC candidates.
        2. Validate auth prerequisites for the attacker role.
        3. Generate scheduler jobs (one per flow × variant).
        4. Scheduler executes via bac.engine.execute_bac_job.
        5. Results stored in bac_results table; verdict: POSSIBLE_BAC | SECURE | UNKNOWN.

Dependencies: talos.projects.bac.candidates, .auth_prereq, .variants, .engine, .cli
"""
