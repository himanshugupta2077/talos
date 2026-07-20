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
    config      — Read/write per-project IV configuration (probe_strategy tiers,
                  max_requests_per_param budget override).
    db          — IV-specific DB operations (cache CRUD, profile CRUD, job queries).
    engine      — Analysis orchestration; planner-driven scheduling (M5–M7).
    phases      — Request prep + pure transform/reflection analysis.
    multiprobe  — Canaries + multiplexed multi-signal probes (Module 4).
    planner     — Event-driven adaptive DAG (Module 5): budget, uncertainty,
                  next-action decisions (pure; no HTTP).
    taxonomy    — Character class map + tiered probe selection (Module 6).
    length_search — Binary/log length search + truncation outcomes (Module 6).
    type_intel  — Passive-first type pruning, semantic validation probes,
                  negative-evidence helpers (Module 7).
    parser_intel — Normalization pipeline stages + parser fingerprinting
                  (duplicate keys, JSON null/empty, array styles) (Module 8).
    surface     — Path/header/cookie/multipart/GraphQL/XML inject + auth-skip
                  policy (Module 9).
    learning    — Multi-level learning (Module 10): endpoint/app aggregation,
                  inheritance priors, confidence decay.
    capabilities — Capability flag derivation from observed/inferred (Module 11).
    candidates  — Attack candidate scores + stable consumer API (Module 11):
                  get_param_intelligence / list_candidates.
    cli         — Operator CLI (Module 12): budget, status confidence,
                  candidates list, export JSON/Markdown, synthesize, show.
    fingerprint — Response fingerprints + differential compare (Module 1).
    outcomes    — Validation outcome vocabulary, schema version, classifier
                  (Module 1).  Profile envelope constants.
    profile     — Versioned multi-level profile data model (Module 2):
                  observed/inferred, confidence, tested, attempts, capabilities;
                  empty skeletons + serialize/deserialize.  Persistence via db.
    synthesize  — Offline profile synthesis from iv_probe_results (Module 3);
                  consumes multiprobe + parser rows; zero new HTTP; M11 scoring.

Module 5 (planner) replaces up-front full-matrix enqueue with an adaptive
state machine: baseline → multiprobe → conditional follow-ups → finalize →
synthesize.  Module 6 replaces per-char/fixed-length matrices with taxonomy
class representatives and binary length search.  Module 7 prunes the type
matrix via passive semantic_type, adds semantic business-rule probes, and
keeps exploit-shaped validation strings off the default path.  Module 8
fingerprints parsers (duplicates/null/array) and builds a normalization
pipeline when reflection allows.  Module 9 makes path, headers, cookies,
multipart (fields + filenames), GraphQL variables, and XML leaves first-class
injection surfaces; session/auth artifacts are skipped by default.  Module 10
aggregates parameter intelligence into endpoint and application/host profiles
so new parameters inherit tested negatives and parser expectations (confidence
capped until local confirm), cutting repeat probes under standard.  Module 11
turns capabilities into attack candidate scores (XSS/SQLi/SSRF/open redirect/
HPP/…) for consumers — prioritization only, not confirmed vulns.  Module 12
wires operator UX (CLI, control panel read APIs, docs) so profiles and
candidates are usable without SQL.  Default ``standard`` aims for far fewer
than ~70 requests/param; ``exhaustive`` keeps the extended matrix.
"""
