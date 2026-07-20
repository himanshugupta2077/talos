"""
Module: talos.input_validation.engine

Purpose:
    Input Validation Engine orchestration.

    Schedules per-probe analysis jobs for parameters discovered by Endpoint
    Intelligence.  Each individual HTTP probe becomes its own scheduler job
    with its own replay flow.

    Module 5 (planner): default ``run`` does **not** enqueue the full matrix
    up front.  The deterministic planner schedules the next wave (baseline →
    multiprobe → conditional follow-ups → finalize → synthesize).  On each
    IV job completion the scheduler calls ``continue_param_plan()`` to enqueue
    the next actions.  Explicit phase shortcuts (``--phase`` / phase CLI) still
    enqueue that phase's probes directly.

    Module 6 (taxonomy + length): ``char_drilldown`` expands class
    representatives (not the full 30-char list under standard); ``length_binary``
    uses logarithmic seeds and binary midpoints from length_search.

    Module 7 (types + semantic): ``type_confirm`` expands passive-first pruned
    type probes; ``semantic_rules`` expands core validation + shallow business
    rules (no SQLi/XSS strings under standard).

    Module 8 (parser + normalization): ``parser_probes`` expands location-aware
    duplicate/null/array fingerprint probes plus trim/case/decode normalization
    stages (deep adds unicode/double-encode).

    Module 9 (surface completeness): path/header/cookie/multipart/GraphQL/XML
    are first-class inject surfaces; auth artifacts (session cookies,
    Authorization) are skipped by default unless include_auth_artifacts.

    Scope support:
        project   — all hosts and parameters in the project
        host      — all parameters on a specific host
        endpoint  — all parameters for a specific endpoint
        parameter — all endpoints where a parameter appears

    Budget tiers (probe_strategy): quick | standard | deep | exhaustive
    with optional max_requests_per_param hard cap.

    Parameter UUID:
        Deterministic: sha256(f"{host}|{location}|{param_name}")[:32].

    Resume behaviour:
        Planner skips completed evidence and continues from current state.
        --ignore-cache resets cache before scheduling.

    This engine NEVER sends requests directly.  Execution happens through
    the scheduler when jobs are picked up by the scheduler daemon.

Dependencies: hashlib, json, sqlite3, uuid, datetime
              talos.input_validation.config, db, multiprobe, phases, planner,
              taxonomy, length_search, type_intel, parser_intel, surface
              talos.scheduler.db, talos.scheduler.job
Data flow:
    CLI -> verify_auth_for_iv_scan() -> schedule_*() -> planner plan_next()
        -> scheduler_jobs -> ReplayScheduler._execute_iv_job()
        -> continue_param_plan() -> more jobs or synthesize
Side effects: DB reads and writes (scheduler jobs, iv cache resets).
"""

import hashlib
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from talos.input_validation.config import IVConfig, load_config
from talos.input_validation import db as iv_db
from talos.input_validation.length_search import (
    next_length_targets,
    parse_length_outcomes,
    seed_lengths,
)
from talos.input_validation.multiprobe import (
    build_multiprobe_payload,
    identifier_probes_for_strategy,
)
from talos.input_validation.phases import (
    IV_TEST_LENGTHS,
    IV_TYPE_PROBES,
    IV_VALIDATION_PROBES,
)
from talos.input_validation.type_intel import (
    select_semantic_probes,
    select_type_probes,
    validation_probes_for_strategy,
)
from talos.input_validation.parser_intel import select_parser_probes
from talos.input_validation.surface import (
    PHASE_SURFACE,
    should_skip_param,
    surface_meta,
)
from talos.input_validation.planner import (
    ACTION_BASELINE,
    ACTION_CHARACTERS,
    ACTION_CHAR_DRILLDOWN,
    ACTION_IDENTIFIER,
    ACTION_LENGTH,
    ACTION_LENGTH_BINARY,
    ACTION_MULTIPROBE,
    ACTION_PARSER_PROBES,
    ACTION_REFLECTION,
    ACTION_SEMANTIC_RULES,
    ACTION_SYNTHESIZE,
    ACTION_TRANSFORMATIONS,
    ACTION_TYPE_CONFIRM,
    ACTION_TYPES,
    ACTION_VALIDATION,
    PlanAction,
    PlanContext,
    plan_next,
    resolve_max_requests,
    signals_from_profile,
)
from talos.input_validation.taxonomy import char_probes_for_strategy
from talos.scheduler.job import (
    IV_BASELINE, IV_MULTIPROBE, IV_IDENTIFIER, IV_CHARACTERS, IV_LENGTH,
    IV_TYPES, IV_TRANSFORMATIONS, IV_REFLECTION, IV_VALIDATION, IV_PARSER,
    PRIORITY_AUTO,
)

_log = logging.getLogger("talos.input_validation.engine")

# Map planner action tokens → scheduler job types.
_ACTION_TO_JOB_TYPE: dict[str, str] = {
    ACTION_BASELINE: IV_BASELINE,
    ACTION_MULTIPROBE: IV_MULTIPROBE,
    ACTION_IDENTIFIER: IV_IDENTIFIER,
    ACTION_CHARACTERS: IV_CHARACTERS,
    ACTION_CHAR_DRILLDOWN: IV_CHARACTERS,
    ACTION_LENGTH: IV_LENGTH,
    ACTION_LENGTH_BINARY: IV_LENGTH,
    ACTION_TYPES: IV_TYPES,
    ACTION_TYPE_CONFIRM: IV_TYPES,
    ACTION_VALIDATION: IV_VALIDATION,
    ACTION_SEMANTIC_RULES: IV_VALIDATION,
    ACTION_PARSER_PROBES: IV_PARSER,
    ACTION_TRANSFORMATIONS: IV_TRANSFORMATIONS,
    ACTION_REFLECTION: IV_REFLECTION,
}


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_param_uuid(host: str, location: str, param_name: str) -> str:
    """
    Purpose:
        Derive a deterministic UUID-format identifier for a parameter.
        The UUID is shared across all endpoints where the same parameter
        appears on the same host in the same location.
    Input:
        host       — hostname (e.g. 'api.example.com').
        location   — parameter location (query|body|header|cookie|path).
        param_name — parameter name string.
    Output:
        32-character hex string (first 32 chars of sha256 digest).
    Side effects: None.
    """
    raw = f"{host}|{location}|{param_name}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Auth pre-check — must pass before scheduling IV jobs
# ---------------------------------------------------------------------------

def verify_auth_for_iv_scan(
    db_path: Path,
    project_id: str,
    host: str | None = None,
    endpoint_id: str | None = None,
    param_name: str | None = None,
) -> list[str]:
    """
    Purpose:
        Verify that every role that will be used by the scoped IV scan has a
        complete, valid, and healthy authentication configuration.

        Called by the CLI before scheduling any jobs.  Returns a list of error
        strings — one per failed role.  An empty list means all roles are ready.

        Checks performed for each role:
            1. Auth artifact names are configured (talos auth set).
            2. Authentication provider is set.
            3. MANUAL: session values exist and are not expired.
               AUTO:   at least one flow + extractor is configured.
            4. Validation flow is configured (add-control-flow).
            5. Session confirmed healthy via validate_session().

    Input:
        db_path    — Path to the project's talos.db.
        project_id — Active project UUID.
        host       — Optional hostname scope.
        endpoint_id — Optional endpoint UUID scope.
        param_name — Optional parameter name scope.
    Output:
        List of error strings, one per problematic role.
        Empty list means all roles are ready.
    Side effects:
        Reads DB.  May send outbound HTTP for validation (Layer 3/4 check).
        Does NOT modify role_auth_state.
    """
    from talos.projects.auth import (
        get_auth_config,
        get_role_auth_state,
        get_session_health_config,
        list_auth_flow_configs,
        list_session_health_control_flows,
    )
    from talos.projects.auth_provider import (
        get_provider, get_manual_session_config, get_manual_session_expiry,
        apply_manual_session,
        PROVIDER_MANUAL,
    )
    from talos.projects.session_health import validate_session

    # Collect all distinct role_ids from captured flows for the scoped endpoints.
    role_ids = _collect_role_ids_in_scope(
        db_path, project_id, host, endpoint_id, param_name
    )

    if not role_ids:
        # No flows captured yet — no roles to check.
        return []

    # Check 1: global auth artifact names must be configured.
    auth_cfg = get_auth_config(db_path)
    if not auth_cfg["cookies"] and not auth_cfg["headers"]:
        return [
            "No auth artifact names configured. "
            "Run 'talos auth set --cookie <name>' or '--header <name>' first."
        ]

    errors: list[str] = []

    for role_id in sorted(role_ids):
        role_errors = _verify_single_role(
            db_path, project_id, role_id,
            get_provider, get_manual_session_config, get_manual_session_expiry,
            apply_manual_session, get_session_health_config,
            list_auth_flow_configs, list_session_health_control_flows,
            validate_session, get_role_auth_state,
            PROVIDER_MANUAL,
        )
        errors.extend(role_errors)

    return errors


def _collect_role_ids_in_scope(
    db_path: Path,
    project_id: str,
    host: str | None,
    endpoint_id: str | None,
    param_name: str | None,
) -> set[str]:
    """
    Purpose:
        Collect distinct non-empty role_ids from captured flows for the
        endpoints that would be scanned.
    Output:
        Set of role_id UUID strings.
    Side effects: None (read-only).
    """
    with sqlite3.connect(str(db_path)) as conn:
        if endpoint_id:
            rows = conn.execute(
                """
                SELECT DISTINCT f.role_id
                FROM flows f
                JOIN endpoints e ON e.id = f.endpoint_id
                WHERE e.id = ? AND f.role_id IS NOT NULL AND f.role_id != ''
                """,
                (endpoint_id,),
            ).fetchall()
        elif host:
            rows = conn.execute(
                """
                SELECT DISTINCT f.role_id
                FROM flows f
                JOIN endpoints e ON e.id = f.endpoint_id
                WHERE e.project_id = ? AND e.host = ?
                  AND f.role_id IS NOT NULL AND f.role_id != ''
                """,
                (project_id, host),
            ).fetchall()
        elif param_name:
            rows = conn.execute(
                """
                SELECT DISTINCT f.role_id
                FROM flows f
                JOIN endpoints e ON e.id = f.endpoint_id
                JOIN parameters p ON p.endpoint_id = e.id
                WHERE e.project_id = ? AND p.name = ?
                  AND f.role_id IS NOT NULL AND f.role_id != ''
                """,
                (project_id, param_name),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT DISTINCT f.role_id
                FROM flows f
                JOIN endpoints e ON e.id = f.endpoint_id
                WHERE e.project_id = ? AND f.role_id IS NOT NULL AND f.role_id != ''
                """,
                (project_id,),
            ).fetchall()
    return {row[0] for row in rows}


def _verify_single_role(
    db_path: Path,
    project_id: str,
    role_id: str,
    get_provider,
    get_manual_session_config,
    get_manual_session_expiry,
    apply_manual_session,
    get_session_health_config,
    list_auth_flow_configs,
    list_session_health_control_flows,
    validate_session,
    get_role_auth_state,
    PROVIDER_MANUAL: str,
) -> list[str]:
    """
    Purpose:
        Run all auth readiness checks for a single role.
    Output:
        List of error strings for this role; empty means role is ready.
    Side effects:
        May apply manual session (writes role_auth_state).
        May send outbound HTTP for validation.
    """
    label = f"role={role_id[:8]}"
    errors: list[str] = []

    provider = get_provider(db_path, role_id)

    if provider == PROVIDER_MANUAL:
        # Check: session values exist.
        cfg = get_manual_session_config(db_path, role_id)
        if cfg is None:
            errors.append(
                f"{label}: No manual session configured. "
                "Run 'talos auth-config set-session <role>'."
            )
            return errors

        # Check: session not expired.
        applied = apply_manual_session(db_path, role_id)
        if not applied:
            expiry = get_manual_session_expiry(db_path, role_id)
            if expiry is None:
                errors.append(
                    f"{label}: Manual session has no expiry defined. "
                    "Run 'talos auth-config set-session <role>'."
                )
            else:
                errors.append(
                    f"{label}: Manual session has expired. "
                    "Run 'talos auth-config set-session <role>' to refresh credentials."
                )
            return errors

    else:
        # AUTO: at least one flow with extractor must be configured.
        configs = list_auth_flow_configs(db_path, role_id)
        if not configs:
            errors.append(
                f"{label}: No login flows configured for AUTO provider. "
                "Run 'talos auth-config add-flow <role> <flow_id>'."
            )
            return errors
        if not any(c["extractor_code"] for c in configs):
            errors.append(
                f"{label}: No extractors configured for any login flow. "
                "Run 'talos auth-config set-extractor <role> <flow_id> <file.py>'."
            )
            return errors

    # Check: validation flow configured.
    control_flows = list_session_health_control_flows(db_path, role_id)
    if not control_flows:
        errors.append(
            f"{label}: No validation flow configured. "
            "Run: talos auth-config add-control-flow <role> <flow_id>"
        )
        return errors

    # Check: validation succeeds using current auth state.
    state_info = get_role_auth_state(db_path, role_id)
    if not state_info["state"]:
        errors.append(
            f"{label}: No active auth state. "
            "Run 'talos auth-config refresh <role>'."
        )
        return errors

    alive = validate_session(db_path, role_id, project_id, state_info["state"])
    if not alive:
        errors.append(
            f"{label}: Validation failed — session is not healthy. "
            "Run 'talos auth-config validate <role>' for details."
        )

    return errors


# Ordered sequence of all phases to schedule (scan + analysis).
# Multiprobe runs early (after baseline) as the primary multi-signal probe.
# Transformations and reflection are analysis phases (0 HTTP requests).
_PARAM_PHASES_ORDERED = (
    IV_BASELINE,
    IV_MULTIPROBE,
    IV_IDENTIFIER,
    IV_CHARACTERS,
    IV_LENGTH,
    IV_TYPES,
    IV_TRANSFORMATIONS,
    IV_VALIDATION,
    IV_REFLECTION,
)

# Static probe lists for phases that do not depend on strategy at import time.
# Identifier / multiprobe / characters / length are built per-schedule (M4/M6).
_PHASE_PROBES_STATIC: dict[str, list[tuple[str, str]]] = {
    IV_TYPES:      [(cls, val) for cls, val in IV_TYPE_PROBES],
    IV_VALIDATION: [(cls, val) for cls, val in IV_VALIDATION_PROBES],
}


def _strategy_skips_identifier(strategy: str, multiprobe_on: bool) -> bool:
    """
    Purpose:
        When multiprobe is enabled, standard/quick skip separate identifier
        jobs (canary reflection comes from multiprobe).  deep/exhaustive keep
        identifier jobs.  When multiprobe is off, never skip.
    Side effects: None.
    """
    if not multiprobe_on:
        return False
    s = (strategy or "standard").lower()
    return s in ("quick", "standard")


def _strategy_skips_characters(strategy: str, multiprobe_on: bool) -> bool:
    """
    Purpose:
        Multiprobe embeds taxonomy samples; separate char_drilldown is only
        needed for deep/exhaustive (or when multiprobe is disabled).
        Standard/quick with multiprobe on skip the per-char phase shortcut.
    Side effects: None.
    """
    if not multiprobe_on:
        return False
    s = (strategy or "standard").lower()
    return s in ("quick", "standard")


def _probes_for_phase(
    phase: str,
    config: IVConfig,
) -> list[tuple[str, str]]:
    """
    Purpose:
        Build (payload_type, payload) list for a scan phase under the current
        probe_strategy and analysis toggles.
    Side effects: May read OS entropy for canaries / multiprobe payload.
    """
    strategy = (config.probe_strategy or "standard").lower()
    multiprobe_on = bool(config.analyses.multiprobe)

    if phase == IV_MULTIPROBE:
        plan = build_multiprobe_payload()
        return [("multiprobe", plan.payload)]

    if phase == IV_IDENTIFIER:
        if _strategy_skips_identifier(strategy, multiprobe_on):
            return []
        ids = identifier_probes_for_strategy(strategy)
        return [("identifier", p) for p in ids]

    if phase == IV_CHARACTERS:
        if _strategy_skips_characters(strategy, multiprobe_on):
            return []
        # Module 6: taxonomy representatives (exhaustive = extended list).
        return [
            (ptype, payload)
            for ptype, payload in char_probes_for_strategy(strategy)
        ]

    if phase == IV_LENGTH:
        # Phase shortcut: logarithmic seeds under non-exhaustive; full matrix
        # only for exhaustive (Module 6).
        if strategy == "exhaustive":
            lengths = list(IV_TEST_LENGTHS)
        else:
            lengths = list(seed_lengths(strategy))
        return [("length", "a" * n) for n in lengths]

    if phase == IV_TYPES:
        # Phase shortcut: without per-param passive intel, use a balanced
        # standard confirm set; exhaustive keeps full matrix.
        if strategy == "exhaustive":
            return [(cls, val) for cls, val in IV_TYPE_PROBES]
        plan = select_type_probes(strategy=strategy)
        return [(cls, val) for cls, val in plan.probes]

    if phase == IV_VALIDATION:
        # Module 7: core validation by default; edge SQLi/XSS on deep+ only.
        if strategy == "exhaustive":
            return [(cls, val) for cls, val in IV_VALIDATION_PROBES]
        return validation_probes_for_strategy(strategy)

    return list(_PHASE_PROBES_STATIC.get(phase, []))


def schedule_project(
    db_path: Path,
    project_id: str,
    phase_filter: str | None = None,
    ignore_cache: bool = False,
    *,
    include_auth_artifacts: bool | None = None,
) -> int:
    """
    Purpose:
        Schedule Input Validation jobs for all parameters in the project.
    Input:
        db_path       — Project database path.
        project_id    — Project UUID.
        phase_filter  — If set, only schedule this specific phase.
        ignore_cache  — If True, clear existing cache before scheduling.
        include_auth_artifacts — Module 9 one-shot override (None = config).
    Output:
        Number of jobs enqueued.
    Side effects:
        - May clear iv cache if ignore_cache is True.
        - Inserts rows into scheduler_jobs.
    """
    if ignore_cache:
        iv_db.clear_all_iv_cache(db_path)

    config = load_config(db_path)
    if include_auth_artifacts is not None:
        config.include_auth_artifacts = bool(include_auth_artifacts)
    params = _list_all_params(db_path, project_id)
    return _enqueue_param_jobs(
        db_path, project_id, params, config, phase_filter, ignore_cache
    )


def schedule_host(
    db_path: Path,
    project_id: str,
    host: str,
    phase_filter: str | None = None,
    ignore_cache: bool = False,
    *,
    include_auth_artifacts: bool | None = None,
) -> int:
    """
    Purpose:
        Schedule Input Validation jobs for all parameters on one host.
    Output:
        Number of jobs enqueued.
    Side effects: Same as schedule_project.
    """
    if ignore_cache:
        iv_db.clear_param_cache(db_path, host=host)

    config = load_config(db_path)
    if include_auth_artifacts is not None:
        config.include_auth_artifacts = bool(include_auth_artifacts)
    params = _list_params_for_host(db_path, project_id, host)
    return _enqueue_param_jobs(
        db_path, project_id, params, config, phase_filter, ignore_cache
    )


def schedule_endpoint(
    db_path: Path,
    project_id: str,
    endpoint_id: str,
    phase_filter: str | None = None,
    ignore_cache: bool = False,
    *,
    include_auth_artifacts: bool | None = None,
) -> int:
    """
    Purpose:
        Schedule Input Validation jobs for all parameters of one endpoint.
    Output:
        Number of jobs enqueued.
    Side effects: Same as schedule_project, scoped to one endpoint.
    """
    if ignore_cache:
        iv_db.clear_reflection_cache(db_path, endpoint_id=endpoint_id)

    config = load_config(db_path)
    if include_auth_artifacts is not None:
        config.include_auth_artifacts = bool(include_auth_artifacts)
    params = _list_params_for_endpoint(db_path, endpoint_id)
    return _enqueue_param_jobs(
        db_path, project_id, params, config, phase_filter, ignore_cache,
        endpoint_id_filter=endpoint_id,
    )


def schedule_parameter(
    db_path: Path,
    project_id: str,
    param_name: str,
    phase_filter: str | None = None,
    ignore_cache: bool = False,
    *,
    include_auth_artifacts: bool | None = None,
) -> int:
    """
    Purpose:
        Schedule Input Validation jobs for a named parameter everywhere it appears.
    Output:
        Number of jobs enqueued.
    Side effects: Same as schedule_project, scoped to one parameter name.
    """
    config = load_config(db_path)
    if include_auth_artifacts is not None:
        config.include_auth_artifacts = bool(include_auth_artifacts)
    params = _list_params_by_name(db_path, project_id, param_name)
    return _enqueue_param_jobs(
        db_path, project_id, params, config, phase_filter, ignore_cache
    )


# ---------------------------------------------------------------------------
# Job scheduling helpers
# ---------------------------------------------------------------------------


def _enqueue_param_jobs(
    db_path: Path,
    project_id: str,
    params: list[dict],
    config: IVConfig,
    phase_filter: str | None,
    ignore_cache: bool,
    endpoint_id_filter: str | None = None,
) -> int:
    """
    Purpose:
        For each parameter, schedule work.

        Default path (no phase_filter): Module 5 planner — only the next wave
        of jobs (typically baseline first).  Follow-ups are enqueued via
        continue_param_plan() after each IV job completes.

        Phase filter path: enqueue only that phase's probes (phase CLI).

    Output:
        Number of jobs inserted (synthesize actions count as 0).
    Side effects: Inserts rows into scheduler_jobs; may run offline synthesize.
    """
    if not params:
        return 0

    excluded_hosts = set(config.excluded_hosts)
    excluded_endpoints = set(config.excluded_endpoints)

    # Explicit phase shortcut — legacy direct enqueue for one phase.
    if phase_filter:
        return _enqueue_phase_filter_jobs(
            db_path,
            project_id,
            params,
            config,
            phase_filter,
            ignore_cache,
            endpoint_id_filter,
            excluded_hosts,
            excluded_endpoints,
        )

    total_enqueued = 0
    for param in params:
        host = param["host"]
        location = param["location"]
        name = param["name"]
        endpoint_id = param.get("endpoint_id", "") or ""

        if host in excluded_hosts:
            continue
        if endpoint_id and endpoint_id in excluded_endpoints:
            continue
        if endpoint_id_filter and endpoint_id != endpoint_id_filter:
            continue

        total_enqueued += plan_and_enqueue_for_param(
            db_path,
            project_id,
            host=host,
            location=location,
            name=name,
            endpoint_id=endpoint_id,
            config=config,
            ignore_cache=ignore_cache,
        )

    return total_enqueued


def plan_and_enqueue_for_param(
    db_path: Path,
    project_id: str,
    *,
    host: str,
    location: str,
    name: str,
    endpoint_id: str,
    config: IVConfig | None = None,
    ignore_cache: bool = False,
) -> int:
    """
    Purpose:
        Build PlanContext for one parameter, call plan_next, enqueue actions.
        Safe to call repeatedly (resume / after each probe completion).

        Module 9: auth artifacts and hop-by-hop headers are skipped by default
        (clear skip reason in iv_param_cache phase=surface).
    Output:
        Number of scheduler jobs inserted.
    Side effects:
        Scheduler inserts; may run synthesize_param_profile inline;
        may write surface skip cache rows.
    """
    if config is None:
        config = load_config(db_path)
    param_uuid = make_param_uuid(host, location, name)

    if _record_surface_skip_if_needed(
        db_path,
        host=host,
        location=location,
        name=name,
        param_uuid=param_uuid,
        endpoint_id=endpoint_id,
        config=config,
    ):
        return 0

    ctx = build_plan_context(
        db_path,
        param_uuid=param_uuid,
        host=host,
        location=location,
        name=name,
        endpoint_id=endpoint_id,
        config=config,
    )
    result = plan_next(ctx)
    if result.done or not result.actions:
        return 0
    return enqueue_plan_actions(
        db_path,
        project_id,
        host=host,
        location=location,
        name=name,
        param_uuid=param_uuid,
        endpoint_id=endpoint_id,
        config=config,
        actions=result.actions,
        ignore_cache=ignore_cache,
    )


def _auth_artifact_names(db_path: Path) -> tuple[list[str], list[str]]:
    """
    Purpose:
        Load configured auth cookie/header artifact names (talos auth set).
    Output:
        (cookies, headers) lists; empty on failure.
    Side effects: Read-only DB via auth helpers.
    """
    try:
        from talos.projects.auth import get_auth_config
        cfg = get_auth_config(db_path)
        return list(cfg.get("cookies") or []), list(cfg.get("headers") or [])
    except Exception:  # noqa: BLE001
        return [], []


def _record_surface_skip_if_needed(
    db_path: Path,
    *,
    host: str,
    location: str,
    name: str,
    param_uuid: str,
    endpoint_id: str,
    config: IVConfig,
) -> bool:
    """
    Purpose:
        If the parameter is a hop-by-hop header or auth artifact (and not
        opted-in), write a skipped surface cache row + minimal profile and
        return True so the planner does not enqueue probes.
    Output:
        True when the parameter must be skipped.
    Side effects: May write iv_param_cache and iv_param_profiles.
    """
    cookies, headers = _auth_artifact_names(db_path)
    passive = _passive_param_intel(db_path, host, location, name)
    semantic = str(passive.get("semantic_type") or "unknown")
    decision = should_skip_param(
        location=location,
        name=name,
        semantic_type=semantic,
        include_auth_artifacts=bool(config.include_auth_artifacts),
        configured_cookies=cookies,
        configured_headers=headers,
    )
    if not decision.skip:
        return False

    result = {
        "skip_reason": decision.reason,
        "detail": decision.detail,
        "surface": surface_meta(
            location=location,
            param_name=name,
            semantic_type=semantic,
            skip=decision,
        ),
    }
    try:
        iv_db.upsert_param_cache(
            db_path,
            host,
            location,
            name,
            PHASE_SURFACE,
            iv_db.STATUS_SKIPPED,
            result,
        )
    except Exception as exc:  # noqa: BLE001
        _log.debug("[iv] surface skip cache write failed: %s", exc)

    # Minimal intelligence profile so show/status expose the skip reason.
    try:
        from talos.input_validation.profile import empty_param_profile

        profile = empty_param_profile(
            param_uuid=param_uuid,
            host=host,
            location=location,
            name=name,
            budget_tier=(config.probe_strategy or "standard"),
        )
        profile["status"] = "skipped"
        profile["skip_reason"] = decision.reason
        profile["skip_detail"] = decision.detail
        observed = profile.setdefault("observed", {})
        observed["surface"] = result["surface"]
        iv_db.upsert_param_profile(
            db_path,
            param_uuid=param_uuid,
            host=host,
            location=location,
            param_name=name,
            profile=profile,
            bump_version=False,
        )
    except Exception as exc:  # noqa: BLE001
        _log.debug("[iv] surface skip profile write failed: %s", exc)

    _log.info(
        "[iv] Skipping %s/%s on %s — %s",
        location,
        name,
        host,
        decision.reason,
    )
    return True


def continue_param_plan(
    db_path: Path,
    project_id: str,
    *,
    host: str,
    location: str,
    parameter_name: str,
    parameter_uuid: str,
    endpoint_id: str = "",
) -> int:
    """
    Purpose:
        Invoked after an IV job settles.  Re-plan and enqueue the next wave.
        Keeps adaptive DAG moving without enqueuing the full matrix up front.
    Output:
        Number of new jobs enqueued.
    Side effects: Scheduler inserts; may synthesize profiles.
    """
    config = load_config(db_path)
    # Lightweight offline synthesize after each scan completion so planner
    # signals (reflection, acceptance classes) stay fresh for the next tick.
    try:
        from talos.input_validation.synthesize import synthesize_param_profile
        probes = iv_db.get_probe_results_for_param(db_path, parameter_uuid)
        completed = [
            p for p in probes if p.get("status") == iv_db.STATUS_COMPLETED
        ]
        if completed:
            synthesize_param_profile(
                db_path, parameter_uuid, persist=True, bump_version=False,
            )
    except Exception as exc:  # noqa: BLE001
        _log.debug("[iv] intermediate synthesize skipped: %s", exc)

    n = plan_and_enqueue_for_param(
        db_path,
        project_id,
        host=host,
        location=location,
        name=parameter_name,
        endpoint_id=endpoint_id or "",
        config=config,
        ignore_cache=False,
    )
    if n:
        _log.info(
            "[iv] planner enqueued %s follow-up job(s) for %s/%s on %s",
            n, location, parameter_name, host,
        )
    return n


def build_plan_context(
    db_path: Path,
    *,
    param_uuid: str,
    host: str,
    location: str,
    name: str,
    endpoint_id: str,
    config: IVConfig,
) -> PlanContext:
    """
    Purpose:
        Assemble a PlanContext from probe rows, caches, profile, and config.
    Side effects: Read-only DB.
    """
    a = config.analyses
    analyses_enabled = {
        "baseline": a.baseline,
        "multiprobe": a.multiprobe,
        "identifier": a.identifier,
        "characters": a.characters,
        "length": a.length,
        "types": a.types,
        "transformations": a.transformations,
        "reflection": a.reflection,
        "validation": a.validation,
    }

    probes = iv_db.get_probe_results_for_param(db_path, param_uuid)
    completed_by_analysis: dict[str, int] = {}
    completed_set: set[str] = set()
    # Treat completed + failed + skipped as "attempted" so the planner advances
    # after permanent failures instead of re-enqueuing forever.
    _settled = {
        iv_db.STATUS_COMPLETED,
        iv_db.STATUS_FAILED,
        iv_db.STATUS_SKIPPED,
    }
    for p in probes:
        if p.get("status") not in _settled:
            continue
        analysis = str(p.get("analysis") or "")
        if not analysis:
            continue
        completed_set.add(analysis)
        if p.get("status") == iv_db.STATUS_COMPLETED:
            completed_by_analysis[analysis] = completed_by_analysis.get(analysis, 0) + 1
        else:
            # Count failed/skipped attempts so multiprobe_count still advances.
            completed_by_analysis[analysis] = completed_by_analysis.get(analysis, 0) + 1

    requests_used = sum(
        1 for p in probes
        if p.get("status") in _settled
        and (p.get("analysis") or "") in (
            "baseline", "multiprobe", "identifier", "characters",
            "length", "types", "validation", "parser",
        )
    )

    profile = iv_db.get_param_profile(db_path, param_uuid)
    signals = signals_from_profile(profile)
    profile_used = int(signals.pop("requests_used", 0) or 0)
    requests_used = max(requests_used, profile_used)
    signals.pop("budget_tier", None)

    passive = _passive_param_intel(db_path, host, location, name)
    content_type = _baseline_content_type_hint(db_path, param_uuid)

    transformations_done = iv_db.is_param_phase_completed(
        db_path, host, location, name, IV_TRANSFORMATIONS
    )
    reflection_done = False
    if endpoint_id:
        reflection_done = iv_db.is_reflection_completed(
            db_path, endpoint_id, name, location
        )

    pending = _pending_actions_for_param(db_path, param_uuid)

    max_req = resolve_max_requests(
        config.probe_strategy,
        config.max_requests_per_param or None,
    )

    max_accepted = signals.get("max_accepted_length")
    if max_accepted is not None:
        try:
            max_accepted = int(max_accepted)
        except (TypeError, ValueError):
            max_accepted = None

    # Module 10: load endpoint/app inheritance priors for this parameter.
    budget_tier = (config.probe_strategy or "standard").lower()
    inheritance = _load_plan_inheritance(
        db_path,
        host=host,
        endpoint_id=endpoint_id or "",
        local_profile=profile,
        budget_tier=budget_tier,
    )

    # Merge inherited class outcomes into acceptance_class_count when local empty.
    acceptance_class_count = int(signals.get("acceptance_class_count") or 0)
    if acceptance_class_count < 1 and inheritance.rejected_classes:
        acceptance_class_count = len(inheritance.rejected_classes)

    return PlanContext(
        budget_tier=budget_tier,
        max_requests=max_req,
        requests_used=requests_used,
        completed_analyses=frozenset(completed_set),
        multiprobe_completed_count=completed_by_analysis.get("multiprobe", 0),
        identifier_completed_count=completed_by_analysis.get("identifier", 0),
        characters_completed_count=completed_by_analysis.get("characters", 0),
        length_completed_count=completed_by_analysis.get("length", 0),
        types_completed_count=completed_by_analysis.get("types", 0),
        validation_completed_count=completed_by_analysis.get("validation", 0),
        parser_completed_count=completed_by_analysis.get("parser", 0),
        transformations_done=transformations_done,
        reflection_done=reflection_done,
        synthesize_done=bool(signals.get("synthesize_done")),
        pending_actions=frozenset(pending),
        reflection_state=str(signals.get("reflection_state") or "unknown"),
        reflection_confidence=int(signals.get("reflection_confidence") or 0),
        reflection_uncertainty=str(signals.get("reflection_uncertainty") or "high"),
        length_state=str(signals.get("length_state") or "unknown"),
        length_confidence=int(signals.get("length_confidence") or 0),
        length_uncertainty=str(signals.get("length_uncertainty") or "high"),
        types_known=bool(signals.get("types_known")),
        types_uncertainty=str(signals.get("types_uncertainty") or "high"),
        types_confidence=int(signals.get("types_confidence") or 0),
        acceptance_class_count=acceptance_class_count,
        parser_known=bool(signals.get("parser_known")),
        semantic_type=str(passive.get("semantic_type") or "unknown"),
        param_name=name,
        max_accepted_length=max_accepted,
        content_type=content_type,
        location=location or "query",
        inheritance_active=inheritance.is_active(),
        inherited_tested=dict(inheritance.tested),
        inherited_rejected_classes=inheritance.rejected_classes,
        inherited_accepted_classes=inheritance.accepted_classes,
        suppress_control_probes=bool(inheritance.suppress_control_probes),
        suppress_parser_probes=bool(inheritance.suppress_parser_probes),
        inheritance_reduced_estimate=int(inheritance.reduced_request_estimate),
        analyses_enabled=analyses_enabled,
        has_endpoint=bool(endpoint_id),
    )


def _load_plan_inheritance(
    db_path: Path,
    *,
    host: str,
    endpoint_id: str,
    local_profile: dict[str, Any] | None,
    budget_tier: str,
):
    """
    Purpose:
        Module 10 helper: load inheritance priors for PlanContext.
    Side effects: Read-only DB.
    """
    from talos.input_validation.learning import (
        InheritancePriors,
        load_inheritance_priors,
    )

    try:
        return load_inheritance_priors(
            db_path,
            host=host,
            endpoint_id=endpoint_id or "",
            local_profile=local_profile,
            budget_tier=budget_tier,
        )
    except Exception as exc:  # noqa: BLE001
        _log.debug("[iv] inheritance load failed: %s", exc)
        return InheritancePriors()


def _baseline_content_type_hint(db_path: Path, param_uuid: str) -> str:
    """
    Purpose:
        Best-effort Content-Type from profile baseline fingerprint or empty.
    Side effects: Read-only DB.
    """
    profile = iv_db.get_param_profile(db_path, param_uuid)
    if not profile:
        return ""
    fp = ((profile.get("observed") or {}).get("baseline_fingerprint") or {})
    ct = fp.get("content_type") or ""
    if isinstance(ct, str) and ct:
        return ct
    # content_type on fingerprint may be a coarse family (json/html).
    return str(ct or "")


def _passive_param_intel(
    db_path: Path,
    host: str,
    location: str,
    name: str,
) -> dict[str, Any]:
    """
    Purpose:
        Load passive Endpoint Intelligence (semantic_type, examples) for a
        parameter identified by (host, location, name).
    Output:
        {semantic_type, examples} — empty/unknown defaults when missing.
    Side effects: Read-only DB.
    """
    out: dict[str, Any] = {"semantic_type": "unknown", "examples": []}
    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT p.semantic_type, p.example_values
                FROM parameters p
                JOIN endpoints e ON e.id = p.endpoint_id
                WHERE e.host = ? AND p.location = ? AND p.name = ?
                ORDER BY p.seen_count DESC
                LIMIT 1
                """,
                (host, location, name),
            ).fetchone()
        if not row:
            return out
        st = (row["semantic_type"] or "unknown").strip().lower()
        out["semantic_type"] = st or "unknown"
        try:
            examples = json.loads(row["example_values"] or "[]")
        except (json.JSONDecodeError, TypeError):
            examples = []
        if isinstance(examples, list):
            out["examples"] = [str(x) for x in examples if x is not None]
    except sqlite3.Error as exc:
        _log.debug("[iv] passive param intel read failed: %s", exc)
    return out


def _pending_actions_for_param(db_path: Path, param_uuid: str) -> set[str]:
    """
    Purpose:
        Collect planner action tokens for pending/running IV jobs of this param.
    Side effects: Read-only.
    """
    actions: set[str] = set()
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            """
            SELECT job_type, meta FROM scheduler_jobs
            WHERE status IN ('pending', 'running')
              AND job_type LIKE 'iv_%'
            """
        ).fetchall()
    for job_type, meta_raw in rows:
        meta: dict = {}
        if meta_raw:
            try:
                meta = json.loads(meta_raw)
            except (ValueError, TypeError):
                continue
        if (meta.get("parameter_uuid") or meta.get("param_uuid")) != param_uuid:
            continue
        planned = meta.get("planner_action")
        if planned:
            actions.add(str(planned))
            continue
        analysis = meta.get("analysis") or str(job_type).replace("iv_", "")
        actions.add(str(analysis))
    return actions


def enqueue_plan_actions(
    db_path: Path,
    project_id: str,
    *,
    host: str,
    location: str,
    name: str,
    param_uuid: str,
    endpoint_id: str,
    config: IVConfig,
    actions: list[PlanAction],
    ignore_cache: bool = False,
) -> int:
    """
    Purpose:
        Expand PlanAction tokens into concrete scheduler jobs (or synthesize).
    Output:
        Number of jobs inserted.
    Side effects: DB writes; may call synthesize_param_profile.
    """
    total = 0
    for action in actions:
        if action.action == ACTION_SYNTHESIZE:
            try:
                from talos.input_validation.synthesize import synthesize_param_profile
                synthesize_param_profile(
                    db_path, param_uuid, persist=True, bump_version=True,
                )
            except Exception as exc:  # noqa: BLE001
                _log.warning("[iv] planner synthesize failed: %s", exc)
            continue

        total += _enqueue_single_action(
            db_path,
            project_id,
            host=host,
            location=location,
            name=name,
            param_uuid=param_uuid,
            endpoint_id=endpoint_id,
            config=config,
            action=action,
            ignore_cache=ignore_cache,
        )
    return total


def _enqueue_single_action(
    db_path: Path,
    project_id: str,
    *,
    host: str,
    location: str,
    name: str,
    param_uuid: str,
    endpoint_id: str,
    config: IVConfig,
    action: PlanAction,
    ignore_cache: bool,
) -> int:
    """Expand one PlanAction into 0..N scheduler jobs. Side effects: inserts."""
    token = action.action

    if token == ACTION_TRANSFORMATIONS:
        if not ignore_cache and iv_db.is_param_phase_completed(
            db_path, host, location, name, IV_TRANSFORMATIONS
        ):
            return 0
        if ACTION_TRANSFORMATIONS in _pending_actions_for_param(db_path, param_uuid):
            return 0
        return _insert_analysis_job(
            db_path, project_id, host, location, name, param_uuid,
            endpoint_id, IV_TRANSFORMATIONS, "transformations",
            planner_action=token, hypothesis=action.hypothesis,
        )

    if token == ACTION_REFLECTION:
        if not endpoint_id:
            return 0
        if not ignore_cache and iv_db.is_reflection_completed(
            db_path, endpoint_id, name, location
        ):
            return 0
        if ACTION_REFLECTION in _pending_actions_for_param(db_path, param_uuid):
            return 0
        return _insert_analysis_job(
            db_path, project_id, host, location, name, param_uuid,
            endpoint_id, IV_REFLECTION, "reflection",
            planner_action=token, hypothesis=action.hypothesis,
        )

    if token == ACTION_BASELINE:
        return _insert_scan_probes(
            db_path, project_id, host, location, name, param_uuid,
            endpoint_id, config, IV_BASELINE, [("baseline", None)],
            planner_action=token, hypothesis=action.hypothesis,
            ignore_cache=ignore_cache,
            payload_index_base=0,
        )

    if token == ACTION_MULTIPROBE:
        plan = build_multiprobe_payload()
        idx = int((action.meta or {}).get("multiprobe_index") or 0)
        return _insert_scan_probes(
            db_path, project_id, host, location, name, param_uuid,
            endpoint_id, config, IV_MULTIPROBE, [("multiprobe", plan.payload)],
            planner_action=token, hypothesis=action.hypothesis,
            ignore_cache=ignore_cache,
            payload_index_base=idx,
            multiprobe_plan=plan.to_dict(),
        )

    # Module 6/7/8: char/length/type/semantic/parser need param context from DB/meta.
    if token in (ACTION_CHARACTERS, ACTION_CHAR_DRILLDOWN):
        probes = _char_probes_for_action(
            db_path, param_uuid, config, action,
            host=host, endpoint_id=endpoint_id,
        )
    elif token in (ACTION_LENGTH, ACTION_LENGTH_BINARY):
        probes = _length_probes_for_action(db_path, param_uuid, config, action)
    elif token in (ACTION_TYPE_CONFIRM, ACTION_TYPES, ACTION_SEMANTIC_RULES, ACTION_VALIDATION):
        probes = _type_or_semantic_probes_for_action(
            db_path, host, location, name, param_uuid, config, action, token,
            endpoint_id=endpoint_id,
        )
    elif token == ACTION_PARSER_PROBES:
        return _enqueue_parser_probes(
            db_path, project_id, host, location, name, param_uuid,
            endpoint_id, config, action, ignore_cache=ignore_cache,
        )
    else:
        probes = _probes_for_planner_action(token, config, action)

    if not probes:
        return 0
    job_type = _ACTION_TO_JOB_TYPE.get(token)
    if not job_type:
        _log.warning("[iv] planner action %s has no executor mapping — skipped", token)
        return 0
    return _insert_scan_probes(
        db_path, project_id, host, location, name, param_uuid,
        endpoint_id, config, job_type, probes,
        planner_action=token, hypothesis=action.hypothesis,
        ignore_cache=ignore_cache,
        payload_index_base=0,
        budget_limit=action.estimated_requests if action.estimated_requests > 0 else None,
    )


def _known_class_outcomes_from_profile(
    db_path: Path,
    param_uuid: str,
    *,
    host: str = "",
    endpoint_id: str = "",
    budget_tier: str = "standard",
) -> dict[str, str]:
    """
    Purpose:
        Read multiprobe / prior acceptance class outcomes from the param profile
        so char_drilldown can skip already-settled classes.

        Module 10: merge inherited rejected/accepted classes from endpoint/app
        (local observed always wins when both present).
    Output: class_name → outcome string (empty dict when no profile).
    Side effects: Read-only DB.
    """
    profile = iv_db.get_param_profile(db_path, param_uuid)
    out: dict[str, str] = {}
    if profile:
        classes = (
            ((profile.get("observed") or {}).get("acceptance") or {}).get("classes")
            or {}
        )
        if isinstance(classes, dict):
            for name, entry in classes.items():
                if isinstance(entry, dict) and entry.get("outcome"):
                    out[str(name)] = str(entry["outcome"])

    # Inheritance fills gaps only (local keys already in out win).
    if host or endpoint_id:
        try:
            from talos.input_validation.learning import load_inheritance_priors

            priors = load_inheritance_priors(
                db_path,
                host=host,
                endpoint_id=endpoint_id,
                local_profile=profile,
                budget_tier=budget_tier,
            )
            for cls, outcome in priors.known_class_outcomes(
                budget_tier=budget_tier,
            ).items():
                if cls not in out:
                    out[cls] = outcome
        except Exception as exc:  # noqa: BLE001
            _log.debug("[iv] inheritance class merge failed: %s", exc)
    return out


def _length_outcomes_from_probes(
    db_path: Path,
    param_uuid: str,
) -> dict[int, str]:
    """
    Purpose:
        Collect completed length-phase outcomes for binary refinement.

        Prefer profile ``observed.length.lengths`` (populated by intermediate
        synthesize after each wave).  Fall back to completed probe payload
        lengths with status-based weak outcomes so seeds are not re-enqueued.
    Output: length → outcome map.
    Side effects: Read-only DB.
    """
    # 1) Profile synthesis (accurate accept/reject/truncated).
    profile = iv_db.get_param_profile(db_path, param_uuid)
    if profile:
        lengths = ((profile.get("observed") or {}).get("length") or {}).get("lengths")
        if isinstance(lengths, dict) and lengths:
            out: dict[int, str] = {}
            for k, v in lengths.items():
                try:
                    out[int(k)] = str(v or "unknown")
                except (TypeError, ValueError):
                    continue
            if out:
                return out

    # 2) Probe rows: mark lengths already attempted (status-based weak outcome).
    probes = iv_db.get_probe_results_for_param(db_path, param_uuid, analysis="length")
    rows: list[dict[str, Any]] = []
    for p in probes:
        if p.get("status") not in (
            iv_db.STATUS_COMPLETED,
            iv_db.STATUS_FAILED,
            iv_db.STATUS_SKIPPED,
        ):
            continue
        payload = p.get("payload") or ""
        if not isinstance(payload, str):
            payload = ""
        # Weak outcome from HTTP status when synthesize has not run yet.
        status_code = p.get("status_code")
        if p.get("status") != iv_db.STATUS_COMPLETED:
            outcome = "rejected"
        elif status_code is not None and int(status_code) >= 400:
            outcome = "rejected"
        else:
            outcome = "accepted"
        rows.append({
            "payload": payload,
            "length_value": len(payload) if payload else p.get("payload_index"),
            "outcome": outcome,
        })
    return parse_length_outcomes(rows)


def _char_probes_for_action(
    db_path: Path,
    param_uuid: str,
    config: IVConfig,
    action: PlanAction,
    *,
    host: str = "",
    endpoint_id: str = "",
) -> list[tuple[str, str | None]]:
    """
    Purpose:
        Module 6 executor: expand char_drilldown / characters into class probes.
        Module 10: skip classes rejected at endpoint/app level (standard).
    Side effects: Read-only DB for known class outcomes.
    """
    strategy = (config.probe_strategy or "standard").lower()
    meta = action.meta or {}
    force_full = bool(meta.get("force_full")) or strategy == "exhaustive"
    reflection_state = str(meta.get("reflection_state") or "unknown")
    known = _known_class_outcomes_from_profile(
        db_path,
        param_uuid,
        host=host or str(meta.get("host") or ""),
        endpoint_id=endpoint_id or str(meta.get("endpoint_id") or ""),
        budget_tier=strategy,
    )
    # Meta may carry explicit inherited rejected classes from planner.
    for cls in meta.get("inherited_rejected_classes") or []:
        known.setdefault(str(cls), "rejected")
    if meta.get("suppress_control"):
        known.setdefault("control", "rejected")
        known.setdefault("null", "rejected")
    max_chars = action.estimated_requests if action.estimated_requests > 0 else None
    pairs = char_probes_for_strategy(
        strategy,
        reflection_state=reflection_state,
        known_class_outcomes=known or None,
        force_full=force_full,
        max_chars=max_chars,
    )
    return [(ptype, payload) for ptype, payload in pairs]


def _length_probes_for_action(
    db_path: Path,
    param_uuid: str,
    config: IVConfig,
    action: PlanAction,
) -> list[tuple[str, str | None]]:
    """
    Purpose:
        Module 6 executor: expand length_binary / length into next length targets.
    Side effects: Read-only DB for prior length outcomes.
    """
    strategy = (config.probe_strategy or "standard").lower()
    meta = action.meta or {}
    method = str(meta.get("method") or "binary")
    observed = _length_outcomes_from_probes(db_path, param_uuid)
    max_new = action.estimated_requests if action.estimated_requests > 0 else None

    if method == "matrix" or strategy == "exhaustive" or action.action == ACTION_LENGTH:
        # Exhaustive / legacy length action: fixed matrix minus already done.
        from talos.input_validation.length_search import EXHAUSTIVE_LENGTHS
        if strategy == "exhaustive" or method == "matrix":
            lengths = [n for n in EXHAUSTIVE_LENGTHS if n not in observed]
        else:
            lengths = next_length_targets(
                strategy, observed, max_new=max_new,
            )
    else:
        lengths = next_length_targets(
            strategy, observed, max_new=max_new,
        )

    if max_new is not None and max_new > 0:
        lengths = lengths[: int(max_new)]
    return [("length", "a" * n) for n in lengths]


def _type_or_semantic_probes_for_action(
    db_path: Path,
    host: str,
    location: str,
    name: str,
    param_uuid: str,
    config: IVConfig,
    action: PlanAction,
    token: str,
    *,
    endpoint_id: str = "",
) -> list[tuple[str, str | None]]:
    """
    Purpose:
        Expand type_confirm / types / semantic_rules / validation into probes
        using Module 7 type_intel (passive pruning + core vs edge validation).
        Module 10: filter probes already rejected via inheritance.
    Side effects: Read-only DB for passive intel / length bounds.
    """
    from talos.input_validation.learning import (
        filter_probes_by_inheritance,
        load_inheritance_priors,
    )

    strategy = (config.probe_strategy or "standard").lower()
    meta = action.meta or {}
    passive = _passive_param_intel(db_path, host, location, name)
    semantic_type = str(
        meta.get("semantic_type") or passive.get("semantic_type") or "unknown"
    )
    examples = passive.get("examples") or []
    param_name = str(meta.get("param_name") or name or "")

    max_accepted = meta.get("max_accepted_length")
    profile = iv_db.get_param_profile(db_path, param_uuid)
    if max_accepted is None and profile:
        raw = ((profile.get("observed") or {}).get("length") or {}).get(
            "max_accepted"
        )
        if raw is not None:
            try:
                max_accepted = int(raw)
            except (TypeError, ValueError):
                max_accepted = None

    probes: list[tuple[str, str | None]] = []
    if token == ACTION_TYPES or (
        token == ACTION_TYPE_CONFIRM and strategy == "exhaustive"
    ):
        probes = [(cls, val) for cls, val in IV_TYPE_PROBES]
    elif token == ACTION_TYPE_CONFIRM:
        plan = select_type_probes(
            semantic_type=semantic_type,
            examples=examples if isinstance(examples, list) else None,
            param_name=param_name,
            strategy=strategy,
            max_probes=action.estimated_requests or None,
        )
        probes = [(cls, val) for cls, val in plan.probes]
    elif token == ACTION_SEMANTIC_RULES:
        plan = select_semantic_probes(
            semantic_type=semantic_type,
            examples=examples if isinstance(examples, list) else None,
            param_name=param_name,
            location=location,
            strategy=strategy,
            max_accepted_length=max_accepted if isinstance(max_accepted, int) else None,
            max_probes=action.estimated_requests or None,
            include_core_validation=True,
        )
        probes = [(cls, val) for cls, val in plan.probes]
    elif token == ACTION_VALIDATION:
        # Direct phase CLI / exhaustive matrix: strategy-aware core vs edge.
        if strategy == "exhaustive":
            probes = [(cls, val) for cls, val in IV_VALIDATION_PROBES]
        else:
            probes = validation_probes_for_strategy(strategy)
            # Skip very_long when length bound already known.
            if isinstance(max_accepted, int):
                probes = [(n, v) for n, v in probes if n != "very_long"]
    else:
        return []

    # Module 10: drop families already rejected at endpoint/app (std only).
    try:
        priors = load_inheritance_priors(
            db_path,
            host=host,
            endpoint_id=endpoint_id,
            local_profile=profile,
            budget_tier=strategy,
        )
        # Planner may pass inherited_tested in meta for unit-testability.
        meta_tested = meta.get("inherited_tested")
        if isinstance(meta_tested, dict) and meta_tested and not priors.tested:
            from talos.input_validation.learning import InheritancePriors

            priors = InheritancePriors(
                tested=meta_tested,
                suppress_control_probes=bool(meta.get("suppress_control")),
            )
        probes = filter_probes_by_inheritance(
            probes, priors, budget_tier=strategy,
        )
    except Exception as exc:  # noqa: BLE001
        _log.debug("[iv] inheritance probe filter failed: %s", exc)
    return probes


def _enqueue_parser_probes(
    db_path: Path,
    project_id: str,
    host: str,
    location: str,
    name: str,
    param_uuid: str,
    endpoint_id: str,
    config: IVConfig,
    action: PlanAction,
    *,
    ignore_cache: bool,
) -> int:
    """
    Purpose:
        Module 8 executor: expand parser_probes into iv_parser jobs with
        injection_mode metadata for structural mutations.
    Side effects: Scheduler inserts.
    """
    strategy = (config.probe_strategy or "standard").lower()
    meta = action.meta or {}
    loc = str(meta.get("location") or location or "query")
    ct = str(meta.get("content_type") or "")
    if not ct:
        ct = _baseline_content_type_hint(db_path, param_uuid)
    reflection_state = str(meta.get("reflection_state") or "unknown")
    if reflection_state == "unknown":
        profile = iv_db.get_param_profile(db_path, param_uuid)
        if profile:
            refl = ((profile.get("observed") or {}).get("reflection") or {})
            reflection_state = str(refl.get("state") or "unknown")

    # Module 10: skip parser_probes when parent profile already fingerprinted.
    try:
        from talos.input_validation.learning import (
            load_inheritance_priors,
            should_skip_parser_probes,
        )
        local = iv_db.get_param_profile(db_path, param_uuid)
        priors = load_inheritance_priors(
            db_path,
            host=host,
            endpoint_id=endpoint_id,
            local_profile=local,
            budget_tier=strategy,
        )
        if should_skip_parser_probes(
            priors,
            budget_tier=strategy,
            local_parser_known=bool(
                (local or {}).get("parser")
                or ((local or {}).get("observed") or {}).get("parser")
            ),
        ):
            _log.debug(
                "[iv] parser_probes skipped via inheritance for %s/%s",
                loc, name,
            )
            return 0
    except Exception as exc:  # noqa: BLE001
        _log.debug("[iv] inheritance parser skip check failed: %s", exc)

    plan = select_parser_probes(
        location=loc,
        content_type=ct,
        strategy=strategy,
        reflection_state=reflection_state,
        max_probes=action.estimated_requests or None,
    )
    if not plan.probes:
        _log.debug(
            "[iv] parser_probes empty for %s/%s (%s)",
            loc, name, plan.reason,
        )
        return 0

    # Convert specs to (payload_type, payload) + store injection_mode per job.
    inserted = 0
    analysis_name = "parser"
    with sqlite3.connect(str(db_path)) as conn:
        for offset, spec in enumerate(plan.probes):
            if (
                action.estimated_requests > 0
                and inserted >= action.estimated_requests
            ):
                break
            idx = offset
            if not ignore_cache and iv_db.is_probe_completed(
                db_path, param_uuid, analysis_name, spec.payload_type, idx
            ):
                continue
            meta_obj: dict[str, Any] = {
                "host": host,
                "location": loc,
                "parameter_name": name,
                "parameter_uuid": param_uuid,
                "project_id": project_id,
                "endpoint_id": endpoint_id,
                "analysis": analysis_name,
                "payload": spec.payload,
                "payload_type": spec.payload_type,
                "payload_index": idx,
                "probe_strategy": config.probe_strategy,
                "planner_action": ACTION_PARSER_PROBES,
                "hypothesis": action.hypothesis or spec.hypothesis,
                "injection_mode": spec.injection_mode,
            }
            conn.execute(
                """
                INSERT INTO scheduler_jobs
                    (job_id, endpoint_id, job_type, priority, status,
                     created_at, meta)
                VALUES (?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    endpoint_id or None,
                    IV_PARSER,
                    PRIORITY_AUTO,
                    _now_utc(),
                    json.dumps(meta_obj),
                ),
            )
            inserted += 1
        conn.commit()
    return inserted


def _probes_for_planner_action(
    token: str,
    config: IVConfig,
    action: PlanAction,
) -> list[tuple[str, str | None]]:
    """
    Purpose:
        Expand a planner action token into (payload_type, payload) pairs for
        tokens that do not need DB context (identifier).  Type/semantic/char/
        length use dedicated helpers.
    Side effects: May read OS entropy for canaries.
    """
    strategy = (config.probe_strategy or "standard").lower()

    if token == ACTION_IDENTIFIER:
        ids = identifier_probes_for_strategy(strategy)
        return [("identifier", p) for p in ids]

    # Handled by dedicated executors.
    if token in (
        ACTION_CHARACTERS, ACTION_CHAR_DRILLDOWN,
        ACTION_LENGTH, ACTION_LENGTH_BINARY,
        ACTION_TYPES, ACTION_TYPE_CONFIRM,
        ACTION_VALIDATION, ACTION_SEMANTIC_RULES,
        ACTION_PARSER_PROBES,
    ):
        return []

    return []


def _insert_analysis_job(
    db_path: Path,
    project_id: str,
    host: str,
    location: str,
    name: str,
    param_uuid: str,
    endpoint_id: str,
    job_type: str,
    analysis: str,
    *,
    planner_action: str,
    hypothesis: str,
) -> int:
    """Insert one 0-HTTP analysis job. Output: 1 on success."""
    meta = {
        "host": host,
        "location": location,
        "parameter_name": name,
        "parameter_uuid": param_uuid,
        "project_id": project_id,
        "endpoint_id": endpoint_id,
        "analysis": analysis,
        "planner_action": planner_action,
        "hypothesis": hypothesis,
    }
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO scheduler_jobs
                (job_id, endpoint_id, job_type, priority, status,
                 created_at, meta)
            VALUES (?, ?, ?, ?, 'pending', ?, ?)
            """,
            (
                str(uuid.uuid4()),
                endpoint_id or None,
                job_type,
                PRIORITY_AUTO,
                _now_utc(),
                json.dumps(meta),
            ),
        )
        conn.commit()
    return 1


def _insert_scan_probes(
    db_path: Path,
    project_id: str,
    host: str,
    location: str,
    name: str,
    param_uuid: str,
    endpoint_id: str,
    config: IVConfig,
    job_type: str,
    probes: list[tuple[str, str | None]],
    *,
    planner_action: str,
    hypothesis: str,
    ignore_cache: bool,
    payload_index_base: int = 0,
    multiprobe_plan: dict[str, Any] | None = None,
    budget_limit: int | None = None,
) -> int:
    """
    Purpose:
        Insert one scheduler job per probe, skipping completed unless ignore_cache.
    Output:
        Count inserted.
    Side effects: scheduler_jobs inserts.
    """
    analysis_name = _phase_to_analysis(job_type)
    inserted = 0
    with sqlite3.connect(str(db_path)) as conn:
        for offset, (payload_type, payload) in enumerate(probes):
            if budget_limit is not None and inserted >= budget_limit:
                break
            # Module 6: length probes use payload length as stable payload_index
            # so binary-search refinement waves do not collide with seed indices.
            if (
                analysis_name == "length"
                and isinstance(payload, str)
                and payload_type == "length"
            ):
                idx = len(payload)
            else:
                idx = payload_index_base + offset
            if not ignore_cache and iv_db.is_probe_completed(
                db_path, param_uuid, analysis_name, str(payload_type), idx
            ):
                continue
            meta_obj: dict[str, Any] = {
                "host": host,
                "location": location,
                "parameter_name": name,
                "parameter_uuid": param_uuid,
                "project_id": project_id,
                "endpoint_id": endpoint_id,
                "analysis": analysis_name,
                "payload": payload,
                "payload_type": payload_type,
                "payload_index": idx,
                "probe_strategy": config.probe_strategy,
                "planner_action": planner_action,
                "hypothesis": hypothesis,
            }
            if multiprobe_plan is not None:
                meta_obj["multiprobe"] = multiprobe_plan
            elif job_type == IV_MULTIPROBE and payload:
                from talos.input_validation.multiprobe import parse_multiprobe_payload
                plan = parse_multiprobe_payload(payload)
                if plan is not None:
                    meta_obj["multiprobe"] = plan.to_dict()
            conn.execute(
                """
                INSERT INTO scheduler_jobs
                    (job_id, endpoint_id, job_type, priority, status,
                     created_at, meta)
                VALUES (?, ?, ?, ?, 'pending', ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    endpoint_id or None,
                    job_type,
                    PRIORITY_AUTO,
                    _now_utc(),
                    json.dumps(meta_obj),
                ),
            )
            inserted += 1
        conn.commit()
    return inserted


def _enqueue_phase_filter_jobs(
    db_path: Path,
    project_id: str,
    params: list[dict],
    config: IVConfig,
    phase_filter: str,
    ignore_cache: bool,
    endpoint_id_filter: str | None,
    excluded_hosts: set[str],
    excluded_endpoints: set[str],
) -> int:
    """
    Purpose:
        Direct phase enqueue for CLI phase shortcuts (bypass adaptive planner).
    Output:
        Jobs inserted.
    Side effects: scheduler_jobs inserts.
    """
    phase_map = {
        IV_BASELINE:        config.analyses.baseline,
        IV_MULTIPROBE:      config.analyses.multiprobe,
        IV_IDENTIFIER:      config.analyses.identifier,
        IV_CHARACTERS:      config.analyses.characters,
        IV_LENGTH:          config.analyses.length,
        IV_TYPES:           config.analyses.types,
        IV_TRANSFORMATIONS: config.analyses.transformations,
        IV_REFLECTION:      config.analyses.reflection,
        IV_VALIDATION:      config.analyses.validation,
    }
    if not phase_map.get(phase_filter, False):
        return 0

    total_enqueued = 0
    seen_jobs: set[tuple] = set()

    with sqlite3.connect(str(db_path)) as conn:
        for param in params:
            host = param["host"]
            location = param["location"]
            name = param["name"]
            endpoint_id = param.get("endpoint_id", "")

            if host in excluded_hosts:
                continue
            if endpoint_id and endpoint_id in excluded_endpoints:
                continue
            if endpoint_id_filter and endpoint_id != endpoint_id_filter:
                continue

            param_uuid = make_param_uuid(host, location, name)
            if _record_surface_skip_if_needed(
                db_path,
                host=host,
                location=location,
                name=name,
                param_uuid=param_uuid,
                endpoint_id=endpoint_id or "",
                config=config,
            ):
                continue
            phase = phase_filter

            if phase == IV_REFLECTION:
                if not endpoint_id:
                    continue
                dedup_key = (endpoint_id, name, location, IV_REFLECTION)
                if dedup_key in seen_jobs:
                    continue
                if not ignore_cache and iv_db.is_reflection_completed(
                    db_path, endpoint_id, name, location
                ):
                    continue
                seen_jobs.add(dedup_key)
                conn.execute(
                    """
                    INSERT INTO scheduler_jobs
                        (job_id, endpoint_id, job_type, priority, status,
                         created_at, meta)
                    VALUES (?, ?, ?, ?, 'pending', ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        endpoint_id,
                        IV_REFLECTION,
                        PRIORITY_AUTO,
                        _now_utc(),
                        json.dumps({
                            "host": host,
                            "location": location,
                            "parameter_name": name,
                            "parameter_uuid": param_uuid,
                            "project_id": project_id,
                            "endpoint_id": endpoint_id,
                            "analysis": "reflection",
                        }),
                    ),
                )
                total_enqueued += 1
                continue

            if phase == IV_TRANSFORMATIONS:
                dedup_key = (param_uuid, IV_TRANSFORMATIONS)
                if dedup_key in seen_jobs:
                    continue
                if not ignore_cache and iv_db.is_param_phase_completed(
                    db_path, host, location, name, IV_TRANSFORMATIONS
                ):
                    continue
                seen_jobs.add(dedup_key)
                conn.execute(
                    """
                    INSERT INTO scheduler_jobs
                        (job_id, endpoint_id, job_type, priority, status,
                         created_at, meta)
                    VALUES (?, ?, ?, ?, 'pending', ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        endpoint_id or None,
                        IV_TRANSFORMATIONS,
                        PRIORITY_AUTO,
                        _now_utc(),
                        json.dumps({
                            "host": host,
                            "location": location,
                            "parameter_name": name,
                            "parameter_uuid": param_uuid,
                            "project_id": project_id,
                            "endpoint_id": endpoint_id,
                            "analysis": "transformations",
                        }),
                    ),
                )
                total_enqueued += 1
                continue

            if phase == IV_BASELINE:
                dedup_key = (param_uuid, IV_BASELINE, "baseline", 0)
                if dedup_key in seen_jobs:
                    continue
                if not ignore_cache and iv_db.is_probe_completed(
                    db_path, param_uuid, "baseline", "baseline", 0
                ):
                    continue
                seen_jobs.add(dedup_key)
                conn.execute(
                    """
                    INSERT INTO scheduler_jobs
                        (job_id, endpoint_id, job_type, priority, status,
                         created_at, meta)
                    VALUES (?, ?, ?, ?, 'pending', ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        endpoint_id or None,
                        IV_BASELINE,
                        PRIORITY_AUTO,
                        _now_utc(),
                        json.dumps({
                            "host": host,
                            "location": location,
                            "parameter_name": name,
                            "parameter_uuid": param_uuid,
                            "project_id": project_id,
                            "endpoint_id": endpoint_id,
                            "analysis": "baseline",
                            "payload": None,
                            "payload_type": "baseline",
                            "payload_index": 0,
                        }),
                    ),
                )
                total_enqueued += 1
                continue

            probes = _probes_for_phase(phase, config)
            for idx, (payload_type, payload) in enumerate(probes):
                dedup_key = (param_uuid, phase, payload_type, idx)
                if dedup_key in seen_jobs:
                    continue
                if not ignore_cache and iv_db.is_probe_completed(
                    db_path, param_uuid, _phase_to_analysis(phase),
                    payload_type, idx
                ):
                    continue
                seen_jobs.add(dedup_key)
                analysis_name = _phase_to_analysis(phase)
                meta_obj: dict = {
                    "host": host,
                    "location": location,
                    "parameter_name": name,
                    "parameter_uuid": param_uuid,
                    "project_id": project_id,
                    "endpoint_id": endpoint_id,
                    "analysis": analysis_name,
                    "payload": payload,
                    "payload_type": payload_type,
                    "payload_index": idx,
                    "probe_strategy": config.probe_strategy,
                }
                if phase == IV_MULTIPROBE:
                    from talos.input_validation.multiprobe import (
                        parse_multiprobe_payload,
                    )
                    plan = parse_multiprobe_payload(payload)
                    if plan is not None:
                        meta_obj["multiprobe"] = plan.to_dict()
                conn.execute(
                    """
                    INSERT INTO scheduler_jobs
                        (job_id, endpoint_id, job_type, priority, status,
                         created_at, meta)
                    VALUES (?, ?, ?, ?, 'pending', ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        endpoint_id or None,
                        phase,
                        PRIORITY_AUTO,
                        _now_utc(),
                        json.dumps(meta_obj),
                    ),
                )
                total_enqueued += 1

        conn.commit()

    return total_enqueued



def _phase_to_analysis(phase: str) -> str:
    """Map a job type constant to the human-readable analysis name."""
    _map = {
        IV_BASELINE:        "baseline",
        IV_MULTIPROBE:      "multiprobe",
        IV_IDENTIFIER:      "identifier",
        IV_CHARACTERS:      "characters",
        IV_LENGTH:          "length",
        IV_TYPES:           "types",
        IV_TRANSFORMATIONS: "transformations",
        IV_REFLECTION:      "reflection",
        IV_VALIDATION:      "validation",
        IV_PARSER:          "parser",
    }
    return _map.get(phase, phase.replace("iv_", ""))


# ---------------------------------------------------------------------------
# Parameter query helpers
# ---------------------------------------------------------------------------


def _list_all_params(db_path: Path, project_id: str) -> list[dict]:
    """List all distinct (host, location, name, endpoint_id) from qualified endpoints in the project."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT DISTINCT e.host, p.location, p.name, e.id AS endpoint_id
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            JOIN endpoint_policy ep ON ep.endpoint_id = e.id
            WHERE e.project_id = ?
              AND ep.qualified = 1
              AND ep.excluded = 0
            ORDER BY e.host, p.location, p.name
            """,
            (project_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def _list_params_for_host(
    db_path: Path, project_id: str, host: str
) -> list[dict]:
    """List params where endpoint host matches and endpoint is qualified."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT DISTINCT e.host, p.location, p.name, e.id AS endpoint_id
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            JOIN endpoint_policy ep ON ep.endpoint_id = e.id
            WHERE e.project_id = ? AND e.host = ?
              AND ep.qualified = 1
              AND ep.excluded = 0
            ORDER BY p.location, p.name
            """,
            (project_id, host),
        ).fetchall()
    return [dict(r) for r in rows]


def _list_params_for_endpoint(db_path: Path, endpoint_id: str) -> list[dict]:
    """List all params for a specific endpoint (endpoint must be qualified)."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT DISTINCT e.host, p.location, p.name, e.id AS endpoint_id
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            JOIN endpoint_policy ep ON ep.endpoint_id = e.id
            WHERE e.id = ?
              AND ep.qualified = 1
              AND ep.excluded = 0
            ORDER BY p.location, p.name
            """,
            (endpoint_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def _list_params_by_name(
    db_path: Path, project_id: str, param_name: str
) -> list[dict]:
    """List all occurrences of a named parameter across all qualified endpoints."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT DISTINCT e.host, p.location, p.name, e.id AS endpoint_id
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            JOIN endpoint_policy ep ON ep.endpoint_id = e.id
            WHERE e.project_id = ? AND p.name = ?
              AND ep.qualified = 1
              AND ep.excluded = 0
            ORDER BY e.host, p.location
            """,
            (project_id, param_name),
        ).fetchall()
    return [dict(r) for r in rows]
