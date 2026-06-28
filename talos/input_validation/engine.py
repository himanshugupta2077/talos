"""
Module: talos.input_validation.engine

Purpose:
    Input Validation Engine orchestration.

    Schedules per-probe analysis jobs for parameters discovered by Endpoint
    Intelligence.  Each individual HTTP probe (one character, one length, one
    type, etc.) becomes its own scheduler job with its own replay flow.

    Scope support:
        project   — all hosts and parameters in the project
        host      — all parameters on a specific host
        endpoint  — all parameters for a specific endpoint
        parameter — all endpoints where a parameter appears

    Per-probe job counts (per parameter):
        baseline        — 1
        identifier      — 9
        characters      — 30
        length          — 10
        types           — 12
        validation      — 8
        transformations — 1  (analysis job, 0 HTTP requests)
        reflection      — 1  (analysis job, per-endpoint, 0 HTTP requests)

    Parameter UUID:
        Deterministic: sha256(f"{host}|{location}|{param_name}")[:32].
        Shared across all endpoints where the same parameter appears on the
        same host in the same location.  Reflection UUID additionally includes
        the endpoint_id because reflection is endpoint-specific.

    Resume behaviour:
        Normal run skips probes that already have a completed iv_probe_results
        row.  Force-refresh (--ignore-cache) resets cache before scheduling.

    This engine NEVER sends requests directly.  Execution happens through
    the scheduler when jobs are picked up by the scheduler daemon.

Dependencies: hashlib, json, sqlite3, uuid, datetime
              talos.input_validation.config, talos.input_validation.db,
              talos.input_validation.phases, talos.scheduler.db,
              talos.scheduler.job
Data flow:
    CLI -> schedule_*() -> scheduler_jobs table -> ReplayScheduler -> _execute_iv_job()
Side effects: DB reads and writes (scheduler jobs, iv cache resets).
"""

import hashlib
import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from talos.input_validation.config import IVConfig, load_config
from talos.input_validation import db as iv_db
from talos.input_validation.phases import (
    IV_IDENTIFIER_PROBES,
    IV_TEST_CHARS,
    IV_TEST_LENGTHS,
    IV_TYPE_PROBES,
    IV_VALIDATION_PROBES,
)
from talos.scheduler import db as sched_db
from talos.scheduler.job import (
    IV_BASELINE, IV_IDENTIFIER, IV_CHARACTERS, IV_LENGTH,
    IV_TYPES, IV_TRANSFORMATIONS, IV_REFLECTION, IV_VALIDATION,
    PRIORITY_AUTO,
)


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


# Ordered sequence of all phases to schedule (scan + analysis).
# Transformations and reflection are analysis phases (0 HTTP requests).
_PARAM_PHASES_ORDERED = (
    IV_BASELINE,
    IV_IDENTIFIER,
    IV_CHARACTERS,
    IV_LENGTH,
    IV_TYPES,
    IV_TRANSFORMATIONS,
    IV_VALIDATION,
    IV_REFLECTION,
)

# Map each analysis phase to its list of (payload_type, payload) tuples.
# Baseline and analysis phases (transformations, reflection) have no probe list.
_PHASE_PROBES: dict[str, list[tuple[str, str]]] = {
    IV_IDENTIFIER: [("identifier", p) for p in IV_IDENTIFIER_PROBES],
    IV_CHARACTERS: [("character", c) for c in IV_TEST_CHARS],
    IV_LENGTH:     [("length", "a" * n) for n in IV_TEST_LENGTHS],
    IV_TYPES:      [(cls, val) for cls, val in IV_TYPE_PROBES],
    IV_VALIDATION: [(cls, val) for cls, val in IV_VALIDATION_PROBES],
}


def schedule_project(
    db_path: Path,
    project_id: str,
    phase_filter: str | None = None,
    ignore_cache: bool = False,
) -> int:
    """
    Purpose:
        Schedule Input Validation jobs for all parameters in the project.
    Input:
        db_path       — Project database path.
        project_id    — Project UUID.
        phase_filter  — If set, only schedule this specific phase.
        ignore_cache  — If True, clear existing cache before scheduling.
    Output:
        Number of jobs enqueued.
    Side effects:
        - May clear iv cache if ignore_cache is True.
        - Inserts rows into scheduler_jobs.
    """
    if ignore_cache:
        iv_db.clear_all_iv_cache(db_path)

    config = load_config(db_path)
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
) -> int:
    """
    Purpose:
        Schedule Input Validation jobs for a named parameter everywhere it appears.
    Output:
        Number of jobs enqueued.
    Side effects: Same as schedule_project, scoped to one parameter name.
    """
    config = load_config(db_path)
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
        For each parameter, create per-probe scheduler jobs.

        Each HTTP-generating phase (baseline, identifier, characters, length,
        types, validation) creates one job per probe.  Analysis phases
        (transformations, reflection) create one aggregate job each.

        Skip jobs whose iv_probe_results row is already 'completed' (unless
        ignore_cache is True).

    Output:
        Number of jobs inserted.
    Side effects: Inserts rows into scheduler_jobs.
    """
    if not params:
        return 0

    excluded_hosts = set(config.excluded_hosts)
    excluded_endpoints = set(config.excluded_endpoints)

    phase_map = {
        IV_BASELINE:        config.analyses.baseline,
        IV_IDENTIFIER:      config.analyses.identifier,
        IV_CHARACTERS:      config.analyses.characters,
        IV_LENGTH:          config.analyses.length,
        IV_TYPES:           config.analyses.types,
        IV_TRANSFORMATIONS: config.analyses.transformations,
        IV_REFLECTION:      config.analyses.reflection,
        IV_VALIDATION:      config.analyses.validation,
    }

    total_enqueued = 0
    # Dedup set: (parameter_uuid, phase, payload_type, payload_index) for scan phases
    # or (endpoint_id, parameter_name, location, phase) for analysis phases.
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

            phases_to_run = (
                [phase_filter]
                if phase_filter
                else list(_PARAM_PHASES_ORDERED)
            )

            for phase in phases_to_run:
                if not phase_map.get(phase, False):
                    continue

                # ── Reflection: per-endpoint analysis job (0 HTTP) ──────────
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

                # ── Transformations: per-param analysis job (0 HTTP) ─────────
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

                # ── Baseline: single probe (no mutation) ─────────────────────
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

                # ── All other scan phases: one job per probe ─────────────────
                probes = _PHASE_PROBES.get(phase, [])
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
                            json.dumps({
                                "host": host,
                                "location": location,
                                "parameter_name": name,
                                "parameter_uuid": param_uuid,
                                "project_id": project_id,
                                "endpoint_id": endpoint_id,
                                "analysis": _phase_to_analysis(phase),
                                "payload": payload,
                                "payload_type": payload_type,
                                "payload_index": idx,
                            }),
                        ),
                    )
                    total_enqueued += 1

        conn.commit()

    return total_enqueued


def _phase_to_analysis(phase: str) -> str:
    """Map a job type constant to the human-readable analysis name."""
    _map = {
        IV_BASELINE:        "baseline",
        IV_IDENTIFIER:      "identifier",
        IV_CHARACTERS:      "characters",
        IV_LENGTH:          "length",
        IV_TYPES:           "types",
        IV_TRANSFORMATIONS: "transformations",
        IV_REFLECTION:      "reflection",
        IV_VALIDATION:      "validation",
    }
    return _map.get(phase, phase.replace("iv_", ""))


# ---------------------------------------------------------------------------
# Parameter query helpers
# ---------------------------------------------------------------------------


def _list_all_params(db_path: Path, project_id: str) -> list[dict]:
    """List all distinct (host, location, name, endpoint_id) in the project."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT DISTINCT e.host, p.location, p.name, e.id AS endpoint_id
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            WHERE e.project_id = ?
            ORDER BY e.host, p.location, p.name
            """,
            (project_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def _list_params_for_host(
    db_path: Path, project_id: str, host: str
) -> list[dict]:
    """List params where endpoint host matches."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT DISTINCT e.host, p.location, p.name, e.id AS endpoint_id
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            WHERE e.project_id = ? AND e.host = ?
            ORDER BY p.location, p.name
            """,
            (project_id, host),
        ).fetchall()
    return [dict(r) for r in rows]


def _list_params_for_endpoint(db_path: Path, endpoint_id: str) -> list[dict]:
    """List all params for a specific endpoint."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT DISTINCT e.host, p.location, p.name, e.id AS endpoint_id
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            WHERE e.id = ?
            ORDER BY p.location, p.name
            """,
            (endpoint_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def _list_params_by_name(
    db_path: Path, project_id: str, param_name: str
) -> list[dict]:
    """List all occurrences of a named parameter across all endpoints."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT DISTINCT e.host, p.location, p.name, e.id AS endpoint_id
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            WHERE e.project_id = ? AND p.name = ?
            ORDER BY e.host, p.location
            """,
            (project_id, param_name),
        ).fetchall()
    return [dict(r) for r in rows]
