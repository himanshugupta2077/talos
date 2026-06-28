"""
Module: talos.input_validation.db

Purpose:
    Input Validation Engine database operations.
    Manages three tables:
        iv_probe_results  — per-HTTP-request evidence (one row per probe sent).
        iv_param_cache    — per-parameter analysis summaries (transformations).
        iv_reflection_cache — per-endpoint reflection analysis results.

    The canonical storage for scan-phase results is iv_probe_results linked to
    a replay flow in the flows table.  iv_param_cache retains its purpose for
    analysis-phase aggregates (transformations, validation aggregates).
    iv_reflection_cache stores per-endpoint reflection conclusions.

Dependencies: sqlite3, json, uuid, datetime
Data flow:
    IV scheduler → db helpers → iv_probe_results / iv_param_cache / iv_reflection_cache
Side effects: DB reads and writes only.
"""

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


def make_param_uuid(host: str, location: str, param_name: str) -> str:
    """
    Purpose:
        Derive a deterministic 32-char hex identifier for a parameter.
        Shared across all endpoints where the same parameter appears on the
        same host in the same location.
        MUST stay in sync with engine.make_param_uuid — same algorithm.
    Side effects: None.
    """
    raw = f"{host}|{location}|{param_name}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# Analysis phase identifiers — must match the scheduler job sub-phases.
PHASE_BASELINE = "baseline"
PHASE_IDENTIFIER = "identifier"
PHASE_CHARACTERS = "characters"
PHASE_LENGTH = "length"
PHASE_TYPES = "types"
PHASE_TRANSFORMATIONS = "transformations"
PHASE_REFLECTION = "reflection"
PHASE_VALIDATION = "validation"

ALL_PARAM_PHASES = (
    PHASE_BASELINE,
    PHASE_IDENTIFIER,
    PHASE_CHARACTERS,
    PHASE_LENGTH,
    PHASE_TYPES,
    PHASE_TRANSFORMATIONS,
    PHASE_VALIDATION,
)

ALL_REFLECTION_PHASES = (PHASE_REFLECTION,)

# Cache status values.
STATUS_NOT_STARTED = "not_started"
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_SKIPPED = "skipped"
STATUS_PARTIAL = "partial"


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# iv_probe_results — per-HTTP-request evidence
# ---------------------------------------------------------------------------

def _decode_body(raw: object, limit: int = 8192) -> str:
    """Decode a response body BLOB or string for analysis, truncated to `limit` bytes."""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")[:limit]
    if isinstance(raw, str):
        return raw[:limit]
    return ""


def upsert_probe_result(
    db_path: Path,
    param_uuid: str,
    endpoint_id: str | None,
    host: str,
    location: str,
    param_name: str,
    analysis: str,
    payload: str | None,
    payload_type: str,
    payload_index: int,
    flow_id: str | None,
    status: str,
) -> None:
    """
    Purpose:
        Insert or update a per-probe evidence row in iv_probe_results.
        HTTP response data (status_code, content_type, body) is NOT stored
        here — it is fetched from the flows table via flow_id when needed.
        UNIQUE key: (param_uuid, analysis, payload_type, payload_index).
    Side effects: DB write.
    """
    now = _now_utc()
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO iv_probe_results
                (id, param_uuid, endpoint_id, host, location, param_name,
                 analysis, payload, payload_type, payload_index,
                 flow_id, status, created_at, completed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(param_uuid, analysis, payload_type, payload_index)
            DO UPDATE SET
                flow_id      = COALESCE(excluded.flow_id, flow_id),
                status       = excluded.status,
                completed_at = CASE WHEN excluded.status IN ('completed','failed','skipped')
                                    THEN excluded.completed_at
                                    ELSE completed_at END
            """,
            (
                str(uuid.uuid4()),
                param_uuid,
                endpoint_id,
                host,
                location,
                param_name,
                analysis,
                payload,
                payload_type,
                payload_index,
                flow_id,
                status,
                now,
                now if status in (STATUS_COMPLETED, STATUS_FAILED, STATUS_SKIPPED) else None,
            ),
        )
        conn.commit()


def is_probe_completed(
    db_path: Path,
    param_uuid: str,
    analysis: str,
    payload_type: str,
    payload_index: int,
) -> bool:
    """
    Purpose:
        Check whether a specific probe has already completed successfully.
        Used by the engine to skip already-completed probes on resume.
    Output:
        True if a 'completed' row exists; False otherwise.
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            """
            SELECT 1 FROM iv_probe_results
            WHERE param_uuid = ? AND analysis = ?
              AND payload_type = ? AND payload_index = ?
              AND status = 'completed'
            LIMIT 1
            """,
            (param_uuid, analysis, payload_type, payload_index),
        ).fetchone()
    return row is not None


def get_probe_results_for_param(
    db_path: Path,
    param_uuid: str,
    analysis: str | None = None,
) -> list[dict]:
    """
    Purpose:
        Retrieve all probe result rows for a parameter UUID, optionally
        filtered to one analysis phase.  HTTP response data (status_code,
        content_type, body) is joined from the flows table via flow_id.
    Output:
        List of dicts with all iv_probe_results columns plus status_code,
        content_type, and decoded body from the linked replay flow.
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        if analysis:
            rows = conn.execute(
                """
                SELECT pr.*,
                       f.status_code, f.content_type AS flow_content_type,
                       f.response_body, f.response_headers
                FROM iv_probe_results pr
                LEFT JOIN flows f ON f.id = pr.flow_id
                WHERE pr.param_uuid = ? AND pr.analysis = ?
                ORDER BY pr.payload_index
                """,
                (param_uuid, analysis),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT pr.*,
                       f.status_code, f.content_type AS flow_content_type,
                       f.response_body, f.response_headers
                FROM iv_probe_results pr
                LEFT JOIN flows f ON f.id = pr.flow_id
                WHERE pr.param_uuid = ?
                ORDER BY pr.analysis, pr.payload_index
                """,
                (param_uuid,),
            ).fetchall()

    result = []
    for row in rows:
        d = dict(row)
        raw_body = d.pop("response_body", None)
        d["body"] = _decode_body(raw_body)
        # Use flow content_type; alias to 'content_type' for consumers
        d["content_type"] = d.pop("flow_content_type", "") or ""
        result.append(d)
    return result


def get_probe_results_for_endpoint(
    db_path: Path,
    endpoint_id: str,
    param_name: str,
    location: str,
) -> list[dict]:
    """
    Purpose:
        Retrieve probe results for a specific endpoint+parameter combination.
        HTTP response data is joined from flows.
        Used by the reflection analysis phase.
    Output:
        List of probe result dicts with decoded body from linked flows.
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT pr.*,
                   f.status_code, f.content_type AS flow_content_type,
                   f.response_body, f.response_headers
            FROM iv_probe_results pr
            LEFT JOIN flows f ON f.id = pr.flow_id
            WHERE pr.endpoint_id = ?
              AND pr.param_name = ?
              AND pr.location = ?
            ORDER BY pr.analysis, pr.payload_index
            """,
            (endpoint_id, param_name, location),
        ).fetchall()

    result = []
    for row in rows:
        d = dict(row)
        raw_body = d.pop("response_body", None)
        d["body"] = _decode_body(raw_body)
        d["content_type"] = d.pop("flow_content_type", "") or ""
        result.append(d)
    return result


def get_probe_flows_for_export(
    db_path: Path,
    param_uuid: str,
) -> list[dict]:
    """
    Purpose:
        Retrieve complete per-probe export data for a parameter, joining
        probe results with full flow metadata, request, and response.
        HTTP data comes from flows; probe identity from iv_probe_results.
    Output:
        List of dicts suitable for Markdown/CSV export.
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT pr.*,
                   f.method, f.url, f.request_headers, f.request_body,
                   f.response_headers, f.response_body,
                   f.status_code, f.content_type AS flow_content_type,
                   f.captured_at AS replay_time,
                   COALESCE(f.flow_meta, '{}') AS flow_meta
            FROM iv_probe_results pr
            LEFT JOIN flows f ON f.id = pr.flow_id
            WHERE pr.param_uuid = ?
            ORDER BY pr.analysis, pr.payload_index
            """,
            (param_uuid,),
        ).fetchall()

    result = []
    for row in rows:
        d = dict(row)
        raw_resp = d.pop("response_body", None)
        d["response_body_text"] = _decode_body(raw_resp, limit=65536)
        raw_req = d.get("request_body")
        if isinstance(raw_req, bytes):
            d["request_body_text"] = raw_req.decode("utf-8", errors="replace")
        elif isinstance(raw_req, str):
            d["request_body_text"] = raw_req
        else:
            d["request_body_text"] = ""
        d["content_type"] = d.pop("flow_content_type", "") or ""
        result.append(d)
    return result


def count_probes_for_param(db_path: Path, param_uuid: str) -> dict:
    """
    Purpose:
        Return probe counts by analysis for a parameter.
    Output:
        dict {analysis: count}.
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            """
            SELECT analysis, COUNT(*) as n
            FROM iv_probe_results
            WHERE param_uuid = ?
            GROUP BY analysis
            """,
            (param_uuid,),
        ).fetchall()
    return {r[0]: r[1] for r in rows}


# ---------------------------------------------------------------------------
# Parameter cache helpers (analysis-phase summaries)
# ---------------------------------------------------------------------------


def get_param_cache_entry(
    db_path: Path,
    host: str,
    location: str,
    param_name: str,
    phase: str,
) -> dict | None:
    """
    Purpose:
        Retrieve a single param cache entry.
    Output:
        Dict with row data, or None if not found.
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT * FROM iv_param_cache
            WHERE host = ? AND location = ? AND param_name = ? AND phase = ?
            """,
            (host, location, param_name, phase),
        ).fetchone()
    return dict(row) if row else None


def is_param_phase_completed(
    db_path: Path,
    host: str,
    location: str,
    param_name: str,
    phase: str,
) -> bool:
    """
    Purpose:
        Check whether a parameter phase analysis has already completed.
        Used to implement resume behaviour — skip completed work.
    """
    entry = get_param_cache_entry(db_path, host, location, param_name, phase)
    return entry is not None and entry["status"] == STATUS_COMPLETED


def upsert_param_cache(
    db_path: Path,
    host: str,
    location: str,
    param_name: str,
    phase: str,
    status: str,
    result: dict,
    flow_id: str | None = None,
) -> None:
    """
    Purpose:
        Insert or update a param cache entry with analysis results.
    Input:
        result   — Dict of phase findings to store as JSON.
        flow_id  — UUID of the base flow used for this analysis (optional).
    Side effects: DB write.
    """
    now = _now_utc()
    with sqlite3.connect(str(db_path)) as conn:
        existing = conn.execute(
            """
            SELECT id FROM iv_param_cache
            WHERE host = ? AND location = ? AND param_name = ? AND phase = ?
            """,
            (host, location, param_name, phase),
        ).fetchone()
        if existing is None:
            conn.execute(
                """
                INSERT INTO iv_param_cache
                    (id, host, location, param_name, phase, status, result,
                     flow_id, started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    host, location, param_name, phase,
                    status,
                    json.dumps(result),
                    flow_id,
                    now if status == STATUS_RUNNING else None,
                    now if status in (STATUS_COMPLETED, STATUS_FAILED, STATUS_SKIPPED) else None,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE iv_param_cache
                SET status = ?, result = ?,
                    flow_id      = COALESCE(?, flow_id),
                    started_at   = COALESCE(started_at, CASE WHEN ? = 'running' THEN ? ELSE NULL END),
                    completed_at = CASE WHEN ? IN ('completed','failed','skipped') THEN ? ELSE completed_at END
                WHERE id = ?
                """,
                (
                    status,
                    json.dumps(result),
                    flow_id,
                    status, now,
                    status, now,
                    existing[0],
                ),
            )
        conn.commit()


def clear_param_cache(
    db_path: Path,
    host: str | None = None,
    param_name: str | None = None,
) -> int:
    """
    Purpose:
        Delete param cache entries.
        Scope options (mutually exclusive):
            host       — delete all entries for one host.
            param_name — delete all entries for one parameter name (all hosts).
            Neither    — delete everything.
    Output:
        Number of rows deleted.
    Side effects: DB write.
    """
    with sqlite3.connect(str(db_path)) as conn:
        if host:
            cur = conn.execute(
                "DELETE FROM iv_param_cache WHERE host = ?", (host,)
            )
        elif param_name:
            cur = conn.execute(
                "DELETE FROM iv_param_cache WHERE param_name = ?", (param_name,)
            )
        else:
            cur = conn.execute("DELETE FROM iv_param_cache")
        conn.commit()
        return cur.rowcount


def clear_param_cache_for_endpoint(db_path: Path, endpoint_id: str) -> int:
    """
    Purpose:
        Delete param cache entries for every parameter that belongs to a
        specific endpoint.  Looks up the endpoint's host and parameter names
        first, then removes matching (host, location, param_name) rows.

        This is the right scope for 'clear-cache --endpoint': param-level
        analyses are shared per host, so clearing them allows a single
        endpoint to be fully re-characterised without touching other endpoints
        on different hosts.
    Input:
        endpoint_id — UUID of the target endpoint.
    Output:
        Number of param cache rows deleted.
    Side effects: DB write.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        # Find all (host, location, param_name) tuples for this endpoint.
        param_rows = conn.execute(
            """
            SELECT e.host, p.location, p.name AS param_name
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            WHERE e.id = ?
            """,
            (endpoint_id,),
        ).fetchall()

        total_deleted = 0
        for row in param_rows:
            cur = conn.execute(
                """
                DELETE FROM iv_param_cache
                WHERE host = ? AND location = ? AND param_name = ?
                """,
                (row["host"], row["location"], row["param_name"]),
            )
            total_deleted += cur.rowcount
        conn.commit()
    return total_deleted


# ---------------------------------------------------------------------------
# Reflection cache helpers
# ---------------------------------------------------------------------------


def get_reflection_cache_entry(
    db_path: Path,
    endpoint_id: str,
    param_name: str,
    location: str,
) -> dict | None:
    """
    Purpose:
        Retrieve a reflection cache entry for a specific endpoint+parameter.
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT * FROM iv_reflection_cache
            WHERE endpoint_id = ? AND param_name = ? AND location = ?
            """,
            (endpoint_id, param_name, location),
        ).fetchone()
    return dict(row) if row else None


def is_reflection_completed(
    db_path: Path,
    endpoint_id: str,
    param_name: str,
    location: str,
) -> bool:
    """Check whether reflection analysis for this endpoint+parameter is complete."""
    entry = get_reflection_cache_entry(db_path, endpoint_id, param_name, location)
    return entry is not None and entry["status"] == STATUS_COMPLETED


def upsert_reflection_cache(
    db_path: Path,
    endpoint_id: str,
    param_name: str,
    location: str,
    status: str,
    result: dict,
    flow_id: str | None = None,
) -> None:
    """
    Purpose:
        Insert or update a reflection cache entry.
    Input:
        flow_id — UUID of the base flow used for this analysis (optional).
    Side effects: DB write.
    """
    now = _now_utc()
    with sqlite3.connect(str(db_path)) as conn:
        existing = conn.execute(
            """
            SELECT id FROM iv_reflection_cache
            WHERE endpoint_id = ? AND param_name = ? AND location = ?
            """,
            (endpoint_id, param_name, location),
        ).fetchone()
        if existing is None:
            conn.execute(
                """
                INSERT INTO iv_reflection_cache
                    (id, endpoint_id, param_name, location, status, result,
                     flow_id, started_at, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    endpoint_id, param_name, location,
                    status,
                    json.dumps(result),
                    flow_id,
                    now if status == STATUS_RUNNING else None,
                    now if status in (STATUS_COMPLETED, STATUS_FAILED, STATUS_SKIPPED) else None,
                ),
            )
        else:
            conn.execute(
                """
                UPDATE iv_reflection_cache
                SET status = ?, result = ?,
                    flow_id      = COALESCE(?, flow_id),
                    started_at   = COALESCE(started_at, CASE WHEN ? = 'running' THEN ? ELSE NULL END),
                    completed_at = CASE WHEN ? IN ('completed','failed','skipped') THEN ? ELSE completed_at END
                WHERE id = ?
                """,
                (
                    status, json.dumps(result),
                    flow_id,
                    status, now,
                    status, now,
                    existing[0],
                ),
            )
        conn.commit()


def clear_reflection_cache(
    db_path: Path,
    endpoint_id: str | None = None,
    param_name: str | None = None,
    host: str | None = None,
) -> int:
    """
    Purpose:
        Delete reflection cache entries.
        Scope options (applied in this priority order):
            endpoint_id — one endpoint only.
            param_name  — one parameter name across all endpoints.
            host        — all endpoints on one host.
            Neither     — delete everything.
    Output:
        Number of rows deleted.
    Side effects: DB write.
    """
    with sqlite3.connect(str(db_path)) as conn:
        if endpoint_id:
            cur = conn.execute(
                "DELETE FROM iv_reflection_cache WHERE endpoint_id = ?",
                (endpoint_id,),
            )
        elif param_name:
            cur = conn.execute(
                "DELETE FROM iv_reflection_cache WHERE param_name = ?",
                (param_name,),
            )
        elif host:
            cur = conn.execute(
                """
                DELETE FROM iv_reflection_cache
                WHERE endpoint_id IN (
                    SELECT id FROM endpoints WHERE host = ?
                )
                """,
                (host,),
            )
        else:
            cur = conn.execute("DELETE FROM iv_reflection_cache")
        conn.commit()
        return cur.rowcount


def clear_all_iv_cache(db_path: Path) -> tuple[int, int]:
    """
    Purpose:
        Delete all Input Validation cache data.
    Output:
        (param_rows_deleted, reflection_rows_deleted)
    Side effects: DB write.
    """
    param_deleted = clear_param_cache(db_path)
    refl_deleted = clear_reflection_cache(db_path)
    return param_deleted, refl_deleted


# ---------------------------------------------------------------------------
# Status summary
# ---------------------------------------------------------------------------


def get_iv_status(db_path: Path) -> dict:
    """
    Purpose:
        Compute a status summary for the Input Validation Engine from the
        cache tables and scheduler jobs.
    Output:
        Dict with counts: total_params, completed, running, queued, failed.
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row

        # Count unique (host, location, param_name) tuples in the cache.
        total_row = conn.execute(
            "SELECT COUNT(DISTINCT host || '|' || location || '|' || param_name) as n FROM iv_param_cache"
        ).fetchone()
        total = total_row["n"] if total_row else 0

        # Count by status.
        status_rows = conn.execute(
            """
            SELECT status, COUNT(*) as n FROM iv_param_cache GROUP BY status
            """
        ).fetchall()
        by_status = {row["status"]: row["n"] for row in status_rows}

        # Pending IV scheduler jobs.
        pending_row = conn.execute(
            """
            SELECT COUNT(*) as n FROM scheduler_jobs
            WHERE job_type LIKE 'iv_%' AND status = 'pending'
            """
        ).fetchone()
        queued = pending_row["n"] if pending_row else 0

        running_row = conn.execute(
            """
            SELECT COUNT(*) as n FROM scheduler_jobs
            WHERE job_type LIKE 'iv_%' AND status = 'running'
            """
        ).fetchone()
        running = running_row["n"] if running_row else 0

    return {
        "total_params": total,
        "completed": by_status.get(STATUS_COMPLETED, 0),
        "running": running,
        "queued": queued,
        "failed": by_status.get(STATUS_FAILED, 0),
    }


def get_parameter_profile(
    db_path: Path,
    param_id: str,
) -> dict | None:
    """
    Purpose:
        Retrieve the complete Input Validation profile for a single parameter
        identified by its UUID.  Combines the parameters table (passive
        intelligence) with iv_param_cache (active analysis results).
    Input:
        param_id — UUID of the parameter row to look up.
    Output:
        A single dict, or None when no parameter with that UUID exists.
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row

        # Fetch the single parameter row by primary key.
        passive_rows = conn.execute(
            """
            SELECT
                p.id, p.name,
                e.host, e.method, e.normalized_path,
                p.location, p.param_type, p.semantic_type,
                p.example_values, p.seen_count,
                p.appears_in_roles, p.appears_in_modules,
                p.is_reflected, p.reflection_count,
                p.reflection_locations, p.reflection_encoding
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            WHERE p.id = ?
            """,
            (param_id,),
        ).fetchall()

        if not passive_rows:
            return None

        # UUID is a primary key — there is exactly one row.
        row = passive_rows[0]

        # Fetch active IV cache for this (host, location, param_name) combo.
        cache_rows = conn.execute(
            """
            SELECT phase, status, result, flow_id FROM iv_param_cache
            WHERE host = ? AND location = ? AND param_name = ?
            """,
            (row["host"], row["location"], row["name"]),
        ).fetchall()

        iv_phases: dict[str, dict] = {}
        for cr in cache_rows:
            try:
                iv_phases[cr["phase"]] = {
                    "status": cr["status"],
                    "flow_id": cr["flow_id"],
                    "result": json.loads(cr["result"]),
                }
            except (json.JSONDecodeError, TypeError):
                iv_phases[cr["phase"]] = {"status": cr["status"], "flow_id": cr["flow_id"], "result": {}}

        # Fetch endpoint-specific reflection cache.
        refl_rows = conn.execute(
            """
            SELECT status, result, flow_id FROM iv_reflection_cache
            WHERE endpoint_id = (SELECT endpoint_id FROM parameters WHERE id = ?)
              AND param_name = ? AND location = ?
            """,
            (param_id, row["name"], row["location"]),
        ).fetchall()
        reflection_iv: dict | None = None
        if refl_rows:
            r = refl_rows[0]
            try:
                reflection_iv = {
                    "status": r["status"],
                    "flow_id": r["flow_id"],
                    "result": json.loads(r["result"]),
                }
            except (json.JSONDecodeError, TypeError):
                reflection_iv = {"status": r["status"], "flow_id": r["flow_id"], "result": {}}

        try:
            examples = json.loads(row["example_values"])
        except (json.JSONDecodeError, TypeError):
            examples = []

        try:
            appears_in_roles = json.loads(row["appears_in_roles"])
        except (json.JSONDecodeError, TypeError):
            appears_in_roles = []

        try:
            appears_in_modules = json.loads(row["appears_in_modules"])
        except (json.JSONDecodeError, TypeError):
            appears_in_modules = []

        try:
            reflection_locations = json.loads(row["reflection_locations"])
        except (json.JSONDecodeError, TypeError):
            reflection_locations = []

        try:
            reflection_encoding = json.loads(row["reflection_encoding"])
        except (json.JSONDecodeError, TypeError):
            reflection_encoding = []

        return {
            "id": row["id"],
            "name": row["name"],
            "host": row["host"],
            "method": row["method"],
            "path": row["normalized_path"],
            "location": row["location"],
            "param_type": row["param_type"],
            "semantic_type": row["semantic_type"],
            "examples": examples,
            "seen_count": row["seen_count"],
            "appears_in_roles": appears_in_roles,
            "appears_in_modules": appears_in_modules,
            "is_reflected": bool(row["is_reflected"]),
            "reflection_count": row["reflection_count"],
            "reflection_locations": reflection_locations,
            "reflection_encoding": reflection_encoding,
            "iv_phases": iv_phases,
            "iv_reflection": reflection_iv,
            "param_uuid": make_param_uuid(row["host"], row["location"], row["name"]),
        }
