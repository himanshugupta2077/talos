"""
Module: talos.input_validation.db

Purpose:
    Input Validation Engine database operations.
    Manages:
        iv_probe_results     — per-HTTP-request evidence (one row per probe sent).
        iv_param_cache       — per-parameter analysis summaries (transformations).
        iv_reflection_cache  — per-endpoint reflection analysis results.
        iv_param_profiles    — versioned parameter intelligence (Module 2).
        iv_endpoint_profiles — endpoint-level profile stubs (Module 2).
        iv_app_profiles      — application/host-level profile stubs (Module 2).

    The canonical storage for scan-phase results is iv_probe_results linked to
    a replay flow in the flows table.  iv_param_cache retains its purpose for
    analysis-phase aggregates (transformations, validation aggregates).
    iv_reflection_cache stores per-endpoint reflection conclusions.

    Profiles (Module 2) are separate documents from phase cache: they hold
    observed/inferred intelligence with confidence, capabilities, and
    placeholders for later modules.  Module 3 (``synthesize``) fills parameter
    profiles offline from probe evidence.  Module 4 multiprobe rows use
    analysis=``multiprobe`` (one flow per multiplexed request).  Module 10
    (``learning``) fills endpoint/app profiles from parameter aggregation and
    feeds inheritance priors into the planner.

Dependencies: sqlite3, json, uuid, datetime, talos.input_validation.profile
Data flow:
    IV scheduler → db helpers → iv_probe_results / iv_param_cache / iv_reflection_cache
    synthesize (Module 3) → upsert_*_profile → iv_*_profiles tables
    learning (Module 10) → list_* / upsert endpoint+app profiles
Side effects: DB reads and writes only.
"""

import hashlib
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from talos.input_validation.profile import (
    LEVEL_APPLICATION,
    LEVEL_ENDPOINT,
    LEVEL_PARAMETER,
    deserialize_profile,
    empty_app_profile,
    empty_endpoint_profile,
    empty_param_profile,
    ensure_profile_shape,
    serialize_profile,
)
from talos.input_validation.outcomes import (
    IV_PROFILE_SCHEMA_VERSION,
    IV_PROFILE_VERSION_INITIAL,
)


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
PHASE_MULTIPROBE = "multiprobe"
PHASE_IDENTIFIER = "identifier"
PHASE_CHARACTERS = "characters"
PHASE_LENGTH = "length"
PHASE_TYPES = "types"
PHASE_TRANSFORMATIONS = "transformations"
PHASE_REFLECTION = "reflection"
PHASE_VALIDATION = "validation"
PHASE_PARSER = "parser"

ALL_PARAM_PHASES = (
    PHASE_BASELINE,
    PHASE_MULTIPROBE,
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
        Does **not** delete intelligence profiles (use clear_all_iv_profiles).
    Output:
        (param_rows_deleted, reflection_rows_deleted)
    Side effects: DB write.
    """
    param_deleted = clear_param_cache(db_path)
    refl_deleted = clear_reflection_cache(db_path)
    return param_deleted, refl_deleted


# ---------------------------------------------------------------------------
# Intelligence profiles (Module 2) — parameter / endpoint / application
# ---------------------------------------------------------------------------

def upsert_param_profile(
    db_path: Path,
    *,
    param_uuid: str | None = None,
    host: str,
    location: str,
    param_name: str,
    profile: dict[str, Any] | None = None,
    bump_version: bool = False,
) -> dict[str, Any]:
    """
    Purpose:
        Insert or update a parameter-level intelligence profile.
        Missing keys are filled via ensure_profile_shape; identity fields
        on the document are aligned with the row key.

    Input:
        param_uuid   — optional; derived from host|location|param_name when None.
        host/location/param_name — parameter identity.
        profile      — partial or full profile dict (None → empty skeleton).
        bump_version — when True and a row already exists, increment
                       profile_version (rewrite counter).

    Output:
        The shaped profile dict that was stored (includes updated_at).

    Side effects: DB write.
    """
    p_uuid = param_uuid or make_param_uuid(host, location, param_name)
    now = _now_utc()
    base = empty_param_profile(
        param_uuid=p_uuid,
        host=host,
        location=location,
        name=param_name,
        updated_at=now,
    )
    merged = ensure_profile_shape(
        {**base, **(profile or {})},
        level=LEVEL_PARAMETER,
    )
    merged["param_uuid"] = p_uuid
    merged["host"] = host
    merged["location"] = location
    merged["name"] = param_name
    merged["level"] = LEVEL_PARAMETER
    merged["updated_at"] = now

    with sqlite3.connect(str(db_path)) as conn:
        existing = conn.execute(
            "SELECT id, profile_version FROM iv_param_profiles WHERE param_uuid = ?",
            (p_uuid,),
        ).fetchone()
        if existing is None:
            merged.setdefault("profile_version", IV_PROFILE_VERSION_INITIAL)
            row_id = str(uuid.uuid4())
            conn.execute(
                """
                INSERT INTO iv_param_profiles
                    (id, param_uuid, host, location, param_name,
                     schema_version, profile_version, profile,
                     created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    row_id,
                    p_uuid,
                    host,
                    location,
                    param_name,
                    int(merged.get("schema_version") or IV_PROFILE_SCHEMA_VERSION),
                    int(merged.get("profile_version") or IV_PROFILE_VERSION_INITIAL),
                    serialize_profile(merged),
                    now,
                    now,
                ),
            )
        else:
            row_id, prev_ver = existing[0], int(existing[1] or 1)
            if bump_version:
                merged["profile_version"] = prev_ver + 1
            else:
                merged["profile_version"] = int(
                    merged.get("profile_version") or prev_ver
                )
            conn.execute(
                """
                UPDATE iv_param_profiles
                SET host = ?, location = ?, param_name = ?,
                    schema_version = ?, profile_version = ?,
                    profile = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    host,
                    location,
                    param_name,
                    int(merged.get("schema_version") or IV_PROFILE_SCHEMA_VERSION),
                    int(merged["profile_version"]),
                    serialize_profile(merged),
                    now,
                    row_id,
                ),
            )
        conn.commit()
    return merged


def get_param_profile(
    db_path: Path,
    param_uuid: str,
) -> dict[str, Any] | None:
    """
    Purpose:
        Load a parameter intelligence profile by param_uuid.
    Output:
        Shaped profile dict, or None if no row exists.
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM iv_param_profiles WHERE param_uuid = ?",
            (param_uuid,),
        ).fetchone()
    if row is None:
        return None
    return _row_to_param_profile(dict(row))


def get_param_profile_by_identity(
    db_path: Path,
    host: str,
    location: str,
    param_name: str,
) -> dict[str, Any] | None:
    """
    Purpose:
        Load a parameter profile by (host, location, param_name).
        Prefer param_uuid lookup when available; this is a convenience path.
    Side effects: Read-only.
    """
    return get_param_profile(db_path, make_param_uuid(host, location, param_name))


def list_param_profiles(
    db_path: Path,
    *,
    host: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """
    Purpose:
        List parameter profiles, optionally filtered by host.
    Output:
        List of shaped profile dicts (newest updated_at first).
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        if host:
            rows = conn.execute(
                """
                SELECT * FROM iv_param_profiles
                WHERE host = ?
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (host, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM iv_param_profiles
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    return [_row_to_param_profile(dict(r)) for r in rows]


def delete_param_profile(db_path: Path, param_uuid: str) -> bool:
    """
    Purpose: Delete one parameter profile by param_uuid.
    Output: True if a row was deleted.
    Side effects: DB write.
    """
    with sqlite3.connect(str(db_path)) as conn:
        cur = conn.execute(
            "DELETE FROM iv_param_profiles WHERE param_uuid = ?",
            (param_uuid,),
        )
        conn.commit()
        return cur.rowcount > 0


def upsert_endpoint_profile(
    db_path: Path,
    *,
    endpoint_id: str,
    host: str = "",
    method: str = "",
    path: str = "",
    profile: dict[str, Any] | None = None,
    bump_version: bool = False,
) -> dict[str, Any]:
    """
    Purpose:
        Insert or update an endpoint-level profile stub.
    Output: Shaped profile dict stored.
    Side effects: DB write.
    """
    now = _now_utc()
    base = empty_endpoint_profile(
        endpoint_id=endpoint_id,
        host=host,
        method=method,
        path=path,
        updated_at=now,
    )
    merged = ensure_profile_shape(
        {**base, **(profile or {})},
        level=LEVEL_ENDPOINT,
    )
    merged["endpoint_id"] = endpoint_id
    if host:
        merged["host"] = host
    if method:
        merged["method"] = method
    if path:
        merged["path"] = path
    merged["level"] = LEVEL_ENDPOINT
    merged["updated_at"] = now

    with sqlite3.connect(str(db_path)) as conn:
        existing = conn.execute(
            "SELECT id, profile_version, host FROM iv_endpoint_profiles WHERE endpoint_id = ?",
            (endpoint_id,),
        ).fetchone()
        stored_host = host or merged.get("host") or ""
        if existing is None:
            conn.execute(
                """
                INSERT INTO iv_endpoint_profiles
                    (id, endpoint_id, host, schema_version, profile_version,
                     profile, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    endpoint_id,
                    stored_host,
                    int(merged.get("schema_version") or IV_PROFILE_SCHEMA_VERSION),
                    int(merged.get("profile_version") or IV_PROFILE_VERSION_INITIAL),
                    serialize_profile(merged),
                    now,
                    now,
                ),
            )
        else:
            row_id, prev_ver, prev_host = existing[0], int(existing[1] or 1), existing[2]
            if bump_version:
                merged["profile_version"] = prev_ver + 1
            else:
                merged["profile_version"] = int(
                    merged.get("profile_version") or prev_ver
                )
            stored_host = host or prev_host or ""
            merged["host"] = stored_host or merged.get("host") or ""
            conn.execute(
                """
                UPDATE iv_endpoint_profiles
                SET host = ?, schema_version = ?, profile_version = ?,
                    profile = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    stored_host,
                    int(merged.get("schema_version") or IV_PROFILE_SCHEMA_VERSION),
                    int(merged["profile_version"]),
                    serialize_profile(merged),
                    now,
                    row_id,
                ),
            )
        conn.commit()
    return merged


def get_endpoint_profile(
    db_path: Path,
    endpoint_id: str,
) -> dict[str, Any] | None:
    """
    Purpose: Load endpoint profile by endpoint_id.
    Output: Shaped profile or None.
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM iv_endpoint_profiles WHERE endpoint_id = ?",
            (endpoint_id,),
        ).fetchone()
    if row is None:
        return None
    return deserialize_profile(row["profile"], level=LEVEL_ENDPOINT)


def upsert_app_profile(
    db_path: Path,
    *,
    host: str,
    profile: dict[str, Any] | None = None,
    bump_version: bool = False,
) -> dict[str, Any]:
    """
    Purpose:
        Insert or update an application/host-level profile stub.
    Output: Shaped profile dict stored.
    Side effects: DB write.
    """
    now = _now_utc()
    base = empty_app_profile(host=host, updated_at=now)
    merged = ensure_profile_shape(
        {**base, **(profile or {})},
        level=LEVEL_APPLICATION,
    )
    merged["host"] = host
    merged["level"] = LEVEL_APPLICATION
    merged["updated_at"] = now

    with sqlite3.connect(str(db_path)) as conn:
        existing = conn.execute(
            "SELECT id, profile_version FROM iv_app_profiles WHERE host = ?",
            (host,),
        ).fetchone()
        if existing is None:
            conn.execute(
                """
                INSERT INTO iv_app_profiles
                    (id, host, schema_version, profile_version,
                     profile, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    host,
                    int(merged.get("schema_version") or IV_PROFILE_SCHEMA_VERSION),
                    int(merged.get("profile_version") or IV_PROFILE_VERSION_INITIAL),
                    serialize_profile(merged),
                    now,
                    now,
                ),
            )
        else:
            row_id, prev_ver = existing[0], int(existing[1] or 1)
            if bump_version:
                merged["profile_version"] = prev_ver + 1
            else:
                merged["profile_version"] = int(
                    merged.get("profile_version") or prev_ver
                )
            conn.execute(
                """
                UPDATE iv_app_profiles
                SET schema_version = ?, profile_version = ?,
                    profile = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    int(merged.get("schema_version") or IV_PROFILE_SCHEMA_VERSION),
                    int(merged["profile_version"]),
                    serialize_profile(merged),
                    now,
                    row_id,
                ),
            )
        conn.commit()
    return merged


def get_app_profile(db_path: Path, host: str) -> dict[str, Any] | None:
    """
    Purpose: Load application/host profile by host key.
    Output: Shaped profile or None.
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM iv_app_profiles WHERE host = ?",
            (host,),
        ).fetchone()
    if row is None:
        return None
    return deserialize_profile(row["profile"], level=LEVEL_APPLICATION)


def list_param_profiles_for_endpoint(
    db_path: Path,
    endpoint_id: str,
) -> list[dict[str, Any]]:
    """
    Purpose:
        Load parameter intelligence profiles for all parameters inventoryed
        on an endpoint (join parameters → host/location/name → profiles).

        Used by Module 10 aggregation.  Params without a profile row are
        omitted.

    Output: List of shaped parameter profiles (may be empty).
    Side effects: Read-only.
    """
    if not endpoint_id:
        return []
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT pp.*
            FROM iv_param_profiles pp
            JOIN endpoints e ON e.host = pp.host
            JOIN parameters p
              ON p.endpoint_id = e.id
             AND p.name = pp.param_name
             AND p.location = pp.location
            WHERE e.id = ?
            ORDER BY pp.updated_at DESC
            """,
            (endpoint_id,),
        ).fetchall()
    return [_row_to_param_profile(dict(r)) for r in rows]


def list_param_profiles_for_host(
    db_path: Path,
    host: str,
    *,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """
    Purpose:
        List parameter profiles on a host (Module 10 app aggregation support).
    Side effects: Read-only.
    """
    return list_param_profiles(db_path, host=host, limit=limit)


def list_endpoint_profiles(
    db_path: Path,
    *,
    host: str | None = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """
    Purpose:
        List endpoint intelligence profiles, optionally filtered by host.
    Output: Shaped endpoint profiles (newest first).
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        if host:
            rows = conn.execute(
                """
                SELECT * FROM iv_endpoint_profiles
                WHERE host = ?
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (host, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT * FROM iv_endpoint_profiles
                ORDER BY updated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        prof = deserialize_profile(r["profile"], level=LEVEL_ENDPOINT)
        prof["endpoint_id"] = r["endpoint_id"] or prof.get("endpoint_id") or ""
        prof["host"] = r["host"] or prof.get("host") or ""
        if r["updated_at"]:
            prof["updated_at"] = r["updated_at"]
        out.append(prof)
    return out


def list_app_profiles(
    db_path: Path,
    *,
    limit: int = 200,
) -> list[dict[str, Any]]:
    """
    Purpose: List all application/host intelligence profiles.
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT * FROM iv_app_profiles
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    out: list[dict[str, Any]] = []
    for r in rows:
        prof = deserialize_profile(r["profile"], level=LEVEL_APPLICATION)
        prof["host"] = r["host"] or prof.get("host") or ""
        if r["updated_at"]:
            prof["updated_at"] = r["updated_at"]
        out.append(prof)
    return out


def get_endpoint_meta(
    db_path: Path,
    endpoint_id: str,
) -> dict[str, str] | None:
    """
    Purpose:
        Resolve host/method/path for an endpoint_id (Module 10 aggregation).
    Output: {host, method, path} or None.
    Side effects: Read-only.
    """
    if not endpoint_id:
        return None
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT host, method, normalized_path, path
            FROM endpoints WHERE id = ?
            """,
            (endpoint_id,),
        ).fetchone()
    if row is None:
        return None
    path = row["normalized_path"] or row["path"] or ""
    return {
        "host": row["host"] or "",
        "method": row["method"] or "",
        "path": path,
    }


def clear_all_iv_profiles(db_path: Path) -> tuple[int, int, int]:
    """
    Purpose:
        Delete all multi-level IV intelligence profiles.
    Output:
        (param_profiles_deleted, endpoint_profiles_deleted, app_profiles_deleted)
    Side effects: DB write.
    """
    with sqlite3.connect(str(db_path)) as conn:
        p = conn.execute("DELETE FROM iv_param_profiles").rowcount
        e = conn.execute("DELETE FROM iv_endpoint_profiles").rowcount
        a = conn.execute("DELETE FROM iv_app_profiles").rowcount
        conn.commit()
    return p, e, a


def _row_to_param_profile(row: dict[str, Any]) -> dict[str, Any]:
    """
    Purpose:
        Map an iv_param_profiles row to a shaped profile dict, ensuring
        identity columns win over any stale JSON fields.
    Side effects: None.
    """
    profile = deserialize_profile(row.get("profile"), level=LEVEL_PARAMETER)
    profile["param_uuid"] = row.get("param_uuid") or profile.get("param_uuid") or ""
    profile["host"] = row.get("host") or profile.get("host") or ""
    profile["location"] = row.get("location") or profile.get("location") or ""
    profile["name"] = row.get("param_name") or profile.get("name") or ""
    if row.get("updated_at"):
        profile["updated_at"] = row["updated_at"]
    if row.get("schema_version") is not None:
        try:
            profile["schema_version"] = int(row["schema_version"])
        except (TypeError, ValueError):
            pass
    if row.get("profile_version") is not None:
        try:
            profile["profile_version"] = int(row["profile_version"])
        except (TypeError, ValueError):
            pass
    return profile


# ---------------------------------------------------------------------------
# Status summary
# ---------------------------------------------------------------------------


def get_iv_status(db_path: Path) -> dict:
    """
    Purpose:
        Compute a status summary for the Input Validation Engine from the
        cache tables, probe evidence, profiles, and scheduler jobs.

        Module 5 adds budget tier, requests_used, max_requests, and pending
        plan state for operator visibility.

        Module 12 adds confidence summary buckets and candidate counts so
        operators can see intelligence readiness without reading SQL.
    Output:
        Dict with counts, planner budget fields, confidence summary, candidates.
    Side effects: Read-only.
    """
    from talos.input_validation.config import load_config
    from talos.input_validation.planner import resolve_max_requests

    config = load_config(db_path)
    budget_tier = (config.probe_strategy or "standard").lower()
    max_requests = resolve_max_requests(
        budget_tier, config.max_requests_per_param or None
    )

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

        # HTTP requests used (completed/failed/skipped scan probe rows).
        requests_row = conn.execute(
            """
            SELECT COUNT(*) as n FROM iv_probe_results
            WHERE status IN ('completed', 'failed', 'skipped')
              AND analysis IN (
                  'baseline', 'multiprobe', 'identifier', 'characters',
                  'length', 'types', 'validation', 'parser'
              )
            """
        ).fetchone()
        requests_used = int(requests_row["n"]) if requests_row else 0

        # Distinct params with any probe evidence.
        params_probed_row = conn.execute(
            "SELECT COUNT(DISTINCT param_uuid) as n FROM iv_probe_results"
        ).fetchone()
        params_probed = int(params_probed_row["n"]) if params_probed_row else 0

        # Params with intelligence profiles (planner/synthesis progress).
        profiles_row = conn.execute(
            "SELECT COUNT(*) as n FROM iv_param_profiles"
        ).fetchone()
        profiles_count = int(profiles_row["n"]) if profiles_row else 0

        # Module 10 multi-level profile counts.
        ep_profiles_row = conn.execute(
            "SELECT COUNT(*) as n FROM iv_endpoint_profiles"
        ).fetchone()
        endpoint_profiles_count = int(ep_profiles_row["n"]) if ep_profiles_row else 0
        app_profiles_row = conn.execute(
            "SELECT COUNT(*) as n FROM iv_app_profiles"
        ).fetchone()
        app_profiles_count = int(app_profiles_row["n"]) if app_profiles_row else 0

        # Pending plan: distinct parameter_uuid values in pending/running IV jobs.
        plan_params: set[str] = set()
        plan_actions: dict[str, int] = {}
        job_rows = conn.execute(
            """
            SELECT meta FROM scheduler_jobs
            WHERE job_type LIKE 'iv_%' AND status IN ('pending', 'running')
            """
        ).fetchall()
        for row in job_rows:
            meta_raw = row["meta"] if "meta" in row.keys() else row[0]
            if not meta_raw:
                continue
            try:
                meta = json.loads(meta_raw)
            except (ValueError, TypeError):
                continue
            pu = meta.get("parameter_uuid") or meta.get("param_uuid") or ""
            if pu:
                plan_params.add(str(pu))
            act = meta.get("planner_action") or meta.get("analysis") or "unknown"
            plan_actions[str(act)] = plan_actions.get(str(act), 0) + 1

        # Module 12: confidence + candidate readiness from stored profiles.
        confidence = _summarize_profile_confidence(conn)

    return {
        "total_params": total,
        "completed": by_status.get(STATUS_COMPLETED, 0),
        "running": running,
        "queued": queued,
        "failed": by_status.get(STATUS_FAILED, 0),
        "budget_tier": budget_tier,
        "max_requests_per_param": max_requests,
        "max_requests_override": int(config.max_requests_per_param or 0),
        "requests_used": requests_used,
        "params_probed": params_probed,
        "profiles": profiles_count,
        "endpoint_profiles": endpoint_profiles_count,
        "app_profiles": app_profiles_count,
        "pending_plan_params": len(plan_params),
        "pending_plan_actions": plan_actions,
        "skipped": by_status.get(STATUS_SKIPPED, 0),
        "confidence": confidence,
    }


def _summarize_profile_confidence(conn: sqlite3.Connection) -> dict:
    """
    Purpose:
        Aggregate operator-facing confidence stats from iv_param_profiles JSON.
        Buckets use consumer guidance (≥90 trust, 60–89 verify, <60 re-probe).
    Output:
        Dict with profile counts, candidate counts, avg confidences, buckets.
    Side effects: Read-only on open connection.
    """
    empty = {
        "profiles_with_capabilities": 0,
        "profiles_with_candidates": 0,
        "candidates_total": 0,
        "candidates_score_ge_60": 0,
        "avg_reflection_confidence": None,
        "avg_type_confidence": None,
        "avg_length_confidence": None,
        "buckets": {"trust": 0, "verify": 0, "reprobe": 0, "unknown": 0},
    }
    try:
        # Column is `profile` (JSON text); tolerate legacy profile_json name.
        cols = {
            r[1]
            for r in conn.execute("PRAGMA table_info(iv_param_profiles)").fetchall()
        }
        col = "profile" if "profile" in cols else (
            "profile_json" if "profile_json" in cols else None
        )
        if not col:
            return empty
        rows = conn.execute(
            f"SELECT {col} FROM iv_param_profiles LIMIT 5000"
        ).fetchall()
    except sqlite3.OperationalError:
        return empty

    refl_vals: list[int] = []
    type_vals: list[int] = []
    length_vals: list[int] = []
    buckets = {"trust": 0, "verify": 0, "reprobe": 0, "unknown": 0}
    with_caps = 0
    with_cands = 0
    cand_total = 0
    cand_ge_60 = 0

    for row in rows:
        raw = row[0]
        if not raw:
            buckets["unknown"] += 1
            continue
        try:
            profile = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            buckets["unknown"] += 1
            continue
        if not isinstance(profile, dict):
            buckets["unknown"] += 1
            continue

        caps = profile.get("capabilities") or []
        if caps:
            with_caps += 1
        cands = profile.get("candidates") or []
        if cands:
            with_cands += 1
        for c in cands:
            if not isinstance(c, dict):
                continue
            cand_total += 1
            try:
                if int(c.get("score") or 0) >= 60:
                    cand_ge_60 += 1
            except (TypeError, ValueError):
                pass

        obs = profile.get("observed") or {}
        if not isinstance(obs, dict):
            obs = {}
        confs: list[int] = []

        refl = obs.get("reflection") or {}
        if isinstance(refl, dict) and refl.get("confidence") is not None:
            try:
                rc = int(refl["confidence"])
                refl_vals.append(rc)
                confs.append(rc)
            except (TypeError, ValueError):
                pass

        length = obs.get("length") or {}
        if isinstance(length, dict) and length.get("confidence") is not None:
            try:
                lc = int(length["confidence"])
                length_vals.append(lc)
                confs.append(lc)
            except (TypeError, ValueError):
                pass

        types = obs.get("types") or {}
        if isinstance(types, dict):
            for entry in types.values():
                if isinstance(entry, dict) and entry.get("confidence") is not None:
                    try:
                        tc = int(entry["confidence"])
                        type_vals.append(tc)
                        confs.append(tc)
                    except (TypeError, ValueError):
                        pass

        if not confs:
            buckets["unknown"] += 1
            continue
        avg = sum(confs) / len(confs)
        if avg >= 90:
            buckets["trust"] += 1
        elif avg >= 60:
            buckets["verify"] += 1
        else:
            buckets["reprobe"] += 1

    def _avg(vals: list[int]) -> float | None:
        if not vals:
            return None
        return round(sum(vals) / len(vals), 1)

    return {
        "profiles_with_capabilities": with_caps,
        "profiles_with_candidates": with_cands,
        "candidates_total": cand_total,
        "candidates_score_ge_60": cand_ge_60,
        "avg_reflection_confidence": _avg(refl_vals),
        "avg_type_confidence": _avg(type_vals),
        "avg_length_confidence": _avg(length_vals),
        "buckets": buckets,
    }


def get_parameter_profile(
    db_path: Path,
    param_id: str,
) -> dict | None:
    """
    Purpose:
        Retrieve the complete Input Validation profile for a single parameter
        identified by its UUID.  Combines the parameters table (passive
        intelligence) with iv_param_cache (active analysis results) and, when
        present, the Module 2 intelligence document from iv_param_profiles
        (key ``intelligence_profile``; None until synthesizer writes it).
    Input:
        param_id — UUID of the parameter row to look up.
    Output:
        A single dict, or None when no parameter with that UUID exists.
    Side effects: Read-only.
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row

        # Fetch the single parameter row by primary key.
        # url_features is schema v53+; fall back when column is absent.
        _param_select_v53 = """
            SELECT
                p.id, p.name,
                e.host, e.method, e.normalized_path,
                p.location, p.param_type, p.semantic_type,
                p.example_values, p.seen_count,
                p.appears_in_roles, p.appears_in_modules,
                p.is_reflected, p.reflection_count,
                p.reflection_locations, p.reflection_encoding,
                p.cross_flow_reflected, p.cross_flow_reflection_count,
                p.cross_flow_sink_endpoints,
                p.url_features
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            WHERE p.id = ?
        """
        _param_select_legacy = """
            SELECT
                p.id, p.name,
                e.host, e.method, e.normalized_path,
                p.location, p.param_type, p.semantic_type,
                p.example_values, p.seen_count,
                p.appears_in_roles, p.appears_in_modules,
                p.is_reflected, p.reflection_count,
                p.reflection_locations, p.reflection_encoding,
                p.cross_flow_reflected, p.cross_flow_reflection_count,
                p.cross_flow_sink_endpoints
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            WHERE p.id = ?
        """
        try:
            passive_rows = conn.execute(_param_select_v53, (param_id,)).fetchall()
        except sqlite3.OperationalError:
            passive_rows = conn.execute(_param_select_legacy, (param_id,)).fetchall()

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

        try:
            cross_flow_sinks = json.loads(row["cross_flow_sink_endpoints"] or "[]")
        except (json.JSONDecodeError, TypeError, KeyError):
            cross_flow_sinks = []
        if not isinstance(cross_flow_sinks, list):
            cross_flow_sinks = []

        # Schema v42+ columns; tolerate pre-migration DBs via KeyError.
        try:
            cross_flow_reflected = bool(row["cross_flow_reflected"])
            cross_flow_count = int(row["cross_flow_reflection_count"] or 0)
        except (KeyError, TypeError, ValueError):
            cross_flow_reflected = False
            cross_flow_count = 0

        # Schema v53+ passive URL sink features (JSON string).
        url_features: dict = {}
        try:
            raw_uf = row["url_features"]
            if isinstance(raw_uf, str) and raw_uf.strip():
                parsed_uf = json.loads(raw_uf)
                if isinstance(parsed_uf, dict):
                    url_features = parsed_uf
            elif isinstance(raw_uf, dict):
                url_features = raw_uf
        except (KeyError, json.JSONDecodeError, TypeError, ValueError):
            url_features = {}

        param_uuid = make_param_uuid(row["host"], row["location"], row["name"])
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
            "cross_flow_reflected": cross_flow_reflected,
            "cross_flow_reflection_count": cross_flow_count,
            "cross_flow_sink_endpoints": cross_flow_sinks,
            "url_features": url_features,
            "iv_phases": iv_phases,
            "iv_reflection": reflection_iv,
            "param_uuid": param_uuid,
            # Module 2 intelligence document (None until synthesizer / M3 fills it).
            "intelligence_profile": get_param_profile(db_path, param_uuid),
        }
