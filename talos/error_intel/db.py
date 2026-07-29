"""
Module: talos.error_intel.db

Purpose:
    SQLite CRUD for Error Intelligence tables (schema v43):

        error_clusters       — unique fingerprint per project
        error_observations   — each flow / attack sighting
        error_intel_config   — single-row defaults (id='default')

    Intelligence only — no finding_id, no auto Findings in v1.

    Every function opens and closes its own connection (same pattern as
    talos.passive.db / talos.findings.db). No persistent handles.

Dependencies:
    sqlite3, json, uuid, datetime, pathlib
    talos.error_intel.{constants, config, models, classify}
Data flow:
    classify → upsert_error_cluster / insert_error_observation
    CLI / later worker → get/list helpers
Side effects:
    All write helpers commit to the project SQLite database.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

from talos.error_intel.classify import ClassifiedError
from talos.error_intel.config import ErrorIntelConfig, config_from_dict, default_config
from talos.error_intel.constants import (
    ATTACK_TYPE_UNKNOWN,
    DEFAULT_PAYLOAD_REDACTED_MAX,
    ERROR_INTEL_VERSION,
)
from talos.error_intel.models import ErrorArtifact, ErrorCluster, ErrorObservation


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _now() -> str:
    """Return current UTC time as ISO-8601 string. Side effects: None."""
    return datetime.now(timezone.utc).isoformat()


def _connect(db_path: Path) -> sqlite3.Connection:
    """
    Purpose:
        Open a WAL-mode connection with foreign keys and Row factory.
    Side effects:
        Opens a file handle to the database.
    """
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def _json_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _json_loads_list(raw: Optional[str]) -> list[Any]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return list(data) if isinstance(data, list) else []
    except (json.JSONDecodeError, TypeError):
        return []


def _cluster_from_row(row: sqlite3.Row) -> ErrorCluster:
    techs = _json_loads_list(row["technologies_json"])
    return ErrorCluster(
        id=row["id"],
        project_id=row["project_id"],
        fingerprint=row["fingerprint"],
        category=row["category"] or "unknown",
        severity=row["severity"] or "low",
        language=row["language"] or "unknown",
        framework=row["framework"],
        database=row["database"],
        server=row["server"],
        exception_type=row["exception_type"],
        message_norm=row["message_norm"],
        technologies=[str(t) for t in techs],
        has_stack_trace=bool(row["has_stack_trace"]),
        has_path_leak=bool(row["has_path_leak"]),
        has_internal_host=bool(row["has_internal_host"]),
        has_version_leak=bool(row["has_version_leak"]),
        confidence=int(row["confidence"] or 0),
        evidence_snippet=row["evidence_snippet"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        observation_count=int(row["observation_count"] or 0),
        scanner_version=row["scanner_version"],
    )


def _observation_from_row(row: sqlite3.Row) -> ErrorObservation:
    raw_arts = _json_loads_list(row["artifacts_json"])
    artifacts: list[ErrorArtifact] = []
    for item in raw_arts:
        if isinstance(item, dict):
            artifacts.append(
                ErrorArtifact(
                    kind=str(item.get("kind") or ""),
                    value=str(item.get("value") or ""),
                    normalized=item.get("normalized"),
                )
            )
    detectors = _json_loads_list(row["detectors_json"])
    return ErrorObservation(
        id=row["id"],
        error_id=row["error_id"],
        flow_id=row["flow_id"],
        endpoint_id=row["endpoint_id"],
        parameter_uuid=row["parameter_uuid"],
        parameter_name=row["parameter_name"],
        attack_type=row["attack_type"] or ATTACK_TYPE_UNKNOWN,
        payload_redacted=row["payload_redacted"],
        response_status=row["response_status"],
        response_length=row["response_length"],
        duration_ms=row["duration_ms"],
        response_hash=row["response_hash"],
        artifacts=artifacts,
        detectors=[str(d) for d in detectors],
        observed_at=row["observed_at"],
    )


def _config_from_row(row: sqlite3.Row) -> ErrorIntelConfig:
    keys = row.keys()
    names_raw = row["error_header_names_json"] if "error_header_names_json" in keys else "[]"
    try:
        names = json.loads(names_raw or "[]")
    except (json.JSONDecodeError, TypeError):
        names = []
    data: dict[str, Any] = {
        "enabled": bool(row["enabled"]),
        "store_generic_http_errors": bool(row["store_generic_http_errors"]),
        "max_body_scan": int(row["max_body_scan"]),
        "gate_sniff_bytes": int(row["gate_sniff_bytes"]),
        "queue_maxsize": int(row["queue_maxsize"]),
        "evidence_snippet_max": int(row["evidence_snippet_max"]),
        "error_header_names": names if isinstance(names, list) else [],
    }
    return config_from_dict(data)


# ------------------------------------------------------------------ #
# Config                                                               #
# ------------------------------------------------------------------ #

def _ensure_schema(db_path: Path) -> None:
    """
    Purpose:
        Apply project schema migrations so error_intel tables exist before
        any CRUD. Safe no-op when already at SCHEMA_VERSION.
    Side effects:
        May CREATE tables / UPDATE schema_version via migrate_project_db.
    """
    # Lazy import avoids a circular dependency at module load
    # (projects.db does not import error_intel).
    from talos.projects.db import migrate_project_db

    migrate_project_db(db_path)


def ensure_config(db_path: Path) -> ErrorIntelConfig:
    """
    Purpose:
        Ensure the single-row error_intel_config exists and return it.
    Side effects:
        May migrate project schema (v43+) so the table exists.
        INSERT OR IGNORE of id='default' when missing.
    """
    _ensure_schema(db_path)
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO error_intel_config (id) VALUES ('default')"
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM error_intel_config WHERE id = 'default'"
        ).fetchone()
    if row is None:
        return default_config()
    return _config_from_row(row)


def get_config(db_path: Path) -> ErrorIntelConfig:
    """Load error intel settings (seeds defaults if missing)."""
    return ensure_config(db_path)


def update_config(db_path: Path, config: ErrorIntelConfig) -> ErrorIntelConfig:
    """
    Purpose:
        Persist a full ErrorIntelConfig as the single default row.
    Side effects:
        May migrate project schema; INSERT OR REPLACE into error_intel_config.
    """
    _ensure_schema(db_path)
    names = sorted(config.error_header_names)
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO error_intel_config (
                id, enabled, store_generic_http_errors,
                max_body_scan, gate_sniff_bytes, queue_maxsize,
                evidence_snippet_max, error_header_names_json
            ) VALUES (
                'default', ?, ?,
                ?, ?, ?,
                ?, ?
            )
            """,
            (
                1 if config.enabled else 0,
                1 if config.store_generic_http_errors else 0,
                int(config.max_body_scan),
                int(config.gate_sniff_bytes),
                int(config.queue_maxsize),
                int(config.evidence_snippet_max),
                _json_dumps(names),
            ),
        )
        conn.commit()
    return config


# ------------------------------------------------------------------ #
# Error clusters                                                       #
# ------------------------------------------------------------------ #

def get_cluster(db_path: Path, error_id: str) -> Optional[ErrorCluster]:
    """Load cluster by primary key. Read-only."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM error_clusters WHERE id = ?",
            (error_id,),
        ).fetchone()
    if row is None:
        return None
    return _cluster_from_row(row)


def get_cluster_by_fingerprint(
    db_path: Path,
    project_id: str,
    fingerprint: str,
) -> Optional[ErrorCluster]:
    """Look up cluster by project + fingerprint unique key. Read-only."""
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT * FROM error_clusters
            WHERE project_id = ? AND fingerprint = ?
            """,
            (project_id, fingerprint),
        ).fetchone()
    if row is None:
        return None
    return _cluster_from_row(row)


def _sync_observation_count(
    conn: sqlite3.Connection,
    error_id: str,
    *,
    last_seen: Optional[str] = None,
) -> None:
    """
    Purpose:
        Set error_clusters.observation_count from COUNT(*) of observations.
        Prefer derived counts over denormalized increments (BUG-08).
    Side effects:
        UPDATE error_clusters (caller owns the transaction).
    """
    if last_seen:
        conn.execute(
            """
            UPDATE error_clusters
            SET observation_count = (
                    SELECT COUNT(*) FROM error_observations
                    WHERE error_id = ?
                ),
                last_seen = ?
            WHERE id = ?
            """,
            (error_id, last_seen, error_id),
        )
    else:
        conn.execute(
            """
            UPDATE error_clusters
            SET observation_count = (
                SELECT COUNT(*) FROM error_observations
                WHERE error_id = ?
            )
            WHERE id = ?
            """,
            (error_id, error_id),
        )


def _upsert_error_cluster_conn(
    conn: sqlite3.Connection,
    project_id: str,
    classified: ClassifiedError,
    *,
    cluster_id: Optional[str] = None,
    observed_at: Optional[str] = None,
) -> tuple[ErrorCluster, bool]:
    """
    Purpose:
        Insert or refresh an error cluster inside an open transaction.

        Does **not** bump observation_count — counts are derived from
        observation rows after insert (BUG-08).

    Output:
        (ErrorCluster, created)
    Side effects:
        INSERT or UPDATE on error_clusters (no commit).
    """
    if not project_id:
        raise ValueError("project_id is required")
    fp = classified.fingerprint
    if not fp:
        raise ValueError("classified.fingerprint is required")

    seen_at = observed_at or _now()
    existing = conn.execute(
        """
        SELECT * FROM error_clusters
        WHERE project_id = ? AND fingerprint = ?
        """,
        (project_id, fp),
    ).fetchone()
    if existing is not None:
        new_sev = classified.severity
        old_sev = existing["severity"] or "low"
        sev = _max_severity(old_sev, new_sev)
        conf = max(int(existing["confidence"] or 0), int(classified.confidence))
        techs = _merge_techs(
            _json_loads_list(existing["technologies_json"]),
            classified.technologies,
        )
        conn.execute(
            """
            UPDATE error_clusters
            SET last_seen = ?,
                severity = ?,
                confidence = ?,
                has_stack_trace = MAX(has_stack_trace, ?),
                has_path_leak = MAX(has_path_leak, ?),
                has_internal_host = MAX(has_internal_host, ?),
                has_version_leak = MAX(has_version_leak, ?),
                technologies_json = ?,
                scanner_version = COALESCE(?, scanner_version),
                evidence_snippet = COALESCE(
                    NULLIF(evidence_snippet, ''),
                    ?
                ),
                message_norm = COALESCE(
                    NULLIF(message_norm, ''),
                    ?
                ),
                exception_type = COALESCE(
                    NULLIF(exception_type, ''),
                    ?
                ),
                framework = COALESCE(framework, ?),
                database = COALESCE(database, ?),
                server = COALESCE(server, ?),
                language = CASE
                    WHEN language IS NULL OR language = '' OR language = 'unknown'
                    THEN ?
                    ELSE language
                END
            WHERE id = ?
            """,
            (
                seen_at,
                sev,
                conf,
                1 if classified.has_stack_trace else 0,
                1 if classified.has_path_leak else 0,
                1 if classified.has_internal_host else 0,
                1 if classified.has_version_leak else 0,
                _json_dumps(techs),
                classified.scanner_version or ERROR_INTEL_VERSION,
                classified.evidence_snippet,
                classified.message_norm,
                classified.exception_type,
                classified.framework,
                classified.database,
                classified.server,
                classified.language or "unknown",
                existing["id"],
            ),
        )
        row = conn.execute(
            "SELECT * FROM error_clusters WHERE id = ?",
            (existing["id"],),
        ).fetchone()
        assert row is not None
        return _cluster_from_row(row), False

    new_id = cluster_id or str(uuid.uuid4())
    conn.execute(
        """
        INSERT INTO error_clusters (
            id, project_id, fingerprint,
            category, severity, language,
            framework, database, server,
            exception_type, message_norm, technologies_json,
            has_stack_trace, has_path_leak,
            has_internal_host, has_version_leak,
            confidence, evidence_snippet,
            first_seen, last_seen, observation_count,
            scanner_version
        ) VALUES (
            ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?, ?,
            ?, ?,
            ?, ?,
            ?, ?,
            ?, ?, 0,
            ?
        )
        """,
        (
            new_id,
            project_id,
            fp,
            classified.category,
            classified.severity,
            classified.language or "unknown",
            classified.framework,
            classified.database,
            classified.server,
            classified.exception_type,
            classified.message_norm,
            _json_dumps(list(classified.technologies or [])),
            1 if classified.has_stack_trace else 0,
            1 if classified.has_path_leak else 0,
            1 if classified.has_internal_host else 0,
            1 if classified.has_version_leak else 0,
            int(classified.confidence),
            classified.evidence_snippet,
            seen_at,
            seen_at,
            classified.scanner_version or ERROR_INTEL_VERSION,
        ),
    )
    row = conn.execute(
        "SELECT * FROM error_clusters WHERE id = ?",
        (new_id,),
    ).fetchone()
    assert row is not None
    return _cluster_from_row(row), True


def upsert_error_cluster(
    db_path: Path,
    project_id: str,
    classified: ClassifiedError,
    *,
    cluster_id: Optional[str] = None,
    observed_at: Optional[str] = None,
) -> tuple[ErrorCluster, bool]:
    """
    Purpose:
        Insert a new error cluster or refresh last_seen / flags on an
        existing fingerprint. Dedup key: (project_id, fingerprint).

        Does **not** increment observation_count (BUG-08). Counts are
        maintained when observations are inserted via
        insert_error_observation / store_classified_error.

    Input:
        db_path / project_id / classified (must have fingerprint set)
        cluster_id — optional UUID for insert
        observed_at — ISO timestamp (default now)

    Output:
        (ErrorCluster, created) where created is True on first insert.

    Side effects:
        May migrate project schema; INSERT or UPDATE on error_clusters; commits.
    """
    _ensure_schema(db_path)
    with _connect(db_path) as conn:
        cluster, created = _upsert_error_cluster_conn(
            conn,
            project_id,
            classified,
            cluster_id=cluster_id,
            observed_at=observed_at,
        )
        conn.commit()
        return cluster, created


def _cluster_filter_clauses(
    project_id: str,
    *,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    severities: Optional[Sequence[str]] = None,
    has_stack_trace: Optional[bool] = None,
    has_path_leak: Optional[bool] = None,
    has_internal_host: Optional[bool] = None,
    has_version_leak: Optional[bool] = None,
    min_observations: Optional[int] = None,
    q: Optional[str] = None,
    hide_low_noise: bool = False,
) -> tuple[list[str], list[Any]]:
    """
    Build WHERE clauses + params shared by list_clusters / count_clusters.

    severities wins over single severity when both are set.
    hide_low_noise excludes category IN (infrastructure, http) AND severity = low.
    """
    clauses = ["project_id = ?"]
    params: list[Any] = [project_id]
    if category:
        clauses.append("category = ?")
        params.append(category)
    sev_list: list[str] = []
    if severities is not None:
        sev_list = [s for s in severities if s]
    elif severity:
        sev_list = [severity]
    if sev_list:
        placeholders = ", ".join("?" for _ in sev_list)
        clauses.append(f"severity IN ({placeholders})")
        params.extend(sev_list)
    if has_stack_trace is not None:
        clauses.append("has_stack_trace = ?")
        params.append(1 if has_stack_trace else 0)
    if has_path_leak is not None:
        clauses.append("has_path_leak = ?")
        params.append(1 if has_path_leak else 0)
    if has_internal_host is not None:
        clauses.append("has_internal_host = ?")
        params.append(1 if has_internal_host else 0)
    if has_version_leak is not None:
        clauses.append("has_version_leak = ?")
        params.append(1 if has_version_leak else 0)
    if min_observations is not None:
        clauses.append("observation_count >= ?")
        params.append(max(1, int(min_observations)))
    if q:
        term = f"%{q.strip()}%"
        clauses.append(
            "(exception_type LIKE ? OR IFNULL(message_norm, '') LIKE ?)"
        )
        params.extend([term, term])
    if hide_low_noise:
        clauses.append(
            "NOT (category IN ('infrastructure', 'http') AND severity = 'low')"
        )
    return clauses, params


def list_clusters(
    db_path: Path,
    project_id: str,
    *,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    severities: Optional[Sequence[str]] = None,
    has_stack_trace: Optional[bool] = None,
    has_path_leak: Optional[bool] = None,
    has_internal_host: Optional[bool] = None,
    has_version_leak: Optional[bool] = None,
    min_observations: Optional[int] = None,
    q: Optional[str] = None,
    hide_low_noise: bool = False,
    limit: int = 100,
    offset: int = 0,
) -> list[ErrorCluster]:
    """
    Purpose:
        List error clusters for a project, newest last_seen first.

        Filters (all optional):
          category, severity (single), severities (multi; wins if set),
          tech flags, min_observations, q (LIKE on exception_type/message_norm),
          hide_low_noise (exclude low infrastructure/http).

    Side effects: None (read-only).
    """
    clauses, params = _cluster_filter_clauses(
        project_id,
        category=category,
        severity=severity,
        severities=severities,
        has_stack_trace=has_stack_trace,
        has_path_leak=has_path_leak,
        has_internal_host=has_internal_host,
        has_version_leak=has_version_leak,
        min_observations=min_observations,
        q=q,
        hide_low_noise=hide_low_noise,
    )
    where = " AND ".join(clauses)
    params.extend([max(1, int(limit)), max(0, int(offset))])
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT * FROM error_clusters
            WHERE {where}
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?
            """,
            params,
        ).fetchall()
    return [_cluster_from_row(r) for r in rows]


# ------------------------------------------------------------------ #
# Observations                                                         #
# ------------------------------------------------------------------ #

def _insert_error_observation_conn(
    conn: sqlite3.Connection,
    error_id: str,
    *,
    flow_id: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    parameter_uuid: Optional[str] = None,
    parameter_name: Optional[str] = None,
    attack_type: Optional[str] = None,
    payload_redacted: Optional[str] = None,
    response_status: Optional[int] = None,
    response_length: Optional[int] = None,
    duration_ms: Optional[float] = None,
    response_hash: Optional[str] = None,
    artifacts: Optional[Sequence[ErrorArtifact]] = None,
    detectors: Optional[Sequence[str]] = None,
    observed_at: Optional[str] = None,
    observation_id: Optional[str] = None,
    replace_flow: bool = False,
) -> tuple[ErrorObservation, bool]:
    """
    Purpose:
        Insert one sighting inside an open transaction.

        When flow_id is set, enforces one observation per flow (BUG-07):
          - default: return existing row if present (no second insert)
          - replace_flow=True: delete prior row(s) for flow_id, then insert
            (CLI --force rescan)

        Syncs parent cluster observation_count from COUNT(*).

    Output:
        (observation, inserted) — inserted False when an existing flow
        observation was returned without writing a new row.

    Side effects:
        INSERT / optional DELETE on error_observations; UPDATE cluster count
        (no commit — caller owns the transaction).
    """
    if not error_id:
        raise ValueError("error_id is required")
    at = observed_at or _now()
    payload = payload_redacted
    if payload is not None and len(payload) > DEFAULT_PAYLOAD_REDACTED_MAX:
        payload = payload[: DEFAULT_PAYLOAD_REDACTED_MAX - 1] + "…"

    arts_json = _json_dumps(
        [
            {
                "kind": a.kind,
                "value": a.value,
                "normalized": a.normalized,
            }
            for a in (artifacts or [])
        ]
    )
    det_json = _json_dumps(list(detectors or []))

    flow_key = (flow_id or "").strip() or None
    if flow_key:
        existing = conn.execute(
            """
            SELECT * FROM error_observations
            WHERE flow_id = ?
            ORDER BY observed_at DESC
            LIMIT 1
            """,
            (flow_key,),
        ).fetchone()
        if existing is not None and not replace_flow:
            return _observation_from_row(existing), False
        if existing is not None and replace_flow:
            # Drop all prior sightings for this flow; recompute old clusters.
            old_rows = conn.execute(
                "SELECT id, error_id FROM error_observations WHERE flow_id = ?",
                (flow_key,),
            ).fetchall()
            old_error_ids = {str(r["error_id"]) for r in old_rows}
            conn.execute(
                "DELETE FROM error_observations WHERE flow_id = ?",
                (flow_key,),
            )
            for old_eid in old_error_ids:
                _sync_observation_count(conn, old_eid)

    obs_id = observation_id or str(uuid.uuid4())
    try:
        conn.execute(
            """
            INSERT INTO error_observations (
                id, error_id, flow_id, endpoint_id,
                parameter_uuid, parameter_name, attack_type,
                payload_redacted, response_status, response_length,
                duration_ms, response_hash,
                artifacts_json, detectors_json, observed_at
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?, ?
            )
            """,
            (
                obs_id,
                error_id,
                flow_key,
                endpoint_id,
                parameter_uuid,
                parameter_name,
                attack_type or ATTACK_TYPE_UNKNOWN,
                payload,
                response_status,
                response_length,
                duration_ms,
                response_hash,
                arts_json,
                det_json,
                at,
            ),
        )
    except sqlite3.IntegrityError:
        # Unique index on flow_id raced with another writer — return existing.
        if flow_key:
            raced = conn.execute(
                "SELECT * FROM error_observations WHERE flow_id = ? LIMIT 1",
                (flow_key,),
            ).fetchone()
            if raced is not None:
                return _observation_from_row(raced), False
        raise

    _sync_observation_count(conn, error_id, last_seen=at)
    row = conn.execute(
        "SELECT * FROM error_observations WHERE id = ?",
        (obs_id,),
    ).fetchone()
    assert row is not None
    return _observation_from_row(row), True


def insert_error_observation(
    db_path: Path,
    error_id: str,
    *,
    flow_id: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    parameter_uuid: Optional[str] = None,
    parameter_name: Optional[str] = None,
    attack_type: Optional[str] = None,
    payload_redacted: Optional[str] = None,
    response_status: Optional[int] = None,
    response_length: Optional[int] = None,
    duration_ms: Optional[float] = None,
    response_hash: Optional[str] = None,
    artifacts: Optional[Sequence[ErrorArtifact]] = None,
    detectors: Optional[Sequence[str]] = None,
    observed_at: Optional[str] = None,
    observation_id: Optional[str] = None,
    replace_flow: bool = False,
) -> ErrorObservation:
    """
    Purpose:
        Insert one sighting of an error cluster.

        When flow_id is set, at most one observation per flow is stored
        (unique index + application guard). Pass replace_flow=True for
        intentional rescan replacement (``--force``).

    Side effects:
        May migrate project schema; INSERT into error_observations;
        syncs cluster observation_count; commits.
    """
    _ensure_schema(db_path)
    with _connect(db_path) as conn:
        obs, _inserted = _insert_error_observation_conn(
            conn,
            error_id,
            flow_id=flow_id,
            endpoint_id=endpoint_id,
            parameter_uuid=parameter_uuid,
            parameter_name=parameter_name,
            attack_type=attack_type,
            payload_redacted=payload_redacted,
            response_status=response_status,
            response_length=response_length,
            duration_ms=duration_ms,
            response_hash=response_hash,
            artifacts=artifacts,
            detectors=detectors,
            observed_at=observed_at,
            observation_id=observation_id,
            replace_flow=replace_flow,
        )
        conn.commit()
        return obs


def get_observation(db_path: Path, observation_id: str) -> Optional[ErrorObservation]:
    """Load observation by id. Read-only."""
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM error_observations WHERE id = ?",
            (observation_id,),
        ).fetchone()
    if row is None:
        return None
    return _observation_from_row(row)


def list_observations(
    db_path: Path,
    *,
    error_id: Optional[str] = None,
    flow_id: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    parameter_uuid: Optional[str] = None,
    attack_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[ErrorObservation]:
    """
    Purpose:
        List observations with optional filters.
    Side effects: None (read-only).
    """
    clauses: list[str] = []
    params: list[Any] = []
    if error_id:
        clauses.append("error_id = ?")
        params.append(error_id)
    if flow_id:
        clauses.append("flow_id = ?")
        params.append(flow_id)
    if endpoint_id:
        clauses.append("endpoint_id = ?")
        params.append(endpoint_id)
    if parameter_uuid:
        clauses.append("parameter_uuid = ?")
        params.append(parameter_uuid)
    if attack_type:
        clauses.append("attack_type = ?")
        params.append(attack_type)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.extend([max(1, int(limit)), max(0, int(offset))])
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT * FROM error_observations
            {where}
            ORDER BY observed_at DESC
            LIMIT ? OFFSET ?
            """,
            params,
        ).fetchall()
    return [_observation_from_row(r) for r in rows]


def store_classified_error(
    db_path: Path,
    project_id: str,
    classified: ClassifiedError,
    *,
    flow_id: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    parameter_uuid: Optional[str] = None,
    parameter_name: Optional[str] = None,
    attack_type: Optional[str] = None,
    payload_redacted: Optional[str] = None,
    response_status: Optional[int] = None,
    response_length: Optional[int] = None,
    duration_ms: Optional[float] = None,
    response_hash: Optional[str] = None,
    artifacts: Optional[Sequence[ErrorArtifact]] = None,
    observed_at: Optional[str] = None,
    replace_flow: bool = False,
) -> tuple[ErrorCluster, ErrorObservation, bool]:
    """
    Purpose:
        High-level store: upsert cluster + insert observation in **one
        transaction** (BUG-08). observation_count is set from COUNT(*) after
        the observation write so bare upserts cannot drift the counter.

        When flow_id is set, duplicate stores for the same flow return the
        existing observation unless replace_flow=True (BUG-07 / ``--force``).

    Output:
        (cluster, observation, cluster_created)

    Side effects:
        May migrate project schema; writes error_clusters and
        error_observations in a single commit.
    """
    _ensure_schema(db_path)
    at = observed_at or _now()
    with _connect(db_path) as conn:
        cluster, created = _upsert_error_cluster_conn(
            conn,
            project_id,
            classified,
            observed_at=at,
        )
        obs, inserted = _insert_error_observation_conn(
            conn,
            cluster.id,
            flow_id=flow_id,
            endpoint_id=endpoint_id,
            parameter_uuid=parameter_uuid,
            parameter_name=parameter_name,
            attack_type=attack_type,
            payload_redacted=payload_redacted,
            response_status=response_status,
            response_length=response_length,
            duration_ms=duration_ms,
            response_hash=response_hash,
            artifacts=artifacts,
            detectors=classified.detectors,
            observed_at=at,
            replace_flow=replace_flow,
        )
        # Re-read cluster so observation_count reflects the observation write.
        row = conn.execute(
            "SELECT * FROM error_clusters WHERE id = ?",
            (cluster.id,),
        ).fetchone()
        assert row is not None
        cluster = _cluster_from_row(row)
        conn.commit()
        # If we short-circuited on an existing flow observation for a
        # different error_id, cluster_created is still meaningful for the
        # fingerprint upsert; callers mainly care about cluster id + obs.
        del inserted  # reserved for future API; suppress unused warning
        return cluster, obs, created


# ------------------------------------------------------------------ #
# Lookups / context enrich / rollups (Phases 6–7)                      #
# ------------------------------------------------------------------ #

def has_observation_for_flow(db_path: Path, flow_id: str) -> bool:
    """
    Purpose:
        True when at least one error_observations row exists for flow_id.
    Side effects: None (read-only).
    """
    if not flow_id:
        return False
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT 1 FROM error_observations
            WHERE flow_id = ?
            LIMIT 1
            """,
            (flow_id,),
        ).fetchone()
    return row is not None


def flow_observation_scanner_version(
    db_path: Path,
    flow_id: str,
) -> Optional[str]:
    """
    Purpose:
        Return the linked cluster ``scanner_version`` for a flow's observation,
        or None when no observation exists (BUG-09).
    Side effects: None (read-only).
    """
    if not flow_id:
        return None
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT c.scanner_version
            FROM error_observations o
            JOIN error_clusters c ON c.id = o.error_id
            WHERE o.flow_id = ?
            ORDER BY o.observed_at DESC
            LIMIT 1
            """,
            (flow_id,),
        ).fetchone()
    if row is None:
        return None
    ver = row[0]
    return str(ver) if ver is not None else ""


def has_current_observation_for_flow(
    db_path: Path,
    flow_id: str,
    *,
    scanner_version: Optional[str] = None,
) -> bool:
    """
    Purpose:
        True when a flow already has an observation whose cluster was
        produced at ``scanner_version`` (default ERROR_INTEL_VERSION).

        Outdated observations (version mismatch) return False so the
        worker reprocesses without requiring ``--force`` (BUG-09).
    Side effects: None (read-only).
    """
    want = scanner_version if scanner_version is not None else ERROR_INTEL_VERSION
    have = flow_observation_scanner_version(db_path, flow_id)
    if have is None:
        return False
    return have == want


def count_clusters(
    db_path: Path,
    project_id: str,
    *,
    category: Optional[str] = None,
    severity: Optional[str] = None,
    severities: Optional[Sequence[str]] = None,
    has_stack_trace: Optional[bool] = None,
    has_path_leak: Optional[bool] = None,
    has_internal_host: Optional[bool] = None,
    has_version_leak: Optional[bool] = None,
    min_observations: Optional[int] = None,
    q: Optional[str] = None,
    hide_low_noise: bool = False,
) -> int:
    """
    Count error clusters for a project with the same filters as list_clusters.
    Read-only. Does not take limit/offset.
    """
    clauses, params = _cluster_filter_clauses(
        project_id,
        category=category,
        severity=severity,
        severities=severities,
        has_stack_trace=has_stack_trace,
        has_path_leak=has_path_leak,
        has_internal_host=has_internal_host,
        has_version_leak=has_version_leak,
        min_observations=min_observations,
        q=q,
        hide_low_noise=hide_low_noise,
    )
    where = " AND ".join(clauses)
    with _connect(db_path) as conn:
        row = conn.execute(
            f"SELECT COUNT(*) FROM error_clusters WHERE {where}",
            params,
        ).fetchone()
    return int(row[0]) if row else 0


def count_observations(
    db_path: Path,
    *,
    project_id: Optional[str] = None,
    error_id: Optional[str] = None,
    flow_id: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    parameter_uuid: Optional[str] = None,
    attack_type: Optional[str] = None,
) -> int:
    """
    Purpose:
        Count observations with optional filters. When project_id is set,
        joins through error_clusters.
    Side effects: None (read-only).
    """
    clauses: list[str] = []
    params: list[Any] = []
    join = ""
    if project_id:
        join = " JOIN error_clusters c ON c.id = o.error_id "
        clauses.append("c.project_id = ?")
        params.append(project_id)
    if error_id:
        clauses.append("o.error_id = ?")
        params.append(error_id)
    if flow_id:
        clauses.append("o.flow_id = ?")
        params.append(flow_id)
    if endpoint_id:
        clauses.append("o.endpoint_id = ?")
        params.append(endpoint_id)
    if parameter_uuid:
        clauses.append("o.parameter_uuid = ?")
        params.append(parameter_uuid)
    if attack_type:
        clauses.append("o.attack_type = ?")
        params.append(attack_type)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    with _connect(db_path) as conn:
        row = conn.execute(
            f"SELECT COUNT(*) FROM error_observations o{join}{where}",
            params,
        ).fetchone()
    return int(row[0]) if row else 0


def update_observations_context(
    db_path: Path,
    flow_id: str,
    *,
    parameter_uuid: Optional[str] = None,
    parameter_name: Optional[str] = None,
    attack_type: Optional[str] = None,
    payload_redacted: Optional[str] = None,
) -> int:
    """
    Purpose:
        Enrich existing observations for a flow with attack/parameter
        context without re-parsing the body (Phase 6 dual-path).

        Only fills empty fields (BUG-06):
          - parameter_uuid / parameter_name — fill only when old is null/empty
          - attack_type — fill only when old is null/empty/unknown
          - payload_redacted — fill only when old is null/empty

    Output:
        Number of rows updated.

    Side effects:
        UPDATE error_observations; commits.
    """
    if not flow_id:
        return 0
    payload = payload_redacted
    if payload is not None and len(payload) > DEFAULT_PAYLOAD_REDACTED_MAX:
        payload = payload[: DEFAULT_PAYLOAD_REDACTED_MAX - 1] + "…"

    def _empty(val: Any) -> bool:
        return val is None or (isinstance(val, str) and not val.strip())

    with _connect(db_path) as conn:
        rows = conn.execute(
            "SELECT id, parameter_uuid, parameter_name, attack_type, "
            "payload_redacted FROM error_observations WHERE flow_id = ?",
            (flow_id,),
        ).fetchall()
        updated = 0
        for row in rows:
            old_pu = row["parameter_uuid"]
            old_pn = row["parameter_name"]
            old_at = row["attack_type"] or ATTACK_TYPE_UNKNOWN
            old_pl = row["payload_redacted"]

            if parameter_uuid and _empty(old_pu):
                new_pu = parameter_uuid
            else:
                new_pu = old_pu

            if parameter_name and _empty(old_pn):
                new_pn = parameter_name
            else:
                new_pn = old_pn

            if attack_type and (
                _empty(old_at) or old_at == ATTACK_TYPE_UNKNOWN
            ):
                new_at = attack_type
            else:
                new_at = old_at

            if payload is not None and _empty(old_pl):
                new_pl = payload
            else:
                new_pl = old_pl

            if (
                new_pu == old_pu
                and new_pn == old_pn
                and new_at == old_at
                and new_pl == old_pl
            ):
                continue
            conn.execute(
                """
                UPDATE error_observations
                SET parameter_uuid = ?,
                    parameter_name = ?,
                    attack_type = ?,
                    payload_redacted = ?
                WHERE id = ?
                """,
                (new_pu, new_pn, new_at, new_pl, row["id"]),
            )
            updated += 1
        conn.commit()
    return updated


def parameter_error_rollup(
    db_path: Path,
    project_id: str,
    *,
    parameter_uuid: Optional[str] = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """
    Purpose:
        Phase 7 rollup: errors linked to parameters.

        When parameter_uuid is set, return clusters seen for that param.
        Otherwise return per-parameter summary rows.

    Output:
        List of dicts (parameter_uuid, parameter_name, error_id, category,
        severity, exception_type, observation_count, …).

    Side effects: None (read-only).
    """
    lim = max(1, int(limit))
    with _connect(db_path) as conn:
        if parameter_uuid:
            rows = conn.execute(
                """
                SELECT
                    o.parameter_uuid,
                    o.parameter_name,
                    c.id AS error_id,
                    c.category,
                    c.severity,
                    c.language,
                    c.framework,
                    c.database,
                    c.exception_type,
                    c.fingerprint,
                    COUNT(*) AS observation_count,
                    MAX(o.observed_at) AS last_seen
                FROM error_observations o
                JOIN error_clusters c ON c.id = o.error_id
                WHERE c.project_id = ?
                  AND o.parameter_uuid = ?
                GROUP BY o.parameter_uuid, o.parameter_name, c.id
                ORDER BY observation_count DESC, last_seen DESC
                LIMIT ?
                """,
                (project_id, parameter_uuid, lim),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT
                    o.parameter_uuid,
                    o.parameter_name,
                    c.id AS error_id,
                    c.category,
                    c.severity,
                    c.language,
                    c.framework,
                    c.database,
                    c.exception_type,
                    c.fingerprint,
                    COUNT(*) AS observation_count,
                    MAX(o.observed_at) AS last_seen
                FROM error_observations o
                JOIN error_clusters c ON c.id = o.error_id
                WHERE c.project_id = ?
                  AND o.parameter_uuid IS NOT NULL
                  AND o.parameter_uuid != ''
                GROUP BY o.parameter_uuid, o.parameter_name, c.id
                ORDER BY observation_count DESC, last_seen DESC
                LIMIT ?
                """,
                (project_id, lim),
            ).fetchall()
    return [dict(r) for r in rows]


def endpoint_error_rollup(
    db_path: Path,
    project_id: str,
    *,
    endpoint_id: Optional[str] = None,
    limit: int = 50,
) -> list[dict[str, Any]]:
    """
    Purpose:
        Phase 7 rollup: top error clusters per endpoint (or one endpoint).
    Side effects: None (read-only).
    """
    lim = max(1, int(limit))
    with _connect(db_path) as conn:
        if endpoint_id:
            rows = conn.execute(
                """
                SELECT
                    o.endpoint_id,
                    c.id AS error_id,
                    c.category,
                    c.severity,
                    c.language,
                    c.framework,
                    c.database,
                    c.exception_type,
                    c.fingerprint,
                    COUNT(*) AS observation_count,
                    MAX(o.observed_at) AS last_seen
                FROM error_observations o
                JOIN error_clusters c ON c.id = o.error_id
                WHERE c.project_id = ?
                  AND o.endpoint_id = ?
                GROUP BY o.endpoint_id, c.id
                ORDER BY observation_count DESC, last_seen DESC
                LIMIT ?
                """,
                (project_id, endpoint_id, lim),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT
                    o.endpoint_id,
                    c.id AS error_id,
                    c.category,
                    c.severity,
                    c.language,
                    c.framework,
                    c.database,
                    c.exception_type,
                    c.fingerprint,
                    COUNT(*) AS observation_count,
                    MAX(o.observed_at) AS last_seen
                FROM error_observations o
                JOIN error_clusters c ON c.id = o.error_id
                WHERE c.project_id = ?
                  AND o.endpoint_id IS NOT NULL
                  AND o.endpoint_id != ''
                GROUP BY o.endpoint_id, c.id
                ORDER BY observation_count DESC, last_seen DESC
                LIMIT ?
                """,
                (project_id, lim),
            ).fetchall()
    return [dict(r) for r in rows]


def severity_counts(db_path: Path, project_id: str) -> dict[str, int]:
    """Count clusters by severity for status CLI. Read-only."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT severity, COUNT(*) AS n
            FROM error_clusters
            WHERE project_id = ?
            GROUP BY severity
            """,
            (project_id,),
        ).fetchall()
    return {str(r["severity"] or "unknown"): int(r["n"]) for r in rows}


def category_counts(db_path: Path, project_id: str) -> dict[str, int]:
    """Count clusters by category for status CLI. Read-only."""
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT category, COUNT(*) AS n
            FROM error_clusters
            WHERE project_id = ?
            GROUP BY category
            """,
            (project_id,),
        ).fetchall()
    return {str(r["category"] or "unknown"): int(r["n"]) for r in rows}


# ------------------------------------------------------------------ #
# Severity merge                                                       #
# ------------------------------------------------------------------ #

_SEV_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _max_severity(a: str, b: str) -> str:
    ra = _SEV_RANK.get((a or "").lower(), 0)
    rb = _SEV_RANK.get((b or "").lower(), 0)
    return a if ra >= rb else b


def _merge_techs(existing: list[Any], new: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for t in list(existing) + list(new or []):
        key = str(t).lower()
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out
