"""
Module: talos.passive.db

Purpose:
    SQLite CRUD for Passive Source Intelligence tables defined in
    talos.projects.db (schema v39+):

        source_documents     — unique body identity (project_id + body_hash)
        source_occurrences   — each flow/URL sighting of a document
        passive_detections   — scored observations (not findings lifecycle)
        passive_scan_config  — single-row per-project scan settings

    Findings lifecycle stays in talos.findings; this module only stores
    intelligence and optionally links via passive_detections.finding_id.

    Every function opens and closes its own connection (same pattern as
    talos.findings.db / talos.input_validation.db). No persistent handles.

Dependencies:
    sqlite3, json, uuid, datetime, pathlib
    talos.passive.constants, models, config
Data flow:
    SourceScanWorker → upsert_document / insert_occurrence /
        insert_detection / mark_document_*
    CLI / config (later) → ensure_config / get_config / update_config
    finding_bridge (Phase 8) → link_detection_finding
Side effects:
    All write helpers commit to the project SQLite database.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from talos.passive.config import PassiveScanConfig, config_from_dict, default_config
from talos.passive.constants import (
    SCAN_STATUS_ERROR,
    SCAN_STATUS_PENDING,
    SCAN_STATUS_SCANNED,
    SourceKind,
)
from talos.passive.models import Detection, SourceDocument, SourceOccurrence


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
    Input:
        db_path — absolute path to project talos.db
    Output:
        Open sqlite3.Connection (caller must close).
    Side effects:
        Opens a file handle to the database.
    """
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def _kind_value(kind: SourceKind | str) -> str:
    """Normalize SourceKind enum or str to stored TEXT value."""
    if isinstance(kind, SourceKind):
        return kind.value
    return str(kind)


def _document_from_row(row: sqlite3.Row) -> SourceDocument:
    """Map a source_documents row to SourceDocument. Side effects: None."""
    kind_raw = row["source_kind"] or SourceKind.UNKNOWN.value
    try:
        kind = SourceKind(kind_raw)
    except ValueError:
        kind = SourceKind.UNKNOWN
    # parent_document_id / logical_source_name added in schema v40
    keys = row.keys()
    parent_id = row["parent_document_id"] if "parent_document_id" in keys else None
    logical = (
        row["logical_source_name"] if "logical_source_name" in keys else None
    )
    return SourceDocument(
        id=row["id"],
        project_id=row["project_id"],
        body_hash=row["body_hash"],
        source_kind=kind,
        body_size=int(row["body_size"] or 0),
        truncated=bool(row["truncated"]),
        scanner_version=row["scanner_version"],
        scan_status=row["scan_status"] or SCAN_STATUS_PENDING,
        first_flow_id=row["first_flow_id"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        last_scanned_at=row["last_scanned_at"],
        error_message=row["error_message"],
        parent_document_id=parent_id,
        logical_source_name=logical,
    )


def _occurrence_from_row(row: sqlite3.Row) -> SourceOccurrence:
    """Map a source_occurrences row to SourceOccurrence. Side effects: None."""
    return SourceOccurrence(
        id=row["id"],
        document_id=row["document_id"],
        flow_id=row["flow_id"] or "",
        endpoint_id=row["endpoint_id"],
        url=row["url"] or "",
        host=row["host"] or "",
        path=row["path"] or "",
        logical_source_name=row["logical_source_name"],
        content_type=row["content_type"] or "",
        observed_at=row["observed_at"] or "",
        role_id=row["role_id"] or "",
        module_id=row["module_id"] or "",
    )


def _detection_from_row(row: sqlite3.Row) -> Detection:
    """Map a passive_detections row to Detection. Side effects: None."""
    try:
        chain = json.loads(row["encoding_chain"] or "[]")
        if not isinstance(chain, list):
            chain = []
    except (json.JSONDecodeError, TypeError):
        chain = []
    return Detection(
        id=row["id"],
        document_id=row["document_id"],
        occurrence_id=row["occurrence_id"],
        detector_id=row["detector_id"],
        detector_family=row["detector_family"],
        category=row["category"],
        secret_type=row["secret_type"] or "",
        matched_key=row["matched_key"],
        redacted_value=row["redacted_value"] or "",
        value_fingerprint=row["value_fingerprint"],
        confidence_score=int(row["confidence_score"] or 0),
        confidence_level=row["confidence_level"],
        entropy=row["entropy"],
        encoding_chain=list(chain),
        decode_depth=int(row["decode_depth"] or 0),
        match_start=int(row["match_start"] or 0),
        match_end=int(row["match_end"] or 0),
        context_before=row["context_before"] or "",
        context_after=row["context_after"] or "",
        suppressed=bool(row["suppressed"]),
        suppression_reason=row["suppression_reason"],
        finding_id=row["finding_id"],
        raw_value_stored=bool(row["raw_value_stored"]),
        created_at=row["created_at"],
        raw_value=None,  # never loaded from DB list path
    )


def _config_from_row(row: sqlite3.Row) -> PassiveScanConfig:
    """
    Purpose:
        Build PassiveScanConfig from a passive_scan_config SQLite row.
    Input:
        row — sqlite3.Row with config columns
    Output:
        PassiveScanConfig (unknown/missing columns fall back via config_from_dict)
    Side effects: None.
    """
    data: dict[str, Any] = {
        "enabled": bool(row["enabled"]),
        "auto_finding_threshold": row["auto_finding_threshold"] or "HIGH",
        "max_document_size": int(row["max_document_size"]),
        "max_decode_depth": int(row["max_decode_depth"]),
        "max_decode_bytes": int(row["max_decode_bytes"]),
        "max_candidates_per_document": int(row["max_candidates_per_document"]),
        "scan_html": bool(row["scan_html"]),
        "scan_javascript": bool(row["scan_javascript"]),
        "scan_json": bool(row["scan_json"]),
        "scan_xml": bool(row["scan_xml"]),
        "scan_text": bool(row["scan_text"]),
        "scan_css": bool(row["scan_css"]),
        "scan_sourcemaps": bool(row["scan_sourcemaps"]),
        "scan_wasm": bool(row["scan_wasm"]),
        "store_raw_secret_in_evidence": bool(row["store_raw_secret_in_evidence"]),
        "store_suppressed_detections": bool(row["store_suppressed_detections"]),
        "queue_maxsize": int(row["queue_maxsize"]),
        # max_scan_time_ms added in schema v41; tolerate older rows mid-upgrade.
        "max_scan_time_ms": int(row["max_scan_time_ms"])
        if "max_scan_time_ms" in row.keys()
        else 0,
    }
    return config_from_dict(data)


# ------------------------------------------------------------------ #
# Config                                                               #
# ------------------------------------------------------------------ #

def ensure_config(db_path: Path) -> PassiveScanConfig:
    """
    Purpose:
        Ensure the single-row passive_scan_config exists and return it.
        Seeds design-contract defaults when the row is absent.
    Input:
        db_path — path to project talos.db
    Output:
        PassiveScanConfig currently stored (or freshly seeded defaults)
    Side effects:
        INSERT OR IGNORE of id='default' when missing.
    """
    with _connect(db_path) as conn:
        conn.execute(
            "INSERT OR IGNORE INTO passive_scan_config (id) VALUES ('default')"
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM passive_scan_config WHERE id = 'default'"
        ).fetchone()
    if row is None:
        return default_config()
    return _config_from_row(row)


def get_config(db_path: Path) -> PassiveScanConfig:
    """
    Purpose:
        Load passive scan settings. Seeds defaults if the row is missing.
    Input:
        db_path — path to project talos.db
    Output:
        PassiveScanConfig
    Side effects:
        May INSERT the default row via ensure_config.
    """
    return ensure_config(db_path)


def update_config(db_path: Path, config: PassiveScanConfig) -> PassiveScanConfig:
    """
    Purpose:
        Persist a full PassiveScanConfig as the single default row.
    Input:
        db_path — path to project talos.db
        config  — settings to store
    Output:
        The same config (after successful write)
    Side effects:
        INSERT OR REPLACE into passive_scan_config.
    """
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO passive_scan_config (
                id, enabled, auto_finding_threshold,
                max_document_size, max_decode_depth, max_decode_bytes,
                max_candidates_per_document,
                scan_html, scan_javascript, scan_json, scan_xml,
                scan_text, scan_css, scan_sourcemaps, scan_wasm,
                store_raw_secret_in_evidence, store_suppressed_detections,
                queue_maxsize, max_scan_time_ms
            ) VALUES (
                'default', ?, ?,
                ?, ?, ?,
                ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?,
                ?, ?
            )
            """,
            (
                1 if config.enabled else 0,
                config.auto_finding_threshold,
                int(config.max_document_size),
                int(config.max_decode_depth),
                int(config.max_decode_bytes),
                int(config.max_candidates_per_document),
                1 if config.scan_html else 0,
                1 if config.scan_javascript else 0,
                1 if config.scan_json else 0,
                1 if config.scan_xml else 0,
                1 if config.scan_text else 0,
                1 if config.scan_css else 0,
                1 if config.scan_sourcemaps else 0,
                1 if config.scan_wasm else 0,
                1 if config.store_raw_secret_in_evidence else 0,
                1 if config.store_suppressed_detections else 0,
                int(config.queue_maxsize),
                int(getattr(config, "max_scan_time_ms", 0) or 0),
            ),
        )
        conn.commit()
    return config


# ------------------------------------------------------------------ #
# Source documents                                                     #
# ------------------------------------------------------------------ #

def get_document_by_hash(
    db_path: Path,
    project_id: str,
    body_hash: str,
) -> Optional[SourceDocument]:
    """
    Purpose:
        Look up a source document by project + body hash (dedup key).
    Input:
        db_path / project_id / body_hash
    Output:
        SourceDocument or None
    Side effects: None (read-only).
    """
    with _connect(db_path) as conn:
        row = conn.execute(
            """
            SELECT * FROM source_documents
            WHERE project_id = ? AND body_hash = ?
            """,
            (project_id, body_hash),
        ).fetchone()
    if row is None:
        return None
    return _document_from_row(row)


def get_document(db_path: Path, document_id: str) -> Optional[SourceDocument]:
    """
    Purpose:
        Load a source document by primary key.
    Input:
        db_path / document_id
    Output:
        SourceDocument or None
    Side effects: None (read-only).
    """
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM source_documents WHERE id = ?",
            (document_id,),
        ).fetchone()
    if row is None:
        return None
    return _document_from_row(row)


def upsert_document(
    db_path: Path,
    project_id: str,
    body_hash: str,
    source_kind: SourceKind | str,
    body_size: int,
    *,
    truncated: bool = False,
    first_flow_id: Optional[str] = None,
    observed_at: Optional[str] = None,
    document_id: Optional[str] = None,
    parent_document_id: Optional[str] = None,
    logical_source_name: Optional[str] = None,
) -> tuple[SourceDocument, bool]:
    """
    Purpose:
        Insert a new source document or refresh last_seen on an existing one.
        Dedup key is (project_id, body_hash). Scan state is preserved on hit
        so callers can skip re-scan when scanner_version already matches.

    Input:
        db_path / project_id / body_hash / source_kind / body_size
        truncated     — capture truncated flag (stored on insert only)
        first_flow_id — flow that first introduced the body
        observed_at   — ISO timestamp (default now)
        document_id   — optional UUID for insert; generated if omitted
        parent_document_id — optional parent for virtual docs (schema v40)
        logical_source_name — optional UI path label (schema v40)

    Output:
        (SourceDocument, created) where created is True on first insert.

    Side effects:
        INSERT or UPDATE on source_documents; commits.
    """
    seen_at = observed_at or _now()
    with _connect(db_path) as conn:
        existing = conn.execute(
            """
            SELECT * FROM source_documents
            WHERE project_id = ? AND body_hash = ?
            """,
            (project_id, body_hash),
        ).fetchone()
        if existing is not None:
            conn.execute(
                """
                UPDATE source_documents
                SET last_seen = ?
                WHERE id = ?
                """,
                (seen_at, existing["id"]),
            )
            conn.commit()
            doc = _document_from_row(existing)
            doc.last_seen = seen_at
            return doc, False

        new_id = document_id or str(uuid.uuid4())
        conn.execute(
            """
            INSERT INTO source_documents (
                id, project_id, body_hash, source_kind, body_size,
                truncated, scanner_version, scan_status,
                first_flow_id, first_seen, last_seen,
                last_scanned_at, error_message,
                parent_document_id, logical_source_name
            ) VALUES (
                ?, ?, ?, ?, ?,
                ?, NULL, ?,
                ?, ?, ?,
                NULL, NULL,
                ?, ?
            )
            """,
            (
                new_id,
                project_id,
                body_hash,
                _kind_value(source_kind),
                int(body_size),
                1 if truncated else 0,
                SCAN_STATUS_PENDING,
                first_flow_id,
                seen_at,
                seen_at,
                parent_document_id,
                logical_source_name,
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM source_documents WHERE id = ?",
            (new_id,),
        ).fetchone()
    assert row is not None
    return _document_from_row(row), True


def mark_document_scanned(
    db_path: Path,
    document_id: str,
    scanner_version: str,
    *,
    scanned_at: Optional[str] = None,
) -> None:
    """
    Purpose:
        Mark a document as successfully scanned at scanner_version.
    Input:
        db_path / document_id / scanner_version
        scanned_at — ISO timestamp (default now)
    Output:
        None
    Side effects:
        UPDATE scan_status=scanned, clear error_message, set last_scanned_at.
    """
    at = scanned_at or _now()
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE source_documents
            SET scan_status = ?,
                scanner_version = ?,
                last_scanned_at = ?,
                error_message = NULL
            WHERE id = ?
            """,
            (SCAN_STATUS_SCANNED, scanner_version, at, document_id),
        )
        conn.commit()


def mark_document_error(
    db_path: Path,
    document_id: str,
    error_message: str,
    *,
    scanned_at: Optional[str] = None,
) -> None:
    """
    Purpose:
        Mark a document scan as failed with an error message.
    Input:
        db_path / document_id / error_message
        scanned_at — ISO timestamp for last_scanned_at (default now)
    Output:
        None
    Side effects:
        UPDATE scan_status=error, store error_message and last_scanned_at.
    """
    at = scanned_at or _now()
    msg = (error_message or "")[:2000]
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE source_documents
            SET scan_status = ?,
                error_message = ?,
                last_scanned_at = ?
            WHERE id = ?
            """,
            (SCAN_STATUS_ERROR, msg, at, document_id),
        )
        conn.commit()


def mark_document_status(
    db_path: Path,
    document_id: str,
    scan_status: str,
    *,
    error_message: Optional[str] = None,
    scanner_version: Optional[str] = None,
    scanned_at: Optional[str] = None,
) -> None:
    """
    Purpose:
        Set an arbitrary scan_status (skipped, too_large, …) with optional
        error_message / scanner_version.
    Input:
        db_path / document_id / scan_status and optional fields
    Output:
        None
    Side effects:
        UPDATE source_documents row.
    """
    at = scanned_at or _now()
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE source_documents
            SET scan_status = ?,
                error_message = COALESCE(?, error_message),
                scanner_version = COALESCE(?, scanner_version),
                last_scanned_at = ?
            WHERE id = ?
            """,
            (
                scan_status,
                error_message,
                scanner_version,
                at,
                document_id,
            ),
        )
        conn.commit()


# ------------------------------------------------------------------ #
# Occurrences                                                          #
# ------------------------------------------------------------------ #

def insert_occurrence(
    db_path: Path,
    *,
    document_id: str,
    flow_id: str,
    url: str,
    host: str,
    path: str,
    content_type: str,
    observed_at: str,
    role_id: str = "",
    module_id: str = "",
    endpoint_id: Optional[str] = None,
    logical_source_name: Optional[str] = None,
    occurrence_id: Optional[str] = None,
) -> SourceOccurrence:
    """
    Purpose:
        Record one sighting of a document on a flow/URL. Always inserts
        (occurrence-level dedup is not applied — document-level is).
    Input:
        document_id + flow/URL metadata fields
        occurrence_id — optional UUID; generated if omitted
    Output:
        SourceOccurrence as stored
    Side effects:
        INSERT into source_occurrences; commits.
    """
    new_id = occurrence_id or str(uuid.uuid4())
    with _connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO source_occurrences (
                id, document_id, flow_id, endpoint_id,
                url, host, path, logical_source_name,
                content_type, observed_at, role_id, module_id
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?
            )
            """,
            (
                new_id,
                document_id,
                flow_id,
                endpoint_id,
                url or "",
                host or "",
                path or "",
                logical_source_name,
                content_type or "",
                observed_at,
                role_id or "",
                module_id or "",
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM source_occurrences WHERE id = ?",
            (new_id,),
        ).fetchone()
    assert row is not None
    return _occurrence_from_row(row)


def list_occurrences(
    db_path: Path,
    document_id: str,
    *,
    limit: int = 100,
) -> list[SourceOccurrence]:
    """
    Purpose:
        List occurrences for a document, newest first.
    Input:
        db_path / document_id / limit
    Output:
        list[SourceOccurrence]
    Side effects: None (read-only).
    """
    lim = max(1, int(limit))
    with _connect(db_path) as conn:
        rows = conn.execute(
            """
            SELECT * FROM source_occurrences
            WHERE document_id = ?
            ORDER BY observed_at DESC
            LIMIT ?
            """,
            (document_id, lim),
        ).fetchall()
    return [_occurrence_from_row(r) for r in rows]


def get_occurrence(db_path: Path, occurrence_id: str) -> Optional[SourceOccurrence]:
    """
    Purpose:
        Load one source_occurrences row by primary key.
    Input:
        db_path / occurrence_id
    Output:
        SourceOccurrence or None
    Side effects: None (read-only).
    """
    if not occurrence_id:
        return None
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM source_occurrences WHERE id = ?",
            (occurrence_id,),
        ).fetchone()
    if row is None:
        return None
    return _occurrence_from_row(row)


def list_documents(
    db_path: Path,
    project_id: str,
    *,
    scan_status: Optional[str] = None,
    source_kind: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[SourceDocument]:
    """
    Purpose:
        List source documents for a project (CLI / status).
    Input:
        project_id / optional scan_status / source_kind filters
        limit / offset pagination
    Output:
        list[SourceDocument] ordered by last_seen DESC
    Side effects: None (read-only).
    """
    clauses = ["project_id = ?"]
    params: list[Any] = [project_id]
    if scan_status:
        clauses.append("scan_status = ?")
        params.append(scan_status)
    if source_kind:
        clauses.append("source_kind = ?")
        params.append(source_kind)
    where = " AND ".join(clauses)
    lim = max(1, int(limit))
    off = max(0, int(offset))
    with _connect(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT * FROM source_documents
            WHERE {where}
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?
            """,
            (*params, lim, off),
        ).fetchall()
    return [_document_from_row(r) for r in rows]


def count_documents(
    db_path: Path,
    project_id: str,
    *,
    scan_status: Optional[str] = None,
) -> int:
    """
    Purpose:
        Count source_documents for status reporting.
    Side effects: None (read-only).
    """
    clauses = ["project_id = ?"]
    params: list[Any] = [project_id]
    if scan_status:
        clauses.append("scan_status = ?")
        params.append(scan_status)
    where = " AND ".join(clauses)
    with _connect(db_path) as conn:
        row = conn.execute(
            f"SELECT COUNT(*) FROM source_documents WHERE {where}",
            params,
        ).fetchone()
    return int(row[0]) if row else 0


def count_detections(
    db_path: Path,
    project_id: str,
    *,
    has_finding: Optional[bool] = None,
    suppressed: Optional[bool] = None,
) -> int:
    """
    Purpose:
        Count passive_detections joined to project documents.
    Side effects: None (read-only).
    """
    clauses = ["sd.project_id = ?"]
    params: list[Any] = [project_id]
    if has_finding is True:
        clauses.append("d.finding_id IS NOT NULL")
    elif has_finding is False:
        clauses.append("d.finding_id IS NULL")
    if suppressed is not None:
        clauses.append("d.suppressed = ?")
        params.append(1 if suppressed else 0)
    where = " AND ".join(clauses)
    with _connect(db_path) as conn:
        row = conn.execute(
            f"""
            SELECT COUNT(*) FROM passive_detections d
            JOIN source_documents sd ON sd.id = d.document_id
            WHERE {where}
            """,
            params,
        ).fetchone()
    return int(row[0]) if row else 0


def reset_document_for_rescan(
    db_path: Path,
    document_id: str,
) -> None:
    """
    Purpose:
        Clear scanner_version / scan_status so the next scan re-runs detectors.
        Does not delete existing detections (unique index dedups on re-insert).
    Input:
        db_path / document_id
    Output: None
    Side effects:
        UPDATE source_documents SET scan_status=pending, scanner_version=NULL.
    """
    with _connect(db_path) as conn:
        conn.execute(
            """
            UPDATE source_documents
            SET scan_status = ?,
                scanner_version = NULL,
                error_message = NULL
            WHERE id = ?
            """,
            (SCAN_STATUS_PENDING, document_id),
        )
        conn.commit()


# ------------------------------------------------------------------ #
# Detections                                                           #
# ------------------------------------------------------------------ #

def insert_detection(
    db_path: Path,
    detection: Detection,
) -> Optional[Detection]:
    """
    Purpose:
        Persist a Detection. Dedup key
        (document_id, detector_id, value_fingerprint, match_start) uses
        INSERT OR IGNORE so rescans do not create duplicates.

    Input:
        db_path   — project DB
        detection — Detection dataclass (id may be empty; generated if so)

    Output:
        Detection as stored, or None when the unique index caused a skip
        (already present).

    Side effects:
        INSERT OR IGNORE into passive_detections; commits.
        Does not store raw_value (in-memory only; evidence policy is Phase 8).
    """
    det_id = detection.id or str(uuid.uuid4())
    created_at = detection.created_at or _now()
    chain_json = json.dumps(list(detection.encoding_chain or []))
    with _connect(db_path) as conn:
        cur = conn.execute(
            """
            INSERT OR IGNORE INTO passive_detections (
                id, document_id, occurrence_id,
                detector_id, detector_family, category, secret_type,
                matched_key, redacted_value, value_fingerprint,
                confidence_score, confidence_level, entropy,
                encoding_chain, decode_depth,
                match_start, match_end,
                context_before, context_after,
                suppressed, suppression_reason,
                finding_id, raw_value_stored, created_at
            ) VALUES (
                ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?,
                ?, ?,
                ?, ?,
                ?, ?, ?
            )
            """,
            (
                det_id,
                detection.document_id,
                detection.occurrence_id,
                detection.detector_id,
                detection.detector_family,
                detection.category,
                detection.secret_type or "",
                detection.matched_key,
                detection.redacted_value or "",
                detection.value_fingerprint,
                int(detection.confidence_score),
                detection.confidence_level,
                detection.entropy,
                chain_json,
                int(detection.decode_depth or 0),
                int(detection.match_start or 0),
                int(detection.match_end or 0),
                detection.context_before or "",
                detection.context_after or "",
                1 if detection.suppressed else 0,
                detection.suppression_reason,
                detection.finding_id,
                1 if detection.raw_value_stored else 0,
                created_at,
            ),
        )
        conn.commit()
        if cur.rowcount == 0:
            # Duplicate — return existing row if present
            existing = conn.execute(
                """
                SELECT * FROM passive_detections
                WHERE document_id = ?
                  AND detector_id = ?
                  AND value_fingerprint = ?
                  AND match_start = ?
                """,
                (
                    detection.document_id,
                    detection.detector_id,
                    detection.value_fingerprint,
                    int(detection.match_start or 0),
                ),
            ).fetchone()
            if existing is None:
                return None
            return _detection_from_row(existing)
        row = conn.execute(
            "SELECT * FROM passive_detections WHERE id = ?",
            (det_id,),
        ).fetchone()
    if row is None:
        return None
    return _detection_from_row(row)


def list_detections(
    db_path: Path,
    *,
    project_id: Optional[str] = None,
    document_id: Optional[str] = None,
    detector_id: Optional[str] = None,
    confidence_level: Optional[str] = None,
    category: Optional[str] = None,
    suppressed: Optional[bool] = None,
    has_finding: Optional[bool] = None,
    value_fingerprint: Optional[str] = None,
    finding_id: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> list[Detection]:
    """
    Purpose:
        List passive detections with optional filters (basic CLI/worker use).

    Input:
        project_id        — restrict via join to source_documents
        document_id       — single document
        detector_id       — rule id
        confidence_level  — exact level match
        category          — secret | infrastructure_disclosure | sensitive_info
        suppressed        — True/False filter; None = both
        has_finding       — True → finding_id set; False → null; None = both
        value_fingerprint — secret cluster key component
        finding_id        — detections already linked to this finding
        limit / offset    — pagination

    Output:
        list[Detection] ordered by created_at DESC

    Side effects: None (read-only).
    """
    clauses: list[str] = []
    params: list[Any] = []

    join = ""
    if project_id:
        join = "JOIN source_documents sd ON sd.id = d.document_id"
        clauses.append("sd.project_id = ?")
        params.append(project_id)

    if document_id:
        clauses.append("d.document_id = ?")
        params.append(document_id)
    if detector_id:
        clauses.append("d.detector_id = ?")
        params.append(detector_id)
    if confidence_level:
        clauses.append("d.confidence_level = ?")
        params.append(confidence_level)
    if category:
        clauses.append("d.category = ?")
        params.append(category)
    if suppressed is not None:
        clauses.append("d.suppressed = ?")
        params.append(1 if suppressed else 0)
    if has_finding is True:
        clauses.append("d.finding_id IS NOT NULL")
    elif has_finding is False:
        clauses.append("d.finding_id IS NULL")
    if value_fingerprint:
        clauses.append("d.value_fingerprint = ?")
        params.append(value_fingerprint)
    if finding_id:
        clauses.append("d.finding_id = ?")
        params.append(finding_id)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    lim = max(1, int(limit))
    off = max(0, int(offset))
    sql = f"""
        SELECT d.* FROM passive_detections d
        {join}
        {where}
        ORDER BY d.created_at DESC
        LIMIT ? OFFSET ?
    """
    params.extend([lim, off])

    with _connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
    return [_detection_from_row(r) for r in rows]


def get_detection(db_path: Path, detection_id: str) -> Optional[Detection]:
    """
    Purpose:
        Load one detection by id.
    Input:
        db_path / detection_id
    Output:
        Detection or None
    Side effects: None (read-only).
    """
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT * FROM passive_detections WHERE id = ?",
            (detection_id,),
        ).fetchone()
    if row is None:
        return None
    return _detection_from_row(row)


def link_detection_finding(
    db_path: Path,
    detection_id: str,
    finding_id: str,
) -> bool:
    """
    Purpose:
        Attach a findings.id to a passive detection after the finding bridge
        creates (or links) a finding. Findings subsystem remains owner of
        lifecycle; this only sets the foreign reference.
    Input:
        db_path / detection_id / finding_id
    Output:
        True if a row was updated, False if detection_id not found
    Side effects:
        UPDATE passive_detections.finding_id; commits.
    """
    with _connect(db_path) as conn:
        cur = conn.execute(
            """
            UPDATE passive_detections
            SET finding_id = ?
            WHERE id = ?
            """,
            (finding_id, detection_id),
        )
        conn.commit()
        return cur.rowcount > 0
