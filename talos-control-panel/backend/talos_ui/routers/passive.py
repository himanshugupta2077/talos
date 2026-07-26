"""
Control Panel Passive Secret Detection routes (Phase 13).

Purpose:
    Read-side APIs for status, documents, detections, rules, and overview —
    plus mutation wrappers that shell out to ``talos passive …``.

    Detection payloads always use redacted_value; raw secrets are never
    returned from detection rows.

Dependencies: FastAPI, talos_ui.db/cli/config, talos.passive (read).
Data flow: HTTP → read-only SQLite / core helpers, or CLI subprocess for writes.
Side effects: Writes only via CLI subprocess.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .. import cli, config, db

router = APIRouter(prefix="/api/passive", tags=["passive"])

# Matches talos.passive.cli._CONFIG_KEYS
CONFIG_KEYS = frozenset({
    "enabled",
    "auto_finding_threshold",
    "max_document_size",
    "max_decode_depth",
    "max_decode_bytes",
    "max_candidates_per_document",
    "scan_html",
    "scan_javascript",
    "scan_json",
    "scan_xml",
    "scan_text",
    "scan_css",
    "scan_sourcemaps",
    "scan_wasm",
    "store_raw_secret_in_evidence",
    "store_suppressed_detections",
    "queue_maxsize",
    "max_scan_time_ms",
})

BOOL_KEYS = frozenset({
    "enabled",
    "scan_html",
    "scan_javascript",
    "scan_json",
    "scan_xml",
    "scan_text",
    "scan_css",
    "scan_sourcemaps",
    "scan_wasm",
    "store_raw_secret_in_evidence",
    "store_suppressed_detections",
})

INT_KEYS = frozenset({
    "max_document_size",
    "max_decode_depth",
    "max_decode_bytes",
    "max_candidates_per_document",
    "queue_maxsize",
    "max_scan_time_ms",
})

# Full project rescan can exceed default CLI_TIMEOUT.
RESCAN_TIMEOUT_S = 300

DISCLAIMER = (
    "Passive local analysis — no outbound secret validation. "
    "MEDIUM / OBSERVATION_ONLY stay intelligence-only by default."
)


def _ensure_talos_on_path() -> None:
    root = str(config.TALOS_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def _db_path(project_id: str) -> Path:
    record = db.get_project_record(project_id)
    return config.project_db_path(project_id, record)


def _empty_status() -> dict[str, Any]:
    _ensure_talos_on_path()
    from talos.passive.constants import SCANNER_VERSION

    return {
        "enabled": False,
        "auto_finding_threshold": "HIGH",
        "scanner_version": SCANNER_VERSION,
        "documents": 0,
        "documents_scanned": 0,
        "documents_pending": 0,
        "documents_error": 0,
        "documents_too_large": 0,
        "detections": 0,
        "detections_with_finding": 0,
        "stale_documents": 0,
        "queue_maxsize": 500,
        "by_confidence": {},
        "by_category": {},
        "by_source_kind": {},
        "by_scan_status": {},
    }


def _document_row(doc: Any) -> dict[str, Any]:
    from talos.passive.constants import SourceKind

    kind = doc.source_kind
    if isinstance(kind, SourceKind):
        kind_val = kind.value
    else:
        kind_val = str(kind)
    return {
        "id": doc.id,
        "project_id": doc.project_id,
        "body_hash": doc.body_hash,
        "source_kind": kind_val,
        "body_size": doc.body_size,
        "truncated": doc.truncated,
        "scanner_version": doc.scanner_version,
        "scan_status": doc.scan_status,
        "first_flow_id": doc.first_flow_id,
        "parent_document_id": doc.parent_document_id,
        "logical_source_name": doc.logical_source_name,
        "first_seen": doc.first_seen,
        "last_seen": doc.last_seen,
        "last_scanned_at": doc.last_scanned_at,
        "error_message": getattr(doc, "error_message", None),
    }


def _detection_row(det: Any) -> dict[str, Any]:
    """Serialize Detection without raw_value (redaction contract)."""
    return {
        "id": det.id,
        "document_id": det.document_id,
        "occurrence_id": det.occurrence_id,
        "detector_id": det.detector_id,
        "detector_family": det.detector_family,
        "category": det.category,
        "secret_type": det.secret_type,
        "matched_key": det.matched_key,
        "redacted_value": det.redacted_value,
        "value_fingerprint": det.value_fingerprint,
        "confidence_score": det.confidence_score,
        "confidence_level": det.confidence_level,
        "entropy": det.entropy,
        "encoding_chain": list(det.encoding_chain or []),
        "decode_depth": det.decode_depth,
        "match_start": det.match_start,
        "match_end": det.match_end,
        "context_before": det.context_before,
        "context_after": det.context_after,
        "suppressed": det.suppressed,
        "suppression_reason": det.suppression_reason,
        "finding_id": det.finding_id,
        "raw_value_stored": det.raw_value_stored,
        "created_at": det.created_at,
    }


def _occurrence_row(occ: Any) -> dict[str, Any]:
    return {
        "id": occ.id,
        "document_id": occ.document_id,
        "flow_id": occ.flow_id,
        "endpoint_id": occ.endpoint_id,
        "url": occ.url,
        "host": occ.host,
        "path": occ.path,
        "logical_source_name": occ.logical_source_name,
        "content_type": occ.content_type,
        "observed_at": occ.observed_at,
        "role_id": occ.role_id,
        "module_id": occ.module_id,
    }


def _resolve_document(db_path: Path, project_id: str, document_id: str):
    from talos.passive import db as passive_db

    doc = passive_db.get_document(db_path, document_id)
    if doc is not None:
        return doc
    if len(document_id) >= 8:
        matches = [
            d
            for d in passive_db.list_documents(db_path, project_id, limit=500)
            if d.id.startswith(document_id)
        ]
        if len(matches) == 1:
            return matches[0]
    return None


def _resolve_detection(db_path: Path, project_id: str, detection_id: str):
    from talos.passive import db as passive_db

    det = passive_db.get_detection(db_path, detection_id)
    if det is not None:
        return det
    if len(detection_id) >= 8:
        matches = [
            d
            for d in passive_db.list_detections(
                db_path, project_id=project_id, limit=500
            )
            if d.id.startswith(detection_id)
        ]
        if len(matches) == 1:
            return matches[0]
    return None


_DOC_GROUP_COLS = frozenset({"source_kind", "scan_status"})
_DET_GROUP_COLS = frozenset({"confidence_level", "category", "detector_id"})


def _group_counts(
    db_path: Path, project_id: str, table: str, column: str
) -> dict[str, int]:
    """Count rows grouped by a column; empty on missing tables."""
    try:
        if table == "source_documents":
            if column not in _DOC_GROUP_COLS:
                return {}
            rows = db.query_all(
                db_path,
                f"SELECT {column} AS k, COUNT(*) AS n FROM source_documents "
                f"WHERE project_id=? GROUP BY {column}",
                (project_id,),
            )
        elif table == "passive_detections":
            if column not in _DET_GROUP_COLS:
                return {}
            rows = db.query_all(
                db_path,
                f"""
                SELECT d.{column} AS k, COUNT(*) AS n
                FROM passive_detections d
                JOIN source_documents sd ON sd.id = d.document_id
                WHERE sd.project_id=?
                GROUP BY d.{column}
                """,
                (project_id,),
            )
        else:
            return {}
        out: dict[str, int] = {}
        for r in rows:
            key = str(r.get("k") or "unknown")
            out[key] = int(r.get("n") or 0)
        return out
    except Exception:
        return {}


def _count_stale(db_path: Path, project_id: str, scanner_version: str) -> int:
    """Parent documents pending or not at current SCANNER_VERSION."""
    try:
        row = db.query_one(
            db_path,
            """
            SELECT COUNT(*) AS n FROM source_documents
            WHERE project_id=?
              AND parent_document_id IS NULL
              AND (
                scan_status = 'pending'
                OR scanner_version IS NULL
                OR scanner_version != ?
              )
            """,
            (project_id, scanner_version),
        )
        return int((row or {}).get("n") or 0)
    except Exception:
        return 0


def build_status(project_id: str) -> dict[str, Any]:
    """Assemble status payload (used by status, overview, dashboard)."""
    _ensure_talos_on_path()
    from talos.passive import db as passive_db
    from talos.passive.constants import SCANNER_VERSION

    db_path = _db_path(project_id)
    if not db_path.exists():
        return _empty_status()

    try:
        cfg = passive_db.get_config(db_path)
    except Exception:
        return _empty_status()

    docs = passive_db.count_documents(db_path, project_id)
    scanned = passive_db.count_documents(
        db_path, project_id, scan_status="scanned"
    )
    pending = passive_db.count_documents(
        db_path, project_id, scan_status="pending"
    )
    err = passive_db.count_documents(db_path, project_id, scan_status="error")
    too_large = passive_db.count_documents(
        db_path, project_id, scan_status="too_large"
    )
    dets = passive_db.count_detections(db_path, project_id)
    dets_finding = passive_db.count_detections(
        db_path, project_id, has_finding=True
    )
    stale = _count_stale(db_path, project_id, SCANNER_VERSION)

    return {
        "enabled": cfg.enabled,
        "auto_finding_threshold": cfg.auto_finding_threshold,
        "scanner_version": SCANNER_VERSION,
        "documents": docs,
        "documents_scanned": scanned,
        "documents_pending": pending,
        "documents_error": err,
        "documents_too_large": too_large,
        "detections": dets,
        "detections_with_finding": dets_finding,
        "stale_documents": stale,
        "queue_maxsize": cfg.queue_maxsize,
        "by_confidence": _group_counts(
            db_path, project_id, "passive_detections", "confidence_level"
        ),
        "by_category": _group_counts(
            db_path, project_id, "passive_detections", "category"
        ),
        "by_source_kind": _group_counts(
            db_path, project_id, "source_documents", "source_kind"
        ),
        "by_scan_status": _group_counts(
            db_path, project_id, "source_documents", "scan_status"
        ),
    }


# ------------------------------------------------------------------ #
# Routes                                                               #
# ------------------------------------------------------------------ #


@router.get("/status")
def get_status(project_id: str):
    return build_status(project_id)


@router.get("/overview")
def get_overview(
    project_id: str,
    top_n: int = Query(8, ge=1, le=50),
):
    """Status + recent high-value detections + empty-state flags."""
    _ensure_talos_on_path()
    from talos.passive import db as passive_db

    status = build_status(project_id)
    db_path = _db_path(project_id)
    top: list[dict[str, Any]] = []
    if db_path.exists():
        try:
            dets = passive_db.list_detections(
                db_path,
                project_id=project_id,
                suppressed=False,
                limit=max(top_n * 4, 40),
            )
            # Prefer secrets at HIGH+; fall back to any non-suppressed
            ranked = sorted(
                dets,
                key=lambda d: (
                    0 if d.category == "secret" else 1,
                    -int(d.confidence_score or 0),
                ),
            )
            top = [_detection_row(d) for d in ranked[:top_n]]
        except Exception:
            top = []

    return {
        "status": status,
        "top_detections": top,
        "empty_state": {
            "no_documents": int(status.get("documents") or 0) == 0,
            "no_detections": int(status.get("detections") or 0) == 0,
            "disabled": not bool(status.get("enabled")),
            "has_stale": int(status.get("stale_documents") or 0) > 0,
        },
        "note": DISCLAIMER,
    }


@router.get("/config")
def get_config(project_id: str):
    _ensure_talos_on_path()
    from talos.passive import db as passive_db
    from talos.passive.config import default_config
    from talos.passive.constants import SCANNER_VERSION

    db_path = _db_path(project_id)
    if not db_path.exists():
        return {
            "config": default_config().to_dict(),
            "scanner_version": SCANNER_VERSION,
            "keys": sorted(CONFIG_KEYS),
        }
    try:
        cfg = passive_db.get_config(db_path)
    except Exception:
        cfg = default_config()
    return {
        "config": cfg.to_dict(),
        "scanner_version": SCANNER_VERSION,
        "keys": sorted(CONFIG_KEYS),
    }


class PassiveConfigBody(BaseModel):
    """Set one or more config keys (each becomes ``passive config set``)."""

    key: Optional[str] = None
    value: Optional[Any] = None
    updates: Optional[dict[str, Any]] = None


def _format_config_value(key: str, value: Any) -> str:
    if key in BOOL_KEYS:
        if isinstance(value, bool):
            return "true" if value else "false"
        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return "true"
        if text in ("0", "false", "no", "off"):
            return "false"
        return text
    if key in INT_KEYS:
        return str(int(value))
    return str(value)


@router.post("/config")
def set_config(project_id: str, body: PassiveConfigBody):
    updates: dict[str, Any] = {}
    if body.updates:
        updates.update(body.updates)
    if body.key is not None:
        if body.value is None:
            raise HTTPException(400, "value required when key is set")
        updates[body.key] = body.value
    if not updates:
        raise HTTPException(400, "Provide key/value or updates map")

    unknown = [k for k in updates if k not in CONFIG_KEYS]
    if unknown:
        raise HTTPException(
            400,
            f"Unknown config keys: {', '.join(sorted(unknown))}. "
            f"Known: {', '.join(sorted(CONFIG_KEYS))}",
        )

    all_results: list[dict[str, Any]] = []
    for key, value in updates.items():
        formatted = _format_config_value(key, value)
        results = cli.run_scoped(
            project_id,
            ["passive", "config", "set", key, formatted],
        )
        all_results.extend(r.to_dict() for r in results)
        if any(not r.ok for r in results):
            break

    return {"steps": all_results}


@router.get("/rules")
def list_rules(project_id: str):
    """Loaded detector rule packs (package-local; project context required)."""
    _ = project_id  # project-scoped API surface
    _ensure_talos_on_path()
    from talos.passive.rules_loader import load_rule_packs

    index = load_rule_packs()
    rows = [
        {
            "id": r.id,
            "name": r.name,
            "family": r.family,
            "secret_type": r.secret_type,
            "confidence_level": r.confidence_level,
            "enabled": r.enabled,
            "pack": r.pack,
            "finding_title": r.finding_title or "",
        }
        for r in index.all_rules
    ]
    return {
        "rules": rows,
        "load_errors": [
            {"pack": pack, "message": msg} for pack, msg in index.load_errors
        ],
    }


@router.get("/documents")
def list_documents(
    project_id: str,
    status: Optional[str] = None,
    kind: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    _ensure_talos_on_path()
    from talos.passive import db as passive_db
    from talos.passive.constants import SCANNER_VERSION

    db_path = _db_path(project_id)
    if not db_path.exists():
        return {
            "documents": [],
            "scanner_version": SCANNER_VERSION,
            "total": 0,
        }
    docs = passive_db.list_documents(
        db_path,
        project_id,
        scan_status=status,
        source_kind=kind,
        limit=limit,
        offset=offset,
    )
    total = passive_db.count_documents(
        db_path, project_id, scan_status=status
    )
    rows = []
    for d in docs:
        row = _document_row(d)
        row["stale"] = (
            d.scanner_version is None or d.scanner_version != SCANNER_VERSION
        )
        rows.append(row)
    return {
        "documents": rows,
        "scanner_version": SCANNER_VERSION,
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@router.get("/documents/{document_id}")
def show_document(project_id: str, document_id: str):
    _ensure_talos_on_path()
    from talos.passive import db as passive_db
    from talos.passive.constants import SCANNER_VERSION

    db_path = _db_path(project_id)
    if not db_path.exists():
        raise HTTPException(404, "Project database not found")
    doc = _resolve_document(db_path, project_id, document_id)
    if doc is None:
        raise HTTPException(404, f"Document not found: {document_id}")

    occs = passive_db.list_occurrences(db_path, doc.id, limit=50)
    dets = passive_db.list_detections(
        db_path, document_id=doc.id, limit=100
    )
    # Child virtual documents
    children: list[dict[str, Any]] = []
    try:
        all_docs = passive_db.list_documents(db_path, project_id, limit=2000)
        children = [
            _document_row(c)
            for c in all_docs
            if c.parent_document_id == doc.id
        ]
    except Exception:
        children = []

    row = _document_row(doc)
    row["stale"] = (
        doc.scanner_version is None or doc.scanner_version != SCANNER_VERSION
    )
    return {
        "document": row,
        "occurrences": [_occurrence_row(o) for o in occs],
        "detections": [_detection_row(d) for d in dets],
        "children": children,
        "scanner_version": SCANNER_VERSION,
    }


@router.get("/detections")
def list_detections(
    project_id: str,
    secret_type: Optional[str] = Query(None, alias="type"),
    confidence: Optional[str] = None,
    category: Optional[str] = None,
    document: Optional[str] = None,
    suppressed: Optional[bool] = None,
    has_finding: Optional[bool] = None,
    detector_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    _ensure_talos_on_path()
    from talos.passive import db as passive_db

    db_path = _db_path(project_id)
    if not db_path.exists():
        return {"detections": [], "total": 0, "limit": limit, "offset": offset}

    # CLI: --suppressed means only suppressed; default list excludes them
    if suppressed is True:
        supp_filter: Optional[bool] = True
    elif suppressed is False:
        supp_filter = False
    else:
        supp_filter = False  # default: non-suppressed only

    dets = passive_db.list_detections(
        db_path,
        project_id=project_id,
        document_id=document,
        detector_id=detector_id,
        confidence_level=confidence,
        category=category,
        suppressed=supp_filter,
        has_finding=has_finding,
        limit=limit,
        offset=offset,
    )
    if secret_type:
        dets = [
            d
            for d in dets
            if (d.secret_type or "") == secret_type
            or d.detector_id == secret_type
        ]
    rows = [_detection_row(d) for d in dets]
    # Redaction invariant: never expose raw_value key
    for r in rows:
        r.pop("raw_value", None)
    return {
        "detections": rows,
        "limit": limit,
        "offset": offset,
        "count": len(rows),
    }


@router.get("/detections/{detection_id}")
def show_detection(project_id: str, detection_id: str):
    _ensure_talos_on_path()
    from talos.passive import db as passive_db

    db_path = _db_path(project_id)
    if not db_path.exists():
        raise HTTPException(404, "Project database not found")
    det = _resolve_detection(db_path, project_id, detection_id)
    if det is None:
        raise HTTPException(404, f"Detection not found: {detection_id}")

    row = _detection_row(det)
    row.pop("raw_value", None)

    siblings: list[dict[str, Any]] = []
    if det.value_fingerprint:
        sibs = passive_db.list_detections(
            db_path,
            project_id=project_id,
            value_fingerprint=det.value_fingerprint,
            limit=20,
        )
        siblings = [
            _detection_row(s) for s in sibs if s.id != det.id
        ]

    document = None
    occurrence = None
    if det.document_id:
        doc = passive_db.get_document(db_path, det.document_id)
        if doc:
            document = _document_row(doc)
    if det.occurrence_id:
        occ = passive_db.get_occurrence(db_path, det.occurrence_id)
        if occ:
            occurrence = _occurrence_row(occ)

    return {
        "detection": row,
        "siblings": siblings,
        "document": document,
        "occurrence": occurrence,
    }


class RescanBody(BaseModel):
    mode: str = Field(..., description="all | document | flow")
    id: Optional[str] = Field(
        None, description="document_id or flow_id when mode is not all"
    )
    force: bool = False


@router.post("/rescan")
def rescan(project_id: str, body: RescanBody):
    mode = (body.mode or "").strip().lower()
    args = ["passive", "rescan"]
    if mode == "all":
        args.append("--all")
    elif mode == "document":
        if not body.id:
            raise HTTPException(400, "id required for document rescan")
        args += ["--document", body.id]
    elif mode == "flow":
        if not body.id:
            raise HTTPException(400, "id required for flow rescan")
        args += ["--flow", body.id]
    else:
        raise HTTPException(400, "mode must be all, document, or flow")
    if body.force:
        args.append("--force")

    results = cli.run_scoped(project_id, args, timeout=RESCAN_TIMEOUT_S)
    return {"steps": [r.to_dict() for r in results]}


@router.get("/by-flow/{flow_id}")
def passive_for_flow(project_id: str, flow_id: str):
    """
    Lightweight lookup for Flow detail: document + detection count for a flow.
    """
    _ensure_talos_on_path()
    from talos.passive import db as passive_db

    db_path = _db_path(project_id)
    empty = {
        "document_id": None,
        "scan_status": None,
        "source_kind": None,
        "detection_count": 0,
        "has_finding": False,
        "scanner_version": None,
    }
    if not db_path.exists():
        return empty

    try:
        with sqlite3.connect(str(db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                """
                SELECT document_id FROM source_occurrences
                WHERE flow_id = ?
                ORDER BY observed_at DESC LIMIT 1
                """,
                (flow_id,),
            ).fetchone()
    except sqlite3.Error:
        return empty

    if row is None:
        return empty

    doc_id = str(row["document_id"])
    doc = passive_db.get_document(db_path, doc_id)
    dets = passive_db.list_detections(
        db_path, document_id=doc_id, limit=100
    )
    has_finding = any(d.finding_id for d in dets)
    kind = None
    status = None
    scanner_version = None
    if doc:
        from talos.passive.constants import SourceKind

        kind = (
            doc.source_kind.value
            if isinstance(doc.source_kind, SourceKind)
            else str(doc.source_kind)
        )
        status = doc.scan_status
        scanner_version = doc.scanner_version

    return {
        "document_id": doc_id,
        "scan_status": status,
        "source_kind": kind,
        "detection_count": len(dets),
        "has_finding": has_finding,
        "scanner_version": scanner_version,
    }
