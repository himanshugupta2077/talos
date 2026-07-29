"""
Control Panel Error Intelligence routes (Phase 9).

Purpose:
    Thin FastAPI wrappers over talos.error_intel.db (reads) and
    ``talos error-intel …`` CLI subprocess (config / rescan mutations).

    Intelligence only in v1 — no Findings bridge. Never log evidence_snippet
    or payload_redacted at INFO.

Dependencies: FastAPI, talos_ui.db/cli/config, talos.error_intel (read).
Data flow: HTTP → SQLite reads / CLI subprocess for writes.
Side effects: Writes only via CLI subprocess.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional, Sequence

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from .. import cli, config, db

router = APIRouter(prefix="/api/error-intel", tags=["error-intel"])

# Matches talos.error_intel.cli._CONFIG_KEYS
CONFIG_KEYS = frozenset({
    "enabled",
    "store_generic_http_errors",
    "max_body_scan",
    "gate_sniff_bytes",
    "queue_maxsize",
    "evidence_snippet_max",
    "error_header_names",
})

BOOL_KEYS = frozenset({
    "enabled",
    "store_generic_http_errors",
})

INT_KEYS = frozenset({
    "max_body_scan",
    "gate_sniff_bytes",
    "queue_maxsize",
    "evidence_snippet_max",
})

# Full project rescan can exceed default CLI_TIMEOUT.
RESCAN_TIMEOUT_S = 300

DISCLAIMER = (
    "Passive local analysis of stored HTTP responses — no extra requests. "
    "Intelligence only in v1; no auto Findings."
)

# Overview top clusters prefer medium+ so low infra flood does not dominate.
_DEFAULT_TOP_SEVERITIES = ("medium", "high", "critical")


def _ensure_talos_on_path() -> None:
    root = str(config.TALOS_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def _db_path(project_id: str) -> Path:
    record = db.get_project_record(project_id)
    return config.project_db_path(project_id, record)


def _empty_status() -> dict[str, Any]:
    _ensure_talos_on_path()
    from talos.error_intel.constants import ERROR_INTEL_VERSION

    return {
        "enabled": False,
        "store_generic_http_errors": False,
        "scanner_version": ERROR_INTEL_VERSION,
        "clusters": 0,
        "observations": 0,
        "by_severity": {},
        "by_category": {},
        "queue_maxsize": 500,
        "max_body_scan": 512000,
    }


def _cluster_row(c: Any) -> dict[str, Any]:
    """Serialize ErrorCluster — field names match CLI _cluster_row."""
    return {
        "id": c.id,
        "project_id": c.project_id,
        "fingerprint": c.fingerprint,
        "category": c.category,
        "severity": c.severity,
        "language": c.language,
        "framework": c.framework,
        "database": c.database,
        "server": c.server,
        "exception_type": c.exception_type,
        "message_norm": c.message_norm,
        "technologies": list(c.technologies or []),
        "has_stack_trace": bool(c.has_stack_trace),
        "has_path_leak": bool(c.has_path_leak),
        "has_internal_host": bool(c.has_internal_host),
        "has_version_leak": bool(c.has_version_leak),
        "confidence": c.confidence,
        "evidence_snippet": c.evidence_snippet,
        "first_seen": c.first_seen,
        "last_seen": c.last_seen,
        "observation_count": c.observation_count,
        "scanner_version": c.scanner_version,
    }


def _obs_row(o: Any) -> dict[str, Any]:
    """Serialize ErrorObservation — field names match CLI _obs_row."""
    return {
        "id": o.id,
        "error_id": o.error_id,
        "flow_id": o.flow_id,
        "endpoint_id": o.endpoint_id,
        "parameter_uuid": o.parameter_uuid,
        "parameter_name": o.parameter_name,
        "attack_type": o.attack_type,
        "payload_redacted": o.payload_redacted,
        "response_status": o.response_status,
        "response_length": o.response_length,
        "duration_ms": o.duration_ms,
        "response_hash": o.response_hash,
        "detectors": list(o.detectors or []),
        "artifacts": [
            {"kind": a.kind, "value": a.value, "normalized": a.normalized}
            for a in (o.artifacts or [])
        ],
        "observed_at": o.observed_at,
    }


def _resolve_cluster(db_path: Path, project_id: str, error_id: str):
    """Full id via get_cluster, else unique prefix within project clusters."""
    from talos.error_intel import db as error_db

    cluster = error_db.get_cluster(db_path, error_id)
    if cluster is not None:
        if cluster.project_id and cluster.project_id != project_id:
            return None
        return cluster
    if len(error_id) >= 8:
        matches = [
            c
            for c in error_db.list_clusters(db_path, project_id, limit=500)
            if c.id.startswith(error_id)
        ]
        if len(matches) == 1:
            return matches[0]
    return None


def _parse_severities(
    severity: Optional[Sequence[str]],
) -> Optional[list[str]]:
    """
    Normalize severity query: comma-separated and/or repeated params → list.
    FastAPI may pass list[str] for repeated Query params.
    """
    if not severity:
        return None
    out: list[str] = []
    for item in severity:
        if not item:
            continue
        for part in str(item).split(","):
            s = part.strip().lower()
            if s:
                out.append(s)
    return out or None


def build_status(project_id: str) -> dict[str, Any]:
    """Assemble status payload (used by status, overview, by-flow)."""
    _ensure_talos_on_path()
    from talos.error_intel import db as error_db
    from talos.error_intel.constants import ERROR_INTEL_VERSION

    db_path = _db_path(project_id)
    if not db_path.exists():
        return _empty_status()

    try:
        cfg = error_db.get_config(db_path)
    except Exception:
        return _empty_status()

    try:
        clusters = error_db.count_clusters(db_path, project_id)
        observations = error_db.count_observations(
            db_path, project_id=project_id
        )
        by_sev = error_db.severity_counts(db_path, project_id)
        by_cat = error_db.category_counts(db_path, project_id)
    except Exception:
        clusters = 0
        observations = 0
        by_sev = {}
        by_cat = {}

    return {
        "enabled": cfg.enabled,
        "store_generic_http_errors": cfg.store_generic_http_errors,
        "scanner_version": ERROR_INTEL_VERSION,
        "clusters": clusters,
        "observations": observations,
        "by_severity": by_sev,
        "by_category": by_cat,
        "queue_maxsize": cfg.queue_maxsize,
        "max_body_scan": cfg.max_body_scan,
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
    """Status + top clusters (medium+ preference) + empty-state flags."""
    _ensure_talos_on_path()
    from talos.error_intel import db as error_db

    status = build_status(project_id)
    db_path = _db_path(project_id)
    top: list[dict[str, Any]] = []
    if db_path.exists():
        try:
            # Prefer medium+ so low infrastructure flood does not dominate.
            rows = error_db.list_clusters(
                db_path,
                project_id,
                severities=list(_DEFAULT_TOP_SEVERITIES),
                limit=top_n,
            )
            if not rows and int(status.get("clusters") or 0) > 0:
                # Fall back to any severity when only low noise exists.
                rows = error_db.list_clusters(
                    db_path, project_id, limit=top_n
                )
            top = [_cluster_row(c) for c in rows]
        except Exception:
            top = []

    return {
        "status": status,
        "top_clusters": top,
        "empty_state": {
            "disabled": not bool(status.get("enabled")),
            "no_clusters": int(status.get("clusters") or 0) == 0,
            "no_observations": int(status.get("observations") or 0) == 0,
        },
        "note": DISCLAIMER,
    }


@router.get("/config")
def get_config(project_id: str):
    _ensure_talos_on_path()
    from talos.error_intel import db as error_db
    from talos.error_intel.config import default_config
    from talos.error_intel.constants import ERROR_INTEL_VERSION

    db_path = _db_path(project_id)
    if not db_path.exists():
        return {
            "config": default_config().to_dict(),
            "scanner_version": ERROR_INTEL_VERSION,
            "keys": sorted(CONFIG_KEYS),
        }
    try:
        cfg = error_db.get_config(db_path)
    except Exception:
        cfg = default_config()
    return {
        "config": cfg.to_dict(),
        "scanner_version": ERROR_INTEL_VERSION,
        "keys": sorted(CONFIG_KEYS),
    }


class ErrorIntelConfigBody(BaseModel):
    """Set one or more config keys (each becomes ``error-intel config set``)."""

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
    if key == "error_header_names":
        if isinstance(value, (list, tuple, set, frozenset)):
            return ",".join(str(v) for v in value)
        return str(value)
    return str(value)


@router.post("/config")
def set_config(project_id: str, body: ErrorIntelConfigBody):
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
            ["error-intel", "config", "set", key, formatted],
        )
        all_results.extend(r.to_dict() for r in results)
        if any(not r.ok for r in results):
            break

    return {"steps": all_results}


@router.get("/errors")
def list_errors(
    project_id: str,
    category: Optional[str] = None,
    severity: Optional[list[str]] = Query(None),
    has_stack_trace: Optional[bool] = None,
    has_path_leak: Optional[bool] = None,
    has_internal_host: Optional[bool] = None,
    has_version_leak: Optional[bool] = None,
    min_observations: Optional[int] = Query(None, ge=1),
    q: Optional[str] = None,
    hide_low_noise: bool = Query(False),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """
    Filtered cluster list with pagination total.

    severity may be repeated or comma-separated (e.g. medium,high,critical).
    """
    _ensure_talos_on_path()
    from talos.error_intel import db as error_db

    db_path = _db_path(project_id)
    severities = _parse_severities(severity)
    filter_kwargs: dict[str, Any] = {
        "category": category,
        "severities": severities,
        "has_stack_trace": has_stack_trace,
        "has_path_leak": has_path_leak,
        "has_internal_host": has_internal_host,
        "has_version_leak": has_version_leak,
        "min_observations": min_observations,
        "q": q,
        "hide_low_noise": hide_low_noise,
    }
    if not db_path.exists():
        return {
            "errors": [],
            "total": 0,
            "limit": limit,
            "offset": offset,
            "count": 0,
        }
    try:
        rows = error_db.list_clusters(
            db_path,
            project_id,
            limit=limit,
            offset=offset,
            **filter_kwargs,
        )
        total = error_db.count_clusters(
            db_path, project_id, **filter_kwargs
        )
    except Exception as exc:
        raise HTTPException(500, f"Failed to list errors: {exc}") from exc

    errors = [_cluster_row(c) for c in rows]
    return {
        "errors": errors,
        "total": total,
        "limit": limit,
        "offset": offset,
        "count": len(errors),
    }


@router.get("/errors/{error_id}")
def get_error(project_id: str, error_id: str):
    """Cluster detail + observations + sibling clusters (same exception_type)."""
    _ensure_talos_on_path()
    from talos.error_intel import db as error_db

    db_path = _db_path(project_id)
    if not db_path.exists():
        raise HTTPException(404, "Project database not found")

    cluster = _resolve_cluster(db_path, project_id, error_id)
    if cluster is None:
        raise HTTPException(404, f"Error cluster not found: {error_id}")

    observations = error_db.list_observations(
        db_path, error_id=cluster.id, limit=100
    )

    siblings: list[dict[str, Any]] = []
    exc_type = (cluster.exception_type or "").strip()
    if exc_type:
        try:
            candidates = error_db.list_clusters(
                db_path, project_id, limit=200
            )
            for c in candidates:
                if c.id == cluster.id:
                    continue
                if (c.exception_type or "").strip() != exc_type:
                    continue
                siblings.append(_cluster_row(c))
                if len(siblings) >= 10:
                    break
        except Exception:
            siblings = []

    return {
        "error": _cluster_row(cluster),
        "observations": [_obs_row(o) for o in observations],
        "sibling_clusters": siblings,
    }


@router.get("/observations")
def list_observations(
    project_id: str,
    error_id: Optional[str] = None,
    flow_id: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    parameter_uuid: Optional[str] = None,
    attack_type: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    _ensure_talos_on_path()
    from talos.error_intel import db as error_db

    db_path = _db_path(project_id)
    if not db_path.exists():
        return {
            "observations": [],
            "limit": limit,
            "offset": offset,
            "count": 0,
        }

    resolved_error_id = error_id
    if error_id:
        cluster = _resolve_cluster(db_path, project_id, error_id)
        if cluster is None:
            raise HTTPException(404, f"Error cluster not found: {error_id}")
        resolved_error_id = cluster.id

    try:
        if resolved_error_id or flow_id or endpoint_id or parameter_uuid or attack_type:
            rows = error_db.list_observations(
                db_path,
                error_id=resolved_error_id,
                flow_id=flow_id,
                endpoint_id=endpoint_id,
                parameter_uuid=parameter_uuid,
                attack_type=attack_type,
                limit=limit,
                offset=offset,
            )
            # When scoped without error_id, filter to this project's clusters.
            if not resolved_error_id and rows:
                project_ids = {
                    c.id
                    for c in error_db.list_clusters(
                        db_path, project_id, limit=1000
                    )
                }
                rows = [o for o in rows if o.error_id in project_ids]
        else:
            # Project-wide: walk clusters (same approach as CLI).
            clusters = error_db.list_clusters(
                db_path, project_id, limit=200
            )
            obs_all: list[Any] = []
            remaining = limit + offset
            for c in clusters:
                if remaining <= 0:
                    break
                batch = error_db.list_observations(
                    db_path, error_id=c.id, limit=remaining
                )
                obs_all.extend(batch)
                remaining = limit + offset - len(obs_all)
            obs_all.sort(key=lambda o: o.observed_at or "", reverse=True)
            rows = obs_all[offset : offset + limit]
    except Exception as exc:
        raise HTTPException(
            500, f"Failed to list observations: {exc}"
        ) from exc

    observations = [_obs_row(o) for o in rows]
    return {
        "observations": observations,
        "limit": limit,
        "offset": offset,
        "count": len(observations),
    }


@router.get("/rollups/parameter")
def rollup_parameter(
    project_id: str,
    parameter_uuid: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
):
    _ensure_talos_on_path()
    from talos.error_intel import db as error_db

    db_path = _db_path(project_id)
    if not db_path.exists():
        return {"rollup": []}
    try:
        rows = error_db.parameter_error_rollup(
            db_path,
            project_id,
            parameter_uuid=parameter_uuid,
            limit=limit,
        )
    except Exception as exc:
        raise HTTPException(500, f"Failed to load rollup: {exc}") from exc
    return {"rollup": rows}


@router.get("/rollups/endpoint")
def rollup_endpoint(
    project_id: str,
    endpoint_id: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500),
):
    _ensure_talos_on_path()
    from talos.error_intel import db as error_db

    db_path = _db_path(project_id)
    if not db_path.exists():
        return {"rollup": []}
    try:
        rows = error_db.endpoint_error_rollup(
            db_path,
            project_id,
            endpoint_id=endpoint_id,
            limit=limit,
        )
    except Exception as exc:
        raise HTTPException(500, f"Failed to load rollup: {exc}") from exc
    return {"rollup": rows}


class RescanBody(BaseModel):
    """Maps to ``talos error-intel rescan`` flags."""

    mode: str = Field("all", description="'all' or 'flow'")
    id: Optional[str] = Field(
        None, description="Flow id when mode=flow"
    )
    force: bool = False
    outdated: bool = False
    limit: int = Field(200, ge=1, le=5000)


@router.post("/rescan")
def rescan(project_id: str, body: RescanBody):
    mode = (body.mode or "all").strip().lower()
    if mode not in ("all", "flow"):
        raise HTTPException(400, "mode must be 'all' or 'flow'")
    if mode == "flow" and not (body.id or "").strip():
        raise HTTPException(400, "id required when mode=flow")

    argv: list[str] = ["error-intel", "rescan"]
    if mode == "all":
        argv.append("--all")
        if body.outdated:
            argv.append("--outdated")
        argv.extend(["--limit", str(int(body.limit))])
    else:
        argv.extend(["--flow", body.id.strip()])  # type: ignore[union-attr]
    if body.force:
        argv.append("--force")

    results = cli.run_scoped(
        project_id,
        argv,
        timeout=RESCAN_TIMEOUT_S,
    )
    return {"steps": [r.to_dict() for r in results]}


@router.get("/by-flow/{flow_id}")
def by_flow(project_id: str, flow_id: str):
    """
    Flow-scoped observations + joined clusters.

    Historical observations are returned even when the scanner is disabled.
    Cap: 20 observations, observed_at DESC.
    """
    _ensure_talos_on_path()
    from talos.error_intel import db as error_db

    status = build_status(project_id)
    db_path = _db_path(project_id)
    empty = {
        "observation_count": 0,
        "observations": [],
        "clusters": [],
        "scanner_enabled": bool(status.get("enabled")),
    }
    if not db_path.exists():
        return empty

    try:
        rows = error_db.list_observations(
            db_path, flow_id=flow_id, limit=20
        )
        # Restrict to this project's clusters.
        project_cluster_ids = {
            c.id
            for c in error_db.list_clusters(db_path, project_id, limit=1000)
        }
        rows = [o for o in rows if o.error_id in project_cluster_ids]
    except Exception:
        return empty

    observations = [_obs_row(o) for o in rows]
    clusters: list[dict[str, Any]] = []
    seen_error: set[str] = set()
    for o in rows:
        eid = o.error_id
        if not eid or eid in seen_error:
            continue
        seen_error.add(eid)
        cluster = error_db.get_cluster(db_path, eid)
        if cluster is not None:
            clusters.append(_cluster_row(cluster))

    return {
        "observation_count": len(observations),
        "observations": observations,
        "clusters": clusters,
        "scanner_enabled": bool(status.get("enabled")),
    }
