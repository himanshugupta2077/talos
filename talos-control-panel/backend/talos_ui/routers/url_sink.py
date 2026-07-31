"""
Control Panel URL Sink Discovery routes (inventory + status).

Purpose:
    Read-only FastAPI surface over parameters.url_features for passive
    network-resource prioritization. No Findings. No mutations (config via
    /api/configuration).

    Default paths do **not** join iv_param_profiles (K14). Config flags load
    per-project effective config only — never process cache (K20).

Dependencies: talos_ui.url_sink_reads, FastAPI
Data flow: HTTP → SQLite parse/filter → JSON
Side effects: None
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, HTTPException, Query

from .. import url_sink_reads as us

router = APIRouter(prefix="/api/url-sink", tags=["url-sink"])


def _bool_param(value: Optional[str | bool], default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in ("1", "true", "yes", "on"):
        return True
    if s in ("0", "false", "no", "off"):
        return False
    return default


@router.get("/status")
def url_sink_status(
    project_id: str,
    include_iv_stats: bool = False,
):
    """
    Parameters-only aggregates + per-project url_sink knobs.
    Set include_iv_stats=true for optional iv_characterized_count (costly).
    """
    return us.project_status(project_id, include_iv_stats=bool(include_iv_stats))


@router.get("/overview")
def url_sink_overview(
    project_id: str,
    top_n: int = Query(10, ge=1, le=50),
):
    return us.project_overview(project_id, top_n=top_n)


@router.get("/inventory")
def url_sink_inventory(
    project_id: str,
    min_score: int = Query(us.DEFAULT_MIN_SCORE, ge=0, le=100),
    nrs_only: Optional[str] = Query("true"),
    category: Optional[str] = None,
    looks_like: Optional[str] = None,
    location: Optional[str] = None,
    host: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    has_iv_profile: Optional[str] = None,
    has_url_sink_obs: Optional[str] = None,
    search: Optional[str] = None,
    sort: str = Query(us.DEFAULT_SORT),
    limit: int = Query(us.DEFAULT_LIMIT, ge=1, le=us.MAX_LIMIT),
    offset: int = Query(0, ge=0),
    include_iv: Optional[str] = Query("false"),
):
    """
    Filterable passive inventory. Query keys match FE K13 canon.

    has_iv_profile / has_url_sink_obs (PR5): optional one-shot capped profile
    uuid index — not used on the default path when both are omitted (K14).
    """
    if sort not in ("score_desc", "score_asc", "name", "host"):
        raise HTTPException(
            400,
            detail="Invalid sort. Expected score_desc|score_asc|name|host",
        )
    nrs = _bool_param(nrs_only, us.DEFAULT_NRS_ONLY)
    inc_iv = _bool_param(include_iv, False)
    # None when omitted → filter not applied; true/false when provided
    has_iv = (
        None if has_iv_profile is None else _bool_param(has_iv_profile, False)
    )
    has_obs = (
        None
        if has_url_sink_obs is None
        else _bool_param(has_url_sink_obs, False)
    )
    return us.project_inventory(
        project_id,
        min_score=min_score,
        nrs_only=nrs,
        category=category or None,
        looks_like=looks_like or None,
        location=location or None,
        host=host or None,
        endpoint_id=endpoint_id or None,
        search=search or None,
        has_iv_profile=has_iv,
        has_url_sink_obs=has_obs,
        sort=sort,
        limit=limit,
        offset=offset,
        include_iv=inc_iv,
    )


@router.get("/params/{parameter_id}")
def url_sink_param_by_id(parameter_id: str, project_id: str):
    detail = us.param_detail(project_id, parameter_id=parameter_id)
    if detail is None:
        raise HTTPException(404, "parameter not found")
    return detail


@router.get("/params")
def url_sink_param_by_uuid(
    project_id: str,
    param_uuid: str = Query(..., min_length=8),
):
    detail = us.param_detail(project_id, param_uuid=param_uuid)
    if detail is None:
        raise HTTPException(404, "parameter not found")
    return detail


@router.get("/by-endpoint/{endpoint_id}")
def url_sink_by_endpoint(
    endpoint_id: str,
    project_id: str,
    limit: int = Query(20, ge=1, le=100),
):
    return us.by_endpoint(project_id, endpoint_id, limit=limit)


@router.get("/rollups/host")
def url_sink_rollup_host(
    project_id: str,
    min_score: int = Query(us.DEFAULT_MIN_SCORE, ge=0, le=100),
    nrs_only: Optional[str] = Query("true"),
    limit: int = Query(50, ge=1, le=200),
):
    """Aggregate all matching sinks by host (not page-truncated)."""
    return us.rollup_by_host(
        project_id,
        min_score=min_score,
        nrs_only=_bool_param(nrs_only, True),
        limit=limit,
    )


@router.get("/rollups/endpoint")
def url_sink_rollup_endpoint(
    project_id: str,
    min_score: int = Query(us.DEFAULT_MIN_SCORE, ge=0, le=100),
    nrs_only: Optional[str] = Query("true"),
    limit: int = Query(50, ge=1, le=200),
):
    """Aggregate all matching sinks by endpoint (not page-truncated)."""
    return us.rollup_by_endpoint(
        project_id,
        min_score=min_score,
        nrs_only=_bool_param(nrs_only, True),
        limit=limit,
    )


@router.get("/rollups/category")
def url_sink_rollup_category(
    project_id: str,
    min_score: int = Query(us.DEFAULT_MIN_SCORE, ge=0, le=100),
    nrs_only: Optional[str] = Query("true"),
    limit: int = Query(50, ge=1, le=200),
):
    """Aggregate all matching sinks by name_category (not page-truncated)."""
    return us.rollup_by_category(
        project_id,
        min_score=min_score,
        nrs_only=_bool_param(nrs_only, True),
        limit=limit,
    )
