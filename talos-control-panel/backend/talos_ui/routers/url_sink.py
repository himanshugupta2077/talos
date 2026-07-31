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

    has_iv_profile / has_url_sink_obs are deferred (PR5) — ignored with note
    when set, not 501 for simple clients.
    """
    if sort not in ("score_desc", "score_asc", "name", "host"):
        raise HTTPException(
            400,
            detail="Invalid sort. Expected score_desc|score_asc|name|host",
        )
    nrs = _bool_param(nrs_only, us.DEFAULT_NRS_ONLY)
    inc_iv = _bool_param(include_iv, False)
    result = us.project_inventory(
        project_id,
        min_score=min_score,
        nrs_only=nrs,
        category=category or None,
        looks_like=looks_like or None,
        location=location or None,
        host=host or None,
        endpoint_id=endpoint_id or None,
        search=search or None,
        sort=sort,
        limit=limit,
        offset=offset,
        include_iv=inc_iv,
    )
    deferred = []
    if has_iv_profile is not None:
        deferred.append("has_iv_profile")
    if has_url_sink_obs is not None:
        deferred.append("has_url_sink_obs")
    if deferred:
        result["deferred_filters"] = deferred
        result["note"] = (
            result.get("note", "")
            + " Deferred filters (PR5): "
            + ", ".join(deferred)
            + " — not applied."
        ).strip()
    return result


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
    inv = us.project_inventory(
        project_id,
        min_score=min_score,
        nrs_only=_bool_param(nrs_only, True),
        sort="score_desc",
        limit=us.MAX_LIMIT,
        offset=0,
        include_iv=False,
    )
    buckets: dict[str, dict] = {}
    for item in inv["items"]:
        key = item.get("host") or ""
        b = buckets.setdefault(
            key, {"key": key, "count": 0, "nrs_count": 0, "max_score": 0, "categories": {}}
        )
        b["count"] += 1
        if item.get("possible_network_resource"):
            b["nrs_count"] += 1
        b["max_score"] = max(b["max_score"], int(item.get("url_score") or 0))
        cat = item.get("name_category")
        if cat:
            b["categories"][cat] = b["categories"].get(cat, 0) + 1
    rollup = sorted(buckets.values(), key=lambda x: (-x["max_score"], -x["count"]))
    return {"rollup": rollup[:limit], "disclaimer": us.DISCLAIMER}


@router.get("/rollups/endpoint")
def url_sink_rollup_endpoint(
    project_id: str,
    min_score: int = Query(us.DEFAULT_MIN_SCORE, ge=0, le=100),
    nrs_only: Optional[str] = Query("true"),
    limit: int = Query(50, ge=1, le=200),
):
    inv = us.project_inventory(
        project_id,
        min_score=min_score,
        nrs_only=_bool_param(nrs_only, True),
        sort="score_desc",
        limit=us.MAX_LIMIT,
        offset=0,
        include_iv=False,
    )
    buckets: dict[str, dict] = {}
    for item in inv["items"]:
        eid = item.get("endpoint_id") or ""
        b = buckets.setdefault(
            eid,
            {
                "key": eid,
                "endpoint_id": eid,
                "method": item.get("method"),
                "host": item.get("host"),
                "normalized_path": item.get("normalized_path"),
                "count": 0,
                "nrs_count": 0,
                "max_score": 0,
            },
        )
        b["count"] += 1
        if item.get("possible_network_resource"):
            b["nrs_count"] += 1
        b["max_score"] = max(b["max_score"], int(item.get("url_score") or 0))
    rollup = sorted(buckets.values(), key=lambda x: (-x["max_score"], -x["count"]))
    return {"rollup": rollup[:limit], "disclaimer": us.DISCLAIMER}


@router.get("/rollups/category")
def url_sink_rollup_category(
    project_id: str,
    min_score: int = Query(us.DEFAULT_MIN_SCORE, ge=0, le=100),
    nrs_only: Optional[str] = Query("true"),
    limit: int = Query(50, ge=1, le=200),
):
    inv = us.project_inventory(
        project_id,
        min_score=min_score,
        nrs_only=_bool_param(nrs_only, True),
        sort="score_desc",
        limit=us.MAX_LIMIT,
        offset=0,
        include_iv=False,
    )
    buckets: dict[str, dict] = {}
    scores: dict[str, list[int]] = {}
    for item in inv["items"]:
        cat = item.get("name_category") or "(none)"
        b = buckets.setdefault(cat, {"key": cat, "count": 0, "max_score": 0})
        b["count"] += 1
        sc = int(item.get("url_score") or 0)
        b["max_score"] = max(b["max_score"], sc)
        scores.setdefault(cat, []).append(sc)
    for cat, b in buckets.items():
        arr = sorted(scores.get(cat) or [])
        if arr:
            mid = arr[len(arr) // 2]
            b["median_score"] = mid
        else:
            b["median_score"] = 0
    rollup = sorted(buckets.values(), key=lambda x: (-x["count"], -x["max_score"]))
    return {"rollup": rollup[:limit], "disclaimer": us.DISCLAIMER}
