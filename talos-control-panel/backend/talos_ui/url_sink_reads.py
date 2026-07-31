"""
Read-only URL Sink Discovery inventory helpers for the Control Panel.

Purpose:
    Parse parameters.url_features, filter/sort for inventory APIs, and load
    per-project effective url_sink knobs. No mutations. No process-level
    url_sink config cache (K20).

Dependencies: talos_ui.db/config; talos.input_validation.db.make_param_uuid;
              talos.url_sink.config.load_url_sink_config_for_project
Data flow: SQLite parameters (+ endpoints) → Python parse/filter → API rows
Side effects: None (read-only).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Optional

from . import config, db

DISCLAIMER = (
    "Passive local analysis of captured parameter values and names — no extra HTTP. "
    "Scores and categories are prioritization intelligence only; not confirmed "
    "vulnerabilities and not Findings."
)

PRIORITIZATION_NOTE = (
    "Prioritization intelligence only — not confirmed SSRF, open redirect, or Findings."
)

URL_FAMILY_ATTACKS = frozenset(
    {"ssrf", "open_redirect", "webhook_abuse", "oauth_redirect"}
)

DEFAULT_MIN_SCORE = 45
DEFAULT_NRS_ONLY = True
DEFAULT_SORT = "score_desc"
DEFAULT_LIMIT = 200
MAX_LIMIT = 1000
# Hard cap when building has_iv_* / url_sink_obs uuid sets (K14 / PR5).
IV_UUID_INDEX_CAP = 5000


def _ensure_talos_on_path() -> None:
    root = str(config.TALOS_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def make_param_uuid(host: str, location: str, name: str) -> str:
    _ensure_talos_on_path()
    from talos.input_validation.db import make_param_uuid as _core

    return _core(host or "", location or "", name or "")


def load_project_url_sink_config(project_id: str, record: dict | None = None):
    """
    Per-project effective url_sink knobs (K20).

    Never uses get_process_url_sink_config / ensure_process_url_sink_config.
    """
    _ensure_talos_on_path()
    from talos.url_sink.config import load_url_sink_config_for_project

    if record is None:
        record = db.get_project_record(project_id)
    data_dir = config.project_data_dir(project_id, record)
    return load_url_sink_config_for_project(data_dir)


def parse_url_features(raw: Any) -> dict[str, Any]:
    uf = db.safe_json(raw, {})
    return uf if isinstance(uf, dict) else {}


def inventory_only(location: str | None, name: str | None) -> bool:
    return (location or "") == "response" or str(name or "").startswith("jwt.")


def _int_score(uf: dict[str, Any]) -> int:
    try:
        return int(uf.get("score") or 0)
    except (TypeError, ValueError):
        return 0


def _name_categories(uf: dict[str, Any]) -> list[str]:
    cats: list[str] = []
    primary = uf.get("name_category")
    if isinstance(primary, str) and primary:
        cats.append(primary)
    raw = uf.get("name_categories") or []
    if isinstance(raw, list):
        for c in raw:
            if isinstance(c, str) and c and c not in cats:
                cats.append(c)
    return cats


def _looks_like_list(uf: dict[str, Any]) -> list[str]:
    raw = uf.get("looks_like") or []
    if not isinstance(raw, list):
        return []
    return [str(x) for x in raw if x is not None]


def row_to_sink(
    p: dict[str, Any],
    *,
    host: str,
    method: str = "",
    normalized_path: str = "",
) -> dict[str, Any]:
    """Build a SinkRow (default without iv block)."""
    uf = parse_url_features(p.get("url_features"))
    name = p.get("name") or ""
    location = p.get("location") or ""
    host_raw = host or ""
    score = _int_score(uf)
    cats = _name_categories(uf)
    examples = db.safe_json(p.get("example_values"), [])
    if not isinstance(examples, list):
        examples = []
    return {
        "parameter_id": p.get("id"),
        "param_uuid": make_param_uuid(host_raw, location, name),
        "endpoint_id": p.get("endpoint_id"),
        "name": name,
        "location": location,
        "param_type": p.get("param_type"),
        "semantic_type": p.get("semantic_type"),
        "host": host_raw,
        "method": method,
        "normalized_path": normalized_path,
        "seen_count": p.get("seen_count") or 0,
        "example_values": examples[:8],
        "url_features": uf,
        "url_score": score,
        "possible_network_resource": bool(uf.get("possible_network_resource")),
        "name_category": uf.get("name_category") or (cats[0] if cats else None),
        "name_categories": cats,
        "looks_like": _looks_like_list(uf),
        "inventory_only": inventory_only(location, name),
    }


def _matches_filters(
    row: dict[str, Any],
    *,
    min_score: int,
    nrs_only: bool,
    category: str | None,
    looks_like: str | None,
    location: str | None,
    host: str | None,
    endpoint_id: str | None,
    search: str | None,
    has_iv_profile: bool | None = None,
    has_url_sink_obs: bool | None = None,
    profile_uuids: set[str] | None = None,
    url_sink_obs_uuids: set[str] | None = None,
) -> bool:
    if row["url_score"] < min_score:
        return False
    if nrs_only and not row["possible_network_resource"]:
        return False
    if category:
        cats = set(row.get("name_categories") or [])
        primary = row.get("name_category")
        if primary:
            cats.add(primary)
        if category not in cats:
            return False
    if looks_like:
        if looks_like not in (row.get("looks_like") or []):
            return False
    if location and str(row.get("location") or "") != location:
        return False
    if endpoint_id and str(row.get("endpoint_id") or "") != endpoint_id:
        return False
    if host:
        h = str(row.get("host") or "").lower()
        if host.lower() not in h:
            return False
    if search:
        q = search.lower().strip()
        blob = " ".join(
            str(row.get(k) or "")
            for k in ("name", "normalized_path", "host", "location")
        ).lower()
        if q not in blob:
            return False
    uid = str(row.get("param_uuid") or "")
    if has_iv_profile is not None:
        in_set = bool(uid and profile_uuids is not None and uid in profile_uuids)
        if has_iv_profile and not in_set:
            return False
        if not has_iv_profile and in_set:
            return False
    if has_url_sink_obs is not None:
        in_obs = bool(
            uid and url_sink_obs_uuids is not None and uid in url_sink_obs_uuids
        )
        if has_url_sink_obs and not in_obs:
            return False
        if not has_url_sink_obs and in_obs:
            return False
    return True


def _sort_key(sort: str):
    if sort == "score_asc":
        return lambda r: (r["url_score"], r.get("name") or "")
    if sort == "name":
        return lambda r: (str(r.get("name") or "").lower(), -r["url_score"])
    if sort == "host":
        return lambda r: (str(r.get("host") or "").lower(), -r["url_score"])
    # score_desc default
    return lambda r: (-r["url_score"], str(r.get("name") or "").lower())


def load_parameter_rows(db_path: Path) -> list[dict[str, Any]]:
    """
    Load parameters JOIN endpoints. Returns raw SQL dicts with host/method/path.
    """
    if not db.db_exists(db_path):
        return []
    try:
        return db.query_all(
            db_path,
            """
            SELECT p.id, p.endpoint_id, p.name, p.location, p.param_type,
                   p.semantic_type, p.example_values, p.seen_count, p.url_features,
                   e.host, e.method, e.normalized_path
            FROM parameters p
            JOIN endpoints e ON e.id = p.endpoint_id
            """,
        )
    except Exception:
        # Older DB without url_features column
        try:
            return db.query_all(
                db_path,
                """
                SELECT p.id, p.endpoint_id, p.name, p.location, p.param_type,
                       p.semantic_type, p.example_values, p.seen_count,
                       e.host, e.method, e.normalized_path
                FROM parameters p
                JOIN endpoints e ON e.id = p.endpoint_id
                """,
            )
        except Exception:
            return []


def build_sink_rows(raw_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for p in raw_rows:
        out.append(
            row_to_sink(
                p,
                host=p.get("host") or "",
                method=p.get("method") or "",
                normalized_path=p.get("normalized_path") or "",
            )
        )
    return out


def filter_inventory(
    rows: list[dict[str, Any]],
    *,
    min_score: int = DEFAULT_MIN_SCORE,
    nrs_only: bool = DEFAULT_NRS_ONLY,
    category: str | None = None,
    looks_like: str | None = None,
    location: str | None = None,
    host: str | None = None,
    endpoint_id: str | None = None,
    search: str | None = None,
    has_iv_profile: bool | None = None,
    has_url_sink_obs: bool | None = None,
    profile_uuids: set[str] | None = None,
    url_sink_obs_uuids: set[str] | None = None,
    sort: str = DEFAULT_SORT,
    limit: int | None = DEFAULT_LIMIT,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], int]:
    """
    Filter + sort sink rows.

    When ``limit`` is None, return the full matched set (used by rollups /
    by-endpoint aggregates so counts are not truncated by MAX_LIMIT pages).
    """
    matched = [
        r
        for r in rows
        if _matches_filters(
            r,
            min_score=min_score,
            nrs_only=nrs_only,
            category=category,
            looks_like=looks_like,
            location=location,
            host=host,
            endpoint_id=endpoint_id,
            search=search,
            has_iv_profile=has_iv_profile,
            has_url_sink_obs=has_url_sink_obs,
            profile_uuids=profile_uuids,
            url_sink_obs_uuids=url_sink_obs_uuids,
        )
    ]
    matched.sort(key=_sort_key(sort or DEFAULT_SORT))
    total = len(matched)
    offset = max(0, int(offset or 0))
    if limit is None:
        return matched[offset:], total
    lim = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    return matched[offset : offset + lim], total


def load_iv_uuid_index(
    db_path: Path,
    *,
    hard_cap: int = IV_UUID_INDEX_CAP,
) -> dict[str, Any]:
    """
    One-shot capped load of param_uuid sets from iv_param_profiles (PR5).

    Used only when has_iv_profile / has_url_sink_obs filters are requested.
    Does not run on the default inventory/status hot path (K14).
    """
    empty: dict[str, Any] = {
        "profile_uuids": set(),
        "url_sink_obs_uuids": set(),
        "scanned": 0,
        "capped": False,
        "cap": hard_cap,
    }
    if not db.db_exists(db_path):
        return empty
    try:
        rows = db.query_all(
            db_path,
            f"""
            SELECT param_uuid, profile FROM iv_param_profiles
            LIMIT {int(hard_cap) + 1}
            """,
        )
    except Exception:
        return empty
    capped = len(rows) > hard_cap
    if capped:
        rows = rows[:hard_cap]
    profile_uuids: set[str] = set()
    url_sink_obs: set[str] = set()
    for pr in rows:
        uid = str(pr.get("param_uuid") or "")
        if not uid:
            continue
        profile_uuids.add(uid)
        prof = db.safe_json(pr.get("profile"), {})
        if not isinstance(prof, dict):
            continue
        observed = (
            prof.get("observed") if isinstance(prof.get("observed"), dict) else {}
        )
        url_sink = (
            observed.get("url_sink")
            if isinstance(observed.get("url_sink"), dict)
            else {}
        )
        try:
            conf = int(url_sink.get("confidence") or 0)
        except (TypeError, ValueError):
            conf = 0
        if conf > 0:
            url_sink_obs.add(uid)
    return {
        "profile_uuids": profile_uuids,
        "url_sink_obs_uuids": url_sink_obs,
        "scanned": len(rows),
        "capped": capped,
        "cap": hard_cap,
    }


def compute_status_aggregates(
    rows: list[dict[str, Any]],
    *,
    score_threshold: int = DEFAULT_MIN_SCORE,
) -> dict[str, Any]:
    total_params = len(rows)
    with_uf = 0
    nrs_count = 0
    score_ge_threshold = 0
    score_ge_70 = 0
    by_category: dict[str, int] = {}
    by_looks_like: dict[str, int] = {}
    by_location: dict[str, int] = {}

    for r in rows:
        uf = r.get("url_features") or {}
        score = int(r.get("url_score") or 0)
        if uf and (score > 0 or r.get("possible_network_resource") or uf.get("evidence")):
            with_uf += 1
        elif uf and any(uf.get(k) for k in ("looks_like", "name_category", "protocols_seen")):
            with_uf += 1
        if r.get("possible_network_resource"):
            nrs_count += 1
        if score >= score_threshold:
            score_ge_threshold += 1
        if score >= 70:
            score_ge_70 += 1
        cat = r.get("name_category")
        if cat:
            by_category[str(cat)] = by_category.get(str(cat), 0) + 1
        for ll in r.get("looks_like") or []:
            by_looks_like[str(ll)] = by_looks_like.get(str(ll), 0) + 1
        loc = r.get("location") or "unknown"
        by_location[str(loc)] = by_location.get(str(loc), 0) + 1

    return {
        "total_params": total_params,
        "with_url_features": with_uf,
        "nrs_count": nrs_count,
        "score_ge_threshold": score_ge_threshold,
        "score_ge_70": score_ge_70,
        "by_category": by_category,
        "by_looks_like": by_looks_like,
        "by_location": by_location,
    }


def attach_iv_slice(
    db_path: Path,
    page_rows: list[dict[str, Any]],
) -> None:
    """
    Attach slim iv block for the current page only (bounded IN query).
    Mutates page_rows in place.
    """
    if not page_rows or not db.db_exists(db_path):
        return
    uuids = [r["param_uuid"] for r in page_rows if r.get("param_uuid")]
    if not uuids:
        return
    # Cap to page size
    uuids = uuids[:MAX_LIMIT]
    placeholders = ",".join("?" * len(uuids))
    try:
        profiles = db.query_all(
            db_path,
            f"""
            SELECT param_uuid, profile FROM iv_param_profiles
            WHERE param_uuid IN ({placeholders})
            """,
            tuple(uuids),
        )
    except Exception:
        return
    by_uuid: dict[str, dict[str, Any]] = {}
    for pr in profiles:
        uid = pr.get("param_uuid")
        prof = db.safe_json(pr.get("profile"), {})
        if not isinstance(prof, dict):
            prof = {}
        by_uuid[str(uid)] = prof

    for row in page_rows:
        uid = row.get("param_uuid")
        prof = by_uuid.get(str(uid)) if uid else None
        if not prof:
            row["iv"] = {
                "has_profile": False,
                "capabilities": [],
                "url_sink_confidence": None,
                "top_url_candidate": None,
            }
            continue
        caps = prof.get("capabilities") or []
        if not isinstance(caps, list):
            caps = []
        observed = prof.get("observed") if isinstance(prof.get("observed"), dict) else {}
        url_sink = (
            observed.get("url_sink")
            if isinstance(observed.get("url_sink"), dict)
            else {}
        )
        try:
            conf = int(url_sink.get("confidence") or 0)
        except (TypeError, ValueError):
            conf = 0
        top_url = None
        best_score = -1
        for c in prof.get("candidates") or []:
            if not isinstance(c, dict):
                continue
            atk = c.get("attack")
            if atk not in URL_FAMILY_ATTACKS:
                continue
            try:
                sc = int(c.get("score") or 0)
            except (TypeError, ValueError):
                sc = 0
            if sc > best_score:
                best_score = sc
                top_url = {
                    "attack": atk,
                    "score": sc,
                    "confidence": c.get("confidence"),
                }
        row["iv"] = {
            "has_profile": True,
            "capabilities": [str(c) for c in caps if c],
            "url_sink_confidence": conf if conf > 0 else None,
            "top_url_candidate": top_url,
        }


def count_iv_characterized(
    db_path: Path,
    nrs_uuids: set[str],
    *,
    hard_cap: int = 5000,
) -> Optional[int]:
    """Optional expensive path: profiles with observed.url_sink.confidence > 0."""
    if not db.db_exists(db_path) or not nrs_uuids:
        return 0
    try:
        rows = db.query_all(
            db_path,
            f"""
            SELECT param_uuid, profile FROM iv_param_profiles
            LIMIT {int(hard_cap)}
            """,
        )
    except Exception:
        return None
    count = 0
    for pr in rows:
        uid = str(pr.get("param_uuid") or "")
        if uid not in nrs_uuids:
            continue
        prof = db.safe_json(pr.get("profile"), {})
        if not isinstance(prof, dict):
            continue
        observed = prof.get("observed") if isinstance(prof.get("observed"), dict) else {}
        url_sink = (
            observed.get("url_sink")
            if isinstance(observed.get("url_sink"), dict)
            else {}
        )
        try:
            conf = int(url_sink.get("confidence") or 0)
        except (TypeError, ValueError):
            conf = 0
        if conf > 0:
            count += 1
    return count


def project_status(
    project_id: str,
    *,
    include_iv_stats: bool = False,
) -> dict[str, Any]:
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    cfg = load_project_url_sink_config(project_id, record)
    raw = load_parameter_rows(db_path)
    rows = build_sink_rows(raw)
    thr = int(cfg.score_threshold)
    agg = compute_status_aggregates(rows, score_threshold=thr)

    iv_count = None
    if include_iv_stats:
        nrs_uuids = {
            r["param_uuid"]
            for r in rows
            if r.get("possible_network_resource") and r.get("param_uuid")
        }
        iv_count = count_iv_characterized(db_path, nrs_uuids)

    return {
        "enabled_passive": bool(cfg.passive_enabled),
        "enabled_html_js": bool(cfg.html_js_enabled),
        "enabled_iv_probes": bool(cfg.iv_probes_enabled),
        "score_threshold": thr,
        **agg,
        "iv_characterized_count": iv_count,
        "disclaimer": DISCLAIMER,
    }


def project_inventory(
    project_id: str,
    *,
    min_score: int = DEFAULT_MIN_SCORE,
    nrs_only: bool = DEFAULT_NRS_ONLY,
    category: str | None = None,
    looks_like: str | None = None,
    location: str | None = None,
    host: str | None = None,
    endpoint_id: str | None = None,
    search: str | None = None,
    has_iv_profile: bool | None = None,
    has_url_sink_obs: bool | None = None,
    sort: str = DEFAULT_SORT,
    limit: int = DEFAULT_LIMIT,
    offset: int = 0,
    include_iv: bool = False,
) -> dict[str, Any]:
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    raw = load_parameter_rows(db_path)
    all_rows = build_sink_rows(raw)

    iv_index: dict[str, Any] | None = None
    profile_uuids: set[str] | None = None
    url_sink_obs_uuids: set[str] | None = None
    if has_iv_profile is not None or has_url_sink_obs is not None:
        iv_index = load_iv_uuid_index(db_path)
        profile_uuids = iv_index["profile_uuids"]
        url_sink_obs_uuids = iv_index["url_sink_obs_uuids"]

    page, total = filter_inventory(
        all_rows,
        min_score=min_score,
        nrs_only=nrs_only,
        category=category,
        looks_like=looks_like,
        location=location,
        host=host,
        endpoint_id=endpoint_id,
        search=search,
        has_iv_profile=has_iv_profile,
        has_url_sink_obs=has_url_sink_obs,
        profile_uuids=profile_uuids,
        url_sink_obs_uuids=url_sink_obs_uuids,
        sort=sort,
        limit=limit,
        offset=offset,
    )
    if include_iv:
        attach_iv_slice(db_path, page)

    note = PRIORITIZATION_NOTE
    if iv_index and iv_index.get("capped"):
        note = (
            f"{PRIORITIZATION_NOTE} "
            f"has_iv_* filters used a capped profile index "
            f"({iv_index.get('cap')} rows scanned)."
        )

    return {
        "items": page,
        "count": len(page),
        "total_matched": total,
        "filters_applied": {
            "min_score": min_score,
            "nrs_only": nrs_only,
            "category": category,
            "looks_like": looks_like,
            "location": location,
            "host": host,
            "endpoint_id": endpoint_id,
            "search": search,
            "has_iv_profile": has_iv_profile,
            "has_url_sink_obs": has_url_sink_obs,
            "sort": sort,
            "limit": limit,
            "offset": offset,
            "include_iv": include_iv,
        },
        "iv_index": (
            {
                "scanned": iv_index.get("scanned"),
                "capped": iv_index.get("capped"),
                "cap": iv_index.get("cap"),
            }
            if iv_index
            else None
        ),
        "note": note,
        "disclaimer": DISCLAIMER,
    }


def matching_sink_rows(
    project_id: str,
    *,
    min_score: int = DEFAULT_MIN_SCORE,
    nrs_only: bool = DEFAULT_NRS_ONLY,
    category: str | None = None,
    looks_like: str | None = None,
    location: str | None = None,
    host: str | None = None,
    endpoint_id: str | None = None,
    search: str | None = None,
) -> list[dict[str, Any]]:
    """All matching sink rows (no pagination) for rollups / endpoint strips."""
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    raw = load_parameter_rows(db_path)
    all_rows = build_sink_rows(raw)
    matched, _ = filter_inventory(
        all_rows,
        min_score=min_score,
        nrs_only=nrs_only,
        category=category,
        looks_like=looks_like,
        location=location,
        host=host,
        endpoint_id=endpoint_id,
        search=search,
        sort=DEFAULT_SORT,
        limit=None,
        offset=0,
    )
    return matched


def project_overview(project_id: str, *, top_n: int = 10) -> dict[str, Any]:
    status = project_status(project_id, include_iv_stats=False)
    inv = project_inventory(
        project_id,
        min_score=0,
        nrs_only=False,
        sort="score_desc",
        limit=max(1, min(top_n, 50)),
        offset=0,
        include_iv=False,
    )
    # Prefer NRS top for default empty_state sense
    nrs_inv = project_inventory(
        project_id,
        min_score=int(status.get("score_threshold") or DEFAULT_MIN_SCORE),
        nrs_only=True,
        sort="score_desc",
        limit=max(1, min(top_n, 50)),
        offset=0,
        include_iv=False,
    )
    top = nrs_inv["items"] if nrs_inv["total_matched"] else inv["items"][:top_n]
    empty = {
        "no_params": status.get("total_params", 0) == 0,
        "no_nrs": status.get("nrs_count", 0) == 0,
        "passive_disabled": status.get("enabled_passive") is False,
    }
    return {
        "status": status,
        "top_sinks": top,
        "empty_state": empty,
        "disclaimer": DISCLAIMER,
    }


def by_endpoint(project_id: str, endpoint_id: str, *, limit: int = 20) -> dict[str, Any]:
    """
    Endpoint strip: aggregate counts over **all** endpoint params, return top items.
    """
    matched = matching_sink_rows(
        project_id,
        min_score=0,
        nrs_only=False,
        endpoint_id=endpoint_id,
    )
    # matching_sink_rows already score_desc sorted
    nrs_count = sum(1 for r in matched if r.get("possible_network_resource"))
    max_score = max((int(r.get("url_score") or 0) for r in matched), default=0)
    lim = max(1, min(int(limit or 20), 100))
    return {
        "endpoint_id": endpoint_id,
        "count": len(matched),
        "nrs_count": nrs_count,
        "max_score": max_score,
        "items": matched[:lim],
        "disclaimer": DISCLAIMER,
    }


def rollup_by_host(
    project_id: str,
    *,
    min_score: int = DEFAULT_MIN_SCORE,
    nrs_only: bool = DEFAULT_NRS_ONLY,
    limit: int = 50,
) -> dict[str, Any]:
    matched = matching_sink_rows(
        project_id, min_score=min_score, nrs_only=nrs_only
    )
    buckets: dict[str, dict[str, Any]] = {}
    for item in matched:
        key = item.get("host") or ""
        b = buckets.setdefault(
            key,
            {
                "key": key,
                "count": 0,
                "nrs_count": 0,
                "max_score": 0,
                "categories": {},
            },
        )
        b["count"] += 1
        if item.get("possible_network_resource"):
            b["nrs_count"] += 1
        b["max_score"] = max(b["max_score"], int(item.get("url_score") or 0))
        cat = item.get("name_category")
        if cat:
            cats = b["categories"]
            cats[cat] = cats.get(cat, 0) + 1
    # Promote top categories list for UI convenience
    for b in buckets.values():
        cats = b.get("categories") or {}
        top = sorted(cats.items(), key=lambda x: (-x[1], x[0]))[:5]
        b["top_categories"] = [c for c, _ in top]
    rollup = sorted(buckets.values(), key=lambda x: (-x["max_score"], -x["count"]))
    lim = max(1, min(int(limit or 50), 200))
    return {"rollup": rollup[:lim], "total_buckets": len(rollup), "disclaimer": DISCLAIMER}


def rollup_by_endpoint(
    project_id: str,
    *,
    min_score: int = DEFAULT_MIN_SCORE,
    nrs_only: bool = DEFAULT_NRS_ONLY,
    limit: int = 50,
) -> dict[str, Any]:
    matched = matching_sink_rows(
        project_id, min_score=min_score, nrs_only=nrs_only
    )
    buckets: dict[str, dict[str, Any]] = {}
    for item in matched:
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
    lim = max(1, min(int(limit or 50), 200))
    return {"rollup": rollup[:lim], "total_buckets": len(rollup), "disclaimer": DISCLAIMER}


def rollup_by_category(
    project_id: str,
    *,
    min_score: int = DEFAULT_MIN_SCORE,
    nrs_only: bool = DEFAULT_NRS_ONLY,
    limit: int = 50,
) -> dict[str, Any]:
    matched = matching_sink_rows(
        project_id, min_score=min_score, nrs_only=nrs_only
    )
    buckets: dict[str, dict[str, Any]] = {}
    scores: dict[str, list[int]] = {}
    for item in matched:
        cat = item.get("name_category") or "(none)"
        b = buckets.setdefault(cat, {"key": cat, "count": 0, "max_score": 0})
        b["count"] += 1
        sc = int(item.get("url_score") or 0)
        b["max_score"] = max(b["max_score"], sc)
        scores.setdefault(cat, []).append(sc)
    for cat, b in buckets.items():
        arr = sorted(scores.get(cat) or [])
        b["median_score"] = arr[len(arr) // 2] if arr else 0
    rollup = sorted(buckets.values(), key=lambda x: (-x["count"], -x["max_score"]))
    lim = max(1, min(int(limit or 50), 200))
    return {"rollup": rollup[:lim], "total_buckets": len(rollup), "disclaimer": DISCLAIMER}


def param_detail(
    project_id: str,
    *,
    parameter_id: str | None = None,
    param_uuid: str | None = None,
) -> dict[str, Any] | None:
    record = db.get_project_record(project_id)
    db_path = config.project_db_path(project_id, record)
    raw = load_parameter_rows(db_path)
    rows = build_sink_rows(raw)
    found = None
    for r in rows:
        if parameter_id and str(r.get("parameter_id")) == parameter_id:
            found = r
            break
        if param_uuid and str(r.get("param_uuid")) == param_uuid:
            found = r
            break
    if found is None:
        return None
    attach_iv_slice(db_path, [found])
    return {
        "item": found,
        "disclaimer": DISCLAIMER,
        "note": PRIORITIZATION_NOTE,
    }
