"""
Module: talos.cors.candidates

Purpose:
    Select CORS probe baselines from captured traffic.

    Eligibility:
        - In-scope (project Basic Scope + out-of-scope prefixes).
        - HTTP 200 on a proxy_capture flow.
        - Method preference: POST, then PATCH, then PUT, then GET.
        - Prefer a captured Origin header; otherwise synthesize later.
        - Skip logout / dangerous / excluded endpoints.
        - One candidate per endpoint (best-scoring 200 flow).
        - Default cap is 5: CORS is an origin-policy check, not an
          endpoint-wide sweep. Ranked baselines first, then techniques.

    Same inclusion spirit as other attack modules (endpoint policy
    exclusions) plus the CORS-specific 200 + method ranking.

Dependencies: sqlite3, talos.projects.db, talos.projects.outscope,
              talos.proxy.scope, talos.cors.payloads
Data flow: CLI run / candidates → select_cors_candidates → job enqueue
Side effects: migrate_project_db (read path).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from talos.cors.payloads import (
    request_origin_from_url,
    resolve_baseline_origin,
    target_origin_key,
)
from talos.projects.db import migrate_project_db
from talos.projects.outscope import list_prefixes as list_outscope
from talos.proxy.scope import is_url_in_scope


METHOD_RANK: dict[str, int] = {
    "POST": 0,
    "PATCH": 1,
    "PUT": 2,
    "GET": 3,
}

_ALLOWED_METHODS = frozenset(METHOD_RANK)

DEFAULT_CANDIDATE_LIMIT = 5
"""Max distinct endpoints a default CORS run probes."""


@dataclass(frozen=True)
class CorsCandidate:
    """
    Purpose:
        One baseline flow chosen for CORS probing.

    Fields:
        flow_id            — captured flow UUID (never mutated).
        endpoint_id        — endpoint UUID if normalized.
        method / url / host / path — request identity.
        status_code        — must be 200.
        baseline_origin    — Origin to seed payloads from.
        origin_was_present — True when the capture already had Origin.
        origin_key         — cluster key (scheme://netloc).
        has_origin_header  — same as origin_was_present (UI alias).
    """

    flow_id: str
    endpoint_id: Optional[str]
    method: str
    url: str
    host: str
    path: str
    status_code: int
    baseline_origin: str
    origin_was_present: bool
    origin_key: str

    @property
    def has_origin_header(self) -> bool:
        """Purpose: UI/CLI alias for origin_was_present."""
        return self.origin_was_present

    def to_dict(self) -> dict:
        """Purpose: JSON-ready candidate row."""
        return {
            "flow_id": self.flow_id,
            "endpoint_id": self.endpoint_id,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "status_code": self.status_code,
            "baseline_origin": self.baseline_origin,
            "origin_was_present": self.origin_was_present,
            "origin_key": self.origin_key,
        }


def _score(method: str, has_origin: bool) -> tuple[int, int]:
    """
    Purpose:
        Rank a 200 OK flow: method family first, then Origin presence.
    Output:
        Sort tuple (lower is better).
    """
    method_rank = METHOD_RANK.get(method.upper(), 99)
    origin_rank = 0 if has_origin else 1
    return (method_rank, origin_rank)


def normalize_flow_ids(raw: object) -> list[str]:
    """
    Purpose:
        Flatten --flow values (repeatable and/or comma-separated).
    Input:
        raw — None, a string, or a sequence of strings.
    Output:
        Deduped flow UUIDs in operator order.
    """
    if raw is None:
        return []
    if isinstance(raw, str):
        items = [raw]
    elif isinstance(raw, (list, tuple, set)):
        items = [str(item) for item in raw]
    else:
        items = [str(raw)]
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        for part in item.split(","):
            fid = part.strip()
            if fid and fid not in seen:
                seen.add(fid)
                out.append(fid)
    return out


def _is_policy_blocked(row: sqlite3.Row) -> bool:
    """Purpose: Skip logout / dangerous / excluded endpoints."""
    return bool(row["logout"] or row["dangerous"] or row["excluded"])


def _candidate_from_row(row: sqlite3.Row) -> CorsCandidate:
    """Purpose: Build a CorsCandidate from a flows join row."""
    url = row["url"] or ""
    method = (row["method"] or "").upper() or "GET"
    baseline, present = resolve_baseline_origin(url, row["request_headers"])
    if not present:
        baseline = baseline or request_origin_from_url(url)
    return CorsCandidate(
        flow_id=row["flow_id"],
        endpoint_id=row["endpoint_id"],
        method=method,
        url=url,
        host=row["host"] or "",
        path=row["path"] or "/",
        status_code=int(row["status_code"] or 0),
        baseline_origin=baseline,
        origin_was_present=present,
        origin_key=target_origin_key(url),
    )


_FLOW_SELECT = """
    SELECT f.id AS flow_id,
           f.method,
           f.url,
           f.host,
           f.path,
           f.status_code,
           f.request_headers,
           f.endpoint_id,
           f.captured_at,
           ep.logout,
           ep.dangerous,
           ep.excluded
    FROM flows f
    LEFT JOIN endpoint_policy ep ON ep.endpoint_id = f.endpoint_id
"""


def select_cors_candidates_for_flows(
    db_path: Path,
    *,
    in_scope_prefixes: list[str],
    flow_ids: list[str],
) -> tuple[list[CorsCandidate], list[str]]:
    """
    Purpose:
        Build CORS baselines from operator-picked flow UUIDs.
        No ranking, 200-OK filter, method filter, or 5-cap.
    Input:
        db_path            — project talos.db.
        in_scope_prefixes  — project.scope entries.
        flow_ids           — captured flow UUIDs (order preserved).
    Output:
        (usable candidates, unknown flow ids). Logout / dangerous /
        excluded / out-of-scope flows are omitted, not listed as missing.
    Side effects: migrate_project_db.
    """
    wanted = normalize_flow_ids(flow_ids)
    if not wanted:
        return [], []
    migrate_project_db(db_path)
    if not db_path.exists():
        return [], wanted

    out_prefixes = [row["prefix"] for row in list_outscope(db_path)]
    placeholders = ",".join("?" for _ in wanted)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"{_FLOW_SELECT} WHERE f.id IN ({placeholders})",
            tuple(wanted),
        ).fetchall()

    found = {row["flow_id"]: row for row in rows}
    missing = [fid for fid in wanted if fid not in found]
    candidates: list[CorsCandidate] = []
    for fid in wanted:
        row = found.get(fid)
        if row is None:
            continue
        if _is_policy_blocked(row):
            continue
        url = row["url"] or ""
        if not is_url_in_scope(url, in_scope_prefixes, out_prefixes):
            continue
        candidates.append(_candidate_from_row(row))
    return candidates, missing


def select_cors_candidates(
    db_path: Path,
    *,
    in_scope_prefixes: list[str],
    limit: int = DEFAULT_CANDIDATE_LIMIT,
    endpoint_id: Optional[str] = None,
    host: Optional[str] = None,
) -> list[CorsCandidate]:
    """
    Purpose:
        Pick in-scope 200 OK baselines for CORS testing.
    Input:
        db_path            — project talos.db.
        in_scope_prefixes  — project.scope entries.
        limit              — max distinct endpoints (default 5; at least 1).
        endpoint_id        — optional single-endpoint filter.
        host               — optional host substring filter (captured host).
    Output:
        Ranked CorsCandidate list (best first), one per endpoint.
    Side effects: migrate_project_db.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return []

    out_prefixes = [row["prefix"] for row in list_outscope(db_path)]

    clauses = [
        "f.status_code = 200",
        "f.source = 'proxy_capture'",
        "UPPER(f.method) IN ('POST', 'PATCH', 'PUT', 'GET')",
        "(ep.endpoint_id IS NULL OR (ep.logout = 0 AND ep.dangerous = 0 AND ep.excluded = 0))",
    ]
    params: list[object] = []
    if endpoint_id:
        clauses.append("f.endpoint_id = ?")
        params.append(endpoint_id)
    if host:
        clauses.append("f.host LIKE ?")
        params.append(f"%{host}%")

    where = " AND ".join(clauses)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"{_FLOW_SELECT} WHERE {where} ORDER BY f.captured_at DESC",
            tuple(params),
        ).fetchall()

    best_by_key: dict[str, tuple[tuple[int, int], CorsCandidate]] = {}
    for row in rows:
        url = row["url"] or ""
        if not is_url_in_scope(url, in_scope_prefixes, out_prefixes):
            continue
        method = (row["method"] or "").upper()
        if method not in _ALLOWED_METHODS:
            continue
        candidate = _candidate_from_row(row)
        dedupe_key = candidate.endpoint_id or f"{method}|{candidate.origin_key}|{candidate.path}"
        score = _score(method, candidate.origin_was_present)
        previous = best_by_key.get(dedupe_key)
        if previous is None or score < previous[0]:
            best_by_key[dedupe_key] = (score, candidate)

    ranked = sorted(best_by_key.values(), key=lambda item: item[0])
    if limit is None:
        cap = DEFAULT_CANDIDATE_LIMIT
    else:
        cap = max(1, int(limit))
    return [item[1] for item in ranked[:cap]]
