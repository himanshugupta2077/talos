"""
Module: talos.host_header.candidates

Purpose:
    Select captured flows the operator asked to scan.

    Eligibility for an explicit --flow list:
        - Flow exists
        - In-scope (project Basic Scope + out-of-scope prefixes)
        - Endpoint is not logout / dangerous / excluded

    v1 does not auto-rank a project-wide candidate set — the operator
    always names the flow(s).

Dependencies: sqlite3, talos.projects.db, talos.projects.outscope,
              talos.proxy.scope, talos.host_header.inject
Data flow: CLI run → select_host_header_candidates_for_flows
Side effects: migrate_project_db (read path).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from talos.host_header.inject import extract_injection_points
from talos.host_header.models import InjectionPoint
from talos.projects.db import migrate_project_db
from talos.projects.flow_scope import resolve_flow_or_endpoint_ids
from talos.projects.outscope import list_prefixes as list_outscope
from talos.proxy.scope import is_url_in_scope


@dataclass(frozen=True)
class HostHeaderCandidate:
    """
    Purpose:
        One captured flow the operator asked to scan.
    """

    flow_id: str
    endpoint_id: Optional[str]
    method: str
    url: str
    host: str
    path: str
    status_code: int
    normalized_path: str
    points: tuple[InjectionPoint, ...]

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
            "normalized_path": self.normalized_path,
            "entry_points": [p.to_dict() for p in self.points],
            "entry_point_count": len(self.points),
        }


def normalize_flow_ids(raw: object) -> list[str]:
    """
    Purpose:
        Flatten --flow values (repeatable and/or comma-separated).
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


_FLOW_SELECT = """
    SELECT f.id AS flow_id,
           f.method,
           f.url,
           f.host,
           f.path,
           f.query,
           f.status_code,
           f.request_headers,
           f.request_body,
           f.endpoint_id,
           COALESCE(e.normalized_path, '') AS normalized_path,
           ep.logout,
           ep.dangerous,
           ep.excluded
    FROM flows f
    LEFT JOIN endpoints e ON e.id = f.endpoint_id
    LEFT JOIN endpoint_policy ep ON ep.endpoint_id = f.endpoint_id
"""


def _candidate_from_row(row: sqlite3.Row) -> HostHeaderCandidate:
    """Purpose: Build a candidate and extract host-header entry points."""
    url = row["url"] or ""
    normalized_path = row["normalized_path"] or ""
    points = extract_injection_points(
        url=url,
        query=row["query"] or "",
        request_headers=row["request_headers"],
        request_body=row["request_body"],
        normalized_path=normalized_path,
    )
    return HostHeaderCandidate(
        flow_id=row["flow_id"],
        endpoint_id=row["endpoint_id"],
        method=(row["method"] or "").upper() or "GET",
        url=url,
        host=row["host"] or "",
        path=row["path"] or "/",
        status_code=int(row["status_code"] or 0),
        normalized_path=normalized_path,
        points=tuple(points),
    )


def select_host_header_candidates_for_flows(
    db_path: Path,
    *,
    in_scope_prefixes: list[str],
    flow_ids: list[str],
) -> tuple[list[HostHeaderCandidate], list[str]]:
    """
    Purpose:
        Load operator-picked flows and drop blocked / out-of-scope ones.
    Output:
        (usable candidates, unknown flow ids). Logout / dangerous /
        excluded / out-of-scope flows are omitted, not listed as missing.
    """
    wanted, unknown = resolve_flow_or_endpoint_ids(db_path, flow_ids)
    if not wanted:
        return [], unknown
    migrate_project_db(db_path)
    if not db_path.exists():
        return [], unknown or list(wanted)

    out_prefixes = [row["prefix"] for row in list_outscope(db_path)]
    placeholders = ",".join("?" for _ in wanted)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"{_FLOW_SELECT} WHERE f.id IN ({placeholders})",
            tuple(wanted),
        ).fetchall()

    found = {row["flow_id"]: row for row in rows}
    missing = unknown + [fid for fid in wanted if fid not in found]
    candidates: list[HostHeaderCandidate] = []
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
