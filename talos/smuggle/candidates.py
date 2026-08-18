"""
Module: talos.smuggle.candidates

Purpose:
    Select captured flows the operator asked to probe.

    Eligibility for an explicit --flow list:
        - Flow exists
        - In-scope (project Basic Scope + out-of-scope prefixes)
        - Endpoint is not logout / dangerous / excluded

    The operator always names the flow(s). Smuggling is a host-level
    parser check; any captured request on that origin is a usable baseline.

Dependencies: sqlite3, talos.projects.db, talos.projects.outscope,
              talos.proxy.scope
Data flow: CLI run → select_smuggle_candidates_for_flows
Side effects: migrate_project_db (read path).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from talos.projects.db import migrate_project_db
from talos.projects.outscope import list_prefixes as list_outscope
from talos.proxy.scope import is_url_in_scope


@dataclass(frozen=True)
class SmuggleCandidate:
    """
    Purpose:
        One captured flow the operator asked to probe.
    """

    flow_id: str
    endpoint_id: Optional[str]
    method: str
    url: str
    host: str
    path: str
    query: str
    status_code: int
    origin_key: str

    def to_dict(self) -> dict:
        """Purpose: JSON-ready candidate row."""
        return {
            "flow_id": self.flow_id,
            "endpoint_id": self.endpoint_id,
            "method": self.method,
            "url": self.url,
            "host": self.host,
            "path": self.path,
            "query": self.query,
            "status_code": self.status_code,
            "origin_key": self.origin_key,
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


def target_origin_key(url: str, fallback_host: str = "") -> str:
    """Purpose: scheme://netloc cluster key."""
    parsed = urlparse(url or "")
    scheme = (parsed.scheme or "https").lower()
    netloc = (parsed.netloc or parsed.hostname or fallback_host or "unknown").lower()
    return f"{scheme}://{netloc}"


def _is_policy_blocked(row: sqlite3.Row) -> bool:
    """Purpose: Skip logout / dangerous / excluded endpoints."""
    return bool(row["logout"] or row["dangerous"] or row["excluded"])


def _candidate_from_row(row: sqlite3.Row) -> SmuggleCandidate:
    """Purpose: Build a SmuggleCandidate from a flows join row."""
    url = row["url"] or ""
    host = row["host"] or ""
    return SmuggleCandidate(
        flow_id=row["flow_id"],
        endpoint_id=row["endpoint_id"],
        method=(row["method"] or "").upper() or "GET",
        url=url,
        host=host,
        path=row["path"] or "/",
        query=row["query"] or "",
        status_code=int(row["status_code"] or 0),
        origin_key=target_origin_key(url, host),
    )


_FLOW_SELECT = """
    SELECT f.id AS flow_id,
           f.method,
           f.url,
           f.host,
           f.path,
           f.query,
           f.status_code,
           f.request_headers,
           f.endpoint_id,
           ep.logout,
           ep.dangerous,
           ep.excluded
    FROM flows f
    LEFT JOIN endpoint_policy ep ON ep.endpoint_id = f.endpoint_id
"""


def select_smuggle_candidates_for_flows(
    db_path: Path,
    *,
    in_scope_prefixes: list[str],
    flow_ids: list[str],
) -> tuple[list[SmuggleCandidate], list[str]]:
    """
    Purpose:
        Build smuggle baselines from operator-picked flow UUIDs.
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
    candidates: list[SmuggleCandidate] = []
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
