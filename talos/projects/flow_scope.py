"""
Module: talos.projects.flow_scope

Purpose:
    Shared helpers for operator-selected flow UUIDs and ranked test
    baselines on endpoints.

    Used by attack CLIs (`--flow`, repeatable) and the Control Panel
    endpoint multi-select launcher (top N 2xx proxy_capture flows
    per endpoint).

Dependencies: sqlite3, pathlib, talos.projects.db
Data flow: CLI / CP → normalize_flow_ids / lookup_flows /
           select_test_flows_for_endpoints → job enqueue
Side effects: migrate_project_db on lookup / select (read path).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from talos.projects.db import migrate_project_db

DEFAULT_TEST_FLOWS_PER_ENDPOINT = 5
"""Max ranked test flows picked per selected endpoint."""

METHOD_RANK: dict[str, int] = {
    "POST": 0,
    "PATCH": 1,
    "PUT": 2,
    "GET": 3,
}


@dataclass(frozen=True)
class FlowRef:
    """
    Purpose:
        Lightweight flow identity for attack scoping.
    Fields:
        flow_id / endpoint_id / method / host / path / status_code /
        source / captured_at — from the flows row.
        logout / dangerous / excluded — endpoint_policy flags (0 if none).
        baseline_flow_id — policy baseline for this endpoint, if any.
    """

    flow_id: str
    endpoint_id: Optional[str]
    method: str
    host: str
    path: str
    status_code: int
    source: str
    captured_at: str
    logout: int = 0
    dangerous: int = 0
    excluded: int = 0
    baseline_flow_id: Optional[str] = None

    @property
    def policy_blocked(self) -> bool:
        """Purpose: Skip logout / dangerous / excluded endpoints."""
        return bool(self.logout or self.dangerous or self.excluded)

    def to_dict(self) -> dict:
        """Purpose: JSON-ready row for Control Panel."""
        return {
            "flow_id": self.flow_id,
            "endpoint_id": self.endpoint_id,
            "method": self.method,
            "host": self.host,
            "path": self.path,
            "status_code": self.status_code,
            "source": self.source,
            "captured_at": self.captured_at,
            "baseline": bool(
                self.baseline_flow_id and self.flow_id == self.baseline_flow_id
            ),
        }


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


def _row_to_ref(row: sqlite3.Row) -> FlowRef:
    """Purpose: Map a flows ⨝ endpoint_policy row to FlowRef."""
    return FlowRef(
        flow_id=row["flow_id"],
        endpoint_id=row["endpoint_id"],
        method=(row["method"] or "").upper() or "GET",
        host=row["host"] or "",
        path=row["path"] or "/",
        status_code=int(row["status_code"] or 0),
        source=row["source"] or "",
        captured_at=row["captured_at"] or "",
        logout=int(row["logout"] or 0),
        dangerous=int(row["dangerous"] or 0),
        excluded=int(row["excluded"] or 0),
        baseline_flow_id=row["baseline_flow_id"],
    )


_FLOW_SELECT = """
    SELECT f.id AS flow_id,
           f.endpoint_id,
           f.method,
           f.host,
           f.path,
           f.status_code,
           f.source,
           f.captured_at,
           COALESCE(ep.logout, 0) AS logout,
           COALESCE(ep.dangerous, 0) AS dangerous,
           COALESCE(ep.excluded, 0) AS excluded,
           ep.baseline_flow_id AS baseline_flow_id
    FROM flows f
    LEFT JOIN endpoint_policy ep ON ep.endpoint_id = f.endpoint_id
"""


def lookup_flows(
    db_path: Path,
    flow_ids: list[str],
) -> tuple[list[FlowRef], list[str]]:
    """
    Purpose:
        Load operator-picked flow UUIDs in the given order.
    Input:
        db_path  — project talos.db.
        flow_ids — already-normalized UUIDs.
    Output:
        (found refs in operator order, unknown ids).
    Side effects: migrate_project_db.
    """
    wanted = normalize_flow_ids(flow_ids)
    if not wanted:
        return [], []
    migrate_project_db(db_path)
    if not db_path.exists():
        return [], list(wanted)

    placeholders = ",".join("?" for _ in wanted)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"{_FLOW_SELECT} WHERE f.id IN ({placeholders})",
            tuple(wanted),
        ).fetchall()

    found = {row["flow_id"]: _row_to_ref(row) for row in rows}
    missing = [fid for fid in wanted if fid not in found]
    refs = [found[fid] for fid in wanted if fid in found]
    return refs, missing


def select_test_flows_for_endpoints(
    db_path: Path,
    endpoint_ids: list[str],
    *,
    limit_per_endpoint: int = DEFAULT_TEST_FLOWS_PER_ENDPOINT,
) -> tuple[list[FlowRef], list[str]]:
    """
    Purpose:
        Pick the top N 2xx proxy_capture flows per selected endpoint
        for attack launchers.
    Ranking (per endpoint, stable):
        1. endpoint_policy.baseline_flow_id first
        2. method family POST / PATCH / PUT / GET
        3. most recent captured_at
    Input:
        db_path            — project talos.db.
        endpoint_ids       — operator-selected endpoint UUIDs.
        limit_per_endpoint — cap per endpoint (default 5, at least 1).
    Output:
        (ranked refs in endpoint-id order, endpoint ids with no usable flow).
        Logout / dangerous / excluded endpoints contribute no flows and
        are listed as skipped.
    Side effects: migrate_project_db.
    """
    wanted = []
    seen: set[str] = set()
    for raw in endpoint_ids:
        eid = (raw or "").strip()
        if eid and eid not in seen:
            seen.add(eid)
            wanted.append(eid)
    if not wanted:
        return [], []

    migrate_project_db(db_path)
    if not db_path.exists():
        return [], list(wanted)

    cap = max(1, int(limit_per_endpoint))
    placeholders = ",".join("?" for _ in wanted)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"""
            {_FLOW_SELECT}
            WHERE f.endpoint_id IN ({placeholders})
              AND f.source = 'proxy_capture'
              AND f.status_code >= 200
              AND f.status_code < 300
            """,
            tuple(wanted),
        ).fetchall()

    by_ep: dict[str, list[FlowRef]] = {eid: [] for eid in wanted}
    for row in rows:
        ref = _row_to_ref(row)
        if not ref.endpoint_id or ref.policy_blocked:
            continue
        by_ep.setdefault(ref.endpoint_id, []).append(ref)

    picked: list[FlowRef] = []
    skipped: list[str] = []
    for eid in wanted:
        bucket = by_ep.get(eid) or []
        if not bucket:
            skipped.append(eid)
            continue
        # Newest first, then method, then baseline — three stable sorts.
        bucket.sort(key=lambda r: r.captured_at or "", reverse=True)
        bucket.sort(key=lambda r: METHOD_RANK.get(r.method, 4))
        bucket.sort(
            key=lambda r: 0 if r.baseline_flow_id and r.flow_id == r.baseline_flow_id else 1
        )
        picked.extend(bucket[:cap])
    return picked, skipped


def unique_endpoint_ids(refs: list[FlowRef]) -> list[str]:
    """Purpose: Endpoint UUIDs in first-seen order, skipping empties."""
    out: list[str] = []
    seen: set[str] = set()
    for ref in refs:
        eid = ref.endpoint_id
        if eid and eid not in seen:
            seen.add(eid)
            out.append(eid)
    return out
