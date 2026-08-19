"""
Module: talos.host_header.db

Purpose:
    Persist and query host_header_results — one row per unique replay flow.

Dependencies: sqlite3, pathlib, talos.projects.db
Data flow: engine insert → CLI / Control Panel list/show
Side effects: writes host_header_results; migrate_project_db on entry.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from talos.projects.db import migrate_project_db


def _now_iso() -> str:
    """Purpose: UTC timestamp for host_header_results.created_at."""
    return datetime.now(timezone.utc).isoformat()


def _connect_rw(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def insert_host_header_result(db_path: Path, row: dict) -> None:
    """
    Purpose:
        Store one host-header probe result keyed by the unique replay flow.
    Side effects: INSERT into host_header_results.
    """
    migrate_project_db(db_path)
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO host_header_results (
                replay_flow_id, original_flow_id, endpoint_id, host,
                technique, technique_family, location, param_name,
                payload_sent, original_value,
                original_status, replay_status, elapsed_ms,
                reflected_url, evidence, verdict, risk_hint,
                failure_reason, created_at
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?
            )
            """,
            (
                row["replay_flow_id"],
                row["original_flow_id"],
                row.get("endpoint_id"),
                row.get("host") or "",
                row["technique"],
                row.get("technique_family") or "",
                row.get("location") or "",
                row.get("param_name") or "",
                row.get("payload_sent") or "",
                row.get("original_value") or "",
                row.get("original_status"),
                row.get("replay_status"),
                row.get("elapsed_ms"),
                row.get("reflected_url") or "",
                row.get("evidence") or "",
                row["verdict"],
                row.get("risk_hint") or "",
                row.get("failure_reason"),
                row.get("created_at") or _now_iso(),
            ),
        )
        conn.commit()


def list_host_header_results(
    db_path: Path,
    *,
    verdict: Optional[str] = None,
    technique: Optional[str] = None,
    family: Optional[str] = None,
    host: Optional[str] = None,
    flow_id: Optional[str] = None,
    limit: int = 200,
) -> list[dict]:
    """
    Purpose:
        List host-header probe results joined to the unique replay flow.
    Output:
        Newest-first dict rows (empty list when none).
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return []

    clauses: list[str] = []
    params: list[object] = []
    if verdict:
        clauses.append("pr.verdict = ?")
        params.append(verdict)
    if technique:
        clauses.append("pr.technique = ?")
        params.append(technique)
    if family:
        clauses.append("pr.technique_family = ?")
        params.append(family)
    if host:
        clauses.append("(pr.host LIKE ? OR f.host LIKE ?)")
        like = f"%{host}%"
        params.extend([like, like])
    if flow_id:
        clauses.append("(pr.original_flow_id = ? OR pr.replay_flow_id = ?)")
        params.extend([flow_id, flow_id])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(min(max(int(limit), 1), 1000))

    with _connect_rw(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT pr.*,
                   f.method, f.path, f.url, f.status_code AS flow_status,
                   f.captured_at
            FROM host_header_results pr
            JOIN flows f ON f.id = pr.replay_flow_id
            {where}
            ORDER BY pr.created_at DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    return [dict(r) for r in rows]


def get_host_header_result(db_path: Path, replay_flow_id: str) -> Optional[dict]:
    """
    Purpose:
        Fetch one host_header_results row by unique replay flow UUID.
    Output:
        Dict or None.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return None
    with _connect_rw(db_path) as conn:
        row = conn.execute(
            """
            SELECT pr.*,
                   f.method, f.path, f.url, f.status_code AS flow_status,
                   f.captured_at
            FROM host_header_results pr
            JOIN flows f ON f.id = pr.replay_flow_id
            WHERE pr.replay_flow_id = ?
            """,
            (replay_flow_id,),
        ).fetchone()
    return dict(row) if row else None


def count_host_header_verdicts(db_path: Path) -> dict[str, int]:
    """
    Purpose:
        Verdict histogram for status / overview KPIs.
    Output:
        {verdict: n}
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return {}
    with _connect_rw(db_path) as conn:
        rows = conn.execute(
            "SELECT verdict, COUNT(*) AS n FROM host_header_results GROUP BY verdict"
        ).fetchall()
    return {str(r["verdict"]): int(r["n"]) for r in rows}
