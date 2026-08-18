"""
Module: talos.smuggle.db

Purpose:
    Persist and query smuggle_results — one row per unique replay flow.

Dependencies: sqlite3, pathlib, talos.projects.db
Data flow: engine insert → CLI / Control Panel list/show
Side effects: writes smuggle_results; migrate_project_db on entry.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from talos.projects.db import migrate_project_db


def _now_iso() -> str:
    """Purpose: UTC timestamp for smuggle_results.created_at."""
    return datetime.now(timezone.utc).isoformat()


def _connect_rw(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def insert_smuggle_result(db_path: Path, row: dict) -> None:
    """
    Purpose:
        Store one smuggling probe result keyed by the unique replay flow.
    Side effects: INSERT into smuggle_results.
    """
    migrate_project_db(db_path)
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO smuggle_results (
                replay_flow_id, original_flow_id, endpoint_id, host,
                technique, technique_family, canary_path, ntlm_used,
                probe_status, followup_status, baseline_status,
                probe_elapsed_ms, followup_elapsed_ms, timeout_hit,
                desync_signal, evidence,
                original_status, verdict, risk_hint,
                failure_reason, created_at
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?, ?,
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
                row.get("canary_path") or "",
                1 if row.get("ntlm_used") else 0,
                row.get("probe_status"),
                row.get("followup_status"),
                row.get("baseline_status"),
                row.get("probe_elapsed_ms"),
                row.get("followup_elapsed_ms"),
                1 if row.get("timeout_hit") else 0,
                row.get("desync_signal") or "",
                row.get("evidence") or "",
                row.get("original_status"),
                row["verdict"],
                row.get("risk_hint") or "",
                row.get("failure_reason"),
                row.get("created_at") or _now_iso(),
            ),
        )
        conn.commit()


def list_smuggle_results(
    db_path: Path,
    *,
    verdict: Optional[str] = None,
    technique: Optional[str] = None,
    host: Optional[str] = None,
    flow_id: Optional[str] = None,
    limit: int = 200,
) -> list[dict]:
    """
    Purpose:
        List smuggling probe results joined to the unique replay flow.
    Output:
        Newest-first dict rows (empty list when none).
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return []

    clauses: list[str] = []
    params: list[object] = []
    if verdict:
        clauses.append("sr.verdict = ?")
        params.append(verdict)
    if technique:
        clauses.append("sr.technique = ?")
        params.append(technique)
    if host:
        clauses.append("(sr.host LIKE ? OR f.host LIKE ?)")
        like = f"%{host}%"
        params.extend([like, like])
    if flow_id:
        clauses.append("(sr.original_flow_id = ? OR sr.replay_flow_id = ?)")
        params.extend([flow_id, flow_id])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(min(max(int(limit), 1), 1000))

    with _connect_rw(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT sr.*,
                   f.method, f.path, f.url, f.status_code AS flow_status,
                   f.captured_at
            FROM smuggle_results sr
            JOIN flows f ON f.id = sr.replay_flow_id
            {where}
            ORDER BY sr.created_at DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    return [dict(r) for r in rows]


def get_smuggle_result(db_path: Path, replay_flow_id: str) -> Optional[dict]:
    """
    Purpose:
        Fetch one smuggle_results row by unique replay flow UUID.
    Output:
        Dict or None.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return None
    with _connect_rw(db_path) as conn:
        row = conn.execute(
            """
            SELECT sr.*,
                   f.method, f.path, f.url, f.status_code AS flow_status,
                   f.captured_at, f.request_headers, f.response_headers
            FROM smuggle_results sr
            JOIN flows f ON f.id = sr.replay_flow_id
            WHERE sr.replay_flow_id = ?
            """,
            (replay_flow_id,),
        ).fetchone()
    return dict(row) if row else None


def count_smuggle_verdicts(db_path: Path) -> dict[str, int]:
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
            "SELECT verdict, COUNT(*) AS n FROM smuggle_results GROUP BY verdict"
        ).fetchall()
    return {str(r["verdict"]): int(r["n"]) for r in rows}
