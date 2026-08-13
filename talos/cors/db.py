"""
Module: talos.cors.db

Purpose:
    Persist and query cors_results — one row per unique replay flow.

Dependencies: sqlite3, pathlib, talos.projects.db
Data flow: engine insert → CLI / Control Panel list/show
Side effects: writes cors_results; migrate_project_db on entry.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from talos.projects.db import migrate_project_db


def _now_iso() -> str:
    """Purpose: UTC timestamp for cors_results.created_at."""
    return datetime.now(timezone.utc).isoformat()


def _connect_rw(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def insert_cors_result(db_path: Path, row: dict) -> None:
    """
    Purpose:
        Store one CORS probe result keyed by the unique replay flow.
    Input:
        db_path — project talos.db.
        row     — replay_flow_id, original_flow_id, technique, verdict, …
    Output: None
    Side effects: INSERT into cors_results.
    """
    migrate_project_db(db_path)
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO cors_results (
                replay_flow_id, original_flow_id, endpoint_id, host,
                technique, technique_family, origin_sent,
                acao, acac, acam, acah,
                reflected, credentials, wildcard,
                original_status, replay_status, verdict, risk_hint,
                failure_reason, created_at
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?, ?,
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
                row.get("origin_sent") or "",
                row.get("acao"),
                row.get("acac"),
                row.get("acam"),
                row.get("acah"),
                1 if row.get("reflected") else 0,
                1 if row.get("credentials") else 0,
                1 if row.get("wildcard") else 0,
                row.get("original_status"),
                row.get("replay_status"),
                row["verdict"],
                row.get("risk_hint") or "",
                row.get("failure_reason"),
                row.get("created_at") or _now_iso(),
            ),
        )
        conn.commit()


def list_cors_results(
    db_path: Path,
    *,
    verdict: Optional[str] = None,
    technique: Optional[str] = None,
    host: Optional[str] = None,
    limit: int = 200,
) -> list[dict]:
    """
    Purpose:
        List CORS probe results joined to the unique replay flow.
    Output:
        Newest-first dict rows (empty list when none).
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return []

    clauses: list[str] = []
    params: list[object] = []
    if verdict:
        clauses.append("cr.verdict = ?")
        params.append(verdict)
    if technique:
        clauses.append("cr.technique = ?")
        params.append(technique)
    if host:
        clauses.append("(cr.host LIKE ? OR f.host LIKE ?)")
        like = f"%{host}%"
        params.extend([like, like])
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(min(max(int(limit), 1), 1000))

    with _connect_rw(db_path) as conn:
        rows = conn.execute(
            f"""
            SELECT cr.*,
                   f.method, f.path, f.url, f.status_code AS flow_status,
                   f.captured_at
            FROM cors_results cr
            JOIN flows f ON f.id = cr.replay_flow_id
            {where}
            ORDER BY cr.created_at DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    return [dict(r) for r in rows]


def get_cors_result(db_path: Path, replay_flow_id: str) -> Optional[dict]:
    """
    Purpose:
        Fetch one cors_results row by unique replay flow UUID.
    Output:
        Dict or None.
    """
    migrate_project_db(db_path)
    if not db_path.exists():
        return None
    with _connect_rw(db_path) as conn:
        row = conn.execute(
            """
            SELECT cr.*,
                   f.method, f.path, f.url, f.status_code AS flow_status,
                   f.captured_at, f.request_headers, f.response_headers
            FROM cors_results cr
            JOIN flows f ON f.id = cr.replay_flow_id
            WHERE cr.replay_flow_id = ?
            """,
            (replay_flow_id,),
        ).fetchone()
    return dict(row) if row else None


def count_cors_verdicts(db_path: Path) -> dict[str, int]:
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
            "SELECT verdict, COUNT(*) AS n FROM cors_results GROUP BY verdict"
        ).fetchall()
    return {str(r["verdict"]): int(r["n"]) for r in rows}
