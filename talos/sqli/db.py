"""
Module: talos.sqli.db

Purpose:
    Persist and query sqli_results — one row per unique replay flow.

Dependencies: sqlite3, pathlib, talos.projects.db
Data flow: engine insert → CLI / Control Panel list/show
Side effects: writes sqli_results; migrate_project_db on entry.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from talos.projects.db import migrate_project_db


def _now_iso() -> str:
    """Purpose: UTC timestamp for sqli_results.created_at."""
    return datetime.now(timezone.utc).isoformat()


def _connect_rw(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    return conn


def insert_sqli_result(db_path: Path, row: dict) -> None:
    """
    Purpose:
        Store one SQLi probe result keyed by the unique replay flow.
    Side effects: INSERT into sqli_results.
    """
    migrate_project_db(db_path)
    with _connect_rw(db_path) as conn:
        conn.execute(
            """
            INSERT INTO sqli_results (
                replay_flow_id, original_flow_id, endpoint_id, host,
                technique, technique_family, location, param_name,
                payload_sent, original_value,
                original_status, replay_status, elapsed_ms,
                dbms, evidence, verdict, risk_hint,
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
                row.get("dbms"),
                row.get("evidence") or "",
                row["verdict"],
                row.get("risk_hint") or "",
                row.get("failure_reason"),
                row.get("created_at") or _now_iso(),
            ),
        )
        conn.commit()


def list_sqli_results(
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
        List SQLi probe results joined to the unique replay flow.
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
    if family:
        clauses.append("sr.technique_family = ?")
        params.append(family)
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
            FROM sqli_results sr
            JOIN flows f ON f.id = sr.replay_flow_id
            {where}
            ORDER BY sr.created_at DESC
            LIMIT ?
            """,
            tuple(params),
        ).fetchall()
    return [dict(r) for r in rows]


def get_sqli_result(db_path: Path, replay_flow_id: str) -> Optional[dict]:
    """
    Purpose:
        Fetch one sqli_results row by unique replay flow UUID.
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
                   f.captured_at
            FROM sqli_results sr
            JOIN flows f ON f.id = sr.replay_flow_id
            WHERE sr.replay_flow_id = ?
            """,
            (replay_flow_id,),
        ).fetchone()
    return dict(row) if row else None


def count_sqli_verdicts(db_path: Path) -> dict[str, int]:
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
            "SELECT verdict, COUNT(*) AS n FROM sqli_results GROUP BY verdict"
        ).fetchall()
    return {str(r["verdict"]): int(r["n"]) for r in rows}
