"""
Low-level, read-only data access.

Mirrors the pattern already used in talos.ui.db: read-only SQLite connections
(file:...?mode=ro), defensive table-existence checks, and plain dict rows.
This module owns nothing — it never writes to Talos's database. All mutations
in this control panel go through the CLI (see app/cli.py), per the project's
architectural rule that the CLI remains the single source of truth.
"""

import json
import sqlite3
from pathlib import Path
from typing import Any, Optional

from . import config


# ------------------------------------------------------------------ #
# Registry                                                            #
# ------------------------------------------------------------------ #

def load_registry() -> dict[str, dict]:
    """Load all project records from registry.json. Empty dict if absent/corrupt."""
    if not config.REGISTRY_PATH.exists():
        return {}
    try:
        with config.REGISTRY_PATH.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return {}
    if not isinstance(data, dict):
        return {}
    return data


def get_project_record(project_id: str) -> Optional[dict]:
    return load_registry().get(project_id)


def get_active_project_id() -> Optional[str]:
    """
    Detect the currently active/open project.
    Talos's ProjectManager stores this as `record["status"] == "active"`
    (see talos.projects.model.ProjectStatus) — exactly one project may have
    this value at a time. We also tolerate a couple of alternate shapes
    (legacy 'active'/'is_active' booleans, or a top-level pointer key) in
    case a different Talos version is pointed at, but the canonical check is
    the 'status' field.
    """
    registry = load_registry()
    for key in ("_active_project_id", "active_project_id", "_active", "active"):
        val = registry.get(key)
        if isinstance(val, str) and val in registry:
            return val
    for project_id, record in registry.items():
        if project_id.startswith("_") or not isinstance(record, dict):
            continue
        if record.get("status") == "active":
            return project_id
        if record.get("active") or record.get("is_active"):
            return project_id
    return None


# ------------------------------------------------------------------ #
# SQLite                                                               #
# ------------------------------------------------------------------ #

def connect(db_path: Path) -> sqlite3.Connection:
    """Open a strictly read-only connection with dict-like rows."""
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def db_exists(db_path: Path) -> bool:
    return db_path.exists()


def query_all(db_path: Path, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
    """Run a SELECT and return a list of plain dicts. Empty list if DB is absent."""
    if not db_exists(db_path):
        return []
    with connect(db_path) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def query_one(db_path: Path, sql: str, params: tuple = ()) -> Optional[dict[str, Any]]:
    if not db_exists(db_path):
        return None
    with connect(db_path) as conn:
        row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None


def scalar(db_path: Path, sql: str, params: tuple = (), default=0):
    if not db_exists(db_path):
        return default
    with connect(db_path) as conn:
        row = conn.execute(sql, params).fetchone()
        return row[0] if row and row[0] is not None else default


def safe_json(text: Optional[str], default):
    if not text:
        return default
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return default
