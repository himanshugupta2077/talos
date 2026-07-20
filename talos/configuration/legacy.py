"""
Module: talos.configuration.legacy

Purpose:
    Bridge existing configuration stores into the layered model so older
    projects keep working without a manual migration:

        - proxy_config table          → proxy.upstream
        - scheduler_config table      → scheduler.*
        - attack_config table         → attack.unauth_auto_run
        - headers_drop.txt            → capture.drop_headers
        - Project.constraints         → capture.store_bodies / max_body_size

    Legacy values form a project-level overlay that sits *under* project.yaml
    (YAML wins when both define the same key).

Dependencies: pathlib, sqlite3, talos.configuration.io
Data flow:
    ConfigurationManager → load_legacy_project_layer → merge under project.yaml
Side effects:
    May call migrate_project_db when reading SQLite tables.
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Any, Optional

from talos.configuration.io import load_headers_drop_file

logger = logging.getLogger(__name__)


def load_legacy_project_layer(
    project_data_dir: Path,
    *,
    store_bodies: Optional[bool] = None,
    max_body_size: Optional[int] = None,
) -> dict:
    """
    Purpose:
        Build a partial config tree from pre-CLI-022 project stores.
    Input:
        project_data_dir — project storage directory (contains talos.db, etc.).
        store_bodies     — optional constraint from Project model.
        max_body_size    — optional constraint from Project model.
    Output:
        Partial nested dict suitable for deep_merge (may be empty).
    Side effects:
        Reads SQLite / headers_drop.txt when present.
    """
    layer: dict[str, Any] = {}
    db_path = project_data_dir / "talos.db"

    # Capture constraints from registry Project object (passed by manager).
    capture: dict[str, Any] = {}
    if store_bodies is not None:
        capture["store_bodies"] = bool(store_bodies)
    if max_body_size is not None:
        capture["max_body_size"] = int(max_body_size)

    drop = load_headers_drop_file(project_data_dir / "headers_drop.txt")
    if drop is not None:
        capture["drop_headers"] = drop

    if capture:
        layer["capture"] = capture

    if db_path.exists():
        proxy_part = _legacy_proxy(db_path)
        if proxy_part:
            layer["proxy"] = proxy_part
        sched_part = _legacy_scheduler(db_path)
        if sched_part:
            layer["scheduler"] = sched_part
        attack_part = _legacy_attack(db_path)
        if attack_part:
            layer["attack"] = attack_part

    return layer


def _legacy_proxy(db_path: Path) -> dict:
    """Read proxy_config.upstream_url when set."""
    try:
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                "SELECT upstream_url FROM proxy_config WHERE id = 'default'"
            ).fetchone()
    except sqlite3.Error as exc:
        logger.debug("legacy proxy_config read skipped: %s", exc)
        return {}
    if row is None or not row[0]:
        return {}
    url = str(row[0]).strip()
    if not url:
        return {}
    return {"upstream": {"enabled": True, "url": url}}


def _legacy_scheduler(db_path: Path) -> dict:
    """Read scheduler_config row when present."""
    try:
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                "SELECT min_delay, max_delay, max_queue_size "
                "FROM scheduler_config LIMIT 1"
            ).fetchone()
    except sqlite3.Error as exc:
        logger.debug("legacy scheduler_config read skipped: %s", exc)
        return {}
    if row is None:
        return {}
    return {
        "min_delay": float(row[0]),
        "max_delay": float(row[1]),
        "max_queue_size": int(row[2]),
    }


def _legacy_attack(db_path: Path) -> dict:
    """Read attack_config.unauth_auto_run when the key exists."""
    try:
        with sqlite3.connect(str(db_path)) as conn:
            row = conn.execute(
                "SELECT value FROM attack_config WHERE key = 'unauth_auto_run'"
            ).fetchone()
    except sqlite3.Error as exc:
        logger.debug("legacy attack_config read skipped: %s", exc)
        return {}
    if row is None:
        return {}
    return {"unauth_auto_run": row[0] == "1"}


def mirror_proxy_to_legacy(db_path: Path, enabled: bool, url: Optional[str]) -> None:
    """
    Purpose:
        Dual-write proxy upstream into the proxy_config table so older
        tools and mid-migration code paths stay consistent.

        Writes SQLite directly (does not call set_upstream_url) to avoid
        recursion when the proxy_config helpers also write project.yaml.
    Side effects: Writes proxy_config.
    """
    try:
        from talos.projects.db import migrate_project_db

        migrate_project_db(db_path)
        stored = url if (enabled and url) else None
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                "INSERT INTO proxy_config (id, upstream_url) VALUES ('default', ?)"
                " ON CONFLICT(id) DO UPDATE SET upstream_url = excluded.upstream_url",
                (stored,),
            )
            conn.commit()
    except Exception as exc:  # pragma: no cover - best-effort dual write
        logger.warning("Failed to mirror proxy config to SQLite: %s", exc)


def mirror_scheduler_to_legacy(
    db_path: Path,
    min_delay: float,
    max_delay: float,
    max_queue_size: int,
) -> None:
    """
    Purpose:
        Dual-write scheduler settings into scheduler_config via direct SQL
        (avoids import cycles with scheduler.db helpers).
    Side effects: Writes scheduler_config.
    """
    try:
        from talos.projects.db import migrate_project_db

        migrate_project_db(db_path)
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute("DELETE FROM scheduler_config")
            conn.execute(
                "INSERT INTO scheduler_config (min_delay, max_delay, max_queue_size) "
                "VALUES (?, ?, ?)",
                (min_delay, max_delay, max_queue_size),
            )
            conn.commit()
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to mirror scheduler config to SQLite: %s", exc)


def mirror_attack_to_legacy(db_path: Path, unauth_auto_run: bool) -> None:
    """
    Purpose:
        Dual-write unauth_auto_run into attack_config via direct SQL.
    Side effects: Writes attack_config.
    """
    try:
        from talos.projects.db import migrate_project_db

        migrate_project_db(db_path)
        value = "1" if unauth_auto_run else "0"
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO attack_config (key, value) "
                "VALUES ('unauth_auto_run', ?)",
                (value,),
            )
            conn.commit()
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to mirror attack config to SQLite: %s", exc)
