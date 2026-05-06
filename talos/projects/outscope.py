"""
Module: talos.projects.outscope

Purpose:
    CRUD operations for the per-project out-of-scope domain list.
    Domains in this list are never captured, processed, or replayed
    regardless of whether they match the scope allow-list.

    Matching semantics (enforced by callers, not this module):
        host == domain  OR  host.endswith('.' + domain)
    This blocks both the exact domain and all its subdomains.

Dependencies: sqlite3, pathlib, uuid, datetime
Data flow:
    outscope_cli / proxy addon / worker → functions here → out_of_scope_domains table
Side effects:
    - Write operations mutate out_of_scope_domains rows.
    - Read operations are connection-scoped with no persistent state.
"""

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path


# ------------------------------------------------------------------ #
# Read operations                                                      #
# ------------------------------------------------------------------ #

def list_domains(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return all out-of-scope domain entries for the project, ordered
        by creation time (oldest first).
    Input:
        db_path — absolute Path to the project's talos.db.
    Output:
        List of dicts with keys: id, domain, created_at.
        Returns empty list when no entries exist or DB is absent.
    Side effects: None (read-only).
    """
    if not db_path.exists():
        return []

    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT id, domain, created_at FROM out_of_scope_domains"
            " ORDER BY created_at ASC"
        ).fetchall()

    return [{"id": row[0], "domain": row[1], "created_at": row[2]} for row in rows]


def load_domain_set(db_path: Path) -> frozenset[str]:
    """
    Purpose:
        Return all blocked domain strings as a frozenset for fast membership
        checks at capture time.  Called once at proxy/worker startup; the
        result is held in memory for the lifetime of the session.
    Input:
        db_path — absolute Path to the project's talos.db.
    Output:
        Frozenset of lowercased domain strings.
        Returns empty frozenset when no entries exist or DB is absent.
    Side effects: None (read-only).
    """
    if not db_path.exists():
        return frozenset()

    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT domain FROM out_of_scope_domains"
        ).fetchall()

    return frozenset(row[0].lower() for row in rows)


# ------------------------------------------------------------------ #
# Write operations                                                     #
# ------------------------------------------------------------------ #

def add_domain(db_path: Path, project_id: str, domain: str) -> bool:
    """
    Purpose:
        Add a domain to the out-of-scope list for this project.
        Lowercases the domain before storage to ensure consistent matching.
    Input:
        db_path    — absolute Path to the project's talos.db.
        project_id — project UUID string; stored for reference queries.
        domain     — domain string (e.g. 'api.stripe.com').
    Output:
        True  if the domain was inserted (new entry).
        False if the domain was already present (no-op).
    Side effects:
        Inserts one row into out_of_scope_domains on success.
        INSERT OR IGNORE — duplicate (project_id, domain) is a no-op.
    """
    domain_lower = domain.strip().lower()
    now = datetime.now(timezone.utc).isoformat()

    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute(
            "INSERT OR IGNORE INTO out_of_scope_domains"
            " (id, project_id, domain, created_at)"
            " VALUES (?, ?, ?, ?)",
            (str(uuid.uuid4()), project_id, domain_lower, now),
        )
        conn.commit()
        # rowcount is 1 on insert, 0 on ignored duplicate.
        return cursor.rowcount == 1


def remove_domain(db_path: Path, project_id: str, domain: str) -> bool:
    """
    Purpose:
        Remove a domain from the out-of-scope list for this project.
    Input:
        db_path    — absolute Path to the project's talos.db.
        project_id — project UUID string; scopes the delete to this project.
        domain     — domain string to remove (case-insensitive).
    Output:
        True  if the domain was found and removed.
        False if the domain was not present (no-op).
    Side effects:
        Deletes one row from out_of_scope_domains when found.
    """
    domain_lower = domain.strip().lower()

    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute(
            "DELETE FROM out_of_scope_domains"
            " WHERE project_id = ? AND domain = ?",
            (project_id, domain_lower),
        )
        conn.commit()
        return cursor.rowcount > 0
