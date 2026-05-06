"""
Module: talos.projects.mutation

Purpose:
    CRUD operations for per-project request mutations.
    A mutation is a static transformation applied to every outgoing request
    inside the proxy request() hook before the request reaches the server.

    Only 'header' mutations are supported: set a named header to a fixed value.
    Mutations are stored per-project in the request_mutations table and loaded
    once at proxy startup.

Dependencies: sqlite3, pathlib, uuid
Data flow:
    mutation_cli / proxy addon → functions here → request_mutations table
Side effects:
    - Write operations mutate request_mutations rows.
    - Read operations are connection-scoped with no persistent state.
"""

import sqlite3
import uuid
from pathlib import Path


# ------------------------------------------------------------------ #
# Read operations                                                      #
# ------------------------------------------------------------------ #

def list_mutations(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return all request mutations for the project, ordered by creation
        order (rowid ascending — insertion order).
    Input:
        db_path — absolute Path to the project's talos.db.
    Output:
        List of dicts with keys: id, type, key, value, enabled.
        Returns empty list when no entries exist or DB is absent.
    Side effects: None (read-only).
    """
    if not db_path.exists():
        return []

    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT id, type, key, value, enabled"
            " FROM request_mutations"
            " ORDER BY rowid ASC"
        ).fetchall()

    return [
        {"id": row[0], "type": row[1], "key": row[2], "value": row[3], "enabled": bool(row[4])}
        for row in rows
    ]


def load_mutations(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return all enabled mutations as a list of dicts for use by the proxy
        addon at startup.  Only mutations with enabled=1 are returned.
    Input:
        db_path — absolute Path to the project's talos.db.
    Output:
        List of dicts with keys: id, type, key, value.
        Returns empty list when no enabled mutations exist or DB is absent.
    Side effects: None (read-only).
    """
    if not db_path.exists():
        return []

    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT id, type, key, value"
            " FROM request_mutations"
            " WHERE enabled = 1"
            " ORDER BY rowid ASC"
        ).fetchall()

    return [{"id": row[0], "type": row[1], "key": row[2], "value": row[3]} for row in rows]


# ------------------------------------------------------------------ #
# Write operations                                                     #
# ------------------------------------------------------------------ #

def add_mutation(db_path: Path, mutation_type: str, key: str, value: str) -> str:
    """
    Purpose:
        Add a new request mutation to the project.
    Input:
        db_path       — absolute Path to the project's talos.db.
        mutation_type — mutation category: only 'header' is accepted.
        key           — header name (e.g. 'X-HackerOne-Research').
        value         — header value (e.g. 'himanshu_2077').
    Output:
        The UUID string assigned to the new mutation.
    Side effects:
        Inserts one row into request_mutations.
        Raises ValueError if mutation_type is not 'header'.
    """
    if mutation_type != "header":
        raise ValueError(f"Unsupported mutation type: '{mutation_type}'. Only 'header' is supported.")

    mutation_id = str(uuid.uuid4())

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO request_mutations (id, type, key, value, enabled)"
            " VALUES (?, ?, ?, ?, 1)",
            (mutation_id, mutation_type, key, value),
        )
        conn.commit()

    return mutation_id


def delete_mutation(db_path: Path, mutation_id: str) -> bool:
    """
    Purpose:
        Remove a mutation from the project by its ID.
    Input:
        db_path     — absolute Path to the project's talos.db.
        mutation_id — UUID string of the mutation to delete.
    Output:
        True  if the mutation was found and deleted.
        False if no mutation with that ID exists (no-op).
    Side effects:
        Deletes one row from request_mutations on success.
    """
    with sqlite3.connect(str(db_path)) as conn:
        cursor = conn.execute(
            "DELETE FROM request_mutations WHERE id = ?",
            (mutation_id,),
        )
        conn.commit()
        return cursor.rowcount == 1
