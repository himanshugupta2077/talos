"""
Module: talos.projects.access

Purpose:
    CRUD operations for roles, modules, and the role-module access map.
    These three entities form the two-layer access-control model used to
    classify captured flows and define BAC (Broken Access Control) boundaries.

    Roles   — identity types (user, admin, support, …).
    Modules — logical application feature areas (billing, auth, orders, …).
    Access map — (role, module) → client_allowed + server_expected, both
                 tri-state: ALLOW | DENY | UNKNOWN | NULL (not yet set).

    Two-layer model:
        client_allowed  — what the UI exposes for this role/module pair.
                          Manually set; reflects observed navigation/buttons.
        server_expected — what the backend SHOULD enforce (your assertion).
                          Manually set; drives BAC test generation.

    Neither value is ever auto-inferred — both must be set explicitly.

Dependencies: sqlite3, uuid, pathlib
Data flow:
    ProjectManager / FlowWorker / CLI → access functions → project SQLite DB
Side effects:
    - Write operations mutate the project SQLite database.
    - Read operations are connection-scoped and leave no persistent state.
"""

import sqlite3
import uuid
from pathlib import Path
from typing import Optional


# ------------------------------------------------------------------ #
# Role operations                                                     #
# ------------------------------------------------------------------ #

def create_role(db_path: Path, name: str) -> str:
    """
    Purpose:
        Insert a new role into the roles table.
    Input:
        db_path — path to the project SQLite database.
        name    — unique role label (e.g. "admin", "user").
    Output:
        UUID string for the newly created role.
    Side effects:
        Inserts one row into roles.
    Raises:
        sqlite3.IntegrityError if a role with this name already exists.
    """
    role_id = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO roles (id, name, is_active) VALUES (?, ?, 0)",
            (role_id, name),
        )
        conn.commit()
    return role_id


def get_role(db_path: Path, name: str) -> Optional[dict]:
    """
    Purpose:
        Fetch a single role by name.
    Input:
        db_path — path to the project SQLite database.
        name    — exact role name to look up.
    Output:
        Dict with keys {id, name, is_active} or None if not found.
    Side effects: None (read-only).
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, name, is_active FROM roles WHERE name = ?", (name,)
        ).fetchone()
    return dict(row) if row else None


def list_roles(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return all roles ordered by name.
    Input:
        db_path — path to the project SQLite database.
    Output:
        List of dicts with keys {id, name, is_active}.
    Side effects: None (read-only).
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, name, is_active FROM roles ORDER BY name"
        ).fetchall()
    return [dict(r) for r in rows]


def get_active_role(db_path: Path) -> str:
    """
    Purpose:
        Return the name of the currently active role.
        Falls back to "global" if no role has is_active = 1.
        The fallback should not happen in practice — _seed_default_context
        always activates "global" when no role is active.
    Input:
        db_path — path to the project SQLite database.
    Output:
        Role name string.
    Side effects: None (read-only).
    """
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT name FROM roles WHERE is_active = 1 LIMIT 1"
        ).fetchone()
    return row[0] if row else "global"


def get_active_role_id(db_path: Path) -> str:
    """
    Purpose:
        Return the ID of the currently active role.
        Falls back to the "global" role ID if no role has is_active = 1.
        The fallback should not happen in practice — seed_default_context always
        activates "global" when no role is active.
    Input:
        db_path — path to the project SQLite database.
    Output:
        Role ID (UUID string).
    Side effects: None (read-only).
    Raises:
        RuntimeError if neither an active role nor a "global" role exists.
    """
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT id FROM roles WHERE is_active = 1 LIMIT 1"
        ).fetchone()
        if row:
            return row[0]
        row = conn.execute(
            "SELECT id FROM roles WHERE name = 'global' LIMIT 1"
        ).fetchone()
        if row:
            return row[0]
    raise RuntimeError(
        "No active or global role found. Ensure seed_default_context has run."
    )


def set_active_role(db_path: Path, name: str) -> None:
    """
    Purpose:
        Mark a role as active, deactivating any previously active role.
        Enforces the "exactly one active role" invariant.
    Input:
        db_path — path to the project SQLite database.
        name    — name of the role to activate.
    Side effects:
        Updates is_active on all role rows.
    Raises:
        ValueError if no role with the given name exists.
    """
    with sqlite3.connect(str(db_path)) as conn:
        exists = conn.execute(
            "SELECT 1 FROM roles WHERE name = ?", (name,)
        ).fetchone()
        if exists is None:
            raise ValueError(f"Role '{name}' does not exist.")
        conn.execute("UPDATE roles SET is_active = 0")
        conn.execute("UPDATE roles SET is_active = 1 WHERE name = ?", (name,))
        conn.commit()


# ------------------------------------------------------------------ #
# Module operations                                                   #
# ------------------------------------------------------------------ #

def create_module(db_path: Path, name: str, description: str = "") -> str:
    """
    Purpose:
        Insert a new module into the modules table.
    Input:
        db_path     — path to the project SQLite database.
        name        — unique module label (e.g. "billing", "auth").
        description — optional human note about this module's scope.
    Output:
        UUID string for the newly created module.
    Side effects:
        Inserts one row into modules.
    Raises:
        sqlite3.IntegrityError if a module with this name already exists.
    """
    module_id = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO modules (id, name, description, is_active) VALUES (?, ?, ?, 0)",
            (module_id, name, description),
        )
        conn.commit()
    return module_id


def get_module(db_path: Path, name: str) -> Optional[dict]:
    """
    Purpose:
        Fetch a single module by name.
    Input:
        db_path — path to the project SQLite database.
        name    — exact module name to look up.
    Output:
        Dict with keys {id, name, description, is_active} or None if not found.
    Side effects: None (read-only).
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, name, description, is_active FROM modules WHERE name = ?",
            (name,),
        ).fetchone()
    return dict(row) if row else None


def list_modules(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return all modules ordered by name.
    Input:
        db_path — path to the project SQLite database.
    Output:
        List of dicts with keys {id, name, description, is_active}.
    Side effects: None (read-only).
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT id, name, description, is_active FROM modules ORDER BY name"
        ).fetchall()
    return [dict(r) for r in rows]


def get_active_module(db_path: Path) -> str:
    """
    Purpose:
        Return the name of the currently active module.
        Falls back to "global" if no module has is_active = 1.
    Input:
        db_path — path to the project SQLite database.
    Output:
        Module name string.
    Side effects: None (read-only).
    """
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT name FROM modules WHERE is_active = 1 LIMIT 1"
        ).fetchone()
    return row[0] if row else "global"


def get_active_module_id(db_path: Path) -> str:
    """
    Purpose:
        Return the ID of the currently active module.
        Falls back to the "global" module ID if no module has is_active = 1.
    Input:
        db_path — path to the project SQLite database.
    Output:
        Module ID (UUID string).
    Side effects: None (read-only).
    Raises:
        RuntimeError if neither an active module nor a "global" module exists.
    """
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT id FROM modules WHERE is_active = 1 LIMIT 1"
        ).fetchone()
        if row:
            return row[0]
        row = conn.execute(
            "SELECT id FROM modules WHERE name = 'global' LIMIT 1"
        ).fetchone()
        if row:
            return row[0]
    raise RuntimeError(
        "No active or global module found. Ensure seed_default_context has run."
    )


def set_active_module(db_path: Path, name: str) -> None:
    """
    Purpose:
        Mark a module as active, deactivating any previously active module.
        Enforces the "exactly one active module" invariant.
    Input:
        db_path — path to the project SQLite database.
        name    — name of the module to activate.
    Side effects:
        Updates is_active on all module rows.
    Raises:
        ValueError if no module with the given name exists.
    """
    with sqlite3.connect(str(db_path)) as conn:
        exists = conn.execute(
            "SELECT 1 FROM modules WHERE name = ?", (name,)
        ).fetchone()
        if exists is None:
            raise ValueError(f"Module '{name}' does not exist.")
        conn.execute("UPDATE modules SET is_active = 0")
        conn.execute("UPDATE modules SET is_active = 1 WHERE name = ?", (name,))
        conn.commit()


# ------------------------------------------------------------------ #
# Access map operations                                               #
# ------------------------------------------------------------------ #

# Valid tri-state values for client_allowed and server_expected.
# Input is normalized to uppercase; storage uses these exact strings.
VALID_STATES = frozenset({"ALLOW", "DENY", "UNKNOWN"})


def _validate_state(state: str) -> str:
    """
    Purpose:
        Normalize and validate a tri-state access value.
    Input:
        state — user-supplied string ('allow', 'deny', 'unknown'), case-insensitive.
    Output:
        Uppercase canonical form: 'ALLOW', 'DENY', or 'UNKNOWN'.
    Raises:
        ValueError if the value is not one of the valid states.
    """
    upper = state.upper()
    if upper not in VALID_STATES:
        raise ValueError(
            f"Invalid state '{state}'. Must be one of: allow, deny, unknown."
        )
    return upper


def _resolve_role_module(
    conn: "sqlite3.Connection", role_name: str, module_name: str
) -> tuple[str, str]:
    """
    Purpose:
        Resolve role and module names to their IDs in a single connection context.
    Input:
        conn        — open SQLite connection.
        role_name   — name of an existing role.
        module_name — name of an existing module.
    Output:
        (role_id, module_id) tuple.
    Raises:
        ValueError if either name is not found.
    """
    role_row = conn.execute(
        "SELECT id FROM roles WHERE name = ?", (role_name,)
    ).fetchone()
    if role_row is None:
        raise ValueError(f"Role '{role_name}' does not exist.")

    module_row = conn.execute(
        "SELECT id FROM modules WHERE name = ?", (module_name,)
    ).fetchone()
    if module_row is None:
        raise ValueError(f"Module '{module_name}' does not exist.")

    return role_row[0], module_row[0]


def set_client_access(
    db_path: Path, role_name: str, module_name: str, state: str
) -> None:
    """
    Purpose:
        Set the client_allowed field for a (role, module) pair.
        Creates the row if it does not exist; updates the field if it does.
        client_allowed represents what the UI exposes for this pair.
    Input:
        db_path     — path to the project SQLite database.
        role_name   — name of an existing role.
        module_name — name of an existing module.
        state       — 'allow', 'deny', or 'unknown' (case-insensitive).
    Side effects:
        Upserts one row in access_map (client_allowed column only).
    Raises:
        ValueError if role/module does not exist or state is invalid.
    """
    state_upper = _validate_state(state)
    with sqlite3.connect(str(db_path)) as conn:
        role_id, module_id = _resolve_role_module(conn, role_name, module_name)
        conn.execute(
            """
            INSERT INTO access_map (role_id, module_id, client_allowed, server_expected)
            VALUES (?, ?, ?, NULL)
            ON CONFLICT(role_id, module_id)
            DO UPDATE SET client_allowed = excluded.client_allowed
            """,
            (role_id, module_id, state_upper),
        )
        conn.commit()


def set_server_access(
    db_path: Path, role_name: str, module_name: str, state: str
) -> None:
    """
    Purpose:
        Set the server_expected field for a (role, module) pair.
        Creates the row if it does not exist; updates the field if it does.
        server_expected is your assertion of what the backend SHOULD enforce.
    Input:
        db_path     — path to the project SQLite database.
        role_name   — name of an existing role.
        module_name — name of an existing module.
        state       — 'allow', 'deny', or 'unknown' (case-insensitive).
    Side effects:
        Upserts one row in access_map (server_expected column only).
    Raises:
        ValueError if role/module does not exist or state is invalid.
    """
    state_upper = _validate_state(state)
    with sqlite3.connect(str(db_path)) as conn:
        role_id, module_id = _resolve_role_module(conn, role_name, module_name)
        conn.execute(
            """
            INSERT INTO access_map (role_id, module_id, client_allowed, server_expected)
            VALUES (?, ?, NULL, ?)
            ON CONFLICT(role_id, module_id)
            DO UPDATE SET server_expected = excluded.server_expected
            """,
            (role_id, module_id, state_upper),
        )
        conn.commit()


def unset_client_access(db_path: Path, role_name: str, module_name: str) -> None:
    """
    Purpose:
        Clear the client_allowed field (set to NULL) for a (role, module) pair.
        Does not remove the row — server_expected is preserved.
    Input:
        db_path     — path to the project SQLite database.
        role_name   — name of an existing role.
        module_name — name of an existing module.
    Side effects:
        Updates client_allowed to NULL in access_map. No-op if row absent.
    Raises:
        ValueError if role or module does not exist.
    """
    with sqlite3.connect(str(db_path)) as conn:
        role_id, module_id = _resolve_role_module(conn, role_name, module_name)
        conn.execute(
            "UPDATE access_map SET client_allowed = NULL"
            " WHERE role_id = ? AND module_id = ?",
            (role_id, module_id),
        )
        conn.commit()


def unset_server_access(db_path: Path, role_name: str, module_name: str) -> None:
    """
    Purpose:
        Clear the server_expected field (set to NULL) for a (role, module) pair.
        Does not remove the row — client_allowed is preserved.
    Input:
        db_path     — path to the project SQLite database.
        role_name   — name of an existing role.
        module_name — name of an existing module.
    Side effects:
        Updates server_expected to NULL in access_map. No-op if row absent.
    Raises:
        ValueError if role or module does not exist.
    """
    with sqlite3.connect(str(db_path)) as conn:
        role_id, module_id = _resolve_role_module(conn, role_name, module_name)
        conn.execute(
            "UPDATE access_map SET server_expected = NULL"
            " WHERE role_id = ? AND module_id = ?",
            (role_id, module_id),
        )
        conn.commit()


def delete_access(db_path: Path, role_name: str, module_name: str) -> None:
    """
    Purpose:
        Remove the entire (role, module) row from access_map.
        Use this only when the mapping itself is wrong (wrong role or module).
        Prefer unset_client_access / unset_server_access when the mapping is
        valid but the value is uncertain.
    Input:
        db_path     — path to the project SQLite database.
        role_name   — name of an existing role.
        module_name — name of an existing module.
    Side effects:
        Deletes one row from access_map. No-op if row absent.
    Raises:
        ValueError if role or module does not exist.
    """
    with sqlite3.connect(str(db_path)) as conn:
        role_id, module_id = _resolve_role_module(conn, role_name, module_name)
        conn.execute(
            "DELETE FROM access_map WHERE role_id = ? AND module_id = ?",
            (role_id, module_id),
        )
        conn.commit()


def list_access_map(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return the full access map as a list of (role, module, client, server) records.
        Used for display and BAC analysis.
    Input:
        db_path — path to the project SQLite database.
    Output:
        List of dicts keyed {role, module, client_allowed, server_expected}.
        client_allowed and server_expected are 'ALLOW', 'DENY', 'UNKNOWN', or None.
    Side effects: None (read-only).
    """
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            """
            SELECT r.name AS role, m.name AS module,
                   am.client_allowed, am.server_expected
            FROM access_map am
            JOIN roles   r ON r.id = am.role_id
            JOIN modules m ON m.id = am.module_id
            ORDER BY r.name, m.name
            """
        ).fetchall()
    return [
        {
            "role":            row[0],
            "module":          row[1],
            "client_allowed":  row[2],  # str or None
            "server_expected": row[3],  # str or None
        }
        for row in rows
    ]

