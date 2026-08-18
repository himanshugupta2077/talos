"""
Module: talos.projects.access

Purpose:
    CRUD operations for roles, modules, and the role-module access map.
    These three entities form the two-layer access-control model used to
    classify captured flows and define BAC (Broken Access Control) boundaries.

    Roles   — identity types (user, admin, support, …) with a privilege rank
              (0 = highest). Same rank = peer accounts; a higher number is a
              lower-privilege identity used for automatic BAC diffs.
    Modules — logical application feature areas (billing, auth, orders, …).
    Access map — (role, module) → client_allowed + server_expected, both
                 tri-state: ALLOW | DENY | UNKNOWN | NULL (not yet set).

    Two-layer model:
        client_allowed  — what the client exposes for this role/module pair.
                          Manually set; reflects observed navigation/buttons.
        server_expected — what the backend SHOULD enforce (your assertion).
                          Manually set; drives BAC test generation.

    Neither value is ever auto-inferred — both must be set explicitly.

    Lifecycle (CLI-006): create, list, resolve (name|uuid), rename (UUID
    stable), delete (cascade config / reassign flows to global). The seeded
    "global" role and module cannot be renamed or deleted.

Dependencies: json, sqlite3, uuid, pathlib
Data flow:
    ProjectManager / FlowWorker / CLI → access functions → project SQLite DB
Side effects:
    - Write operations mutate the project SQLite database.
    - Read operations are connection-scoped and leave no persistent state.
"""

import json
import sqlite3
import uuid
from pathlib import Path
from typing import Optional


# ------------------------------------------------------------------ #
# Role operations                                                     #
# ------------------------------------------------------------------ #

_ROLE_COLUMNS = "id, name, is_active, COALESCE(privilege, 0) AS privilege"


def normalize_privilege(value) -> int:
    """
    Purpose:
        Validate a privilege rank. 0 is highest; larger numbers are weaker.
    Input:
        value — int-like privilege (None treated as 0).
    Output:
        Non-negative integer.
    Raises:
        ValueError when the value is not a non-negative integer.
    """
    if value is None or value == "":
        return 0
    try:
        rank = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Privilege must be a non-negative integer (0 = highest)."
        ) from exc
    if rank < 0:
        raise ValueError(
            "Privilege must be a non-negative integer (0 = highest)."
        )
    return rank


def create_role(db_path: Path, name: str, privilege: int = 0) -> str:
    """
    Purpose:
        Insert a new role into the roles table.
    Input:
        db_path    — path to the project SQLite database.
        name       — unique role label (e.g. "admin", "user").
        privilege  — rank (0 = highest). Same rank = peer accounts.
    Output:
        UUID string for the newly created role.
    Side effects:
        Inserts one row into roles.
    Raises:
        ValueError if privilege is invalid.
        sqlite3.IntegrityError if a role with this name already exists.
    """
    rank = normalize_privilege(privilege)
    from talos.projects.db import migrate_project_db

    migrate_project_db(db_path)
    role_id = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO roles (id, name, is_active, privilege) VALUES (?, ?, 0, ?)",
            (role_id, name, rank),
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
        Dict with keys {id, name, is_active, privilege} or None if not found.
    Side effects: None (read-only).
    """
    from talos.projects.db import migrate_project_db

    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            f"SELECT {_ROLE_COLUMNS} FROM roles WHERE name = ?", (name,)
        ).fetchone()
    return dict(row) if row else None


def get_role_by_id(db_path: Path, role_id: str) -> Optional[dict]:
    """
    Purpose:
        Fetch a single role by UUID.
    Input:
        db_path — path to the project SQLite database.
        role_id — exact role UUID to look up.
    Output:
        Dict with keys {id, name, is_active, privilege} or None if not found.
    Side effects: None (read-only).
    """
    from talos.projects.db import migrate_project_db

    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            f"SELECT {_ROLE_COLUMNS} FROM roles WHERE id = ?", (role_id,)
        ).fetchone()
    return dict(row) if row else None


def resolve_role(db_path: Path, name_or_id: str) -> Optional[dict]:
    """
    Purpose:
        Resolve a role reference supplied by the user: name first, then UUID.
        Preferring name keeps human-readable CLI args stable even if a future
        role were ever named like a UUID fragment.
    Input:
        db_path    — path to the project SQLite database.
        name_or_id — role name or full UUID string.
    Output:
        Dict with keys {id, name, is_active, privilege} or None if not found.
    Side effects: None (read-only).
    """
    role = get_role(db_path, name_or_id)
    if role is not None:
        return role
    return get_role_by_id(db_path, name_or_id)


def list_roles(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return all roles ordered by privilege (highest first), then name.
    Input:
        db_path — path to the project SQLite database.
    Output:
        List of dicts with keys {id, name, is_active, privilege}.
    Side effects: None (read-only).
    """
    from talos.projects.db import migrate_project_db

    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"SELECT {_ROLE_COLUMNS} FROM roles "
            "ORDER BY privilege ASC, name ASC"
        ).fetchall()
    return [dict(r) for r in rows]


def set_role_privilege(db_path: Path, name_or_id: str, privilege: int) -> dict:
    """
    Purpose:
        Set the privilege rank for a role. 0 is highest; the same number
        on two roles means peer accounts (no automatic BAC between them).
    Input:
        db_path    — path to the project SQLite database.
        name_or_id — role name or UUID.
        privilege  — non-negative integer rank.
    Output:
        Dict {id, name, is_active, privilege} after the update.
    Side effects:
        Updates roles.privilege for one row.
    Raises:
        ValueError if the role is missing or privilege is invalid.
    """
    rank = normalize_privilege(privilege)
    from talos.projects.db import migrate_project_db

    migrate_project_db(db_path)
    role = resolve_role(db_path, name_or_id)
    if role is None:
        raise ValueError(f"Role '{name_or_id}' not found.")
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "UPDATE roles SET privilege = ? WHERE id = ?",
            (rank, role["id"]),
        )
        conn.commit()
    updated = resolve_role(db_path, role["id"])
    if updated is None:
        raise RuntimeError(f"Role '{role['id']}' vanished after privilege update.")
    return updated


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


def rename_role(db_path: Path, name_or_id: str, new_name: str) -> dict:
    """
    Purpose:
        Rename a role. UUID is stable so FK references (flows, access map,
        auth config) need no propagation — only the display name changes.
    Input:
        db_path    — path to the project SQLite database.
        name_or_id — existing role name or UUID.
        new_name   — desired unique name (non-empty).
    Output:
        Dict {id, old_name, new_name, is_active} for the renamed role.
    Side effects:
        Updates roles.name for one row.
    Raises:
        ValueError if role missing, name is 'global', new_name empty/taken,
        or new_name collides with another role.
    """
    new_name = (new_name or "").strip()
    if not new_name:
        raise ValueError("New role name must not be empty.")

    role = resolve_role(db_path, name_or_id)
    if role is None:
        raise ValueError(f"Role '{name_or_id}' not found.")
    if role["name"] == "global":
        raise ValueError("The built-in 'global' role cannot be renamed.")
    if new_name == role["name"]:
        return {
            "id": role["id"],
            "old_name": role["name"],
            "new_name": new_name,
            "is_active": role["is_active"],
        }
    if get_role(db_path, new_name) is not None:
        raise ValueError(f"Role '{new_name}' already exists.")

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "UPDATE roles SET name = ? WHERE id = ?",
            (new_name, role["id"]),
        )
        conn.commit()
    return {
        "id": role["id"],
        "old_name": role["name"],
        "new_name": new_name,
        "is_active": role["is_active"],
    }


def role_dependency_counts(db_path: Path, role_id: str) -> dict[str, int]:
    """
    Purpose:
        Count live references to a role for safe-delete messaging.
        Labels are human-facing keys used by the CLI summary.
    Input:
        db_path — path to the project SQLite database.
        role_id — role UUID.
    Output:
        Dict of label → count for non-zero references (empty if none).
        Possible keys: access_map, flows, endpoint_roles, auth_flows,
        auth_provider, manual_session, session_health, bac_results,
        findings_evidence.
    Side effects: None (read-only).
    """
    counts: dict[str, int] = {}
    with sqlite3.connect(str(db_path)) as conn:
        def _count(sql: str, params: tuple = (role_id,)) -> int:
            row = conn.execute(sql, params).fetchone()
            return int(row[0]) if row else 0

        n = _count("SELECT COUNT(*) FROM access_map WHERE role_id = ?")
        if n:
            counts["access_map"] = n

        n = _count("SELECT COUNT(*) FROM flows WHERE role_id = ?")
        if n:
            counts["flows"] = n

        if _table_exists(conn, "endpoint_roles"):
            n = _count("SELECT COUNT(*) FROM endpoint_roles WHERE role_id = ?")
            if n:
                counts["endpoint_roles"] = n

        if _table_exists(conn, "auth_flow_config"):
            n = _count("SELECT COUNT(*) FROM auth_flow_config WHERE role_id = ?")
            if n:
                counts["auth_flows"] = n

        if _table_exists(conn, "role_auth_provider"):
            n = _count("SELECT COUNT(*) FROM role_auth_provider WHERE role_id = ?")
            if n:
                counts["auth_provider"] = n

        if _table_exists(conn, "manual_session_config"):
            n = _count("SELECT COUNT(*) FROM manual_session_config WHERE role_id = ?")
            if n:
                counts["manual_session"] = n

        session_health = 0
        for table in (
            "session_health_config",
            "session_health_control_flows",
            "session_suspicion_state",
            "role_auth_state",
            "role_auth",
            "role_session_tokens",
        ):
            if _table_exists(conn, table):
                session_health += _count(
                    f"SELECT COUNT(*) FROM {table} WHERE role_id = ?"
                )
        if session_health:
            counts["session_health"] = session_health

        if _table_exists(conn, "bac_results"):
            n = _count(
                "SELECT COUNT(*) FROM bac_results "
                "WHERE attacker_role_id = ? OR target_role_id = ?",
                (role_id, role_id),
            )
            if n:
                counts["bac_results"] = n

        if _table_exists(conn, "finding_evidence"):
            n = _count(
                "SELECT COUNT(*) FROM finding_evidence "
                "WHERE reference_id = ? AND evidence_type IN "
                "('attacker_role', 'target_role', 'role')",
            )
            if n:
                counts["findings_evidence"] = n

    return counts


def delete_role(db_path: Path, name_or_id: str) -> dict:
    """
    Purpose:
        Permanently remove a role and cascade/clean dependent rows.
        Flows tagged with the role are reassigned to the built-in 'global'
        role (role_id is NOT NULL). Access map, auth config, BAC result rows,
        and endpoint_roles for this role are deleted. Finding evidence that
        only references the UUID is left in place (historical).
    Input:
        db_path    — path to the project SQLite database.
        name_or_id — role name or UUID.
    Output:
        Dict {id, name, reassigned_flows, deleted_access_map, was_active}.
    Side effects:
        Mutates multiple tables; may activate 'global' if the deleted role
        was active.
    Raises:
        ValueError if role missing or is the protected 'global' role.
        RuntimeError if the 'global' role is missing (seed required).
    """
    role = resolve_role(db_path, name_or_id)
    if role is None:
        raise ValueError(f"Role '{name_or_id}' not found.")
    if role["name"] == "global":
        raise ValueError("The built-in 'global' role cannot be deleted.")

    role_id = role["id"]
    was_active = bool(role.get("is_active"))

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        global_row = conn.execute(
            "SELECT id FROM roles WHERE name = 'global' LIMIT 1"
        ).fetchone()
        if global_row is None:
            raise RuntimeError(
                "No 'global' role found. Ensure seed_default_context has run."
            )
        global_id = global_row[0]

        # Activate global before removing the active role so capture context
        # remains valid for the rest of this transaction and after commit.
        if was_active:
            conn.execute("UPDATE roles SET is_active = 0")
            conn.execute(
                "UPDATE roles SET is_active = 1 WHERE id = ?", (global_id,)
            )

        reassigned_flows = conn.execute(
            "UPDATE flows SET role_id = ? WHERE role_id = ?",
            (global_id, role_id),
        ).rowcount

        deleted_access = 0
        if _table_exists(conn, "access_map"):
            deleted_access = conn.execute(
                "DELETE FROM access_map WHERE role_id = ?", (role_id,)
            ).rowcount

        for table in (
            "endpoint_roles",
            "auth_flow_config",
            "role_auth_state",
            "role_auth_provider",
            "manual_session_config",
            "session_health_config",
            "session_health_control_flows",
            "session_suspicion_state",
            "role_auth",
            "role_session_tokens",
        ):
            if _table_exists(conn, table):
                conn.execute(f"DELETE FROM {table} WHERE role_id = ?", (role_id,))

        if _table_exists(conn, "bac_results"):
            conn.execute(
                "DELETE FROM bac_results "
                "WHERE attacker_role_id = ? OR target_role_id = ?",
                (role_id, role_id),
            )

        _strip_uuid_from_json_lists(conn, "parameters", "appears_in_roles", role_id)

        conn.execute("DELETE FROM roles WHERE id = ?", (role_id,))
        conn.commit()

    return {
        "id": role_id,
        "name": role["name"],
        "reassigned_flows": max(reassigned_flows, 0),
        "deleted_access_map": max(deleted_access, 0),
        "was_active": was_active,
    }


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


def get_module_by_id(db_path: Path, module_id: str) -> Optional[dict]:
    """
    Purpose:
        Fetch a single module by UUID.
    Input:
        db_path   — path to the project SQLite database.
        module_id — exact module UUID to look up.
    Output:
        Dict with keys {id, name, description, is_active} or None if not found.
    Side effects: None (read-only).
    """
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, name, description, is_active FROM modules WHERE id = ?",
            (module_id,),
        ).fetchone()
    return dict(row) if row else None


def resolve_module(db_path: Path, name_or_id: str) -> Optional[dict]:
    """
    Purpose:
        Resolve a module reference supplied by the user: name first, then UUID.
        Same resolution order as resolve_role() so CLI resources share one rule
        (CLI-004): human-readable names are preferred; UUIDs remain valid.
    Input:
        db_path    — path to the project SQLite database.
        name_or_id — module name or full UUID string.
    Output:
        Dict with keys {id, name, description, is_active} or None if not found.
    Side effects: None (read-only).
    """
    module = get_module(db_path, name_or_id)
    if module is not None:
        return module
    return get_module_by_id(db_path, name_or_id)


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


def rename_module(db_path: Path, name_or_id: str, new_name: str) -> dict:
    """
    Purpose:
        Rename a module. UUID is stable so FK references need no propagation.
    Input:
        db_path    — path to the project SQLite database.
        name_or_id — existing module name or UUID.
        new_name   — desired unique name (non-empty).
    Output:
        Dict {id, old_name, new_name, is_active, description}.
    Side effects:
        Updates modules.name for one row.
    Raises:
        ValueError if module missing, name is 'global', new_name empty,
        or new_name collides with another module.
    """
    new_name = (new_name or "").strip()
    if not new_name:
        raise ValueError("New module name must not be empty.")

    module = resolve_module(db_path, name_or_id)
    if module is None:
        raise ValueError(f"Module '{name_or_id}' not found.")
    if module["name"] == "global":
        raise ValueError("The built-in 'global' module cannot be renamed.")
    if new_name == module["name"]:
        return {
            "id": module["id"],
            "old_name": module["name"],
            "new_name": new_name,
            "is_active": module["is_active"],
            "description": module.get("description", ""),
        }
    if get_module(db_path, new_name) is not None:
        raise ValueError(f"Module '{new_name}' already exists.")

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "UPDATE modules SET name = ? WHERE id = ?",
            (new_name, module["id"]),
        )
        conn.commit()
    return {
        "id": module["id"],
        "old_name": module["name"],
        "new_name": new_name,
        "is_active": module["is_active"],
        "description": module.get("description", ""),
    }


def module_dependency_counts(db_path: Path, module_id: str) -> dict[str, int]:
    """
    Purpose:
        Count live references to a module for safe-delete messaging.
    Input:
        db_path   — path to the project SQLite database.
        module_id — module UUID.
    Output:
        Dict of label → count for non-zero references (empty if none).
        Possible keys: access_map, flows, bac_results, findings_evidence.
    Side effects: None (read-only).
    """
    counts: dict[str, int] = {}
    with sqlite3.connect(str(db_path)) as conn:
        def _count(sql: str, params: tuple = (module_id,)) -> int:
            row = conn.execute(sql, params).fetchone()
            return int(row[0]) if row else 0

        n = _count("SELECT COUNT(*) FROM access_map WHERE module_id = ?")
        if n:
            counts["access_map"] = n

        n = _count("SELECT COUNT(*) FROM flows WHERE module_id = ?")
        if n:
            counts["flows"] = n

        if _table_exists(conn, "bac_results"):
            n = _count("SELECT COUNT(*) FROM bac_results WHERE module_id = ?")
            if n:
                counts["bac_results"] = n

        if _table_exists(conn, "finding_evidence"):
            n = _count(
                "SELECT COUNT(*) FROM finding_evidence "
                "WHERE reference_id = ? AND evidence_type = 'module'",
            )
            if n:
                counts["findings_evidence"] = n

    return counts


def delete_module(db_path: Path, name_or_id: str) -> dict:
    """
    Purpose:
        Permanently remove a module and cascade/clean dependent rows.
        Flows tagged with the module are reassigned to the built-in 'global'
        module. Access map and BAC result rows for this module are deleted.
        Finding evidence that only references the UUID is left in place.
    Input:
        db_path    — path to the project SQLite database.
        name_or_id — module name or UUID.
    Output:
        Dict {id, name, reassigned_flows, deleted_access_map, was_active}.
    Side effects:
        Mutates multiple tables; may activate 'global' if the deleted module
        was active.
    Raises:
        ValueError if module missing or is the protected 'global' module.
        RuntimeError if the 'global' module is missing (seed required).
    """
    module = resolve_module(db_path, name_or_id)
    if module is None:
        raise ValueError(f"Module '{name_or_id}' not found.")
    if module["name"] == "global":
        raise ValueError("The built-in 'global' module cannot be deleted.")

    module_id = module["id"]
    was_active = bool(module.get("is_active"))

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("PRAGMA foreign_keys = ON")
        global_row = conn.execute(
            "SELECT id FROM modules WHERE name = 'global' LIMIT 1"
        ).fetchone()
        if global_row is None:
            raise RuntimeError(
                "No 'global' module found. Ensure seed_default_context has run."
            )
        global_id = global_row[0]

        if was_active:
            conn.execute("UPDATE modules SET is_active = 0")
            conn.execute(
                "UPDATE modules SET is_active = 1 WHERE id = ?", (global_id,)
            )

        reassigned_flows = conn.execute(
            "UPDATE flows SET module_id = ? WHERE module_id = ?",
            (global_id, module_id),
        ).rowcount

        deleted_access = 0
        if _table_exists(conn, "access_map"):
            deleted_access = conn.execute(
                "DELETE FROM access_map WHERE module_id = ?", (module_id,)
            ).rowcount

        if _table_exists(conn, "bac_results"):
            conn.execute(
                "DELETE FROM bac_results WHERE module_id = ?", (module_id,)
            )

        _strip_uuid_from_json_lists(
            conn, "parameters", "appears_in_modules", module_id
        )

        conn.execute("DELETE FROM modules WHERE id = ?", (module_id,))
        conn.commit()

    return {
        "id": module_id,
        "name": module["name"],
        "reassigned_flows": max(reassigned_flows, 0),
        "deleted_access_map": max(deleted_access, 0),
        "was_active": was_active,
    }


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
        client_allowed represents what the client exposes for this pair.
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


# ------------------------------------------------------------------ #
# Access analysis / BAC signal queries (read-only)                    #
# ------------------------------------------------------------------ #

def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    """Return True if *table* exists in the connected database."""
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    return row is not None


def _strip_uuid_from_json_lists(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    value: str,
) -> None:
    """
    Purpose:
        Remove *value* from every JSON array stored in table.column.
        Used when deleting a role/module so parameters.appears_in_* does not
        retain orphaned UUIDs (those columns have no FK).
    Input:
        conn   — open SQLite connection (caller owns commit).
        table  — table name (must already exist; no-op if absent).
        column — TEXT column holding a JSON array of strings.
        value  — UUID string to remove from each array.
    Side effects:
        Updates matching rows in-place. Skips rows with invalid JSON.
    """
    if not _table_exists(conn, table):
        return
    # parameters always has an id PK in this schema; keep the helper narrow.
    if table != "parameters" or column not in (
        "appears_in_roles",
        "appears_in_modules",
    ):
        return
    rows = conn.execute(
        f"SELECT id, {column} FROM {table} WHERE {column} LIKE ?",
        (f"%{value}%",),
    ).fetchall()
    for row_id, raw in rows:
        try:
            items = json.loads(raw or "[]")
        except (TypeError, json.JSONDecodeError):
            continue
        if not isinstance(items, list) or value not in items:
            continue
        cleaned = [item for item in items if item != value]
        conn.execute(
            f"UPDATE {table} SET {column} = ? WHERE id = ?",
            (json.dumps(cleaned), row_id),
        )


def list_endpoints_multi_role(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return endpoints accessed by more than one role.
        These are the primary candidates for BAC/IDOR testing:
        shared endpoints where role boundaries may not be enforced.
    Input:
        db_path — Path to talos.db.
    Output:
        List of dicts: endpoint_id, method, host, normalized_path, role_count,
        role_names (comma-separated resolved role names).
        Ordered by role_count descending (most-shared first).
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        if not _table_exists(conn, "endpoint_roles"):
            return []
        rows = conn.execute(
            """
            SELECT
                er.endpoint_id,
                e.method,
                e.host,
                e.normalized_path,
                COUNT(er.role_id)          AS role_count,
                GROUP_CONCAT(r.name, ', ') AS role_names
            FROM endpoint_roles er
            JOIN endpoints e ON e.id = er.endpoint_id
            JOIN roles     r ON r.id = er.role_id
            GROUP BY er.endpoint_id
            HAVING COUNT(er.role_id) > 1
            ORDER BY role_count DESC, e.normalized_path
            """
        ).fetchall()
        return [dict(r) for r in rows]


def detect_server_deny_endpoints(db_path: Path) -> list[dict]:
    """
    Purpose:
        Return specific endpoints reached under (role, module) pairs where the
        access map asserts server_expected = 'DENY'.

        This is a module boundary violation signal:
        "the backend should block this role from this module, yet traffic reached
        a specific endpoint" — indicating missing server-side enforcement.
    Input:
        db_path — Path to talos.db.
    Output:
        List of dicts: endpoint_id, method, host, normalized_path,
                       role_name, module_name, client_allowed, server_expected,
                       flow_count, flow_ids.
        Ordered by role_name, module_name, normalized_path.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        if (
            not _table_exists(conn, "access_map")
            or not _table_exists(conn, "flows")
            or not _table_exists(conn, "endpoints")
        ):
            return []
        rows = conn.execute(
            """
            SELECT
                e.id              AS endpoint_id,
                e.method,
                e.host,
                e.normalized_path,
                r.name            AS role_name,
                m.name            AS module_name,
                am.client_allowed,
                am.server_expected,
                COUNT(f.id)       AS flow_count,
                GROUP_CONCAT(f.id) AS flow_ids_raw
            FROM access_map am
            JOIN roles     r ON r.id = am.role_id
            JOIN modules   m ON m.id = am.module_id
            JOIN flows     f ON f.role_id   = am.role_id
                             AND f.module_id = am.module_id
            JOIN endpoints e ON e.id = f.endpoint_id
            WHERE am.server_expected = 'DENY'
            GROUP BY e.id, am.role_id, am.module_id
            ORDER BY r.name, m.name, e.normalized_path
            """
        ).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            raw = d.pop("flow_ids_raw", "") or ""
            seen: dict = {}
            for fid in raw.split(","):
                if fid and fid not in seen:
                    seen[fid] = True
                    if len(seen) >= 10:
                        break
            d["flow_ids"] = list(seen.keys())
            result.append(d)
        return result


def detect_deny_with_flows(db_path: Path) -> list[dict]:
    """
    Purpose:
        Case 1 — Client says DENY but traffic exists.
        Signals: client-side bypass, hidden feature exposure, or misconfigured access gate.

        Logic:
            access_map.client_allowed = 'DENY'
            AND flows exist for that (role_id, module_id) pair.
    Input:
        db_path — Path to talos.db.
    Output:
        List of dicts: role_id, role_name, module_id, module_name,
                       client_allowed, server_expected, flow_count.
        Ordered by flow_count descending.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        if not _table_exists(conn, "access_map") or not _table_exists(conn, "flows"):
            return []
        rows = conn.execute(
            """
            SELECT
                am.role_id,
                r.name  AS role_name,
                am.module_id,
                m.name  AS module_name,
                am.client_allowed,
                am.server_expected,
                COUNT(f.id) AS flow_count
            FROM access_map am
            JOIN roles   r ON r.id = am.role_id
            JOIN modules m ON m.id = am.module_id
            JOIN flows   f ON f.role_id = am.role_id AND f.module_id = am.module_id
            WHERE am.client_allowed = 'DENY'
            GROUP BY am.role_id, am.module_id
            ORDER BY flow_count DESC
            """
        ).fetchall()
        return [dict(r) for r in rows]


def detect_allow_without_flows(db_path: Path) -> list[dict]:
    """
    Purpose:
        Case 2 — Client says ALLOW but no traffic observed.
        Signals: missing test coverage for this role/module pair.

        Logic:
            access_map.client_allowed = 'ALLOW'
            AND no flows exist for that (role_id, module_id) pair.
    Input:
        db_path — Path to talos.db.
    Output:
        List of dicts: role_id, role_name, module_id, module_name,
                       client_allowed, server_expected.
        Ordered by role_name, module_name.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        if not _table_exists(conn, "access_map") or not _table_exists(conn, "flows"):
            return []
        rows = conn.execute(
            """
            SELECT
                am.role_id,
                r.name  AS role_name,
                am.module_id,
                m.name  AS module_name,
                am.client_allowed,
                am.server_expected
            FROM access_map am
            JOIN roles   r ON r.id = am.role_id
            JOIN modules m ON m.id = am.module_id
            WHERE am.client_allowed = 'ALLOW'
              AND NOT EXISTS (
                  SELECT 1 FROM flows f
                  WHERE f.role_id = am.role_id
                    AND f.module_id = am.module_id
              )
            ORDER BY r.name, m.name
            """
        ).fetchall()
        return [dict(r) for r in rows]


def get_access_coverage(db_path: Path) -> list[dict]:
    """
    Purpose:
        Full join of access_map + observed flow counts + endpoint exposure counts.
        Single query to answer "expected vs observed" for every (role, module) pair
        that has an access_map entry.

        Columns:
            role_name, module_name  — identity of the pair.
            client_allowed          — what the client exposes.
            server_expected         — asserted backend enforcement.
            flow_count              — flows observed for this pair (0 = none captured).
            endpoint_count          — distinct endpoints touched by this role in this module.
    Input:
        db_path — Path to talos.db.
    Output:
        List of dicts with the columns above, ordered by role_name, module_name.
    Side effects: None.
    """
    if not db_path.exists():
        return []
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        if not _table_exists(conn, "access_map"):
            return []
        rows = conn.execute(
            """
            SELECT
                r.name                      AS role_name,
                m.name                      AS module_name,
                am.client_allowed,
                am.server_expected,
                COUNT(DISTINCT f.id)        AS flow_count,
                COUNT(DISTINCT f.endpoint_id) AS endpoint_count
            FROM access_map am
            JOIN roles   r ON r.id = am.role_id
            JOIN modules m ON m.id = am.module_id
            LEFT JOIN flows f ON f.role_id = am.role_id AND f.module_id = am.module_id
            GROUP BY am.role_id, am.module_id
            ORDER BY r.name, m.name
            """
        ).fetchall()
        return [dict(r) for r in rows]

