"""
Module: talos.projects.role_ntlm

Purpose:
    Bind a Talos role to one named platform-auth (NTLM) profile.

    Cookie/header BAC swaps tokens. NTLM BAC swaps *identity*: the
    attacker role's bound profile is the only credential the outbound
    client may use. Captured Authorization blobs are never replayed.

Dependencies: sqlite3, datetime, pathlib
              talos.projects.db, talos.projects.proxy_config
Data flow:
    auth-config bind-ntlm / Control Panel → role_platform_auth
        → BAC engine resolve_attacker_profile → httpx NTLM handshake
Side effects:
    Bind / unbind write role_platform_auth.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from talos.configuration.model import PlatformAuthEntry
from talos.projects.db import migrate_project_db
from talos.projects.proxy_config import (
    get_platform_auth_entry,
    load_proxy_transport,
)
from talos.proxy.platform_auth import host_matches


class RoleNtlmError(ValueError):
    """Operator-facing bind/unbind error."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def resolve_profile(db_path: Path, key: str) -> Optional[PlatformAuthEntry]:
    """
    Purpose:
        Resolve a platform-auth profile by id, unique host, or unique name.
    Input:
        db_path — project talos.db.
        key     — profile id, host, or display name.
    Output:
        Matching entry, or None when missing / ambiguous.
    Side effects: None.
    """
    needle = (key or "").strip()
    if not needle:
        return None
    hit = get_platform_auth_entry(db_path, needle)
    if hit is not None:
        return hit
    rows = list(load_proxy_transport(db_path).platform_auth_entries)
    lowered = needle.lower()
    name_hits = [
        row
        for row in rows
        if (row.name or "").lower() == lowered
        or row.display_name().lower() == lowered
    ]
    if len(name_hits) == 1:
        return name_hits[0]
    return None


def bind_role_ntlm(db_path: Path, role_id: str, profile_key: str) -> PlatformAuthEntry:
    """
    Purpose:
        Attach one NTLM profile to a role. Replaces any previous binding.
    Input:
        db_path     — project talos.db.
        role_id     — role UUID.
        profile_key — profile id, unique host, or unique name.
    Output:
        The bound PlatformAuthEntry.
    Raises:
        RoleNtlmError when the profile cannot be resolved or has no
        username/password (strip-only rows cannot authenticate a send).
    Side effects: Upserts role_platform_auth.
    """
    migrate_project_db(db_path)
    entry = resolve_profile(db_path, profile_key)
    if entry is None:
        raise RoleNtlmError(
            f"No platform-auth profile matches {profile_key!r}. "
            "Add one with 'talos proxy auth add' or pick an id from "
            "'talos proxy auth list'."
        )
    if not entry.username or not entry.password:
        raise RoleNtlmError(
            f"Profile {entry.display_name()!r} has no username/password. "
            "Strip-only rows cannot be bound as a BAC identity."
        )
    if not entry.id:
        raise RoleNtlmError(
            f"Profile {entry.display_name()!r} has no id. "
            "Re-add it with 'talos proxy auth add'."
        )
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO role_platform_auth (role_id, profile_id, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(role_id) DO UPDATE SET
                profile_id = excluded.profile_id,
                updated_at = excluded.updated_at
            """,
            (role_id, entry.id, _now()),
        )
        conn.commit()
    return entry


def unbind_role_ntlm(db_path: Path, role_id: str) -> bool:
    """
    Purpose:
        Remove the NTLM profile binding for a role.
    Output:
        True when a row was deleted.
    Side effects: Deletes from role_platform_auth.
    """
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        cur = conn.execute(
            "DELETE FROM role_platform_auth WHERE role_id = ?",
            (role_id,),
        )
        conn.commit()
        return cur.rowcount > 0


def get_role_ntlm_profile_id(db_path: Path, role_id: str) -> Optional[str]:
    """Return the bound profile id, or None. Side effects: may migrate."""
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT profile_id FROM role_platform_auth WHERE role_id = ?",
            (role_id,),
        ).fetchone()
    return str(row[0]) if row and row[0] else None


def get_role_ntlm_profile(db_path: Path, role_id: str) -> Optional[PlatformAuthEntry]:
    """
    Purpose:
        Load the bound profile object (including password) for a role.
    Output:
        PlatformAuthEntry, or None when unbound / profile was deleted.
    Side effects: None beyond migrate.
    """
    profile_id = get_role_ntlm_profile_id(db_path, role_id)
    if not profile_id:
        return None
    return resolve_profile(db_path, profile_id)


def resolve_attacker_profile(
    db_path: Path,
    role_id: str,
    host: str = "",
) -> Optional[PlatformAuthEntry]:
    """
    Purpose:
        Identity injector for NTLM BAC: the role's bound profile, when it
        can authenticate the destination host.
    Input:
        db_path — project talos.db.
        role_id — attacker role UUID.
        host    — destination host / origin (optional coverage check).
    Output:
        Credentialed PlatformAuthEntry, or None when unbound, strip-only,
        disabled, or host does not match the profile pattern.
    Side effects: None beyond migrate.
    """
    entry = get_role_ntlm_profile(db_path, role_id)
    if entry is None:
        return None
    if not getattr(entry, "enabled", True):
        return None
    if not entry.username or not entry.password:
        return None
    if host:
        from talos.projects.auth_mechanism import hostname_for_auth_match

        needle = hostname_for_auth_match(host)
        if needle and not host_matches(entry.host, needle):
            return None
    return entry


def list_role_ntlm_bindings(db_path: Path) -> list[dict[str, Any]]:
    """
    Purpose:
        All role → profile bindings for the Auth / Roles UI.
    Output:
        List of dicts: role_id, role_name, profile_id, profile_name, host,
        username, enabled. Missing profiles stay listed with profile_missing.
    Side effects: None beyond migrate.
    """
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT r.id AS role_id, r.name AS role_name,
                   b.profile_id, b.updated_at
            FROM role_platform_auth b
            JOIN roles r ON r.id = b.role_id
            ORDER BY r.name
            """
        ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        entry = resolve_profile(db_path, row["profile_id"])
        out.append(
            {
                "role_id": row["role_id"],
                "role_name": row["role_name"],
                "profile_id": row["profile_id"],
                "profile_name": entry.display_name() if entry else row["profile_id"],
                "host": entry.host if entry else "",
                "username": entry.username if entry else "",
                "enabled": bool(entry.enabled) if entry else False,
                "profile_missing": entry is None,
                "updated_at": row["updated_at"],
            }
        )
    return out
