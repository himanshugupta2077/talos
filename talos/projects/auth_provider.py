"""
Module: talos.projects.auth_provider

Purpose:
    Authentication Provider model — decouples HOW a session is obtained from
    HOW Talos uses the session.

    Every role selects exactly one provider:

        AUTO   — Talos replays configured login flows and extracts artifacts
                 automatically.  This is the existing Session Health Engine path.

        MANUAL — The tester supplies authentication artifacts directly.  Talos
                 never attempts to log in; it simply injects the provided values
                 into every replay for that role.  This works with any auth
                 technology (OAuth2, OIDC, SAML, MFA, device-bound auth, etc.)
                 because Talos only needs the final authenticated artifacts.

    Session states:

        READY            — Authentication is valid and can be used.
        EXPIRING         — Session is approaching expiration.
        EXPIRED          — Session is past its expiry; no longer usable.
        WAITING_FOR_USER — Talos requires new auth artifacts from the tester.
                           This is the terminal state for MANUAL sessions when
                           the session has expired.
        REFRESHING       — AUTO provider is currently refreshing.
        FAILED           — Session refresh or validation failed.

    Manual session file format (produced by set-session, consumed by parser):

        --header
        Authorization
        Bearer eyJ...

        --cookie
        session
        abc123

        --cookie
        csrf
        xyz789

        expires_at
        2026-07-03 13:00 UTC

        (or)

        ttl_seconds
        3600

    At least one of expires_at / ttl_seconds must be set.
    If neither is provided the session is immediately WAITING_FOR_USER.

Dependencies: json, sqlite3, datetime, pathlib
Data flow:
    auth_config_cli → functions here → project SQLite DB
    session_health  → get_provider(), apply_manual_session() → role_auth_state
Side effects:
    Write functions mutate role_auth_provider and manual_session_config tables.
    apply_manual_session() also writes auth_config and role_auth_state.
"""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional


# ------------------------------------------------------------------ #
# Provider type constants                                              #
# ------------------------------------------------------------------ #

PROVIDER_AUTO = "auto"
"""Talos replays login flows to obtain a session automatically."""

PROVIDER_MANUAL = "manual"
"""Tester supplies authentication artifacts directly."""

VALID_PROVIDERS = (PROVIDER_AUTO, PROVIDER_MANUAL)


# ------------------------------------------------------------------ #
# Session state constants                                              #
# ------------------------------------------------------------------ #

SESSION_READY = "READY"
"""Authentication is valid and ready to use."""

SESSION_EXPIRING = "EXPIRING"
"""Session is approaching expiration; refresh is recommended."""

SESSION_EXPIRED = "EXPIRED"
"""Session is past its expiry; no longer usable."""

SESSION_WAITING_FOR_USER = "WAITING_FOR_USER"
"""Talos requires new authentication artifacts from the tester."""

SESSION_REFRESHING = "REFRESHING"
"""AUTO provider is currently refreshing the session."""

SESSION_FAILED = "FAILED"
"""Session refresh or validation explicitly failed."""


# ------------------------------------------------------------------ #
# Provider CRUD                                                        #
# ------------------------------------------------------------------ #

def get_provider(db_path: Path, role_id: str) -> str:
    """
    Purpose:
        Return the configured provider for a role.
    Input:
        db_path — Path to the project's talos.db.
        role_id — UUID of the role.
    Output:
        PROVIDER_AUTO or PROVIDER_MANUAL; defaults to PROVIDER_AUTO when no
        row is stored for this role.
    Side effects: None (read-only).
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT provider FROM role_auth_provider WHERE role_id = ?",
            (role_id,),
        ).fetchone()
    return row[0] if row else PROVIDER_AUTO


def set_provider(db_path: Path, role_id: str, provider: str) -> None:
    """
    Purpose:
        Set the authentication provider for a role.
        Validates that the provider value is one of VALID_PROVIDERS.
    Input:
        db_path  — Path to the project's talos.db.
        role_id  — UUID of the role.
        provider — PROVIDER_AUTO or PROVIDER_MANUAL.
    Output: None
    Side effects:
        Upserts one row into role_auth_provider.
    Raises:
        ValueError if provider is not a recognised value.
    """
    if provider not in VALID_PROVIDERS:
        raise ValueError(
            f"Unknown provider '{provider}'. Valid values: {', '.join(VALID_PROVIDERS)}"
        )
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO role_auth_provider (role_id, provider, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(role_id) DO UPDATE SET
                provider   = excluded.provider,
                updated_at = excluded.updated_at
            """,
            (role_id, provider, now),
        )
        conn.commit()


# ------------------------------------------------------------------ #
# Manual session config CRUD                                          #
# ------------------------------------------------------------------ #

def get_manual_session_config(db_path: Path, role_id: str) -> Optional[dict]:
    """
    Purpose:
        Load the manual session configuration for a role.
    Input:
        db_path — Path to the project's talos.db.
        role_id — UUID of the role.
    Output:
        Dict with keys:
            'headers'     — {name: value} dict of request headers to inject.
            'cookies'     — {name: value} dict of cookies to inject.
            'expires_at'  — UTC ISO-8601 expiry string or None.
            'ttl_seconds' — Integer TTL or None.
            'created_at'  — ISO-8601 string when this config was last saved.
            'updated_at'  — ISO-8601 string of last update.
        Returns None when no config is stored for this role.
    Side effects: None (read-only).
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            """
            SELECT headers_json, cookies_json, expires_at, ttl_seconds,
                   created_at, updated_at
            FROM manual_session_config WHERE role_id = ?
            """,
            (role_id,),
        ).fetchone()
    if row is None:
        return None
    return {
        "headers":     json.loads(row["headers_json"] or "{}"),
        "cookies":     json.loads(row["cookies_json"] or "{}"),
        "expires_at":  row["expires_at"],
        "ttl_seconds": row["ttl_seconds"],
        "created_at":  row["created_at"],
        "updated_at":  row["updated_at"],
    }


def set_manual_session_config(
    db_path: Path,
    role_id: str,
    headers: dict,
    cookies: dict,
    expires_at: Optional[str],
    ttl_seconds: Optional[int],
) -> None:
    """
    Purpose:
        Store or replace the manual session configuration for a role.
        Updates auth_config with the artifact names so the BAC engine knows
        which headers and cookies to inject.
    Input:
        db_path     — Path to the project's talos.db.
        role_id     — UUID of the role.
        headers     — {header_name: value} dict to inject.
        cookies     — {cookie_name: value} dict to inject.
        expires_at  — UTC ISO-8601 string, or None.
        ttl_seconds — Token lifetime from now, or None.
    Output: None
    Side effects:
        Upserts one row in manual_session_config.
        Inserts missing artifact names into auth_config.
    """
    from talos.projects.db import migrate_project_db
    from talos.projects.auth import set_auth_fields
    migrate_project_db(db_path)
    now = datetime.now(timezone.utc).isoformat()
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO manual_session_config
                (role_id, headers_json, cookies_json, expires_at, ttl_seconds,
                 created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(role_id) DO UPDATE SET
                headers_json = excluded.headers_json,
                cookies_json = excluded.cookies_json,
                expires_at   = excluded.expires_at,
                ttl_seconds  = excluded.ttl_seconds,
                created_at   = excluded.created_at,
                updated_at   = excluded.updated_at
            """,
            (
                role_id,
                json.dumps(headers),
                json.dumps(cookies),
                expires_at,
                ttl_seconds,
                now,
                now,
            ),
        )
        conn.commit()

    # Keep auth_config in sync so the BAC engine knows which artifacts to inject.
    set_auth_fields(
        db_path,
        cookies=list(cookies.keys()),
        headers=list(headers.keys()),
    )


def clear_manual_session_config(db_path: Path, role_id: str) -> None:
    """
    Purpose:
        Remove the manual session configuration for a role.
    Input:
        db_path — Path to the project's talos.db.
        role_id — UUID of the role.
    Output: None
    Side effects:
        Deletes the row from manual_session_config.
    """
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "DELETE FROM manual_session_config WHERE role_id = ?", (role_id,)
        )
        conn.commit()


# ------------------------------------------------------------------ #
# Manual session expiry computation                                    #
# ------------------------------------------------------------------ #

def get_manual_session_expiry(db_path: Path, role_id: str) -> Optional[datetime]:
    """
    Purpose:
        Compute the effective expiry datetime for a manual session.
        Checks expires_at first; falls back to created_at + ttl_seconds.
    Input:
        db_path — Path to the project's talos.db.
        role_id — UUID of the role.
    Output:
        Timezone-aware UTC datetime of expiry, or None when the config is
        absent or no TTL/expiry is defined.
    Side effects: None (read-only).
    """
    cfg = get_manual_session_config(db_path, role_id)
    if cfg is None:
        return None

    if cfg["expires_at"]:
        try:
            dt = datetime.fromisoformat(
                cfg["expires_at"].replace("UTC", "+00:00").strip()
            )
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            pass

    if cfg["ttl_seconds"] is not None:
        try:
            created = datetime.fromisoformat(cfg["created_at"])
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            return created + timedelta(seconds=cfg["ttl_seconds"])
        except (ValueError, TypeError):
            pass

    return None


# ------------------------------------------------------------------ #
# Apply manual session → role_auth_state                              #
# ------------------------------------------------------------------ #

def apply_manual_session(db_path: Path, role_id: str) -> bool:
    """
    Purpose:
        Load the stored manual session config and write its artifacts into
        role_auth_state so the BAC engine and replay engine can use them.
        Called by session_health.refresh_auth_state() when provider is MANUAL.
    Input:
        db_path — Path to the project's talos.db.
        role_id — UUID of the role.
    Output:
        True  — Artifacts written; session is valid.
        False — Config is absent, no TTL/expiry defined, or session is expired.
    Side effects:
        Writes role_auth_state rows on success.
    """
    from talos.projects.auth import store_role_auth_state
    from talos.projects.db import migrate_project_db
    migrate_project_db(db_path)

    cfg = get_manual_session_config(db_path, role_id)
    if cfg is None:
        return False

    # Must have at least one expiry definition.
    expiry = get_manual_session_expiry(db_path, role_id)
    if expiry is None:
        return False

    now = datetime.now(timezone.utc)
    if now >= expiry:
        # Session is past its expiry.
        return False

    # Merge headers and cookies into a flat artifact dict for role_auth_state.
    state: dict[str, str] = {}
    for name, value in cfg["headers"].items():
        state[name] = str(value)
    for name, value in cfg["cookies"].items():
        state[name] = str(value)

    if not state:
        # No artifacts to inject — nothing useful.
        return False

    collected_at = now.isoformat()
    store_role_auth_state(db_path, role_id, state, collected_at)
    return True


# ------------------------------------------------------------------ #
# Session state display                                                #
# ------------------------------------------------------------------ #

def get_session_display_state(db_path: Path, role_id: str) -> str:
    """
    Purpose:
        Compute and return the human-visible session state for a role.
        Used by 'talos auth-config status' for the MANUAL provider.
    Input:
        db_path — Path to the project's talos.db.
        role_id — UUID of the role.
    Output:
        One of: SESSION_READY, SESSION_EXPIRING, SESSION_EXPIRED,
                SESSION_WAITING_FOR_USER.
    Side effects: None (read-only).
    """
    provider = get_provider(db_path, role_id)

    if provider == PROVIDER_MANUAL:
        cfg = get_manual_session_config(db_path, role_id)
        if cfg is None:
            return SESSION_WAITING_FOR_USER

        expiry = get_manual_session_expiry(db_path, role_id)
        if expiry is None:
            return SESSION_WAITING_FOR_USER

        now = datetime.now(timezone.utc)
        remaining = (expiry - now).total_seconds()

        if remaining <= 0:
            return SESSION_EXPIRED
        if remaining < 300:  # less than 5 minutes
            return SESSION_EXPIRING
        return SESSION_READY

    # AUTO provider — derive from role_auth_state age.
    from talos.projects.auth import get_role_auth_state, get_session_health_config
    state_info = get_role_auth_state(db_path, role_id)
    if not state_info["state"] or state_info["collected_at"] is None:
        return SESSION_WAITING_FOR_USER

    health_cfg = get_session_health_config(db_path, role_id)
    ttl = health_cfg["ttl_seconds"]
    refresh_before = health_cfg["refresh_before_seconds"]

    try:
        collected_at = datetime.fromisoformat(state_info["collected_at"])
        if collected_at.tzinfo is None:
            collected_at = collected_at.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return SESSION_WAITING_FOR_USER

    now = datetime.now(timezone.utc)
    age = (now - collected_at).total_seconds()

    if age >= ttl:
        return SESSION_EXPIRED
    if age >= ttl - refresh_before:
        return SESSION_EXPIRING
    return SESSION_READY


# ------------------------------------------------------------------ #
# Manual session file parsing and formatting                          #
# ------------------------------------------------------------------ #

def parse_session_file(content: str) -> dict:
    """
    Purpose:
        Parse the manual session file format into structured data.
        Handles --cookie and --header sections, expires_at, and ttl_seconds.
    Input:
        content — full text of the session file.
    Output:
        Dict with keys:
            'headers'     — {name: value} dict.
            'cookies'     — {name: value} dict.
            'expires_at'  — string or None.
            'ttl_seconds' — int or None.
        Empty dicts and None values on parse error.
    Side effects: None.
    """
    headers: dict = {}
    cookies: dict = {}
    expires_at: Optional[str] = None
    ttl_seconds: Optional[int] = None

    lines = [line.rstrip() for line in content.splitlines()]
    mode: Optional[str] = None  # 'header' | 'cookie' | None
    pending_key: Optional[str] = None

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        if line == "--header":
            mode = "header"
            pending_key = None
            i += 1
            continue

        if line == "--cookie":
            mode = "cookie"
            pending_key = None
            i += 1
            continue

        if line == "expires_at":
            mode = None
            pending_key = None
            i += 1
            if i < len(lines) and lines[i].strip():
                expires_at = lines[i].strip()
            i += 1
            continue

        if line == "ttl_seconds":
            mode = None
            pending_key = None
            i += 1
            if i < len(lines) and lines[i].strip():
                try:
                    ttl_seconds = int(lines[i].strip())
                except ValueError:
                    pass
            i += 1
            continue

        # Comments and blank lines.
        if not line or line.startswith("#"):
            if not line:
                pending_key = None  # blank line resets pending key
            i += 1
            continue

        # Key-value pair in cookie or header mode.
        if mode in ("cookie", "header"):
            if pending_key is None:
                pending_key = line
            else:
                if mode == "header":
                    headers[pending_key] = line
                else:
                    cookies[pending_key] = line
                pending_key = None

        i += 1

    return {
        "headers":     headers,
        "cookies":     cookies,
        "expires_at":  expires_at,
        "ttl_seconds": ttl_seconds,
    }


_SESSION_TEMPLATE = """\
# Manual session configuration for role: {role_name}
#
# Provide the authentication artifacts for this role.
# Lines starting with # are comments and are ignored.
#
# HEADERS
# -------
# Use --header followed by key/value pairs (one key, one value per line).
# Example:
#
--header
# Authorization
# Bearer eyJ...

# COOKIES
# -------
# Use --cookie followed by key/value pairs (one key, one value per line).
# Example:
#
--cookie
# session
# abc123def456

# EXPIRY
# ------
# Provide either expires_at (absolute UTC datetime) or ttl_seconds (relative).
# At least one is required. If neither is set, the session is not usable.
#
# expires_at
# 2026-07-03 13:00 UTC
#
# ttl_seconds
# 3600
"""


def format_session_template(role_name: str, existing: Optional[dict] = None) -> str:
    """
    Purpose:
        Produce the session file template to show in the editor.
        If existing config is provided, pre-fill the current values.
    Input:
        role_name — Human-readable role name for the comment header.
        existing  — Optional dict from get_manual_session_config().
    Output:
        Multi-line string ready to write to a temp file.
    Side effects: None.
    """
    if existing is None:
        return _SESSION_TEMPLATE.format(role_name=role_name)

    lines = [
        f"# Manual session configuration for role: {role_name}",
        "# Lines starting with # are comments and are ignored.",
        "",
    ]

    if existing["headers"]:
        lines.append("--header")
        for name, value in existing["headers"].items():
            lines.append(name)
            lines.append(value)
            lines.append("")
    else:
        lines += [
            "--header",
            "# HeaderName",
            "# value",
            "",
        ]

    if existing["cookies"]:
        lines.append("--cookie")
        for name, value in existing["cookies"].items():
            lines.append(name)
            lines.append(value)
            lines.append("")
    else:
        lines += [
            "--cookie",
            "# cookie_name",
            "# value",
            "",
        ]

    if existing["expires_at"]:
        lines += [
            "expires_at",
            existing["expires_at"],
            "",
        ]
    elif existing["ttl_seconds"] is not None:
        lines += [
            "ttl_seconds",
            str(existing["ttl_seconds"]),
            "",
        ]
    else:
        lines += [
            "# expires_at",
            "# 2026-07-03 13:00 UTC",
            "#",
            "# ttl_seconds",
            "# 3600",
            "",
        ]

    return "\n".join(lines)
