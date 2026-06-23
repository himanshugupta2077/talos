"""
Module: talos.projects.bac.auth_prereq

Purpose:
    Validate auth prerequisites for a role before BAC attack jobs are generated.

    A role is attack-ready when all four conditions hold:
        1. login_flow_id is assigned in role_auth.
        2. checkpoint_flow_id is assigned in role_auth.
        3. auth_config is non-empty (at least one cookie or header name configured).
        4. An active session token exists in role_session_tokens.

    If condition 4 fails and auto_generate=True, this module replays the login
    flow inline to extract and store a JWT before returning.

    Any missing prerequisite produces a clear error string so the CLI can
    surface actionable remediation steps to the user.

Dependencies: asyncio, re, pathlib
Data flow:
    bac.cli → check_auth_prereqs → project SQLite DB; optionally → replay engine
Side effects:
    auto_generate=False — None (read-only).
    auto_generate=True  — may send outbound HTTP; writes to role_session_tokens.
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from talos.projects.auth import (
    get_auth_config,
    get_role_auth,
    get_active_session_token,
    store_session_token,
)
from talos.replay.engine import replay_flow

_log = logging.getLogger(__name__)

# Standard compact JWT regex (same as auth_cli.py).
_JWT_RE = re.compile(
    r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"
)


@dataclass
class PrereqResult:
    """
    Purpose:
        Outcome of an auth prerequisite check for a single role.

    Fields:
        role_id      — UUID of the role checked.
        role_name    — Name of the role (for display messages).
        passed       — True when all four conditions are satisfied.
        errors       — Human-readable error strings (empty when passed=True).
        active_token — The active session token string if passed=True; None otherwise.
    """

    role_id: str
    role_name: str
    passed: bool
    errors: list[str] = field(default_factory=list)
    active_token: Optional[str] = None


def check_auth_prereqs(
    db_path: Path,
    project_id: str,
    role_id: str,
    role_name: str,
    auto_generate: bool = False,
) -> PrereqResult:
    """
    Purpose:
        Validate all auth prerequisites for a role.
        Checks login flow, checkpoint flow, auth config, and active session token.
        Optionally generates a session token when one is missing.
    Input:
        db_path       — Path to the project's talos.db.
        project_id    — Project identifier.
        role_id       — UUID of the role to check.
        role_name     — Name of the role (used in error messages).
        auto_generate — When True, replay the login flow to generate a token if
                        one is missing.  When False, missing token → error.
    Output:
        PrereqResult; passed=True with active_token set, or passed=False
        with populated errors list.
    Side effects:
        auto_generate=True: may send outbound HTTP; writes to role_session_tokens.
    """
    errors: list[str] = []

    # Check 3: auth injection config must be non-empty.
    auth_config = get_auth_config(db_path)
    if not auth_config["cookies"] and not auth_config["headers"]:
        errors.append(
            "Auth injection not configured. "
            "Run 'talos auth set --cookie <name>' or 'talos auth set --header <name>' first."
        )

    # Check 1 & 2: login and checkpoint flows must be assigned.
    role_auth = get_role_auth(db_path, role_id)

    if role_auth is None or not role_auth.get("login_flow_id"):
        errors.append(
            f"Missing login flow for role: {role_name}. "
            f"Run 'talos auth mark-login {role_id} <flow_id>'."
        )

    if role_auth is None or not role_auth.get("checkpoint_flow_id"):
        errors.append(
            f"Missing checkpoint flow for role: {role_name}. "
            f"Run 'talos auth mark-checkpoint {role_id} <flow_id>'."
        )

    # Return early — token check/generation is pointless without a login flow.
    if errors:
        return PrereqResult(
            role_id=role_id,
            role_name=role_name,
            passed=False,
            errors=errors,
        )

    # Check 4: active session token must exist.
    token_info = get_active_session_token(db_path, role_id)

    if token_info is None:
        if not auto_generate:
            errors.append(
                f"No active session token for role: {role_name}. "
                f"Run 'talos auth generate {role_id}' to create one."
            )
            return PrereqResult(
                role_id=role_id,
                role_name=role_name,
                passed=False,
                errors=errors,
            )

        # Auto-generate: replay login flow and extract JWT.
        login_flow_id: str = role_auth["login_flow_id"]  # type: ignore[index]
        token = _generate_token_inline(db_path, project_id, role_id, login_flow_id)

        if token is None:
            errors.append(
                f"Auto-generate failed for role: {role_name}. "
                "Login flow replay did not return a JWT. "
                f"Run 'talos auth generate {role_id}' manually to diagnose."
            )
            return PrereqResult(
                role_id=role_id,
                role_name=role_name,
                passed=False,
                errors=errors,
            )

        token_info = {"token": token}
        _log.info("[bac] Auto-generated session token for role %s.", role_name)

    return PrereqResult(
        role_id=role_id,
        role_name=role_name,
        passed=True,
        active_token=token_info["token"],
    )


def _generate_token_inline(
    db_path: Path,
    project_id: str,
    role_id: str,
    login_flow_id: str,
) -> Optional[str]:
    """
    Purpose:
        Replay the login flow, extract a JWT from the response body, and store it.
    Input:
        db_path       — Path to the project DB.
        project_id    — Project identifier.
        role_id       — UUID of the role.
        login_flow_id — UUID of the login flow to replay.
    Output:
        Raw JWT string if extraction succeeded; None otherwise.
    Side effects:
        Sends outbound HTTP; writes replay flow row; writes role_session_tokens row.
    """
    import talos.replay.db as replay_db

    outcome = asyncio.run(
        replay_flow(
            flow_id=login_flow_id,
            db_path=db_path,
            project_id=project_id,
            source="manual_replay",
            replay_reason="bac_token_generate",
        )
    )

    if not outcome.success or outcome.replayed_flow_id is None:
        return None

    replayed = replay_db.get_flow_for_replay(db_path, outcome.replayed_flow_id)
    if replayed is None:
        return None

    resp_body = replayed.get("response_body")
    if resp_body is None:
        return None

    body_str = (
        resp_body.decode("utf-8", errors="replace")
        if isinstance(resp_body, bytes)
        else resp_body
    )

    match = _JWT_RE.search(body_str)
    if match is None:
        return None

    token = match.group(0)
    store_session_token(db_path, role_id, token)
    return token
