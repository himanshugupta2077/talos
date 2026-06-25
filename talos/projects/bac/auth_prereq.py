"""
Module: talos.projects.bac.auth_prereq

Purpose:
    Validate auth prerequisites for a role before BAC attack jobs are generated.

    A role is attack-ready when all three conditions hold:
        1. At least one flow is configured in auth_flow_config with an extractor.
        2. auth_config is non-empty (at least one cookie or header name).
        3. A current auth state exists in role_auth_state (all required artifacts
           are present).

    If condition 3 fails and auto_generate=True, this module runs a full session
    refresh (replays all flows, executes extractors, stores state) before returning.

    Any missing prerequisite produces a clear error string so the CLI can
    surface actionable remediation steps to the user.

Dependencies: pathlib
Data flow:
    bac.cli -> check_auth_prereqs -> project SQLite DB; optionally -> replay engine
Side effects:
    auto_generate=False -- None (read-only).
    auto_generate=True  -- may send outbound HTTP; writes to role_auth_state.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from talos.projects.auth import (
    get_auth_config,
    list_auth_flow_configs,
    get_role_auth_state,
)
from talos.projects.session_health import refresh_auth_state

_log = logging.getLogger(__name__)


@dataclass
class PrereqResult:
    """
    Purpose:
        Outcome of an auth prerequisite check for a single role.

    Fields:
        role_id    -- UUID of the role checked.
        role_name  -- Name of the role (for display messages).
        passed     -- True when all conditions are satisfied.
        errors     -- Human-readable error strings (empty when passed=True).
        auth_state -- Current {artifact: value} dict if passed=True; None otherwise.
    """

    role_id: str
    role_name: str
    passed: bool
    errors: list[str] = field(default_factory=list)
    auth_state: Optional[dict] = None


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
        Checks auth_flow_config (flows + extractors), auth_config (requirements),
        and role_auth_state (current collected artifacts).
        Optionally triggers a full session refresh when auth state is absent.
    Input:
        db_path       -- Path to the project's talos.db.
        project_id    -- Project identifier.
        role_id       -- UUID of the role to check.
        role_name     -- Name of the role (used in error messages).
        auto_generate -- When True, refresh auth state if it is missing.
                         When False, missing state -> error.
    Output:
        PrereqResult; passed=True with auth_state set, or passed=False
        with populated errors list.
    Side effects:
        auto_generate=True: may send outbound HTTP; writes role_auth_state.
    """
    errors: list[str] = []

    # Check 1: auth requirements must be non-empty.
    auth_req = get_auth_config(db_path)
    if not auth_req["cookies"] and not auth_req["headers"]:
        errors.append(
            "Auth requirements not configured. "
            "Run 'talos auth set --cookie <name>' or '--header <name>' first."
        )

    # Check 2: at least one flow with an extractor must be configured.
    flow_configs = list_auth_flow_configs(db_path, role_id)
    flows_with_extractor = [c for c in flow_configs if c["extractor_code"] is not None]

    if not flow_configs:
        errors.append(
            f"No auth flows configured for role: {role_name}. "
            f"Run 'talos auth-config add-flow {role_id} <flow_id>'."
        )
    elif not flows_with_extractor:
        errors.append(
            f"No extractors set for any flow in role: {role_name}. "
            f"Run 'talos auth-config set-extractor {role_id} <flow_id> <file.py>'."
        )

    if errors:
        return PrereqResult(
            role_id=role_id,
            role_name=role_name,
            passed=False,
            errors=errors,
        )

    # Check 3: current auth state must cover all required artifacts.
    required = set(auth_req["cookies"] + auth_req["headers"])
    state_info = get_role_auth_state(db_path, role_id)
    state = state_info["state"]
    missing = required - set(state.keys())

    if missing:
        if not auto_generate:
            errors.append(
                f"Auth state missing for role: {role_name}. "
                f"Missing artifacts: {', '.join(sorted(missing))}. "
                f"Run 'talos auth-config refresh {role_id}' to generate."
            )
            return PrereqResult(
                role_id=role_id,
                role_name=role_name,
                passed=False,
                errors=errors,
            )

        # Auto-generate: replay all flows and collect artifacts.
        _log.info("[bac] Auto-generating auth state for role %s.", role_name)
        success = refresh_auth_state(db_path, role_id, project_id)

        if not success:
            errors.append(
                f"Auto-generate failed for role: {role_name}. "
                "Auth flow replay or extractor did not produce all required artifacts. "
                f"Run 'talos auth-config refresh {role_id}' manually to diagnose."
            )
            return PrereqResult(
                role_id=role_id,
                role_name=role_name,
                passed=False,
                errors=errors,
            )

        # Re-read state after successful refresh.
        state_info = get_role_auth_state(db_path, role_id)
        state = state_info["state"]

    return PrereqResult(
        role_id=role_id,
        role_name=role_name,
        passed=True,
        auth_state=state,
    )
