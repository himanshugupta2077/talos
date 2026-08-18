"""
Module: talos.projects.auth_mode

Purpose:
    Project-level authentication *model*. Two first-class, separate paths:

        artifacts      — cookie / header session. BAC injects attacker
                         tokens from role_auth_state. Default for ordinary
                         web apps.

        platform_ntlm  — Windows Integrated Auth (NTLMv2 / IIS
                         Persistent-Auth). Identity is a named platform-auth
                         profile bound to a role. BAC never injects or
                         replays Authorization blobs.

    Stored at ``auth.mode`` in project.yaml. Existing NTLM-only projects
    (credentialed proxy-auth profiles, no HTTP artifact names) resolve as
    platform_ntlm even before the operator sets the key.

Dependencies: pathlib; talos.configuration, talos.projects.auth_mechanism
Data flow:
    project.yaml / inference → resolve_auth_mode → BAC / UI / CLI
Side effects:
    set_auth_mode writes project.yaml. apply_platform_ntlm_defaults also
    forces HTTP/1.1 + keep-alive + platform-auth master switch.
"""

from __future__ import annotations

from pathlib import Path

AUTH_MODE_ARTIFACTS = "artifacts"
AUTH_MODE_PLATFORM_NTLM = "platform_ntlm"
VALID_AUTH_MODES = (AUTH_MODE_ARTIFACTS, AUTH_MODE_PLATFORM_NTLM)

AUTH_MODE_LABELS = {
    AUTH_MODE_ARTIFACTS: "Cookie / header session",
    AUTH_MODE_PLATFORM_NTLM: "Windows / NTLM platform auth",
}


class UnknownAuthMode(ValueError):
    """Raised when an auth.mode value is not in VALID_AUTH_MODES."""


def normalize_auth_mode(value: str) -> str:
    """
    Purpose:
        Canonicalize an operator-supplied auth mode.
    Input:
        value — artifacts | platform_ntlm (case-insensitive; hyphen ok).
    Output:
        AUTH_MODE_ARTIFACTS or AUTH_MODE_PLATFORM_NTLM.
    Raises:
        UnknownAuthMode when the value is not recognised.
    Side effects: None.
    """
    raw = (value or "").strip().lower().replace("-", "_")
    aliases = {
        "artifact": AUTH_MODE_ARTIFACTS,
        "artifacts": AUTH_MODE_ARTIFACTS,
        "cookie": AUTH_MODE_ARTIFACTS,
        "cookies": AUTH_MODE_ARTIFACTS,
        "header": AUTH_MODE_ARTIFACTS,
        "headers": AUTH_MODE_ARTIFACTS,
        "session": AUTH_MODE_ARTIFACTS,
        "platform_ntlm": AUTH_MODE_PLATFORM_NTLM,
        "platform": AUTH_MODE_PLATFORM_NTLM,
        "ntlm": AUTH_MODE_PLATFORM_NTLM,
        "ntlmv2": AUTH_MODE_PLATFORM_NTLM,
    }
    if raw in aliases:
        return aliases[raw]
    raise UnknownAuthMode(
        f"Unknown auth mode {value!r}. "
        f"Valid values: {', '.join(VALID_AUTH_MODES)}."
    )


def get_stored_auth_mode(db_path: Path) -> str:
    """
    Purpose:
        Read ``auth.mode`` from layered config (default artifacts).
        Does not infer from NTLM profiles.
    Input:
        db_path — project talos.db (parent holds project.yaml).
    Output:
        AUTH_MODE_ARTIFACTS or AUTH_MODE_PLATFORM_NTLM.
    Side effects: May read project.yaml / global config.
    """
    from talos.config import TalosConfig
    from talos.configuration.manager import ConfigurationManager

    mgr = ConfigurationManager(TalosConfig.from_env().data_dir)
    effective = mgr.load(
        project_data_dir=db_path.parent if db_path else None,
    )
    raw = ""
    if getattr(effective, "auth", None) is not None:
        raw = str(getattr(effective.auth, "mode", "") or "")
    if not raw:
        raw = str(effective.get("auth.mode") or AUTH_MODE_ARTIFACTS)
    try:
        return normalize_auth_mode(raw)
    except UnknownAuthMode:
        return AUTH_MODE_ARTIFACTS


def resolve_auth_mode(db_path: Path) -> str:
    """
    Purpose:
        Effective project auth model.
        Explicit platform_ntlm always wins. Otherwise NTLM-only projects
        (credentialed profiles, no cookie/header names) infer platform_ntlm
        so existing IIS projects do not need a migration step. Mixed
        (artifacts + NTLM) stays artifacts until the operator sets the mode.
    Input:
        db_path — project talos.db.
    Output:
        AUTH_MODE_ARTIFACTS or AUTH_MODE_PLATFORM_NTLM.
    Side effects: Reads config + auth_config + proxy transport.
    """
    stored = get_stored_auth_mode(db_path)
    if stored == AUTH_MODE_PLATFORM_NTLM:
        return AUTH_MODE_PLATFORM_NTLM
    from talos.projects.auth_mechanism import resolve_auth_mechanism

    if resolve_auth_mechanism(db_path).ntlm_only:
        return AUTH_MODE_PLATFORM_NTLM
    return AUTH_MODE_ARTIFACTS


def is_platform_ntlm_project(db_path: Path) -> bool:
    """True when BAC / Auth UI should use the NTLM identity path."""
    return resolve_auth_mode(db_path) == AUTH_MODE_PLATFORM_NTLM


def set_auth_mode(db_path: Path, mode: str) -> str:
    """
    Purpose:
        Persist ``auth.mode`` on the project. Switching to platform_ntlm
        also applies IIS-safe origin defaults (HTTP/1.1, keep-alive,
        platform-auth master on). Switching to artifacts does not disable
        existing NTLM profiles — capture can still use them.
    Input:
        db_path — project talos.db.
        mode    — artifacts | platform_ntlm.
    Output:
        Canonical mode that was stored.
    Side effects: Writes project.yaml; may update proxy transport knobs.
    """
    canonical = normalize_auth_mode(mode)
    from talos.projects.proxy_config import _set_project_yaml

    _set_project_yaml(db_path, "auth.mode", canonical)
    if canonical == AUTH_MODE_PLATFORM_NTLM:
        apply_platform_ntlm_defaults(db_path)
    return canonical


def apply_platform_ntlm_defaults(db_path: Path) -> None:
    """
    Purpose:
        Force origin settings NTLM / Persistent-Auth needs: HTTP/1.1,
        keep-alive, platform-auth master switch on.
    Side effects: Writes project.yaml via proxy_config helpers.
    """
    from talos.projects.proxy_config import (
        set_http2,
        set_keep_alive,
        set_platform_auth_enabled,
    )

    set_http2(db_path, False)
    set_keep_alive(db_path, True)
    set_platform_auth_enabled(db_path, True)


def auth_mode_public_dict(db_path: Path) -> dict:
    """
    Purpose:
        UI / JSON snapshot of the project's auth model.
    Output:
        mode, stored_mode, inferred, label, ntlm_only, has_artifacts,
        has_platform_ntlm.
    Side effects: Reads config + auth mechanism.
    """
    from talos.projects.auth_mechanism import resolve_auth_mechanism

    stored = get_stored_auth_mode(db_path)
    effective = resolve_auth_mode(db_path)
    mech = resolve_auth_mechanism(db_path)
    return {
        "mode": effective,
        "stored_mode": stored,
        "inferred": effective != stored,
        "label": AUTH_MODE_LABELS.get(effective, effective),
        "ntlm_only": mech.ntlm_only,
        "has_artifacts": mech.has_artifacts,
        "has_platform_ntlm": mech.has_platform_ntlm,
        "profiles": [
            {
                "id": row.id,
                "name": row.name,
                "host": row.host,
                "username": row.username,
                "enabled": row.enabled,
            }
            for row in mech.platform_profiles
        ],
    }
