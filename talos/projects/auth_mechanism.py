"""
Module: talos.projects.auth_mechanism

Purpose:
    Resolve how a project authenticates for engines (IV, unauth, auth-test).

    Two first-class mechanisms:

        1. HTTP artifacts — cookie/header *names* from ``talos auth set``.
           Values live in per-role session state and are stripped/injected
           on the wire.

        2. Platform NTLM — ``talos proxy auth add`` (IIS Windows Integrated
           Auth / Persistent-Auth). The session is the origin TCP handshake,
           not a replayable header. After the handshake, captured requests
           typically have no ``Authorization`` header. Talos also drops
           browser NTLM tokens so it can own the handshake.

    Engines must not require invented cookie/header names when platform
    NTLM is the session. Leftover cookie/header names do not re-enable
    session refresh — NTLM cannot be renewed by extractors. Unauth /
    auth-test must send *without* NTLM
    (``create_async_client(..., platform_auth=False)``); IV / replay keep
    the default client so the handshake still runs.

Dependencies: pathlib, urllib.parse, talos.projects.auth,
              talos.projects.proxy_config, talos.proxy.platform_auth,
              talos.url_identity
Data flow:
    db_path → auth_config + proxy.platform_auth → AuthMechanism
Side effects: None — read-only.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from talos.projects.auth import get_auth_config
from talos.projects.proxy_config import load_proxy_transport
from talos.proxy.platform_auth import host_matches, normalize_host
from talos.url_identity import parse_request_url


# Shared operator text when neither mechanism is configured.
MISSING_AUTH_HINT = (
    "IIS / Windows Integrated Auth (NTLM, Persistent-Auth) does not put an "
    "Authorization header on captured requests after the handshake. "
    "Do not invent a cookie or header name.\n"
    "For NTLM, configure platform authentication (this *is* the session):\n"
    "  talos proxy auth add --host <host> --type ntlmv2 "
    "--username USER --password PASS\n"
    "  talos proxy auth list\n"
    "Then run IV (sends with NTLM) or unauth (sends without NTLM).\n"
    "Cookie/header apps instead: talos auth set --cookie <name> "
    "or --header <name>"
)


@dataclass(frozen=True)
class PlatformNtlmProfile:
    """
    Purpose:
        Public view of one credentialed platform-auth profile.
    Fields:
        id / name / host / username / enabled — no password.
    Side effects: None.
    """

    id: str
    name: str
    host: str
    username: str
    enabled: bool


@dataclass(frozen=True)
class AuthMechanism:
    """
    Purpose:
        Which authentication mechanism(s) the project can use.
    Fields:
        cookies / headers     — configured HTTP artifact names.
        platform_ntlm_enabled — master switch is on and at least one
                                credentialed enabled profile exists.
        platform_profiles     — those credentialed enabled profiles.
    Side effects: None.
    """

    cookies: tuple[str, ...]
    headers: tuple[str, ...]
    platform_ntlm_enabled: bool
    platform_profiles: tuple[PlatformNtlmProfile, ...]

    @property
    def has_artifacts(self) -> bool:
        """True when cookie or header names are configured."""
        return bool(self.cookies or self.headers)

    @property
    def has_platform_ntlm(self) -> bool:
        """True when platform NTLM can authenticate outbound requests."""
        return bool(self.platform_ntlm_enabled and self.platform_profiles)

    @property
    def ntlm_only(self) -> bool:
        """True when NTLM is the session and no HTTP artifacts exist."""
        return self.has_platform_ntlm and not self.has_artifacts

    @property
    def ready(self) -> bool:
        """True when at least one mechanism can authenticate a send."""
        return self.has_artifacts or self.has_platform_ntlm


def hostname_for_auth_match(value: str) -> str:
    """
    Purpose:
        Extract a matchable hostname from an endpoint host / origin / URL.
        Endpoint ``host`` is a canonical origin (``https://app.example``);
        platform-auth profiles store a bare host or ``*.suffix``.
    Input:
        value — origin, URL, or host[:port].
    Output:
        Lowercased hostname, or empty string when unparseable.
    Side effects: None.
    """
    raw = (value or "").strip()
    if not raw:
        return ""
    if "://" in raw:
        try:
            return parse_request_url(raw).hostname
        except ValueError:
            parsed = urlsplit(raw)
            if parsed.hostname:
                return normalize_host(parsed.hostname)
            return ""
    return normalize_host(raw)


def resolve_auth_mechanism(db_path: Path) -> AuthMechanism:
    """
    Purpose:
        Load HTTP artifacts and credentialed platform-NTLM profiles.
    Input:
        db_path — project talos.db (layered proxy config is loaded from it).
    Output:
        AuthMechanism. Strip-only NTLM rows (no username/password) are
        omitted — they cannot authenticate a send.
    Side effects: Reads auth_config and layered proxy YAML.
    """
    cfg = get_auth_config(db_path)
    cookies = tuple(cfg.get("cookies") or [])
    headers = tuple(cfg.get("headers") or [])

    transport = load_proxy_transport(db_path)
    profiles: list[PlatformNtlmProfile] = []
    if transport.platform_auth_enabled:
        for row in transport.platform_auth_entries:
            if not getattr(row, "enabled", True):
                continue
            if not row.username or not row.password:
                continue
            if not (row.host or "").strip():
                continue
            profiles.append(
                PlatformNtlmProfile(
                    id=str(row.id or ""),
                    name=str(row.name or row.host),
                    host=str(row.host),
                    username=str(row.username),
                    enabled=True,
                )
            )

    return AuthMechanism(
        cookies=cookies,
        headers=headers,
        platform_ntlm_enabled=bool(transport.platform_auth_enabled and profiles),
        platform_profiles=tuple(profiles),
    )


def platform_ntlm_covers_host(mechanism: AuthMechanism, host: str) -> bool:
    """
    Purpose:
        True when a credentialed NTLM profile matches ``host``.
    Input:
        mechanism — from resolve_auth_mechanism.
        host      — endpoint origin, URL, or hostname.
    Output:
        bool.
    Side effects: None.
    """
    if not mechanism.has_platform_ntlm:
        return False
    needle = hostname_for_auth_match(host)
    if not needle:
        return False
    return any(host_matches(row.host, needle) for row in mechanism.platform_profiles)


def uncovered_ntlm_hosts(
    mechanism: AuthMechanism,
    hosts: list[str] | set[str] | tuple[str, ...],
) -> list[str]:
    """
    Purpose:
        Return stored host values that have no matching NTLM profile.
    Input:
        mechanism — from resolve_auth_mechanism.
        hosts     — endpoint origins / hostnames in the scan scope.
    Output:
        Sorted unique stored host strings that are not covered.
        Empty hosts are ignored.
    Side effects: None.
    """
    missing: set[str] = set()
    for raw in hosts:
        value = (raw or "").strip()
        if not value:
            continue
        if not platform_ntlm_covers_host(mechanism, value):
            missing.add(value)
    return sorted(missing)


def missing_auth_error(hosts: list[str] | None = None) -> str:
    """
    Purpose:
        Actionable error when neither HTTP artifacts nor platform NTLM exist.
    Input:
        hosts — optional scan-scope hosts to mention.
    Output:
        Single error string (may contain newlines).
    Side effects: None.
    """
    if hosts:
        shown = ", ".join(sorted({h for h in hosts if h}))
        if shown:
            return (
                f"No HTTP auth artifacts and no platform NTLM session "
                f"for: {shown}.\n{MISSING_AUTH_HINT}"
            )
    return (
        "No HTTP auth artifacts and no platform NTLM session.\n"
        + MISSING_AUTH_HINT
    )
