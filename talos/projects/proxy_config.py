"""
Module: talos.projects.proxy_config

Purpose:
    Read/write helpers and shared resolution for per-project proxy transport:

        - Direct vs Upstream Proxy (legacy proxy_config.upstream_url + YAML)
        - HTTP/2 vs forced HTTP/1.1
        - Origin keep-alive
        - Platform authentication (NTLMv2) rows

    All consumers (proxy launcher, replay/BAC/unauth engines, addon) must
    obtain transport settings only via this module — never hardcode host,
    port, URL, or credentials.

Dependencies: sqlite3, pathlib, urllib.parse, dataclasses
              talos.projects.db (migrate_project_db)
              talos.configuration
Data flow:
    talos.proxy.cli → resolve_upstream_url / set_* / platform-auth CRUD
    talos.proxy.launcher.build_mitmdump_command consumes http2 + upstream
    replay / BAC / unauth → load_proxy_transport → httpx
Side effects:
    Writers update project.yaml (and dual-write upstream to SQLite).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from talos.configuration.model import PlatformAuthEntry
from talos.projects.db import migrate_project_db


class InvalidUpstreamUrl(ValueError):
    """
    Purpose:
        Raised when an upstream proxy URL fails validation.
        Callers in the CLI layer map this to EXIT_USAGE (2).
    """


def validate_upstream_url(url: str) -> str:
    """
    Purpose:
        Validate and normalize an upstream proxy URL string.
    Input:
        url — candidate upstream proxy URL from CLI or stored config.
    Output:
        Stripped URL string safe to pass to mitmdump --mode upstream:<url>
        and to httpx as proxy=.
    Side effects: None.
    Raises:
        InvalidUpstreamUrl when the URL is empty, missing a scheme/host,
        or uses a scheme other than http/https.
    """
    cleaned = (url or "").strip()
    if not cleaned:
        raise InvalidUpstreamUrl(
            "Upstream proxy URL must not be empty."
        )

    parsed = urlparse(cleaned)
    if parsed.scheme not in ("http", "https"):
        raise InvalidUpstreamUrl(
            "Upstream proxy URL must start with http:// or https:// "
            f"(got {cleaned!r})."
        )
    if not parsed.hostname:
        raise InvalidUpstreamUrl(
            f"Upstream proxy URL must include a host (got {cleaned!r})."
        )
    # Reject bare credentials without a host (urlparse edge cases) and
    # schemes that look valid but have no netloc.
    if not parsed.netloc:
        raise InvalidUpstreamUrl(
            f"Upstream proxy URL must include a host (got {cleaned!r})."
        )
    return cleaned


def get_upstream_url(db_path: Path) -> Optional[str]:
    """
    Purpose:
        Read the effective upstream proxy URL for a project database path.
        Uses the layered configuration system (defaults → global → legacy
        SQLite / project.yaml) so global inheritance and YAML overrides apply.
    Input:
        db_path — absolute Path to the project's talos.db.
    Output:
        The upstream URL string, or None when the project is in Direct mode
        (no upstream configured) or the DB does not exist yet.
    Side effects:
        May migrate the project DB when reading the legacy bridge.
    """
    if not db_path.exists() and not (db_path.parent / "project.yaml").exists():
        return None
    from talos.configuration.manager import ConfigurationManager
    from talos.config import TalosConfig

    mgr = ConfigurationManager(TalosConfig.from_env().data_dir)
    effective = mgr.load(project_data_dir=db_path.parent)
    return effective.upstream_url()


def set_upstream_url(db_path: Path, url: str) -> str:
    """
    Purpose:
        Configure Talos to use Upstream Proxy mode, forwarding traffic to
        the given proxy (Burp, ZAP, corporate proxy, etc.).
    Input:
        db_path — absolute Path to the project's talos.db.
        url     — upstream proxy URL (http:// or https:// host[:port]).
    Output:
        The validated URL that was stored.
    Side effects:
        Dual-writes project.yaml (proxy.upstream) and the proxy_config table.
    Raises:
        InvalidUpstreamUrl when url fails validation.
    """
    validated = validate_upstream_url(url)
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO proxy_config (id, upstream_url) VALUES ('default', ?)"
            " ON CONFLICT(id) DO UPDATE SET upstream_url = excluded.upstream_url",
            (validated,),
        )
        conn.commit()
    _write_project_upstream_yaml(db_path.parent, enabled=True, url=validated)
    return validated


def clear_upstream_url(db_path: Path) -> None:
    """
    Purpose:
        Revert Talos to Direct mode — no upstream proxy; mitmdump and
        outbound clients connect straight to the target server.
    Input:
        db_path — absolute Path to the project's talos.db.
    Side effects:
        Dual-writes project.yaml and proxy_config (upstream cleared).
    """
    migrate_project_db(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO proxy_config (id, upstream_url) VALUES ('default', NULL)"
            " ON CONFLICT(id) DO UPDATE SET upstream_url = NULL"
        )
        conn.commit()
    _write_project_upstream_yaml(db_path.parent, enabled=False, url=None)


def resolve_upstream_url(
    db_path: Path,
    *,
    cli_upstream: Optional[str] = None,
    cli_no_upstream: bool = False,
) -> Optional[str]:
    """
    Purpose:
        Single shared resolution for the effective upstream proxy URL.
        Used by `talos proxy start` (and any other CLI that may accept a
        one-shot override) so project config and CLI flags never diverge.
    Input:
        db_path          — absolute Path to the project's talos.db.
        cli_upstream     — when set, this URL overrides project config
                           (does not write the DB).
        cli_no_upstream  — when True, force Direct mode for this invocation
                           regardless of project config (does not write the DB).
    Output:
        Validated upstream URL string, or None for Direct mode.
    Side effects: None (reads layered config only when falling back).
    Raises:
        InvalidUpstreamUrl when a CLI-supplied URL fails validation, or
        when the stored project URL is present but invalid.
    Resolution order:
        1. cli_no_upstream → None (Direct)
        2. cli_upstream set → validated CLI URL
        3. else layered config (get_upstream_url); None if unset
    """
    if cli_no_upstream:
        return None
    if cli_upstream is not None:
        return validate_upstream_url(cli_upstream)

    stored = get_upstream_url(db_path)
    if stored is None:
        return None
    # Re-validate stored values so corrupt/legacy rows surface as usage errors
    # instead of being passed blindly to mitmdump or httpx.
    return validate_upstream_url(stored)


def _write_project_upstream_yaml(
    project_data_dir: Path, *, enabled: bool, url: Optional[str]
) -> None:
    """
    Purpose:
        Keep project.yaml in sync when proxy config is written via the
        legacy proxy_config helpers / `talos proxy config` CLI.
    Side effects:
        Creates or updates project.yaml proxy.upstream keys.
    """
    try:
        from talos.configuration.io import load_yaml_file, project_config_path, save_yaml_file
        from talos.configuration.merge import set_path

        path = project_config_path(project_data_dir)
        current = load_yaml_file(path) if path.exists() else {}
        current = set_path(current, "proxy.upstream.enabled", bool(enabled and url))
        current = set_path(
            current, "proxy.upstream.url", url if (enabled and url) else None
        )
        save_yaml_file(path, current)
    except Exception:
        # Best-effort: SQLite remains authoritative for this write path.
        pass


# ------------------------------------------------------------------ #
# Origin transport (HTTP/1.1, keep-alive, platform auth)               #
# ------------------------------------------------------------------ #


@dataclass(frozen=True)
class ProxyTransport:
    """
    Purpose:
        Snapshot of origin-connection settings for one project.
    Fields:
        upstream_url            — httpx/mitmdump upstream, or None for Direct.
        http2                   — False forces HTTP/1.1.
        keep_alive              — reuse origin connections.
        platform_auth_enabled   — master switch for NTLM handshake / strip.
        platform_auth_entries   — host-scoped credential rows.
    """

    upstream_url: Optional[str]
    http2: bool
    keep_alive: bool
    platform_auth_enabled: bool
    platform_auth_entries: tuple[PlatformAuthEntry, ...]


def load_proxy_transport(db_path: Path) -> ProxyTransport:
    """
    Purpose:
        Load the effective origin-transport settings for a project DB.
    Input:
        db_path — absolute Path to the project's talos.db.
    Output:
        ProxyTransport (defaults when the project has no overrides).
    Side effects: May migrate the project DB via the layered config loader.
    """
    from talos.configuration.manager import ConfigurationManager
    from talos.config import TalosConfig

    if not db_path.exists() and not (db_path.parent / "project.yaml").exists():
        return ProxyTransport(
            upstream_url=None,
            http2=True,
            keep_alive=True,
            platform_auth_enabled=False,
            platform_auth_entries=(),
        )
    mgr = ConfigurationManager(TalosConfig.from_env().data_dir)
    effective = mgr.load(project_data_dir=db_path.parent)
    auth = effective.proxy.platform_auth
    return ProxyTransport(
        upstream_url=effective.upstream_url(),
        http2=bool(effective.proxy.http2),
        keep_alive=bool(effective.proxy.keep_alive),
        platform_auth_enabled=bool(auth.enabled),
        platform_auth_entries=tuple(auth.entries),
    )


def set_http2(db_path: Path, enabled: bool) -> None:
    """
    Purpose:
        Persist proxy.http2 (False = force HTTP/1.1).
    Side effects: Writes project.yaml.
    """
    _set_project_yaml(db_path, "proxy.http2", bool(enabled))


def set_keep_alive(db_path: Path, enabled: bool) -> None:
    """
    Purpose:
        Persist proxy.keep_alive.
    Side effects: Writes project.yaml.
    """
    _set_project_yaml(db_path, "proxy.keep_alive", bool(enabled))


def set_platform_auth_enabled(db_path: Path, enabled: bool) -> None:
    """
    Purpose:
        Persist proxy.platform_auth.enabled.
    Side effects: Writes project.yaml.
    """
    _set_project_yaml(db_path, "proxy.platform_auth.enabled", bool(enabled))


def replace_platform_auth_entries(
    db_path: Path, entries: list[PlatformAuthEntry]
) -> None:
    """
    Purpose:
        Replace the full platform-auth entry list and enable the feature
        when at least one row remains.
    Side effects: Writes project.yaml.
    """
    serialized = [_entry_to_storage(entry) for entry in entries]
    _set_project_yaml(db_path, "proxy.platform_auth.entries", serialized)
    _set_project_yaml(
        db_path, "proxy.platform_auth.enabled", bool(serialized)
    )


def add_platform_auth_entry(db_path: Path, entry: PlatformAuthEntry) -> PlatformAuthEntry:
    """
    Purpose:
        Insert or replace the row for entry.host (case-insensitive).
    Output:
        The stored entry.
    Side effects: Writes project.yaml.
    """
    current = list(load_proxy_transport(db_path).platform_auth_entries)
    host_key = entry.host.lower()
    next_entries = [row for row in current if row.host.lower() != host_key]
    next_entries.append(entry)
    replace_platform_auth_entries(db_path, next_entries)
    return entry


def remove_platform_auth_entry(db_path: Path, host: str) -> bool:
    """
    Purpose:
        Remove the row whose host matches (case-insensitive).
    Output:
        True when a row was removed.
    Side effects: Writes project.yaml when a row existed.
    """
    host_key = (host or "").strip().lower()
    current = list(load_proxy_transport(db_path).platform_auth_entries)
    next_entries = [row for row in current if row.host.lower() != host_key]
    if len(next_entries) == len(current):
        return False
    replace_platform_auth_entries(db_path, next_entries)
    return True


def _entry_to_storage(entry: PlatformAuthEntry) -> dict:
    return {
        "host": entry.host,
        "auth_type": entry.auth_type,
        "username": entry.username,
        "password": entry.password,
        "domain": entry.domain,
        "domain_hostname": entry.domain_hostname,
        "spnego": bool(entry.spnego),
        "negotiate": bool(entry.negotiate),
    }


def _set_project_yaml(db_path: Path, path: str, value: object) -> None:
    """
    Purpose:
        Write one dotted key to project.yaml via ConfigurationManager.
    Side effects: Creates/updates project.yaml.
    """
    from talos.configuration.manager import ConfigurationManager
    from talos.config import TalosConfig

    mgr = ConfigurationManager(TalosConfig.from_env().data_dir)
    mgr.set_value(
        path,
        value,
        global_scope=False,
        project_data_dir=db_path.parent,
        project_db_path=db_path if db_path.exists() else None,
    )
