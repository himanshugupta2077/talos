"""
Module: talos.proxy.http_client

Purpose:
    Single factory for outbound httpx clients used by replay, BAC, unauth,
    auth-strip, and the proxy platform-auth bridge.

    Every client honors the project's layered proxy transport:
        - upstream URL (or Direct)
        - HTTP/2 on/off (HTTP/1.1 when false)
        - keep-alive
        - platform authentication (NTLMv2)

    NTLM / Persistent-Auth is bound to the origin TCP socket. An intercepting
    upstream (Burp with platform auth off) owns that socket, so Type 1 and
    Type 3 land on different origin connections and the browser sees a 401
    loop. Matching platform-auth hosts therefore mount a *direct* transport;
    every other host still uses the configured upstream.

Dependencies: httpx, pathlib, talos.projects.proxy_config, platform_auth
Data flow:
    db_path → load_proxy_transport → httpx.AsyncClient / httpx.Client
Side effects: None — constructs clients only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional, Sequence, Union

import httpx

from talos.configuration.model import PlatformAuthEntry
from talos.projects.proxy_config import ProxyTransport, load_proxy_transport
from talos.proxy.platform_auth import HttpxPlatformAuth, normalize_host

TimeoutLike = Union[httpx.Timeout, float, int]


def _direct_http_transport(*, verify: bool, limits: httpx.Limits) -> httpx.HTTPTransport:
    """
    Purpose:
        HTTP/1.1 transport that never uses a proxy or HTTP_PROXY env.
    Input:
        verify — TLS verify flag (False matches mitmdump --ssl-insecure).
        limits — connection pool limits (keep-alive on for NTLM).
    Output:
        httpx.HTTPTransport speaking directly to the origin.
    Side effects: None.
    """
    return httpx.HTTPTransport(
        verify=verify,
        trust_env=False,
        http1=True,
        http2=False,
        limits=limits,
        retries=0,
    )


def platform_auth_direct_mounts(
    entries: Sequence[PlatformAuthEntry],
    *,
    verify: bool,
    limits: httpx.Limits,
) -> dict[str, httpx.HTTPTransport]:
    """
    Purpose:
        httpx mount map so NTLM hosts skip an intercepting upstream.
    Input:
        entries — configured platform-auth profiles.
        verify  — TLS verify for the direct transport.
        limits  — pool limits (keep-alive required for Persistent-Auth).
    Output:
        ``{"all://host": transport, ...}``. Wildcard ``*.example`` also
        mounts the apex ``example`` (same rule as host_matches).
    Side effects: None.
    """
    transport = _direct_http_transport(verify=verify, limits=limits)
    mounts: dict[str, httpx.HTTPTransport] = {}
    for row in entries:
        if not getattr(row, "enabled", True):
            continue
        if not row.username or not row.password:
            continue
        host = normalize_host(row.host)
        if not host:
            continue
        mounts[f"all://{host}"] = transport
        if host.startswith("*."):
            mounts[f"all://{host[2:]}"] = transport
    return mounts


def client_kwargs(
    db_path: Path,
    *,
    timeout: TimeoutLike,
    follow_redirects: bool = False,
    verify: bool = False,
    transport: Optional[ProxyTransport] = None,
) -> dict[str, Any]:
    """
    Purpose:
        Keyword arguments shared by sync and async httpx clients.
    Input:
        db_path          — project talos.db (transport loaded when omitted).
        timeout          — httpx timeout.
        follow_redirects — engines always disable redirects.
        verify           — TLS verify; False matches mitmdump --ssl-insecure.
        transport        — optional preloaded ProxyTransport.
    Output:
        Dict suitable for httpx.Client / httpx.AsyncClient.
    Side effects: May read layered config when transport is None.
    """
    settings = transport or load_proxy_transport(db_path)
    auth_active = settings.platform_auth_enabled and any(
        row.enabled and row.username and row.password
        for row in settings.platform_auth_entries
    )
    # NTLM/Persistent-Auth needs a reused origin socket even if the operator
    # turned keep-alive off for the mitmproxy hop to the browser.
    if auth_active:
        limits = httpx.Limits()
    elif not settings.keep_alive:
        limits = httpx.Limits(max_keepalive_connections=0, keepalive_expiry=0)
    else:
        limits = httpx.Limits()
    kwargs: dict[str, Any] = {
        "verify": verify,
        "proxy": settings.upstream_url,
        "follow_redirects": follow_redirects,
        "timeout": timeout,
        # Outbound engines always speak HTTP/1.1. Forcing http2=True requires
        # the optional `h2` extra and is unnecessary — IIS Persistent-Auth and
        # NTLM need HTTP/1.1. mitmdump honors proxy.http2 separately.
        "http2": False,
        "limits": limits,
        # HTTP_PROXY must not pull NTLM hosts back through Burp.
        "trust_env": False,
    }
    if auth_active:
        kwargs["auth"] = HttpxPlatformAuth(
            settings.platform_auth_entries,
            enabled=True,
        )
        if settings.upstream_url:
            mounts = platform_auth_direct_mounts(
                settings.platform_auth_entries,
                verify=verify,
                limits=limits,
            )
            if mounts:
                kwargs["mounts"] = mounts
    return kwargs


def create_async_client(
    db_path: Path,
    *,
    timeout: TimeoutLike,
    follow_redirects: bool = False,
    verify: bool = False,
    transport: Optional[ProxyTransport] = None,
) -> httpx.AsyncClient:
    """
    Purpose: Build an AsyncClient honoring project proxy transport.
    Side effects: None.
    """
    return httpx.AsyncClient(
        **client_kwargs(
            db_path,
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=verify,
            transport=transport,
        )
    )


def create_client(
    db_path: Path,
    *,
    timeout: TimeoutLike,
    follow_redirects: bool = False,
    verify: bool = False,
    transport: Optional[ProxyTransport] = None,
) -> httpx.Client:
    """
    Purpose: Build a sync Client honoring project proxy transport.
    Side effects: None.
    """
    return httpx.Client(
        **client_kwargs(
            db_path,
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=verify,
            transport=transport,
        )
    )
