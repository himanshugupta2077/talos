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

Dependencies: httpx, pathlib, talos.projects.proxy_config, platform_auth
Data flow:
    db_path → load_proxy_transport → httpx.AsyncClient / httpx.Client
Side effects: None — constructs clients only.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional, Union

import httpx

from talos.projects.proxy_config import ProxyTransport, load_proxy_transport
from talos.proxy.platform_auth import HttpxPlatformAuth

TimeoutLike = Union[httpx.Timeout, float, int]


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
    limits = httpx.Limits()
    if not settings.keep_alive:
        limits = httpx.Limits(max_keepalive_connections=0, keepalive_expiry=0)
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
    }
    if settings.platform_auth_enabled and any(
        row.enabled and row.username and row.password
        for row in settings.platform_auth_entries
    ):
        kwargs["auth"] = HttpxPlatformAuth(
            settings.platform_auth_entries,
            enabled=True,
        )
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
