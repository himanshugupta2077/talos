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

    ``encode_outbound_headers`` prepares captured / mutated header maps so
    httpx can send Latin-1 and UTF-8 field values (IV unicode probes).

    Unauth and auth-test pass ``platform_auth=False`` so IIS Persistent-Auth
    is not re-applied after HTTP artifacts are stripped. Authenticated
    engines (IV, replay, BAC) leave the default (project setting).

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

from collections.abc import Mapping, Sequence as AbcSequence
from pathlib import Path
from typing import Any, Optional, Sequence, Union

import httpx

from talos.configuration.model import PlatformAuthEntry
from talos.projects.proxy_config import ProxyTransport, load_proxy_transport
from talos.proxy.platform_auth import HttpxPlatformAuth, normalize_host

TimeoutLike = Union[httpx.Timeout, float, int]
DirectTransport = Union[httpx.HTTPTransport, httpx.AsyncHTTPTransport]
HeaderValue = Union[str, bytes, list[Any], tuple[Any, ...]]
OutboundHeaders = Union[Mapping[Any, Any], Sequence[tuple[Any, Any]], None]


def _header_text_is_ascii(text: str) -> bool:
    """True when every code point is in the US-ASCII range. Side effects: None."""
    return all(ord(ch) < 128 for ch in text)


def _encode_header_text(text: str) -> bytes:
    """
    Purpose:
        Encode a header name or value for httpx/h11.

        httpx.Headers defaults to ASCII and raises UnicodeEncodeError
        (``'ascii' codec can't encode character '\\xe9'...``) on Latin-1
        such as the IV unicode probe ``é``. Historical HTTP field values
        are ISO-8859-1; characters outside that set (e.g. ``中``) go as
        UTF-8 octets (RFC 7230 obs-text).
    Side effects: None.
    """
    try:
        return text.encode("latin-1")
    except UnicodeEncodeError:
        return text.encode("utf-8")


def _encode_header_value(value: Any) -> HeaderValue:
    """Encode one header value (or list of values) for httpx. Side effects: None."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, (list, tuple)):
        encoded = [_encode_header_value(item) for item in value]
        return type(value)(encoded)  # type: ignore[return-value]
    text = value if isinstance(value, str) else str(value if value is not None else "")
    if _header_text_is_ascii(text):
        return text
    return _encode_header_text(text)


def _header_item_needs_bytes(key: Any, value: Any) -> bool:
    """True when name or value has non-ASCII text. Side effects: None."""
    if isinstance(key, str) and not _header_text_is_ascii(key):
        return True
    if isinstance(value, str) and not _header_text_is_ascii(value):
        return True
    if isinstance(value, (list, tuple)):
        return any(_header_item_needs_bytes("", item) for item in value)
    return False


def encode_outbound_headers(headers: OutboundHeaders) -> Any:
    """
    Purpose:
        Return headers that httpx can send. ASCII-only maps are returned
        unchanged so stored string headers and existing tests stay intact.

        Non-ASCII values (IV ``é``, captured Latin-1 cookies, CJK) are
        encoded as bytes so httpx does not fail with unexpected_error
        ``ascii codec can't encode``.
    Input:
        headers — mapping or sequence of (name, value) pairs.
    Output:
        Same shape as input; values that need it are ``bytes``.
    Side effects: None.
    """
    if headers is None:
        return {}
    if isinstance(headers, Mapping):
        if not any(_header_item_needs_bytes(k, v) for k, v in headers.items()):
            return headers
        out: dict[Any, Any] = {}
        for key, value in headers.items():
            name = key
            if isinstance(key, str) and not _header_text_is_ascii(key):
                name = _encode_header_text(key)
            out[name] = _encode_header_value(value)
        return out
    if isinstance(headers, AbcSequence) and not isinstance(headers, (str, bytes)):
        pairs = list(headers)
        if not any(_header_item_needs_bytes(k, v) for k, v in pairs):
            return headers
        encoded_pairs: list[tuple[Any, Any]] = []
        for key, value in pairs:
            name = key
            if isinstance(key, str) and not _header_text_is_ascii(key):
                name = _encode_header_text(key)
            encoded_pairs.append((name, _encode_header_value(value)))
        return encoded_pairs
    return headers


def _direct_http_transport(
    *,
    verify: bool,
    limits: httpx.Limits,
    async_client: bool = False,
) -> DirectTransport:
    """
    Purpose:
        HTTP/1.1 transport that never uses a proxy or HTTP_PROXY env.
    Input:
        verify       — TLS verify flag (False matches mitmdump --ssl-insecure).
        limits       — connection pool limits (keep-alive on for NTLM).
        async_client — True builds AsyncHTTPTransport (AsyncClient mounts).
    Output:
        Sync or async transport speaking directly to the origin.
    Side effects: None.
    """
    cls = httpx.AsyncHTTPTransport if async_client else httpx.HTTPTransport
    return cls(
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
    async_client: bool = False,
) -> dict[str, DirectTransport]:
    """
    Purpose:
        httpx mount map so NTLM hosts skip an intercepting upstream.
    Input:
        entries      — configured platform-auth profiles.
        verify       — TLS verify for the direct transport.
        limits       — pool limits (keep-alive required for Persistent-Auth).
        async_client — True mounts AsyncHTTPTransport for AsyncClient.
    Output:
        ``{"all://host": transport, ...}``. Wildcard ``*.example`` also
        mounts the apex ``example`` (same rule as host_matches).
    Side effects: None.
    """
    transport = _direct_http_transport(
        verify=verify, limits=limits, async_client=async_client
    )
    mounts: dict[str, DirectTransport] = {}
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
    platform_auth: Optional[bool] = None,
    platform_auth_entries: Optional[Sequence[PlatformAuthEntry]] = None,
    async_client: bool = False,
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
        platform_auth    — None: honor project setting (authenticated send).
                           False: never attach NTLM (unauth / auth-test).
                           True: attach NTLM when credentialed profiles exist.
        platform_auth_entries — when set, use *these* profiles only (BAC
                           attacker identity). Ignores the project-wide
                           enabled-row list so two NTLM accounts on the
                           same host cannot collide.
        async_client     — True mounts AsyncHTTPTransport (required by
                           AsyncClient; sync HTTPTransport has no __aenter__).
    Output:
        Dict suitable for httpx.Client / httpx.AsyncClient.
    Side effects: May read layered config when transport is None.
    """
    settings = transport or load_proxy_transport(db_path)
    entries = (
        list(platform_auth_entries)
        if platform_auth_entries is not None
        else list(settings.platform_auth_entries)
    )
    have_creds = any(
        row.enabled and row.username and row.password
        for row in entries
    )
    if platform_auth is False:
        auth_active = False
    elif platform_auth_entries is not None:
        # Caller selected the identity (BAC attacker profile).
        auth_active = have_creds
    elif platform_auth is True:
        auth_active = have_creds
    else:
        auth_active = bool(settings.platform_auth_enabled and have_creds)
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
            entries,
            enabled=True,
        )
        if settings.upstream_url:
            mounts = platform_auth_direct_mounts(
                entries,
                verify=verify,
                limits=limits,
                async_client=async_client,
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
    platform_auth: Optional[bool] = None,
    platform_auth_entries: Optional[Sequence[PlatformAuthEntry]] = None,
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
            platform_auth=platform_auth,
            platform_auth_entries=platform_auth_entries,
            async_client=True,
        )
    )


def create_client(
    db_path: Path,
    *,
    timeout: TimeoutLike,
    follow_redirects: bool = False,
    verify: bool = False,
    transport: Optional[ProxyTransport] = None,
    platform_auth: Optional[bool] = None,
    platform_auth_entries: Optional[Sequence[PlatformAuthEntry]] = None,
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
            platform_auth=platform_auth,
            platform_auth_entries=platform_auth_entries,
        )
    )
