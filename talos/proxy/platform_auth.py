"""
Module: talos.proxy.platform_auth

Purpose:
    Burp-style platform authentication toward the origin:

        - Match a destination host to a configured credential row.
        - Complete NTLMv2 (raw NTLM scheme by default) on httpx clients.
        - Optionally strip WWW-Authenticate: Negotiate so a browser can
          fall back to NTLM on an HTTP/1.1 keep-alive connection.

    Negotiate/Kerberos AP-REQ blobs are one-time-use and connection-bound;
    Talos never replays a captured Authorization: Negotiate token.

Dependencies: base64, logging, httpx, talos.configuration.model, talos.proxy.ntlm
Data flow:
    EffectiveConfig.proxy.platform_auth → match_platform_auth
        → HttpxPlatformAuth (replay / BAC / unauth / addon)
    401 WWW-Authenticate → strip_negotiate_challenges
Side effects: Sends extra 401 handshake requests on matching hosts.
"""

from __future__ import annotations

import base64
import logging
from typing import Iterable, Mapping, Optional, Sequence
from urllib.parse import urlsplit

import httpx

from talos.configuration.model import PlatformAuthEntry
from talos.proxy.ntlm import NtlmContext, NtlmError, ntlm_message_type

logger = logging.getLogger(__name__)

# Hop-by-hop / reconstructed headers we never copy onto the origin request.
_SKIP_REQUEST_HEADERS = frozenset(
    {
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "upgrade",
        "expect",
    }
)


def normalize_host(host: str) -> str:
    """
    Purpose:
        Lowercase host and strip a trailing :port (not IPv6 brackets).
    Side effects: None.
    """
    value = (host or "").strip().lower()
    if value.startswith("[") and "]" in value:
        return value[1 : value.index("]")]
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    return value


def host_matches(pattern: str, host: str) -> bool:
    """
    Purpose:
        Exact host match, or ``*.example.com`` suffix match.
    Side effects: None.
    """
    needle = normalize_host(host)
    pat = normalize_host(pattern)
    if not pat or not needle:
        return False
    if pat.startswith("*."):
        suffix = pat[1:]
        return needle.endswith(suffix) or needle == pat[2:]
    return needle == pat


def match_platform_auth(
    entries: Sequence[PlatformAuthEntry],
    host: str,
) -> Optional[PlatformAuthEntry]:
    """
    Purpose:
        Return the first entry whose host pattern matches ``host``.
    Side effects: None.
    """
    for entry in entries:
        if host_matches(entry.host, host):
            return entry
    return None


def authorization_scheme(entry: PlatformAuthEntry) -> str:
    """
    Purpose:
        HTTP auth scheme for this row. Negotiate is off unless the operator
        explicitly enabled it (Burp "Negotiate Auth Scheme").
    Side effects: None.
    """
    if entry.negotiate:
        return "Negotiate"
    return "NTLM"


def encode_auth_header(entry: PlatformAuthEntry, token: bytes) -> str:
    """
    Purpose:
        Build an Authorization header value. SPNEGO wrapping is not implemented;
        ``spnego=True`` is accepted for config compatibility and still sends
        raw NTLMSSP (same as Burp with SPNEGO Encoding disabled).
    Side effects: None.
    """
    del entry  # reserved for a future SPNEGO wrapper
    return base64.b64encode(token).decode("ascii")


def parse_www_authenticate(values: Iterable[str]) -> dict[str, Optional[str]]:
    """
    Purpose:
        Map scheme → optional token from one or more WWW-Authenticate values.
    Output:
        Lowercased scheme name → token string or None (challenge with no blob).
    Side effects: None.
    """
    found: dict[str, Optional[str]] = {}
    for raw in values:
        text = (raw or "").strip()
        if not text:
            continue
        parts = text.split(None, 1)
        scheme = parts[0].lower()
        token = parts[1].strip() if len(parts) > 1 else None
        found[scheme] = token
    return found


def collect_www_authenticate(headers: Mapping[str, str]) -> list[str]:
    """
    Purpose:
        Collect WWW-Authenticate values from a header mapping (httpx or dict).
    Side effects: None.
    """
    get_list = getattr(headers, "get_list", None)
    if callable(get_list):
        try:
            values = list(get_list("www-authenticate") or [])
            if values:
                return [str(v) for v in values]
        except Exception:
            pass
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        try:
            values = list(get_all("WWW-Authenticate") or [])
            if values:
                return [str(v) for v in values]
        except Exception:
            pass
    single = None
    for key, value in headers.items():
        if str(key).lower() == "www-authenticate":
            single = value
            break
    if single is None:
        return []
    return [str(single)]


def strip_negotiate_challenges(values: Sequence[str]) -> list[str]:
    """
    Purpose:
        Drop WWW-Authenticate: Negotiate… and keep NTLM (and anything else).
    Side effects: None.
    """
    kept: list[str] = []
    for raw in values:
        scheme = (raw or "").strip().split(None, 1)[0].lower() if raw else ""
        if scheme != "negotiate":
            kept.append(raw)
    return kept


def filter_request_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """
    Purpose:
        Copy request headers that are safe to replay toward the origin.
    Side effects: None.
    """
    out: dict[str, str] = {}
    for key, value in headers.items():
        if str(key).lower() in _SKIP_REQUEST_HEADERS:
            continue
        out[str(key)] = str(value)
    return out


class HttpxPlatformAuth(httpx.Auth):
    """
    Purpose:
        httpx Auth that runs NTLMv2 for matching hosts and passes through
        everything else. Reads the request URL host on each request.
    """

    requires_request_body = True
    requires_response_body = True

    def __init__(self, entries: Sequence[PlatformAuthEntry], *, enabled: bool = True) -> None:
        self.entries: tuple[PlatformAuthEntry, ...] = tuple(entries)
        self.enabled = bool(enabled)

    def auth_flow(self, request: httpx.Request):
        """
        Purpose:
            Generator httpx uses to attach NTLM Type 1 / Type 3 as needed.
        Side effects: May yield extra handshake requests on the same connection.
        """
        if not self.enabled:
            yield request
            return
        host = request.url.host or ""
        entry = match_platform_auth(self.entries, host)
        if entry is None or not entry.username or not entry.password:
            yield request
            return
        yield from _ntlm_auth_flow(request, entry)


def _ntlm_auth_flow(request: httpx.Request, entry: PlatformAuthEntry):
    """
    Purpose:
        401 → Type 1 → 401 Type 2 → Type 3. Scheme is NTLM unless negotiate=True.
    """
    scheme = authorization_scheme(entry)
    workstation = entry.domain_hostname or entry.host or "WORKSTATION"
    ctx = NtlmContext(
        username=entry.username,
        password=entry.password,
        domain=entry.domain,
        workstation=workstation,
    )

    response = yield request
    if response.status_code != 401:
        return
    challenges = parse_www_authenticate(collect_www_authenticate(response.headers))
    if not _challenge_usable(challenges, entry):
        return

    request.headers["Authorization"] = (
        f"{scheme} {encode_auth_header(entry, ctx.type1())}"
    )
    response = yield request
    if response.status_code != 401:
        return

    token_b64 = _challenge_token(response, scheme, entry)
    if not token_b64:
        logger.info(
            "Platform auth: no %s Type 2 challenge from %s",
            scheme,
            request.url.host,
        )
        return
    try:
        type2 = base64.b64decode(token_b64)
    except (ValueError, TypeError) as exc:
        logger.info("Platform auth: invalid Type 2 blob: %s", exc)
        return
    if ntlm_message_type(type2) != 2:
        logger.info("Platform auth: challenge is not NTLM Type 2")
        return
    try:
        type3 = ctx.type3(type2)
    except NtlmError as exc:
        logger.info("Platform auth: Type 3 failed: %s", exc)
        return
    request.headers["Authorization"] = f"{scheme} {encode_auth_header(entry, type3)}"
    yield request


def _challenge_usable(
    challenges: Mapping[str, Optional[str]], entry: PlatformAuthEntry
) -> bool:
    """True when the 401 offers a scheme we are willing to speak."""
    if entry.negotiate and "negotiate" in challenges:
        return True
    return "ntlm" in challenges


def _challenge_token(
    response: httpx.Response, scheme: str, entry: PlatformAuthEntry
) -> Optional[str]:
    challenges = parse_www_authenticate(collect_www_authenticate(response.headers))
    token = challenges.get(scheme.lower())
    if token:
        return token
    if not entry.negotiate:
        return challenges.get("ntlm")
    return challenges.get("negotiate") or challenges.get("ntlm")


def host_from_url(url: str) -> str:
    """
    Purpose: Hostname of a request URL, or empty.
    Side effects: None.
    """
    try:
        return urlsplit(url).hostname or ""
    except ValueError:
        return ""
