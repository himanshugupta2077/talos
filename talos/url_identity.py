"""
Module: talos.url_identity

Purpose:
    Shared canonical URL identity for Talos core. Every subsystem that needs
    scheme/host/port/path identity (scope, capture, endpoint clustering,
    replay/attack eligibility) must use this module instead of ad-hoc
    urlparse / host splitting.

Conceptual API:
    effective_port("http", None)  -> 80
    effective_port("https", None) -> 443
    canonical_authority("http://example.com")       -> "example.com"
    canonical_authority("http://example.com:80")    -> "example.com"
    canonical_authority("http://example.com:8000")  -> "example.com:8000"
    canonical_origin("http://example.com")          -> "http://example.com"
    canonical_origin("http://example.com:80")       -> "http://example.com"
    canonical_origin("http://example.com:8000")     -> "http://example.com:8000"

Dependencies: dataclasses, ipaddress, re, urllib.parse
Data flow:
    Callers pass raw URLs or component tuples → UrlIdentity / helpers →
    normalized scheme, hostname, ports, authority, origin, path.
Side effects: None — pure functions only.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

# Default ports for schemes Talos scopes as HTTP(S) application traffic.
_DEFAULT_PORTS: dict[str, int] = {
    "http": 80,
    "https": 443,
}

_SUPPORTED_SCHEMES = frozenset({"http", "https"})

# Host[:port] before an optional path. IPv6 authorities use brackets.
_HOSTPORT_RE = re.compile(
    r"^(?:"
    r"\[(?P<ipv6>[^\]]+)\]"  # [2001:db8::1]
    r"|(?P<host>[^/:]+)"  # hostname or IPv4
    r")"
    r"(?::(?P<port>\d+))?"  # optional :port
    r"$"
)

_DUPLICATE_SLASH_RE = re.compile(r"/{2,}")


class UrlIdentityError(ValueError):
    """Raised when a URL or scope prefix cannot be parsed into a valid identity."""


@dataclass(frozen=True, slots=True)
class UrlIdentity:
    """
    Purpose:
        Immutable parsed representation of a request URL or scopeable target.
    Fields:
        scheme          — "http", "https", or None when the input omitted protocol.
        hostname        — lowercased hostname or canonical IP text.
        explicit_port   — port as written in the authority, or None if omitted.
        effective_port  — explicit port, or scheme default, or None if unknown.
        path            — normalized absolute path (leading slash; no query).
        raw             — original input string (stripped).
    """

    scheme: str | None
    hostname: str
    explicit_port: int | None
    effective_port: int | None
    path: str
    raw: str

    @property
    def canonical_authority(self) -> str:
        """Hostname with non-default port when required (see module docstring)."""
        return format_canonical_authority(
            self.scheme, self.hostname, self.explicit_port
        )

    @property
    def canonical_origin(self) -> str:
        """
        scheme://authority using default-port elision.
        Requires a scheme; raises UrlIdentityError when scheme is absent.
        """
        if not self.scheme:
            raise UrlIdentityError(
                f"Cannot form canonical origin without a scheme: {self.raw!r}"
            )
        return format_canonical_origin(
            self.scheme, self.hostname, self.explicit_port
        )


def effective_port(scheme: str | None, port: int | None) -> int | None:
    """
    Purpose:
        Resolve the effective TCP port for a scheme + optional explicit port.
    Input:
        scheme — "http", "https", or None.
        port   — explicit port from the authority, or None.
    Output:
        Explicit port when present; otherwise the scheme default (80/443);
        None when scheme is missing or unsupported and port is omitted.
    Side effects: None.
    """
    if port is not None:
        return port
    if scheme is None:
        return None
    return _DEFAULT_PORTS.get(scheme.lower())


def format_canonical_authority(
    scheme: str | None,
    hostname: str,
    port: int | None,
) -> str:
    """
    Purpose:
        Build the canonical authority string (host, optional :port).
    Rules:
        - Default ports for the scheme are omitted (http→80, https→443).
        - When scheme is None, any explicit port is kept (port-specific host rule).
        - IPv6 hostnames are bracketed when a port is appended.
    Side effects: None.
    """
    host_out = _format_host_for_authority(hostname)
    if port is None:
        return host_out

    scheme_l = scheme.lower() if scheme else None
    default = _DEFAULT_PORTS.get(scheme_l) if scheme_l else None
    if default is not None and port == default:
        return host_out
    # No scheme: port is always part of identity when explicit.
    if scheme_l is None:
        return f"{host_out}:{port}"
    # Non-default port for a known scheme.
    if default is None or port != default:
        return f"{host_out}:{port}"
    return host_out


def format_canonical_origin(
    scheme: str,
    hostname: str,
    port: int | None,
) -> str:
    """
    Purpose:
        Build scheme://canonical_authority.
    Input:
        scheme   — must be http or https.
        hostname — normalized hostname.
        port     — explicit port or None.
    Output:
        e.g. "http://example.com", "http://example.com:8000".
    Side effects: None.
    """
    scheme_l = scheme.lower()
    if scheme_l not in _SUPPORTED_SCHEMES:
        raise UrlIdentityError(f"Unsupported scheme for origin: {scheme!r}")
    authority = format_canonical_authority(scheme_l, hostname, port)
    return f"{scheme_l}://{authority}"


def normalize_url_path(path: str | None) -> str:
    """
    Purpose:
        Normalize a URL path for scope prefix matching and endpoint identity.
    Rules:
        - Empty / missing → "/".
        - Ensure a single leading slash.
        - Collapse duplicate slashes.
        - Do not strip a trailing slash (prefix matching may rely on it).
        - Query and fragment must not be present (caller strips them).
    Side effects: None.
    """
    if not path:
        return "/"
    normalized = path if path.startswith("/") else f"/{path}"
    normalized = _DUPLICATE_SLASH_RE.sub("/", normalized)
    return normalized or "/"


def normalize_endpoint_path(path: str | None) -> str:
    """
    Purpose:
        Canonical path for endpoint deduplication (trailing slash stripped
        except for root). Matches historical endpoint clustering behaviour.
    Side effects: None.
    """
    normalized = normalize_url_path(path)
    if len(normalized) > 1:
        normalized = normalized.rstrip("/") or "/"
    return normalized


def parse_request_url(url: str) -> UrlIdentity:
    """
    Purpose:
        Parse a full request URL into UrlIdentity.
        Request URLs are expected to include a scheme (proxy / capture path).
    Input:
        url — absolute URL, e.g. "https://api.example.com:8443/v1/users?x=1".
    Output:
        UrlIdentity (query/fragment ignored for identity).
    Raises:
        UrlIdentityError on empty input, missing host, or unsupported scheme.
    Side effects: None.
    """
    raw = (url or "").strip()
    if not raw:
        raise UrlIdentityError("URL is empty")

    parsed = urlsplit(raw)
    scheme = (parsed.scheme or "").lower() or None
    if scheme not in _SUPPORTED_SCHEMES:
        raise UrlIdentityError(
            f"Unsupported or missing URL scheme in {raw!r}; "
            "expected http:// or https://"
        )

    hostname = _normalize_hostname(parsed.hostname)
    if not hostname:
        raise UrlIdentityError(f"URL has no hostname: {raw!r}")

    explicit_port = parsed.port
    return UrlIdentity(
        scheme=scheme,
        hostname=hostname,
        explicit_port=explicit_port,
        effective_port=effective_port(scheme, explicit_port),
        path=normalize_url_path(parsed.path),
        raw=raw,
    )


def parse_authority_and_path(
    value: str,
    *,
    default_scheme: str | None = None,
) -> UrlIdentity:
    """
    Purpose:
        Parse a host, host:port, scheme://host, or scheme://host/path value
        into UrlIdentity. Used for Basic Scope prefixes and similar inputs.
    Input:
        value          — one complete prefix (never comma-split by callers).
        default_scheme — optional scheme when the value omits one (usually None
                         so both http and https match).
    Output:
        UrlIdentity with path "/" when the input has no path component.
    Raises:
        UrlIdentityError on invalid syntax.
    Side effects: None.
    """
    raw = (value or "").strip()
    if not raw:
        raise UrlIdentityError("Value is empty")

    # Full URL form.
    if "://" in raw:
        parsed = urlsplit(raw)
        scheme = (parsed.scheme or "").lower() or None
        if scheme not in _SUPPORTED_SCHEMES:
            raise UrlIdentityError(
                f"Unsupported scheme in {raw!r}; only http and https are allowed"
            )
        hostname = _normalize_hostname(parsed.hostname)
        if not hostname:
            raise UrlIdentityError(f"Missing hostname in {raw!r}")
        explicit_port = parsed.port
        path = parsed.path or ""
        if path == "" or path == "/":
            path_norm = "/"
        else:
            path_norm = normalize_url_path(path)
        return UrlIdentity(
            scheme=scheme,
            hostname=hostname,
            explicit_port=explicit_port,
            effective_port=effective_port(scheme, explicit_port),
            path=path_norm,
            raw=raw,
        )

    # scheme-less: host[:port][/path...]
    path_part = ""
    authority = raw
    if "/" in raw:
        authority, _, rest = raw.partition("/")
        path_part = "/" + rest

    if not authority:
        raise UrlIdentityError(f"Missing host in {raw!r}")

    host, explicit_port = _split_host_port(authority)
    hostname = _normalize_hostname(host)
    if not hostname:
        raise UrlIdentityError(f"Missing host in {raw!r}")

    scheme = default_scheme.lower() if default_scheme else None
    if scheme is not None and scheme not in _SUPPORTED_SCHEMES:
        raise UrlIdentityError(f"Unsupported scheme: {default_scheme!r}")

    if path_part == "" or path_part == "/":
        path_norm = "/"
    else:
        path_norm = normalize_url_path(path_part)

    return UrlIdentity(
        scheme=scheme,
        hostname=hostname,
        explicit_port=explicit_port,
        effective_port=effective_port(scheme, explicit_port),
        path=path_norm,
        raw=raw,
    )


def _split_host_port(authority: str) -> tuple[str, int | None]:
    """
    Purpose:
        Split host[:port] without treating the hostname as a URL scheme.
        Supports IPv6 authorities written as [addr] or [addr]:port.
    Side effects: None.
    """
    match = _HOSTPORT_RE.match(authority)
    if not match:
        raise UrlIdentityError(f"Invalid host/port authority: {authority!r}")

    if match.group("ipv6") is not None:
        host = match.group("ipv6")
    else:
        host = match.group("host")

    port_s = match.group("port")
    port = int(port_s) if port_s is not None else None
    if port is not None and not (0 < port <= 65535):
        raise UrlIdentityError(f"Port out of range in {authority!r}")
    return host, port


def _normalize_hostname(host: str | None) -> str:
    """
    Purpose:
        Lowercase hostnames; canonicalize IP literals via ipaddress.
        Rejects commas/spaces so Basic Scope never treats a comma-list as one host.
    Side effects: None.
    """
    if not host:
        return ""
    text = host.strip()
    if not text:
        return ""
    # Strip zone id if present (rare in scope rules).
    if "%" in text:
        text = text.split("%", 1)[0]
    if "," in text or " " in text:
        raise UrlIdentityError(
            f"Invalid hostname {text!r}: commas and spaces are not allowed "
            "(each scope prefix is one complete entry; do not use comma-separated lists)"
        )
    try:
        ip = ipaddress.ip_address(text)
        return str(ip)
    except ValueError:
        return text.lower()


def _format_host_for_authority(hostname: str) -> str:
    """
    Purpose:
        Bracket IPv6 literals when embedding in an authority string.
    Side effects: None.
    """
    try:
        ip = ipaddress.ip_address(hostname)
        if isinstance(ip, ipaddress.IPv6Address):
            return f"[{ip.compressed}]"
        return str(ip)
    except ValueError:
        return hostname
