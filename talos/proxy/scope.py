"""
Module: talos.proxy.scope

Purpose:
    Domain and optional path-based scope filtering for traffic capture.
    Determines whether a given request URL falls within a project's defined scope.

Matching rules:
    - Bare domain : "example.com"
        → matches ONLY "example.com" exactly, for all paths.
    - Wildcard    : "*.api.example.com"
        → matches "sub.api.example.com"
          but NOT "api.example.com".
    - Full URL    : "https://example.com"
        → matches every path on "example.com".
    - URL + path  : "https://example.com/book/"
        → matches ONLY requests whose path begins with "/book/".
    - URL paths are treated as prefix matches.
        Example:
            Scope : https://example.com/book/
            Match : /book/, /book/123, /book/search
            Reject: /api/, /login
    - Out-of-scope hosts are silently dropped.
    - Empty scope list means nothing is in scope (strict opt-in).

Dependencies: None (stdlib only)

Data flow:
    proxy addon calls:
        in_scope(flow.request.url, project.scope)

Side effects:
    None — pure filter logic.
"""

from urllib.parse import urlsplit


def _parse_scope_pattern(pattern: str) -> tuple[str, str | None]:
    """
    Purpose:
        Normalize a scope pattern into a hostname pattern and an optional
        path prefix.

    Supported forms:
        - Full URL
            "https://example.com:8443/path"
                -> ("example.com", "/path")

        - Full URL without path
            "https://example.com"
                -> ("example.com", None)

        - Host with port
            "example.com:8080"
                -> ("example.com", None)

        - Bare host
            "example.com"
                -> ("example.com", None)

        - Wildcard host
            "*.example.com"
                -> ("*.example.com", None)

    Input:
        pattern
            Raw scope entry.

    Output:
        Tuple:
            (
                host_pattern,
                path_prefix_or_None,
            )

    Notes:
        - Ports are always discarded.
        - "/" is treated as no path restriction.
    """
    pattern = pattern.strip().lower()

    if "://" not in pattern:
        return pattern.split(":")[0], None

    parsed = urlsplit(pattern)

    host = parsed.hostname or ""

    path = parsed.path or ""

    if path == "/":
        path = None

    return host, path


def matches_domain(pattern: str, host: str) -> bool:
    """
    Purpose:
        Test whether a hostname matches a scope host pattern.

    Input:
        pattern
            Host portion of a scope entry.

        host
            Request hostname (already lowercased).

    Output:
        True if the host matches.

    Matching rules:
        - example.com
            matches ONLY example.com

        - *.example.com
            matches:
                a.example.com
                api.example.com
                foo.bar.example.com

            does NOT match:
                example.com
    """
    if pattern.startswith("*."):
        suffix = pattern[2:]

        if host == suffix:
            return False

        return host.endswith("." + suffix)

    return host == pattern


def in_scope(url: str, scope: list[str]) -> bool:
    """
    Purpose:
        Determine whether a request URL falls within the configured project
        scope.

    Input:
        url
            Full request URL from the proxy.

            Examples:
                https://www.agoda.com/book/123
                https://www.agoda.com/api/gw/pages/HotelsBookingForm

        scope
            List of project scope entries.

    Output:
        True if at least one scope rule matches.

    Matching process:
        1. Host must match.
        2. If the rule has no path restriction,
           the request is in scope.
        3. If the rule contains a path,
           request.path must begin with that path.

    Edge cases:
        - Empty scope -> False.
        - URL ports are ignored.
        - Path comparison is prefix-based.
    """
    if not scope:
        return False

    parsed = urlsplit(url)

    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"

    for pattern in scope:

        rule_host, rule_path = _parse_scope_pattern(pattern)

        if not matches_domain(rule_host, host):
            continue

        # Host matches and no path restriction exists.
        if rule_path is None:
            return True

        # Host matches and request path falls under the configured prefix.
        if path.startswith(rule_path):
            return True

    return False


def is_out_of_scope(host: str, blocked: frozenset[str]) -> bool:
    """
    Purpose:
        Determine whether a host is explicitly blocked by the project's
        out-of-scope domain list.

    Out-of-scope always overrides the allow-list.

    Matching semantics:

        host == domain

    OR

        host.endswith("." + domain)

    Therefore blocking:

        example.com

    also blocks:

        api.example.com
        cdn.example.com
        foo.bar.example.com

    Input:
        host
            Raw hostname from the HTTP flow.
            May include a port suffix.

        blocked
            Lowercased domain set loaded from the project's
            out-of-scope configuration.

    Output:
        True if the host is blocked.

    Side effects:
        None.

    Edge cases:
        - Empty blocked set -> False.
        - Port suffix is ignored.
    """
    if not blocked:
        return False

    host_clean = host.split(":")[0].lower()

    for domain in blocked:
        if host_clean == domain or host_clean.endswith("." + domain):
            return True

    return False
