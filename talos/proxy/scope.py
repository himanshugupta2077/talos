"""
Module: talos.proxy.scope

Purpose:
    Domain-based scope filtering for traffic capture.
    Determines whether a given hostname falls within a project's defined scope.

Matching rules:
    - Bare domain : "example.com"       → matches ONLY "example.com" exactly.
    - Wildcard    : "*.api.example.com" → matches "sub.api.example.com"
                    but NOT "api.example.com" (a leading subdomain label is required)
    - Full URL    : "https://example.com/path" → hostname ("example.com") is extracted
                    before matching, so URL-style scope entries work correctly.
    - Out-of-scope hosts are silently dropped — no logging, no partial handling.
    - Empty scope list means nothing is in scope (strict opt-in).

Dependencies: None (stdlib only)
Data flow:
    proxy addon calls in_scope(host, project.scope) per flow before extraction.
Side effects: None — pure filter logic.
"""

from urllib.parse import urlsplit


def _extract_host_from_pattern(pattern: str) -> str:
    """
    Purpose:
        Normalize a scope pattern to a bare hostname/wildcard string.
        Handles three input forms:
          - Full URL  : "https://example.com:8080/path" → "example.com"
          - host:port : "example.com:8080"              → "example.com"
          - bare host : "example.com" / "*.example.com" → unchanged
    Input:
        pattern — raw scope entry, already lowercased.
    Output:
        Hostname portion only (port stripped), ready for matches_domain().
    """
    if "://" in pattern:
        parsed = urlsplit(pattern)
        # urlsplit.hostname already strips the port.
        return parsed.hostname or pattern
    # Bare "host:port" — strip the port.  Wildcard patterns like "*.example.com"
    # contain no ":" so this is a no-op for them.
    return pattern.split(":")[0]


def matches_domain(pattern: str, host: str) -> bool:
    """
    Purpose:
        Test whether a single host matches one scope pattern.
    Input:
        pattern — scope entry, already lowercased (e.g. "example.com",
                  "*.api.example.com").
        host    — lowercased hostname with port stripped
                  (e.g. "sub.api.example.com").
    Output:
        True if host is covered by this pattern.
    Assumptions:
        - Both pattern and host are lowercased by the caller.
        - No port numbers in either argument.
    Edge cases:
        - Bare domain "example.com" matches ONLY "example.com".
          Use "*.example.com" to also match subdomains.
        - Wildcard pattern base itself ("api.example.com" for "*.api.example.com")
          is NOT a match — a subdomain label must be present.
        - Pattern "*.example.com" does NOT match "sub.sub.example.com" variants;
          fnmatch handles multi-label wildcards if needed in future.
    """
    if pattern.startswith("*."):
        # Wildcard: host must end with ".<suffix>" — at least one extra label.
        suffix = pattern[2:]  # strip leading "*."
        if host == suffix:
            # Base domain itself is not covered by the wildcard.
            return False
        return host.endswith("." + suffix)

    # Exact match only — use "*.example.com" to match subdomains.
    return host == pattern


def in_scope(host: str, scope: list[str]) -> bool:
    """
    Purpose:
        Determine whether a host falls within any of the project's scope entries.

    Input:
        host  — raw hostname from the HTTP flow; may include a port suffix.
        scope — list of scope pattern strings from the active project config.
    Output:
        True only if host matches at least one pattern in scope.
    Side effects: None.
    Edge cases:
        - Empty scope → False (no scope defined = nothing is in scope).
        - Port in host is stripped before matching ("example.com:8080" → "example.com").
    """
    if not scope:
        # Strict opt-in: no patterns configured means no traffic is in scope.
        return False

    # Strip port if present.
    host_clean = host.split(":")[0].lower()

    for pattern in scope:
        normalized = _extract_host_from_pattern(pattern.lower())
        if matches_domain(normalized, host_clean):
            return True

    return False


def is_out_of_scope(host: str, blocked: frozenset[str]) -> bool:
    """
    Purpose:
        Determine whether a host is explicitly blocked by the out-of-scope
        domain list.  Out-of-scope always overrides the scope allow-list.

    Matching semantics for each blocked domain D:
        - host == D            (exact match)
        - host.endswith('.'+D) (D and all its subdomains)

    Input:
        host    — raw hostname from the HTTP flow; may include a port suffix.
        blocked — frozenset of lowercased domain strings from
                  talos.projects.outscope.load_domain_set().
    Output:
        True if the host matches any blocked domain entry.
    Side effects: None.
    Edge cases:
        - Empty blocked set → False (nothing blocked).
        - Port in host is stripped before matching.
    """
    if not blocked:
        return False

    host_clean = host.split(":")[0].lower()

    for domain in blocked:
        if host_clean == domain or host_clean.endswith("." + domain):
            return True

    return False
