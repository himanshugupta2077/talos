"""
Module: talos.proxy.scope

Purpose:
    Basic Scope matching for Talos — Burp-inspired URL-prefix scope control.
    Single shared evaluator for in-scope allow rules and out-of-scope exclude
    rules. Used by the proxy capture path, worker backstop, and any subsystem
    that needs the same eligibility boundary.

Basic Scope (canonical model):
    One entry is one complete URL prefix or host prefix. Never comma-split.

    Examples:
        example.com
        example.com/api/
        http://example.com
        https://example.com:8443/admin/
        example.com:8000
        http://10.10.10.25:8000

Matching semantics:
    Protocol — omitted → HTTP and HTTPS; present → that scheme only.
    Host     — exact match, case-insensitive; IPs via ipaddress.
               Subdomains are NOT implicitly included.
    Port     — omitted → any port; present → that port only.
               Default ports canonicalize (http:80, https:443) for identity,
               but host-only rules still match any port.
    Path     — omitted or "/" → any path; otherwise normalized path prefix.
               Parenthetical path parameters (SAP WebGUI session form
               ``/sap(...)/...``, ASP.NET cookieless ``/(S(...))/...``) are
               stripped before prefix comparison so a rule ending in ``/sap/``
               matches both ``/sap/bc/...`` and ``/sap(<session>)/bc/...``.
    Query    — never part of Basic Scope identity.

Precedence (evaluate_scope):
    1. Parse URL.
    2. If any out-of-scope rule matches → OUT_OF_SCOPE (False).
    3. Else if any in-scope rule matches → IN_SCOPE (True).
    4. Else → OUT_OF_SCOPE (False).

Empty in-scope list → nothing is in scope (strict opt-in).

Legacy wildcards ("*.example.com") are rejected at parse/validate time with
an actionable error — Basic Scope does not use wildcards.

Dependencies: dataclasses, talos.url_identity
Data flow:
    CLI / registry / DB → parse_scope_prefix → ScopeRule list
    capture/worker → evaluate_scope(url, in_rules, out_rules) → bool
Side effects: None — pure filter logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from talos.url_identity import (
    UrlIdentity,
    UrlIdentityError,
    parse_authority_and_path,
    parse_request_url,
    normalize_url_path,
    strip_url_path_parameters,
)


class ScopeParseError(ValueError):
    """Raised when a scope / outscope prefix is invalid for Basic Scope."""


class ScopeDecision(str, Enum):
    """Result of evaluating a URL against in-scope and out-of-scope rules."""

    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"


@dataclass(frozen=True, slots=True)
class ScopeRule:
    """
    Purpose:
        Parsed Basic Scope prefix ready for matching.
    Fields:
        raw           — original prefix text (trimmed).
        scheme        — "http" / "https" / None (both).
        hostname      — normalized host (exact match only).
        port          — explicit port or None (any port).
        path_prefix   — normalized path prefix, or None for any path.
    """

    raw: str
    scheme: str | None
    hostname: str
    port: int | None
    path_prefix: str | None


def parse_scope_prefix(prefix: str) -> ScopeRule:
    """
    Purpose:
        Parse and validate one Basic Scope prefix.
    Input:
        prefix — one complete entry (never split on commas).
    Output:
        ScopeRule.
    Raises:
        ScopeParseError — empty, wildcard, or unparseable value.
    Side effects: None.
    """
    raw = (prefix or "").strip()
    if not raw:
        raise ScopeParseError("Scope prefix is empty")

    if "*" in raw:
        raise ScopeParseError(
            f"Wildcard scope is not supported in Basic Scope: {raw!r}. "
            "Use an explicit host or URL prefix instead "
            "(e.g. 'api.example.com' or 'https://api.example.com/v1/'). "
            "Subdomains are not implied by a parent host — add each host you need."
        )

    # Reject accidental multi-entry paste that used commas as separators.
    # Commas may appear in rare edge cases; Basic Scope treats the whole line
    # as one prefix, but a bare comma-separated host list is almost always a
    # user error when validating interactive add (we still accept the string
    # as a single prefix if it parses — matching does not split on commas).
    try:
        identity = parse_authority_and_path(raw)
    except UrlIdentityError as exc:
        raise ScopeParseError(str(exc)) from exc

    path_prefix: str | None
    if identity.path in ("", "/"):
        path_prefix = None
    else:
        path_prefix = normalize_url_path(identity.path)

    return ScopeRule(
        raw=raw,
        scheme=identity.scheme,
        hostname=identity.hostname,
        port=identity.explicit_port,
        path_prefix=path_prefix,
    )


def validate_scope_prefix(prefix: str) -> str:
    """
    Purpose:
        Validate a prefix and return the trimmed raw form for storage.
    Side effects: None.
    """
    rule = parse_scope_prefix(prefix)
    return rule.raw


def rule_matches(rule: ScopeRule, identity: UrlIdentity) -> bool:
    """
    Purpose:
        Test whether a parsed request URL matches one Basic Scope rule.
    Matching:
        - scheme: None in rule → http or https; else exact scheme.
        - host: exact equality on normalized hostname.
        - port: None in rule → any port; else identity.effective_port == rule.port.
        - path: None in rule → any path; else path-prefix match after stripping
          parenthetical path parameters (SAP/ASP.NET session forms). Plain paths
          without parentheses are unchanged by stripping.
    Side effects: None.
    """
    if rule.scheme is not None:
        if identity.scheme != rule.scheme:
            return False
    elif identity.scheme not in ("http", "https"):
        return False

    if identity.hostname != rule.hostname:
        return False

    if rule.port is not None:
        # Port-specific rule: compare against the request's effective port.
        if identity.effective_port != rule.port:
            return False

    if rule.path_prefix is not None:
        # Fast path: ordinary string prefix (no session-encoding in the path).
        req_path = identity.path or "/"
        if req_path.startswith(rule.path_prefix):
            return True
        # Path-parameter-aware match: /sap(...)/bc under scope .../sap/.
        req_cmp = strip_url_path_parameters(req_path)
        rule_cmp = strip_url_path_parameters(rule.path_prefix)
        if not req_cmp.startswith(rule_cmp):
            return False

    return True


def any_rule_matches(url: str, prefixes: list[str] | tuple[str, ...] | frozenset[str]) -> bool:
    """
    Purpose:
        Return True if any stored prefix matches the request URL.
        Invalid stored prefixes are skipped (should not occur after validate).
    Side effects: None.
    """
    if not prefixes:
        return False
    try:
        identity = parse_request_url(url)
    except UrlIdentityError:
        return False

    for prefix in prefixes:
        try:
            rule = parse_scope_prefix(prefix)
        except ScopeParseError:
            continue
        if rule_matches(rule, identity):
            return True
    return False


def evaluate_scope(
    url: str,
    in_scope_prefixes: list[str] | tuple[str, ...] | frozenset[str],
    out_of_scope_prefixes: list[str] | tuple[str, ...] | frozenset[str] | None = None,
) -> ScopeDecision:
    """
    Purpose:
        Shared scope evaluator — out-of-scope overrides in-scope.
    Input:
        url                   — full request URL.
        in_scope_prefixes     — project allow list (registry scope).
        out_of_scope_prefixes — project exclude list (DB); optional.
    Output:
        ScopeDecision.IN_SCOPE or ScopeDecision.OUT_OF_SCOPE.
    Side effects: None.
    """
    out_list = out_of_scope_prefixes or ()
    if any_rule_matches(url, out_list):
        return ScopeDecision.OUT_OF_SCOPE
    if any_rule_matches(url, in_scope_prefixes):
        return ScopeDecision.IN_SCOPE
    return ScopeDecision.OUT_OF_SCOPE


def is_url_in_scope(
    url: str,
    in_scope_prefixes: list[str] | tuple[str, ...] | frozenset[str],
    out_of_scope_prefixes: list[str] | tuple[str, ...] | frozenset[str] | None = None,
) -> bool:
    """
    Purpose:
        Boolean convenience wrapper around evaluate_scope.
    Output:
        True only when the decision is IN_SCOPE.
    Side effects: None.
    """
    return (
        evaluate_scope(url, in_scope_prefixes, out_of_scope_prefixes)
        is ScopeDecision.IN_SCOPE
    )


# ------------------------------------------------------------------ #
# Backward-compatible names (route through the shared evaluator)       #
# ------------------------------------------------------------------ #


def in_scope(url: str, scope: list[str]) -> bool:
    """
    Purpose:
        Legacy name: True if URL matches any in-scope prefix.
        Does not apply out-of-scope rules — callers that need full evaluation
        should use is_url_in_scope / evaluate_scope.
    Side effects: None.
    """
    return any_rule_matches(url, scope)


def is_out_of_scope(url_or_host: str, blocked: frozenset[str] | list[str]) -> bool:
    """
    Purpose:
        True if any out-of-scope prefix matches.
        Accepts a full URL (preferred) or, for transitional callers, a value
        that parse_request_url can handle. Host-only strings without a scheme
        are matched by synthesizing http:// and https:// candidates.
    Side effects: None.
    """
    if not blocked:
        return False

    text = (url_or_host or "").strip()
    if not text:
        return False

    # Full URL path (capture / worker with request URL).
    if "://" in text:
        return any_rule_matches(text, blocked)

    # Transitional: host or host:port without scheme — test both schemes.
    for scheme in ("http", "https"):
        candidate = f"{scheme}://{text}"
        if any_rule_matches(candidate, blocked):
            return True
    return False


def matches_domain(pattern: str, host: str) -> bool:
    """
    Purpose:
        Legacy helper retained for tests/callers that only compare hosts.
        Basic Scope: exact hostname match only (no wildcard, no subdomain).
    Side effects: None.
    """
    try:
        rule = parse_scope_prefix(pattern)
    except ScopeParseError:
        return False
    host_l = (host or "").split(":")[0].lower()
    return rule.hostname == host_l and rule.path_prefix is None
