"""
Module: talos.projects.endpoints

Purpose:
    Convert raw captured request paths and query strings into stable,
    host-aware endpoint identities. Endpoint identity is intentionally limited
    to (method, host, normalized_path); the cleaned query is retained for flow
    storage and later parameter analysis but does not participate in endpoint
    deduplication.

Dependencies: dataclasses, re, urllib.parse
Data flow:
    FlowWorker → normalize_flow_url() → endpoint upsert / flow persistence
Side effects: None (pure normalization only).
"""

from dataclasses import dataclass
import re
from urllib.parse import parse_qsl, urlencode


_DUPLICATE_SLASH_RE = re.compile(r"/{2,}")
_TRACKING_PARAM_PREFIXES = ("utm_",)
_TRACKING_PARAM_NAMES = frozenset({"fbclid", "gclid"})
_CACHE_BUSTER_PARAM_NAMES = frozenset(
    {
        "_",
        "_cb",
        "_t",
        "cache_bust",
        "cache_buster",
        "cachebuster",
        "cb",
        "nocache",
        "no_cache",
    }
)


@dataclass(frozen=True, slots=True)
class NormalizedFlowURL:
    """
    Purpose:
        Carry the canonical endpoint path and cleaned query derived from a raw
        captured flow URL.
    Fields:
        normalized_path — canonical path used for endpoint identity.
        cleaned_query   — stable query string with known noise removed.
    Side effects: None.
    """

    normalized_path: str
    cleaned_query: str


def normalize_flow_url(path: str, query: str) -> NormalizedFlowURL:
    """
    Purpose:
        Normalize one captured request path and query string for endpoint
        clustering.
    Input:
        path  — raw request path captured from the proxy.
        query — raw request query string captured from the proxy.
    Output:
        NormalizedFlowURL with a canonical path and a cleaned query string.
    Rules:
        - Path normalization removes duplicate slashes and strips a trailing
          slash except for the root path.
        - Query normalization removes known tracking/cache-buster parameters and
          sorts the remaining pairs by name and value.
        - Host and method are intentionally not modified here.
    Side effects: None.
    """
    return NormalizedFlowURL(
        normalized_path=_normalize_path(path),
        cleaned_query=_normalize_query(query),
    )


def _normalize_path(path: str) -> str:
    """
    Purpose:
        Canonicalize a request path without changing its routing semantics.
    Input:
        path — raw request path.
    Output:
        Canonical path beginning with a single slash.
    Side effects: None.
    """
    normalized = path or "/"
    if not normalized.startswith("/"):
        normalized = f"/{normalized}"

    normalized = _DUPLICATE_SLASH_RE.sub("/", normalized)
    if len(normalized) > 1:
        normalized = normalized.rstrip("/") or "/"
    return normalized


def _normalize_query(query: str) -> str:
    """
    Purpose:
        Remove known noise from a query string and return a stable ordering.
    Input:
        query — raw query string without the leading '?'.
    Output:
        Canonical query string suitable for storage on the flow record.
    Side effects: None.
    """
    if not query:
        return ""

    cleaned_pairs = [
        (name, value)
        for name, value in parse_qsl(query, keep_blank_values=True)
        if not _should_drop_param(name)
    ]
    cleaned_pairs.sort(key=lambda item: (item[0], item[1]))
    return urlencode(cleaned_pairs, doseq=True)


def _should_drop_param(name: str) -> bool:
    """
    Purpose:
        Decide whether a query parameter is endpoint noise and should be removed
        from the cleaned flow query.
    Input:
        name — raw query parameter name.
    Output:
        True when the parameter is known tracking or cache-buster noise.
    Side effects: None.
    """
    lowered = name.lower()
    if lowered.startswith(_TRACKING_PARAM_PREFIXES):
        return True
    if lowered in _TRACKING_PARAM_NAMES:
        return True
    if lowered in _CACHE_BUSTER_PARAM_NAMES:
        return True
    return False