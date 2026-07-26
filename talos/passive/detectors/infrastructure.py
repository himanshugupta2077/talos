"""
Module: talos.passive.detectors.infrastructure

Purpose:
    Stage for OWASP-style information disclosure observations (Phase 12).

    Categories of hits (default OBSERVATION_ONLY / MEDIUM — never auto-finding
    via the secret bridge because category != secret):

        - INTERNAL_IP          RFC1918 / link-local / unique-local IPv6-ish
        - INTERNAL_HOSTNAME    *.internal / *.local / *.corp hostnames
        - SENSITIVE_ROUTE      aggregated API/admin/debug paths (capped set)
        - DEBUG_PATH           stack-trace / absolute source paths
        - EMAIL                email addresses (low signal)

    Aggregation strategy for routes: one detection per document holding a
    capped, deduped list of paths in metadata (and a compact redacted_value
    summary).  This avoids 500 findings / 500 rows for a large SPA route table.

    Future hook (comment only): JS Endpoint Extraction can feed the attack
    surface map without creating findings from this detector.

Dependencies: re, json; talos.passive.detectors.base, constants, models
Data flow: text → list[RawMatch]
Side effects: None.
"""

from __future__ import annotations

import json
import re
from typing import Optional

from talos.passive.constants import (
    CATEGORY_INFRASTRUCTURE_DISCLOSURE,
    CATEGORY_SENSITIVE_INFO,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_OBSERVATION_ONLY,
    DETECTOR_FAMILY_INFRA,
)
from talos.passive.detectors.base import build_raw_match
from talos.passive.models import RawMatch, SourceDocument

# --- IPs -----------------------------------------------------------------
_IPV4 = re.compile(
    r"(?<![0-9])"
    r"("
    r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"|(?:192\.168\.\d{1,3}\.\d{1,3})"
    r"|(?:172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})"
    r"|(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"|(?:169\.254\.\d{1,3}\.\d{1,3})"
    r")"
    r"(?![0-9])"
)

# --- Hostnames -----------------------------------------------------------
_INTERNAL_HOST = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*"
    r"\.(?:internal|local|corp|lan|intranet|home))"
    r"(?![A-Za-z0-9_.-])",
    re.IGNORECASE,
)

# --- Sensitive / API-ish routes ------------------------------------------
# Paths starting with common API/admin/debug prefixes inside quoted strings
# or path literals.  We collect uniquely and emit ONE aggregated match.
_ROUTE = re.compile(
    r"""["'`](/(?:api|v[0-9]+|admin|internal|debug|graphql|private"""
    r"""|_next|actuator|manage|metrics|healthz?|swagger|console)"""
    r"""[A-Za-z0-9_./\-]{0,200})["'`]""",
    re.IGNORECASE,
)

# Cap unique routes stored per document (DB protection).
_MAX_ROUTES_PER_DOC = 40

# --- Debug / stack paths -------------------------------------------------
_DEBUG_PATH = re.compile(
    r"(?<![A-Za-z0-9_/])"
    r"("
    r"(?:/(?:home|Users|var|opt|usr|app|src)/[A-Za-z0-9_./\-]{3,200})"
    r"|(?:[A-Za-z]:\\(?:Users|home|src|app)\\[A-Za-z0-9_\\.\-]{3,200})"
    r"|(?:Traceback \(most recent call last\):)"
    r"|(?:at [A-Za-z0-9_.$]+\([A-Za-z0-9_./\-]+:\d+:\d+\))"
    r")",
)

# --- Emails (low signal) -------------------------------------------------
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+\-])"
    r"([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24})"
    r"(?![A-Za-z0-9._%+\-])"
)
_MAX_EMAILS = 10

# Placeholders / public docs noise for emails
_EMAIL_SUPPRESS_DOMAINS = frozenset({
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "localhost",
    "email.com",
    "domain.com",
    "sentry.io",
})


class InfrastructureDetector:
    """
    Purpose:
        Emit observation-first infrastructure / disclosure RawMatches.

    Fields:
        max_candidates — hard cap on total matches emitted (after aggregation)
    """

    def __init__(self, *, max_candidates: int = 100) -> None:
        self._max_candidates = max(1, int(max_candidates))

    def detect(
        self,
        text: str,
        *,
        document: Optional[SourceDocument] = None,
        encoding_chain: Optional[list[str]] = None,
        decode_depth: int = 0,
    ) -> list[RawMatch]:
        """
        Purpose:
            Find disclosure-style observations in text.
        Input:
            text / encoding context
        Output:
            list[RawMatch] (capped; routes aggregated)
        Side effects: None.
        """
        if not text:
            return []

        matches: list[RawMatch] = []
        # Skip nested decode rescans for infra noise (optional): still allow
        # depth 0 primarily; encoded infra is low value.
        if decode_depth and decode_depth > 1:
            return []

        # 1) Internal IPs
        seen_ip: set[str] = set()
        for m in _IPV4.finditer(text):
            ip = m.group(1)
            if ip in seen_ip:
                continue
            seen_ip.add(ip)
            matches.append(
                build_raw_match(
                    detector_id="internal_ip",
                    detector_family=DETECTOR_FAMILY_INFRA,
                    category=CATEGORY_INFRASTRUCTURE_DISCLOSURE,
                    secret_type="internal_ip",
                    raw_value=ip,
                    match_start=m.start(1),
                    match_end=m.end(1),
                    text=text,
                    encoding_chain=encoding_chain,
                    decode_depth=decode_depth,
                    compute_entropy=False,
                    metadata={
                        "base_score": 45,
                        "base_level": CONFIDENCE_OBSERVATION_ONLY,
                        "disclosure_kind": "INTERNAL_IP",
                        "auto_finding": False,
                    },
                )
            )
            if len(matches) >= self._max_candidates:
                return matches

        # 2) Internal hostnames
        seen_host: set[str] = set()
        for m in _INTERNAL_HOST.finditer(text):
            host = m.group(1)
            key = host.lower()
            if key in seen_host:
                continue
            seen_host.add(key)
            matches.append(
                build_raw_match(
                    detector_id="internal_hostname",
                    detector_family=DETECTOR_FAMILY_INFRA,
                    category=CATEGORY_INFRASTRUCTURE_DISCLOSURE,
                    secret_type="internal_hostname",
                    raw_value=host,
                    match_start=m.start(1),
                    match_end=m.end(1),
                    text=text,
                    encoding_chain=encoding_chain,
                    decode_depth=decode_depth,
                    compute_entropy=False,
                    metadata={
                        "base_score": 50,
                        "base_level": CONFIDENCE_MEDIUM,
                        "disclosure_kind": "INTERNAL_HOSTNAME",
                        "auto_finding": False,
                    },
                )
            )
            if len(matches) >= self._max_candidates:
                return matches

        # 3) Sensitive routes — AGGREGATED (one row, capped unique paths)
        routes: list[str] = []
        route_seen: set[str] = set()
        first_start = -1
        first_end = -1
        for m in _ROUTE.finditer(text):
            path = m.group(1)
            # Normalize trailing punctuation
            path = path.rstrip(".,;")
            if path in route_seen:
                continue
            route_seen.add(path)
            if first_start < 0:
                first_start = m.start(1)
                first_end = m.end(1)
            routes.append(path)
            if len(routes) >= _MAX_ROUTES_PER_DOC:
                break

        if routes:
            summary = f"{len(routes)} sensitive route(s): " + ", ".join(
                routes[:5]
            )
            if len(routes) > 5:
                summary += f", … (+{len(routes) - 5} more)"
            # Fingerprint material = sorted joined routes (stable)
            raw_for_fp = "\n".join(sorted(routes))
            matches.append(
                build_raw_match(
                    detector_id="sensitive_routes_aggregate",
                    detector_family=DETECTOR_FAMILY_INFRA,
                    category=CATEGORY_INFRASTRUCTURE_DISCLOSURE,
                    secret_type="sensitive_route",
                    raw_value=raw_for_fp[:4000],
                    match_start=max(0, first_start),
                    match_end=max(first_end, first_start + 1),
                    text=text,
                    encoding_chain=encoding_chain,
                    decode_depth=decode_depth,
                    compute_entropy=False,
                    metadata={
                        "base_score": 40,
                        "base_level": CONFIDENCE_OBSERVATION_ONLY,
                        "disclosure_kind": "SENSITIVE_ROUTE",
                        "auto_finding": False,
                        "routes": routes,
                        "route_count": len(routes),
                        "summary": summary,
                        # Future: JS Endpoint Extraction can consume routes[]
                        "endpoint_extraction_candidate": True,
                    },
                )
            )
            if len(matches) >= self._max_candidates:
                return matches

        # 4) Debug / stack paths
        seen_dbg: set[str] = set()
        for m in _DEBUG_PATH.finditer(text):
            val = m.group(1)
            if len(val) > 300:
                val = val[:300]
            if val in seen_dbg:
                continue
            seen_dbg.add(val)
            matches.append(
                build_raw_match(
                    detector_id="debug_path",
                    detector_family=DETECTOR_FAMILY_INFRA,
                    category=CATEGORY_INFRASTRUCTURE_DISCLOSURE,
                    secret_type="debug_path",
                    raw_value=val,
                    match_start=m.start(1),
                    match_end=m.end(1),
                    text=text,
                    encoding_chain=encoding_chain,
                    decode_depth=decode_depth,
                    compute_entropy=False,
                    metadata={
                        "base_score": 55,
                        "base_level": CONFIDENCE_MEDIUM,
                        "disclosure_kind": "DEBUG_PATH",
                        "auto_finding": False,
                    },
                )
            )
            if len(matches) >= self._max_candidates:
                return matches
            if len(seen_dbg) >= 15:
                break

        # 5) Emails (sensitive_info, low)
        seen_em: set[str] = set()
        for m in _EMAIL.finditer(text):
            email = m.group(1)
            domain = email.rsplit("@", 1)[-1].lower()
            if domain in _EMAIL_SUPPRESS_DOMAINS:
                continue
            key = email.lower()
            if key in seen_em:
                continue
            seen_em.add(key)
            matches.append(
                build_raw_match(
                    detector_id="email_address",
                    detector_family=DETECTOR_FAMILY_INFRA,
                    category=CATEGORY_SENSITIVE_INFO,
                    secret_type="email",
                    raw_value=email,
                    match_start=m.start(1),
                    match_end=m.end(1),
                    text=text,
                    encoding_chain=encoding_chain,
                    decode_depth=decode_depth,
                    compute_entropy=False,
                    metadata={
                        "base_score": 30,
                        "base_level": CONFIDENCE_OBSERVATION_ONLY,
                        "disclosure_kind": "EMAIL",
                        "auto_finding": False,
                    },
                )
            )
            if len(matches) >= self._max_candidates:
                return matches
            if len(seen_em) >= _MAX_EMAILS:
                break

        return matches


def routes_metadata_json(raw: RawMatch) -> str:
    """
    Purpose:
        Serialize routes list from infrastructure match metadata for
        debugging / CLI (not stored as a separate column).
    Side effects: None.
    """
    routes = (raw.metadata or {}).get("routes") or []
    return json.dumps(routes, ensure_ascii=False)
