"""
Module: talos.cors.payloads

Purpose:
    Dynamically generate CORS Origin payloads from the application's
    observed or synthesized origin.

    Baseline origin:
        1. Origin header from the captured request, if present.
        2. Otherwise scheme://netloc of the request URL (host URL).

    Attack payloads cover the common CORS allowlist bugs: arbitrary
    reflection, any-subdomain, prefix/suffix concatenation, unescaped
    regex dots, encoded/underscore breakouts, null, scheme/port, and
    preflight OPTIONS.

    The attacker registrable domain is always ``talos-cors-<nonce>.invalid``
    (RFC 2606 reserved) so probes never resolve to a real host.

Dependencies: secrets, urllib.parse, talos.cors.models
Data flow: candidates / CLI → generate_cors_payloads → engine job meta
Side effects: None (nonce is random unless the caller supplies one).
"""

from __future__ import annotations

import json
import secrets
from typing import Optional
from urllib.parse import urlparse

from talos.cors.models import (
    FAMILY_ARBITRARY,
    FAMILY_BASELINE,
    FAMILY_PARSER,
    FAMILY_PREFIX_SUFFIX,
    FAMILY_PREFLIGHT,
    FAMILY_SCHEME_PORT,
    FAMILY_SPECIAL,
    FAMILY_SUBDOMAIN,
    TECHNIQUE_NAMES,
    CorsPayload,
)


ATTACKER_TLD = "invalid"
"""Reserved TLD — attacker origins must not collide with a real site."""


def parse_headers(raw: object) -> dict[str, str]:
    """
    Purpose:
        Normalize stored request/response headers to a str→str map.
    Input:
        raw — JSON string, dict, list of pairs, or None.
    Output:
        Lower-preserving dict (original key casing kept; last value wins).
    Side effects: None.
    """
    if raw is None:
        return {}
    data = raw
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, str):
        try:
            data = json.loads(raw) if raw.strip() else {}
        except (ValueError, TypeError):
            return {}
    if isinstance(data, dict):
        out: dict[str, str] = {}
        for key, value in data.items():
            if value is None:
                continue
            if isinstance(value, list):
                out[str(key)] = str(value[0]) if value else ""
            else:
                out[str(key)] = str(value)
        return out
    return {}


def header_value(headers: dict, name: str) -> Optional[str]:
    """
    Purpose:
        Case-insensitive header lookup.
    Input:
        headers — map from parse_headers.
        name    — header name, e.g. 'Origin'.
    Output:
        Stripped value or None.
    """
    want = name.lower()
    for key, value in headers.items():
        if key.lower() == want:
            text = str(value).strip()
            return text or None
    return None


def request_origin_from_url(url: str) -> str:
    """
    Purpose:
        Synthesize an Origin from the request URL when none was captured.
    Input:
        url — absolute request URL.
    Output:
        scheme://netloc (no path). Falls back to https://host if unparsable.
    """
    parsed = urlparse(url or "")
    scheme = (parsed.scheme or "https").lower()
    netloc = parsed.netloc or parsed.hostname or ""
    if not netloc:
        return "https://localhost"
    return f"{scheme}://{netloc}"


def resolve_baseline_origin(
    url: str,
    request_headers: object,
) -> tuple[str, bool]:
    """
    Purpose:
        Choose the Origin the app already uses, else synthesize from the URL.
    Input:
        url             — captured request URL.
        request_headers — stored headers (JSON or dict).
    Output:
        (origin, origin_was_present)
    """
    headers = parse_headers(request_headers)
    existing = header_value(headers, "origin")
    if existing:
        return existing, True
    return request_origin_from_url(url), False


def origin_host(origin: str) -> str:
    """
    Purpose:
        Extract hostname from an Origin-like string.
    Input:
        origin — e.g. https://app.example.com:8443
    Output:
        hostname or the raw string if unparsable. 'null' stays 'null'.
    """
    text = (origin or "").strip()
    if not text or text.lower() == "null" or text == "*":
        return text
    parsed = urlparse(text if "://" in text else f"https://{text}")
    return (parsed.hostname or text).lower()


def target_origin_key(url: str) -> str:
    """
    Purpose:
        Stable cluster key for one target origin (scheme://host[:port]).
    Input:
        url — request URL.
    Output:
        Lowercased origin key.
    """
    parsed = urlparse(url or "")
    scheme = (parsed.scheme or "https").lower()
    netloc = (parsed.netloc or parsed.hostname or "unknown").lower()
    return f"{scheme}://{netloc}"


def _attacker_base(nonce: str) -> str:
    """Purpose: Registrable attacker domain for this run."""
    return f"talos-cors-{nonce}.{ATTACKER_TLD}"


def generate_cors_payloads(
    *,
    baseline_origin: str,
    request_method: str = "GET",
    nonce: Optional[str] = None,
    techniques: Optional[list[str]] = None,
) -> list[CorsPayload]:
    """
    Purpose:
        Build the CORS probe set for one candidate flow.
    Input:
        baseline_origin — app Origin or synthesized host origin.
        request_method  — captured method (used for preflight ACR-Method).
        nonce           — optional 8-hex token; generated when omitted.
        techniques      — optional allow-list of technique ids.
    Output:
        Ordered CorsPayload list (baseline first).
    Side effects: None.
    """
    token = (nonce or secrets.token_hex(4)).lower()
    attacker = _attacker_base(token)
    target = origin_host(baseline_origin)
    method = (request_method or "GET").upper()
    if method == "OPTIONS":
        method = "GET"

    arbitrary_https = f"https://{attacker}"
    payloads: list[CorsPayload] = [
        CorsPayload(
            technique="baseline_origin",
            family=FAMILY_BASELINE,
            origin=baseline_origin,
            description="Application Origin (captured or synthesized from the host URL).",
            attacker_controlled=False,
        ),
        CorsPayload(
            technique="arbitrary_https",
            family=FAMILY_ARBITRARY,
            origin=arbitrary_https,
            description="Random https attacker origin.",
            attacker_controlled=True,
        ),
        CorsPayload(
            technique="arbitrary_http",
            family=FAMILY_ARBITRARY,
            origin=f"http://{attacker}",
            description="Random http attacker origin.",
            attacker_controlled=True,
        ),
        CorsPayload(
            technique="attacker_subdomain",
            family=FAMILY_ARBITRARY,
            origin=f"https://sub.{attacker}",
            description="Subdomain of the random attacker origin.",
            attacker_controlled=True,
        ),
    ]

    if target and target not in {"null", "*", "localhost", "127.0.0.1"}:
        payloads.append(
            CorsPayload(
                technique="subdomain_of_target",
                family=FAMILY_SUBDOMAIN,
                origin=f"https://talos-cors-{token}.{target}",
                description="Attacker-controlled subdomain of the target host.",
                attacker_controlled=True,
            )
        )
        payloads.append(
            CorsPayload(
                technique="prefix_bypass",
                family=FAMILY_PREFIX_SUFFIX,
                origin=f"https://{target}.{attacker}",
                description="Target host used as a prefix of an attacker domain.",
                attacker_controlled=True,
            )
        )
        payloads.append(
            CorsPayload(
                technique="suffix_bypass",
                family=FAMILY_PREFIX_SUFFIX,
                origin=f"https://talos{target}",
                description="Attacker label prepended to the target host (endswith).",
                attacker_controlled=True,
            )
        )
        payloads.append(
            CorsPayload(
                technique="trusted_plus",
                family=FAMILY_PREFIX_SUFFIX,
                origin=f"{baseline_origin}.{attacker}",
                description="Trusted origin concatenated before an attacker host.",
                attacker_controlled=True,
            )
        )
        if "." in target:
            unescaped = target.replace(".", "a", 1)
            payloads.append(
                CorsPayload(
                    technique="unescaped_dot",
                    family=FAMILY_PARSER,
                    origin=f"https://{unescaped}",
                    description="First host dot replaced (regex '.' vs '\\.').",
                    attacker_controlled=True,
                )
            )
        payloads.append(
            CorsPayload(
                technique="encoded_dot",
                family=FAMILY_PARSER,
                origin=f"https://{target}%2e{attacker}",
                description="Percent-encoded dot between target and attacker host.",
                attacker_controlled=True,
            )
        )
        payloads.append(
            CorsPayload(
                technique="underscore",
                family=FAMILY_PARSER,
                origin=f"https://{target}_.{attacker}",
                description="Underscore after the target host before attacker domain.",
                attacker_controlled=True,
            )
        )

    payloads.extend(
        [
            CorsPayload(
                technique="null_origin",
                family=FAMILY_SPECIAL,
                origin="null",
                description="Origin: null (sandboxed iframe classic).",
                attacker_controlled=True,
            ),
            CorsPayload(
                technique="wildcard_origin",
                family=FAMILY_SPECIAL,
                origin="*",
                description="Origin: * (observation; ACAO:* is not an issue).",
                attacker_controlled=False,
            ),
            CorsPayload(
                technique="localhost",
                family=FAMILY_SPECIAL,
                origin="https://localhost",
                description="https://localhost as Origin.",
                attacker_controlled=True,
            ),
            CorsPayload(
                technique="loopback",
                family=FAMILY_SPECIAL,
                origin="http://127.0.0.1",
                description="http://127.0.0.1 as Origin.",
                attacker_controlled=True,
            ),
        ]
    )

    parsed_base = urlparse(
        baseline_origin if "://" in baseline_origin else f"https://{baseline_origin}"
    )
    if (parsed_base.scheme or "").lower() == "https" and parsed_base.netloc:
        payloads.append(
            CorsPayload(
                technique="scheme_downgrade",
                family=FAMILY_SCHEME_PORT,
                origin=f"http://{parsed_base.netloc}",
                description="http:// variant of the application origin (observation).",
                attacker_controlled=False,
            )
        )

    payloads.extend(
        [
            CorsPayload(
                technique="port_443",
                family=FAMILY_SCHEME_PORT,
                origin=f"https://{attacker}:443",
                description="Attacker origin with explicit :443.",
                attacker_controlled=True,
            ),
            CorsPayload(
                technique="port_80",
                family=FAMILY_SCHEME_PORT,
                origin=f"https://{attacker}:80",
                description="Attacker origin with explicit :80.",
                attacker_controlled=True,
            ),
            CorsPayload(
                technique="port_8080",
                family=FAMILY_SCHEME_PORT,
                origin=f"https://{attacker}:8080",
                description="Attacker origin with explicit :8080.",
                attacker_controlled=True,
            ),
        ]
    )

    payloads.append(
        CorsPayload(
            technique="preflight",
            family=FAMILY_PREFLIGHT,
            origin=arbitrary_https,
            description="OPTIONS preflight with attacker Origin.",
            attacker_controlled=True,
            method_override="OPTIONS",
            acr_method=method,
            acr_headers="content-type",
        )
    )

    if techniques:
        allow = {name.strip() for name in techniques if name and name.strip()}
        unknown = allow - set(TECHNIQUE_NAMES)
        if unknown:
            raise ValueError(
                "unknown CORS technique(s): " + ", ".join(sorted(unknown))
            )
        payloads = [item for item in payloads if item.technique in allow]
    return payloads
