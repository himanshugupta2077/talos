"""
Module: talos.url_sink.jwt_claims

Purpose:
    Inventory-only extraction of URL-bearing JWT claims as virtual parameters.
    Decodes the JWT payload segment (base64url) **without verification** —
    this is passive characterization, not auth validation.

    Target claims (when value is URL / network-resource shaped):
        jku, x5u, iss, aud
    ``kid`` is only emitted when the value itself classifies as a network
    resource (rare; most kids are opaque key ids).

Dependencies: base64, binascii, json, re (stdlib); talos.url_sink.value_classify
Data flow: JWT compact string → list of (claim_name, claim_value, evidence)
Side effects: None.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Any

from talos.url_sink.value_classify import (
    NETWORK_RESOURCE_SCORE_THRESHOLD,
    classify_value,
)

# Compact JWT: header.payload.signature (signature may be empty for "none").
_JWT_COMPACT_RE = re.compile(
    r"^(?:Bearer\s+|Token\s+)?"
    r"([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)$",
    re.IGNORECASE,
)

# Claims that commonly carry URLs / issuer identifiers.
_PRIMARY_URL_CLAIMS: frozenset[str] = frozenset({
    "jku",   # JWK Set URL
    "x5u",   # X.509 URL
    "iss",   # issuer (often URL)
    "aud",   # audience (sometimes URL)
})
# Only if value looks like a network resource.
_CONDITIONAL_URL_CLAIMS: frozenset[str] = frozenset({
    "kid",
    "sub",
})

# Caps
_MAX_JWT_LEN: int = 16_384
_MAX_CLAIMS: int = 20


@dataclass(frozen=True, slots=True)
class JwtClaimParam:
    """
    Purpose:
        One virtual parameter derived from a JWT claim.
    Fields:
        name         — virtual name, e.g. ``jwt.jku``.
        sample_value — claim value as string.
        claim        — raw claim key.
        evidence     — tokens linking parent param + claim + decode path.
    Side effects: None.
    """

    name: str
    sample_value: str
    claim: str
    evidence: tuple[str, ...]


def extract_jwt_token(raw: str | None) -> str | None:
    """
    Purpose:
        Pull a compact JWT string from a header/cookie/param value.
    Input:
        raw — e.g. ``Bearer eyJ…`` or bare compact JWT.
    Output:
        Compact JWT string without auth scheme prefix, or None.
    Side effects: None.
    """
    if not raw:
        return None
    text = raw.strip()
    if len(text) < 20 or len(text) > _MAX_JWT_LEN:
        return None
    m = _JWT_COMPACT_RE.match(text)
    if not m:
        return None
    return f"{m.group(1)}.{m.group(2)}.{m.group(3)}"


def decode_jwt_payload(token: str) -> dict[str, Any] | None:
    """
    Purpose:
        Base64url-decode the JWT payload segment to a JSON object.
    Input:
        token — compact JWT (three segments).
    Output:
        Payload dict, or None on failure.
    Side effects: None.
    """
    parts = token.split(".")
    if len(parts) < 2:
        return None
    payload_b64 = parts[1]
    pad = (-len(payload_b64)) % 4
    if pad:
        payload_b64 = payload_b64 + ("=" * pad)
    try:
        raw = base64.urlsafe_b64decode(payload_b64)
    except (binascii.Error, ValueError):
        return None
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def extract_url_claim_params(
    raw_value: str | None,
    *,
    parent_name: str = "",
    parent_location: str = "",
) -> list[JwtClaimParam]:
    """
    Purpose:
        From a JWT-bearing parameter value, emit virtual params for
        URL-shaped claims (inventory enrichment only).
    Input:
        raw_value       — Authorization header / cookie / body field value.
        parent_name     — e.g. ``authorization`` (for evidence).
        parent_location — e.g. ``header`` / ``cookie`` (for evidence).
    Output:
        List of JwtClaimParam (may be empty). Names are ``jwt.<claim>``.
    Side effects: None.
    """
    token = extract_jwt_token(raw_value)
    if not token:
        return []
    payload = decode_jwt_payload(token)
    if not payload:
        return []

    results: list[JwtClaimParam] = []
    for claim, raw_claim_val in payload.items():
        if len(results) >= _MAX_CLAIMS:
            break
        if not isinstance(claim, str) or not claim:
            continue
        claim_l = claim.lower()
        values = _claim_values_as_strings(raw_claim_val)
        emitted_for_claim = 0
        for sample in values:
            if not sample:
                continue
            if not _should_emit_claim(claim_l, sample):
                continue
            evidence = [
                "jwt_claim",
                f"jwt_claim:{claim_l}",
                "decode:jwt_payload",
            ]
            if parent_name:
                evidence.append(f"parent:{parent_name}")
            if parent_location:
                evidence.append(f"parent_location:{parent_location}")
            # Array claims (aud: [url1, url2]) get distinct inventory names so
            # de-dupe does not drop secondary values.
            if emitted_for_claim == 0:
                vname = f"jwt.{claim_l}"
            else:
                vname = f"jwt.{claim_l}[{emitted_for_claim}]"
                evidence.append("jwt_claim_array")
            results.append(JwtClaimParam(
                name=vname,
                sample_value=sample,
                claim=claim_l,
                evidence=tuple(evidence),
            ))
            emitted_for_claim += 1
            if len(results) >= _MAX_CLAIMS:
                break
    return results


def _claim_values_as_strings(raw: Any) -> list[str]:
    """Normalize claim values (string or list of strings) to strings."""
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        out: list[str] = []
        for item in raw:
            if isinstance(item, str) and item:
                out.append(item)
            elif item is not None and not isinstance(item, (dict, list)):
                out.append(str(item))
        return out
    if raw is None or isinstance(raw, (dict, list, bool)):
        return []
    return [str(raw)]


def _should_emit_claim(claim: str, sample: str) -> bool:
    """
    Emit primary URL claims only when value looks network-ish;
    conditional claims (kid/sub) require stronger network-resource score.
    """
    vf = classify_value(sample)
    if claim in _PRIMARY_URL_CLAIMS:
        # iss/aud may be bare issuer names — emit when URL/host/IP-ish
        # or absolute URL; skip pure opaque strings.
        if vf.possible_url_value or vf.possible_hostname or vf.possible_ip:
            return True
        if vf.possible_protocol and vf.score >= 55:
            return True
        # Absolute-looking issuer without classifier hit is rare; skip noise.
        return False
    if claim in _CONDITIONAL_URL_CLAIMS:
        return (
            vf.possible_network_resource
            or vf.score >= NETWORK_RESOURCE_SCORE_THRESHOLD
        )
    # Other claims: only if clearly a network resource (value-first).
    return bool(vf.possible_url_value and vf.score >= 70)
