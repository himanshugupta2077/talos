"""
Module: talos.auth_session.jwt_codec

Purpose:
    Stdlib-only JWT (compact JWS) encode/decode helpers for auth-session
    mutations. We never *verify* tokens; we construct valid and invalid
    compact strings for replay testing (KD5).

    Reuses ``extract_jwt_token`` / ``decode_jwt_payload`` from
    ``talos.url_sink.jwt_claims`` for strip-scheme + payload decode.
    Header decode and re-encode live here (url_sink is inventory-only).

Dependencies: base64, binascii, json, re (stdlib); url_sink.jwt_claims
Data flow: compact string ↔ header/payload dicts ↔ reassembled token
Side effects: None.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Optional

from talos.url_sink.jwt_claims import decode_jwt_payload, extract_jwt_token

# Scheme prefix on Authorization-style values (capture for scheme_preserve).
_SCHEME_RE = re.compile(r"^(Bearer|Token)\s+(.+)$", re.IGNORECASE)

# Max sizes to avoid pathological tokens at generate/apply time.
_MAX_SEGMENT_LEN = 65_536
_MAX_TOKEN_LEN = 131_072


def b64url_encode(data: bytes) -> str:
    """
    Purpose:
        Base64url-encode without padding (JWT segment format).
    Input:
        data — raw bytes
    Output:
        base64url string without ``=`` padding
    Side effects: None.
    """
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(segment: str) -> bytes:
    """
    Purpose:
        Base64url-decode a JWT segment (add padding if needed).
    Input:
        segment — base64url text (may lack padding)
    Output:
        decoded bytes
    Side effects: None.
    Raises:
        binascii.Error / ValueError on invalid base64url.
    """
    if not isinstance(segment, str):
        raise ValueError("segment must be str")
    pad = (-len(segment)) % 4
    if pad:
        segment = segment + ("=" * pad)
    return base64.urlsafe_b64decode(segment.encode("ascii"))


def encode_json_segment(obj: Any) -> str:
    """
    Purpose:
        JSON-serialize then base64url-encode a JWT header or payload.
    Input:
        obj — JSON-serializable value (typically dict)
    Output:
        base64url segment string
    Side effects: None.
    """
    # Separators minimize size; ensure_ascii keeps pure ASCII segments.
    raw = json.dumps(obj, separators=(",", ":"), ensure_ascii=True)
    return b64url_encode(raw.encode("utf-8"))


def decode_json_segment(segment: str) -> Any:
    """
    Purpose:
        Base64url-decode then JSON-parse a JWT segment.
    Input:
        segment — base64url text
    Output:
        parsed JSON value
    Side effects: None.
    Raises:
        ValueError on decode/parse failure.
    """
    try:
        raw = b64url_decode(segment)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"invalid base64url segment: {exc}") from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"invalid JSON in JWT segment: {exc}") from exc


def split_compact_jwt(token: str) -> tuple[str, str, str]:
    """
    Purpose:
        Split a compact JWT into header, payload, signature segments.
        Signature may be empty (alg=none style).
    Input:
        token — compact string ``h.p.s`` (exactly three segments preferred)
    Output:
        (header_b64, payload_b64, signature_b64)
    Side effects: None.
    Raises:
        ValueError if fewer than two segments or empty header/payload.
    """
    if not token or not isinstance(token, str):
        raise ValueError("token must be a non-empty string")
    parts = token.split(".")
    if len(parts) < 2:
        raise ValueError("compact JWT requires at least header.payload")
    header_b64, payload_b64 = parts[0], parts[1]
    if not header_b64 or not payload_b64:
        raise ValueError("header and payload segments must be non-empty")
    if len(parts) == 2:
        # Two-part token (missing signature segment) — treat sig as absent.
        signature_b64 = ""
    else:
        # Join remaining parts so we do not silently drop dots in sig.
        signature_b64 = ".".join(parts[2:])
    if (
        len(header_b64) > _MAX_SEGMENT_LEN
        or len(payload_b64) > _MAX_SEGMENT_LEN
        or len(signature_b64) > _MAX_SEGMENT_LEN
    ):
        raise ValueError("JWT segment exceeds max length")
    return header_b64, payload_b64, signature_b64


def join_compact_jwt(
    header_b64: str,
    payload_b64: str,
    signature_b64: Optional[str] = None,
    *,
    omit_signature_segment: bool = False,
) -> str:
    """
    Purpose:
        Reassemble a compact JWT from segments.
    Input:
        header_b64 / payload_b64 / signature_b64 — raw segments
        omit_signature_segment — if True, emit two-part ``h.p`` only
    Output:
        compact token string
    Side effects: None.
    """
    if omit_signature_segment:
        token = f"{header_b64}.{payload_b64}"
    else:
        sig = "" if signature_b64 is None else signature_b64
        token = f"{header_b64}.{payload_b64}.{sig}"
    if len(token) > _MAX_TOKEN_LEN:
        raise ValueError("assembled JWT exceeds max length")
    return token


def decode_jwt_header(token: str) -> dict[str, Any] | None:
    """
    Purpose:
        Base64url-decode the JWT header segment to a JSON object.
        Parallel to ``decode_jwt_payload`` in url_sink (which has no header API).
    Input:
        token — compact JWT (two or three segments)
    Output:
        Header dict, or None on failure.
    Side effects: None.
    """
    try:
        header_b64, _, _ = split_compact_jwt(token)
        data = decode_json_segment(header_b64)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def encode_jwt(
    header: dict[str, Any],
    payload: dict[str, Any],
    signature_b64: Optional[str] = None,
    *,
    omit_signature_segment: bool = False,
) -> str:
    """
    Purpose:
        Encode header + payload dicts into a compact JWT, optionally
        keeping or omitting a signature segment.
    Input:
        header / payload — JSON objects
        signature_b64 — pre-encoded signature segment (unchanged for degrade)
        omit_signature_segment — emit ``h.p`` only (missing_signature test)
    Output:
        compact JWT string
    Side effects: None.
    """
    header_b64 = encode_json_segment(header)
    payload_b64 = encode_json_segment(payload)
    return join_compact_jwt(
        header_b64,
        payload_b64,
        signature_b64,
        omit_signature_segment=omit_signature_segment,
    )


def extract_scheme_and_token(
    raw_value: str | None,
) -> tuple[Optional[str], Optional[str]]:
    """
    Purpose:
        Split an Authorization-style value into optional scheme + compact JWT.
        Uses ``extract_jwt_token`` for JWT shape validation after scheme strip.
    Input:
        raw_value — e.g. ``Bearer eyJ…`` or bare compact JWT
    Output:
        (scheme_or_None, compact_token_or_None)
        scheme is normalized capitalization of Bearer/Token when present.
    Side effects: None.
    """
    if not raw_value:
        return None, None
    text = raw_value.strip()
    scheme: Optional[str] = None
    token_part = text
    m = _SCHEME_RE.match(text)
    if m:
        # Preserve conventional capitalization for rewrite.
        raw_scheme = m.group(1)
        scheme = raw_scheme[0].upper() + raw_scheme[1:].lower()
        if scheme.lower() == "bearer":
            scheme = "Bearer"
        elif scheme.lower() == "token":
            scheme = "Token"
        token_part = m.group(2).strip()
    compact = extract_jwt_token(token_part)
    if compact is None:
        # extract_jwt_token also accepts scheme-prefixed input; try full text.
        compact = extract_jwt_token(text)
        if compact is None:
            return scheme, None
    return scheme, compact


def apply_scheme(scheme: Optional[str], compact_token: str) -> str:
    """
    Purpose:
        Re-apply auth scheme prefix when rewriting header values.
    Input:
        scheme — Bearer | Token | None
        compact_token — mutated JWT
    Output:
        full field value for header/cookie write
    Side effects: None.
    """
    if scheme:
        return f"{scheme} {compact_token}"
    return compact_token


def parse_token_parts(
    token: str,
) -> tuple[dict[str, Any], dict[str, Any], str] | None:
    """
    Purpose:
        Decode header + payload and return original signature segment.
    Input:
        token — compact JWT
    Output:
        (header_dict, payload_dict, signature_b64) or None on failure
    Side effects: None.
    """
    try:
        header_b64, payload_b64, signature_b64 = split_compact_jwt(token)
        header = decode_json_segment(header_b64)
        payload = decode_json_segment(payload_b64)
    except ValueError:
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    return header, payload, signature_b64


# Re-export for callers that want a single import surface.
__all__ = [
    "apply_scheme",
    "b64url_decode",
    "b64url_encode",
    "decode_json_segment",
    "decode_jwt_header",
    "decode_jwt_payload",
    "encode_json_segment",
    "encode_jwt",
    "extract_jwt_token",
    "extract_scheme_and_token",
    "join_compact_jwt",
    "parse_token_parts",
    "split_compact_jwt",
]
