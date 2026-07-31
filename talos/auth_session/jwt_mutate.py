"""
Module: talos.auth_session.jwt_mutate

Purpose:
    Pure JWT mutation functions for the auth-session suite. Each public
    mutator takes a TokenContext (+ optional config) and returns a MutatedToken
    for exactly one test_id. No network, no crypto libraries (KD5).

    Algorithm degradation rewrites header ``alg`` only and keeps the original
    signature segment byte-for-byte (KD15 / design hard rule).

Dependencies: copy, json, secrets; jwt_codec; models
Data flow: TokenContext → MutatedToken
Side effects: None.
"""

from __future__ import annotations

import copy
import json
import secrets
import time
from typing import Any, Callable, Optional

from talos.auth_session.jwt_codec import (
    apply_scheme,
    b64url_encode,
    encode_json_segment,
    encode_jwt,
    join_compact_jwt,
    parse_token_parts,
    split_compact_jwt,
)
from talos.auth_session.models import MutatedToken, TokenContext

# Caps (design: huge_kid ~8–16 KiB; v1 uses 8 KiB).
_HUGE_KID_BYTES = 8 * 1024
_FAR_FUTURE_OFFSET_S = 10 * 365 * 24 * 3600  # ~10 years
_PAST_OFFSET_S = 365 * 24 * 3600  # ~1 year ago


def _with_scheme(ctx: TokenContext, compact: str) -> str:
    """Re-apply scheme for headers; cookies stay bare compact JWT."""
    if ctx.location == "cookie":
        return compact
    return apply_scheme(ctx.scheme, compact)


def _base_parts(ctx: TokenContext) -> tuple[dict[str, Any], dict[str, Any], str]:
    """
    Purpose:
        Copy header/payload and load original signature from raw token.
    """
    header = copy.deepcopy(ctx.header)
    payload = copy.deepcopy(ctx.payload)
    parsed = parse_token_parts(ctx.raw_token)
    if parsed is None:
        # Fall back: re-split raw_token for signature only.
        try:
            _, _, sig = split_compact_jwt(ctx.raw_token)
        except ValueError:
            sig = ""
    else:
        _, _, sig = parsed
    return header, payload, sig


def _result(
    test_id: str,
    ctx: TokenContext,
    compact: str,
    summary: str,
    metadata: Optional[dict[str, Any]] = None,
) -> MutatedToken:
    return MutatedToken(
        test_id=test_id,
        new_raw_token=compact,
        new_header_or_cookie_value=_with_scheme(ctx, compact),
        mutation_summary=summary,
        metadata=dict(metadata or {}),
    )


def _header_only(
    ctx: TokenContext,
    test_id: str,
    *,
    summary: str,
    metadata: Optional[dict[str, Any]] = None,
    mutate_header: Callable[[dict[str, Any]], None],
) -> MutatedToken:
    """
    Purpose:
        Rewrite JWT header dict only; keep original payload and signature
        segments **byte-for-byte** (design hard rule for degradation and
        other signature-preserving header probes).
    """
    _header_b64, payload_b64, sig = split_compact_jwt(ctx.raw_token)
    header = copy.deepcopy(ctx.header)
    mutate_header(header)
    new_header_b64 = encode_json_segment(header)
    compact = join_compact_jwt(new_header_b64, payload_b64, sig)
    return _result(test_id, ctx, compact, summary, metadata)


def _normalize_alg_id(alg: Any) -> str:
    """
    Normalize alg for test_id segments (lowercase alnum).
    Aligns with suite_jwt.normalize_alg for empty/missing semantics where
    possible; empty string → ``empty`` (not ``unknown``).
    """
    if alg is None:
        return "missing"
    if not isinstance(alg, str):
        return "unknown"
    text = alg.strip()
    if text == "":
        return "empty"
    cleaned = "".join(ch for ch in text.lower() if ch.isalnum())
    return cleaned or "unknown"


# ------------------------------------------------------------------ #
# Algorithm family (core owns pure none)                               #
# ------------------------------------------------------------------ #


def mutate_alg_none(ctx: TokenContext, *, casing: str = "none") -> MutatedToken:
    """
    Purpose:
        Set header alg to none / None / NONE.

        - ``jwt.alg_none`` (casing ``none``): **stripped** signature — two-part
          token ``h.p`` (no third segment). Differentiates from empty-sig sibling.
        - ``jwt.alg_None`` / ``jwt.alg_NONE``: three-part with empty third segment.
    """
    header, payload, _sig = _base_parts(ctx)
    header["alg"] = casing
    tid = {
        "none": "jwt.alg_none",
        "None": "jwt.alg_None",
        "NONE": "jwt.alg_NONE",
    }.get(casing, "jwt.alg_none")
    if casing == "none":
        # Stripped signature segment (two-part compact JWT).
        compact = encode_jwt(header, payload, omit_signature_segment=True)
        summary = f"Set alg={casing!r}; stripped signature segment (two-part token)"
        meta: dict[str, Any] = {"alg": casing, "signature": "stripped"}
    else:
        compact = encode_jwt(header, payload, "")
        summary = f"Set alg={casing!r} with empty signature segment"
        meta = {"alg": casing, "signature": "empty"}
    return _result(tid, ctx, compact, summary, meta)


def mutate_alg_none_empty_sig(ctx: TokenContext) -> MutatedToken:
    """
    alg=none with explicitly empty third segment (``h.p.``).

    Distinct from ``jwt.alg_none`` which emits a two-part stripped token.
    """
    header, payload, _sig = _base_parts(ctx)
    header["alg"] = "none"
    compact = encode_jwt(header, payload, "")
    return _result(
        "jwt.alg_none_empty_sig",
        ctx,
        compact,
        "Set alg='none' with empty signature segment (three-part h.p.)",
        {"alg": "none", "signature": "empty"},
    )


def mutate_alg_empty(ctx: TokenContext) -> MutatedToken:
    """Set alg to empty string; preserve original payload + signature segments."""

    def _set(h: dict[str, Any]) -> None:
        h["alg"] = ""

    return _header_only(
        ctx,
        "jwt.alg_empty",
        summary="Set alg to empty string (payload+signature segments unchanged)",
        metadata={"alg": ""},
        mutate_header=_set,
    )


def mutate_alg_missing(ctx: TokenContext) -> MutatedToken:
    """Delete alg header claim; preserve original payload + signature segments."""

    def _drop(h: dict[str, Any]) -> None:
        h.pop("alg", None)

    return _header_only(
        ctx,
        "jwt.alg_missing",
        summary="Removed alg header claim (payload+signature segments unchanged)",
        metadata={"alg": None},
        mutate_header=_drop,
    )


def mutate_alg_unknown(ctx: TokenContext) -> MutatedToken:
    """Set alg to a non-standard value; preserve payload + signature segments."""
    fake = "TalosFakeAlg"

    def _set(h: dict[str, Any]) -> None:
        h["alg"] = fake

    return _header_only(
        ctx,
        "jwt.alg_unknown",
        summary=f"Set alg={fake!r} (payload+signature segments unchanged)",
        metadata={"alg": fake},
        mutate_header=_set,
    )


def mutate_alg_degrade(
    ctx: TokenContext,
    target_alg: str,
    *,
    test_id: Optional[str] = None,
) -> MutatedToken:
    """
    Purpose:
        Algorithm degradation: rewrite header ``alg`` only.

    Hard rule (design KD15):
        - re-encode **header** segment only
        - keep **payload** segment byte-for-byte
        - keep **signature** segment byte-for-byte
    """
    original_alg = ctx.header.get("alg")
    if original_alg is None:
        original_display = "missing"
    elif original_alg == "":
        original_display = ""
    else:
        original_display = str(original_alg)

    from_norm = _normalize_alg_id(original_alg)
    to_norm = _normalize_alg_id(target_alg)
    tid = test_id or f"jwt.alg_degrade.{from_norm}_to_{to_norm}"

    def _set_alg(h: dict[str, Any]) -> None:
        h["alg"] = target_alg

    return _header_only(
        ctx,
        tid,
        summary=(
            f"Degrade alg {original_display!r} → {target_alg!r} "
            "(payload+signature segments unchanged)"
        ),
        metadata={
            "from_alg": original_display if original_display != "missing" else None,
            "to_alg": target_alg,
            "signature_policy": "unchanged",
            "payload_policy": "unchanged",
        },
        mutate_header=_set_alg,
    )


# ------------------------------------------------------------------ #
# Signature / structure                                                #
# ------------------------------------------------------------------ #


def mutate_invalid_signature(ctx: TokenContext, *, flip_chars: int = 4) -> MutatedToken:
    """Flip last N characters of the signature segment."""
    header_b64, payload_b64, sig = split_compact_jwt(ctx.raw_token)
    if not sig:
        # No signature to flip — invent a short corrupt segment.
        new_sig = "XXXX"
    else:
        n = max(1, min(flip_chars, len(sig)))
        # Flip by XOR-ish replacement of last n chars with different base64url.
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        tail = list(sig[-n:])
        for i, ch in enumerate(tail):
            # Pick a different alphabet char deterministically from index.
            idx = alphabet.find(ch)
            if idx < 0:
                tail[i] = "X"
            else:
                tail[i] = alphabet[(idx + 7) % len(alphabet)]
        new_sig = sig[:-n] + "".join(tail)
        if new_sig == sig:
            new_sig = sig[:-1] + ("A" if sig[-1] != "A" else "B")
    compact = join_compact_jwt(header_b64, payload_b64, new_sig)
    return _result(
        "jwt.invalid_signature",
        ctx,
        compact,
        f"Corrupted last {min(flip_chars, len(sig) or 4)} chars of signature",
        {"flip_chars": flip_chars},
    )


def mutate_missing_signature(ctx: TokenContext) -> MutatedToken:
    """Two-part token h.p (no third segment)."""
    header, payload, _sig = _base_parts(ctx)
    compact = encode_jwt(header, payload, omit_signature_segment=True)
    return _result(
        "jwt.missing_signature",
        ctx,
        compact,
        "Removed signature segment entirely (two-part token)",
        {"segments": 2},
    )


def mutate_empty_payload(ctx: TokenContext) -> MutatedToken:
    """Replace payload with empty object {}."""
    header, _payload, sig = _base_parts(ctx)
    compact = encode_jwt(header, {}, sig)
    return _result(
        "jwt.empty_payload",
        ctx,
        compact,
        "Replaced payload with empty object {}",
        {},
    )


def mutate_empty_header(ctx: TokenContext) -> MutatedToken:
    """Replace header with empty object {}."""
    _header, payload, sig = _base_parts(ctx)
    compact = encode_jwt({}, payload, sig)
    return _result(
        "jwt.empty_header",
        ctx,
        compact,
        "Replaced header with empty object {}",
        {},
    )


def mutate_corrupted_b64(ctx: TokenContext) -> MutatedToken:
    """
    Break the payload segment so strict parsers reject it.

    Uses non-JSON base64url bytes plus illegal characters. (Python's
    base64 decoder ignores non-alphabet chars unless validate=True, so
    non-JSON content is required for a reliable decode failure.)
    """
    header_b64, payload_b64, sig = split_compact_jwt(ctx.raw_token)
    # Valid-looking base64url of non-JSON + illegal chars for strict clients.
    broken = b64url_encode(b"{{{{{NOT_JSON") + "!!!" + payload_b64[:4]
    compact = join_compact_jwt(header_b64, broken, sig)
    return _result(
        "jwt.corrupted_b64",
        ctx,
        compact,
        "Corrupted payload segment (non-JSON + illegal base64url chars)",
        {},
    )


# ------------------------------------------------------------------ #
# Claims                                                               #
# ------------------------------------------------------------------ #


def mutate_remove_claim(ctx: TokenContext, claim: str, *, test_id: str) -> MutatedToken:
    """Delete a payload claim if present (caller may still invoke when absent)."""
    header, payload, sig = _base_parts(ctx)
    payload.pop(claim, None)
    compact = encode_jwt(header, payload, sig)
    return _result(
        test_id,
        ctx,
        compact,
        f"Removed payload claim {claim!r}",
        {"claim": claim, "action": "remove"},
    )


def mutate_exp_far_future(ctx: TokenContext) -> MutatedToken:
    header, payload, sig = _base_parts(ctx)
    payload["exp"] = int(time.time()) + _FAR_FUTURE_OFFSET_S
    compact = encode_jwt(header, payload, sig)
    return _result(
        "jwt.exp_far_future",
        ctx,
        compact,
        f"Set exp to far future ({payload['exp']})",
        {"exp": payload["exp"]},
    )


def mutate_exp_past(ctx: TokenContext) -> MutatedToken:
    header, payload, sig = _base_parts(ctx)
    payload["exp"] = int(time.time()) - _PAST_OFFSET_S
    compact = encode_jwt(header, payload, sig)
    return _result(
        "jwt.exp_past",
        ctx,
        compact,
        f"Set exp to past ({payload['exp']})",
        {"exp": payload["exp"]},
    )


def mutate_modify_sub(ctx: TokenContext, *, suffix: str = "-talos") -> MutatedToken:
    header, payload, sig = _base_parts(ctx)
    original = payload.get("sub", "user")
    if isinstance(original, str):
        payload["sub"] = f"{original}{suffix}"
    else:
        payload["sub"] = f"talos{suffix}"
    compact = encode_jwt(header, payload, sig)
    return _result(
        "jwt.modify_sub",
        ctx,
        compact,
        f"Changed sub to {payload['sub']!r}",
        {"sub": payload["sub"]},
    )


def _elevate_value(current: Any, ladder: list[Any]) -> Any | None:
    """
    Purpose:
        Compute elevated claim value from a from→to ladder.
    Output:
        New value, or None if already at top / no change needed.
    """
    if not ladder or len(ladder) < 2:
        return None
    low, high = ladder[0], ladder[-1]

    # List/array claims (e.g. roles: ["user"]): promote membership.
    if isinstance(current, list):
        # Already holds high privilege marker.
        if high in current or (
            isinstance(high, str)
            and any(isinstance(x, str) and x.lower() == high.lower() for x in current)
        ):
            return None
        elevated = list(current)
        # Drop low-priv scalar if present; append high.
        elevated = [
            x
            for x in elevated
            if not (
                x == low
                or (isinstance(x, str) and isinstance(low, str) and x.lower() == low.lower())
            )
        ]
        elevated.append(high)
        return elevated

    if current == high:
        return None
    if isinstance(current, str) and isinstance(high, str) and current.lower() == high.lower():
        return None
    if current == low or (
        isinstance(current, str)
        and isinstance(low, str)
        and current.lower() == low.lower()
    ):
        return high
    # Present but neither low nor high — still force high (claim elevation probe).
    if current != high:
        return high
    return None


def mutate_elevate_role(
    ctx: TokenContext,
    elevation_map: Optional[dict[str, list[Any]]] = None,
) -> MutatedToken:
    """
    Purpose:
        Apply claim-elevation map to matching payload claims.
        Default map elevates role/user→admin style claims when present.
        Does **not** invent claims that were absent (generate skips when none
        present). List-valued claims keep list shape (e.g. roles → […, admin]).
    """
    header, payload, sig = _base_parts(ctx)
    elev = elevation_map or default_claim_elevation_map()
    applied: dict[str, Any] = {}
    for claim, ladder in elev.items():
        if claim not in payload:
            continue
        if not isinstance(ladder, (list, tuple)) or len(ladder) < 2:
            continue
        current = payload[claim]
        new_val = _elevate_value(current, list(ladder))
        if new_val is None:
            continue
        payload[claim] = new_val
        applied[claim] = {"from": current, "to": new_val}
    if applied:
        compact = encode_jwt(header, payload, sig)
        summary = f"Elevated claims: {applied}"
    else:
        # No semantic change — keep original compact token (avoid false
        # re-encode diffs when claims are already elevated).
        compact = ctx.raw_token
        summary = "No claim elevation applied (already elevated or empty map)"
    return _result(
        "jwt.elevate_role",
        ctx,
        compact,
        summary,
        {"elevated": applied},
    )


def default_claim_elevation_map() -> dict[str, list[Any]]:
    """Built-in claim elevation defaults (design Open Q #1 decided)."""
    return {
        "role": ["user", "admin"],
        "roles": ["user", "admin"],
        "is_admin": [False, True],
        "scope": ["read", "admin"],
        "admin": [False, True],
        "isAdmin": [False, True],
        "privilege": ["user", "admin"],
        "permissions": ["read", "admin"],
    }


def mutate_duplicate_claim_role(ctx: TokenContext) -> MutatedToken:
    """
    Purpose:
        Craft payload segment with duplicated ``role`` key via string concat
        (json.dumps cannot emit duplicate keys).
    """
    header, payload, sig = _base_parts(ctx)
    # Build JSON manually: original keys then a second role.
    body = dict(payload)
    # Ensure a first role exists for duplication semantics.
    first_role = body.get("role", "user")
    # Remove role so we control order; append twice at end.
    body.pop("role", None)
    base = json.dumps(body, separators=(",", ":"), ensure_ascii=True)
    if base == "{}":
        crafted = f'{{"role":{json.dumps(first_role)},"role":"admin"}}'
    else:
        # Insert before closing brace.
        inner = base[1:-1]
        if inner:
            crafted = (
                "{"
                + inner
                + f',"role":{json.dumps(first_role)},"role":"admin"'
                + "}"
            )
        else:
            crafted = f'{{"role":{json.dumps(first_role)},"role":"admin"}}'
    header_b64 = encode_json_segment(header)
    # Encode crafted JSON as base64url without re-parsing.
    payload_b64 = b64url_encode(crafted.encode("utf-8"))
    compact = join_compact_jwt(header_b64, payload_b64, sig)
    return _result(
        "jwt.duplicate_claim_role",
        ctx,
        compact,
        "Payload segment contains duplicate JSON key 'role'",
        {"duplicate_claim": "role"},
    )


# ------------------------------------------------------------------ #
# kid                                                                  #
# ------------------------------------------------------------------ #


def mutate_invalid_kid(ctx: TokenContext) -> MutatedToken:
    kid = f"talos-invalid-{secrets.token_hex(8)}"

    def _set(h: dict[str, Any]) -> None:
        h["kid"] = kid

    return _header_only(
        ctx,
        "jwt.invalid_kid",
        summary=f"Set kid to random value {kid!r} (payload+signature unchanged)",
        metadata={"kid": kid},
        mutate_header=_set,
    )


def mutate_empty_kid(ctx: TokenContext) -> MutatedToken:
    def _set(h: dict[str, Any]) -> None:
        h["kid"] = ""

    return _header_only(
        ctx,
        "jwt.empty_kid",
        summary="Set kid to empty string (payload+signature unchanged)",
        metadata={"kid": ""},
        mutate_header=_set,
    )


def mutate_huge_kid(ctx: TokenContext, *, size: int = _HUGE_KID_BYTES) -> MutatedToken:
    n = max(1, min(size, 16 * 1024))
    kid = "K" * n

    def _set(h: dict[str, Any]) -> None:
        h["kid"] = kid

    return _header_only(
        ctx,
        "jwt.huge_kid",
        summary=f"Set kid to {n}-byte string (payload+signature unchanged)",
        metadata={"kid_bytes": n},
        mutate_header=_set,
    )


# ------------------------------------------------------------------ #
# Dispatch map                                                         #
# ------------------------------------------------------------------ #

MutatorFn = Callable[[TokenContext], MutatedToken]


def _alg_none(ctx: TokenContext) -> MutatedToken:
    return mutate_alg_none(ctx, casing="none")


def _alg_None(ctx: TokenContext) -> MutatedToken:
    return mutate_alg_none(ctx, casing="None")


def _alg_NONE(ctx: TokenContext) -> MutatedToken:
    return mutate_alg_none(ctx, casing="NONE")


def _remove_exp(ctx: TokenContext) -> MutatedToken:
    return mutate_remove_claim(ctx, "exp", test_id="jwt.remove_exp")


def _remove_nbf(ctx: TokenContext) -> MutatedToken:
    return mutate_remove_claim(ctx, "nbf", test_id="jwt.remove_nbf")


def _remove_iss(ctx: TokenContext) -> MutatedToken:
    return mutate_remove_claim(ctx, "iss", test_id="jwt.remove_iss")


def _remove_aud(ctx: TokenContext) -> MutatedToken:
    return mutate_remove_claim(ctx, "aud", test_id="jwt.remove_aud")


# Core fixed mutators (degradation dispatched dynamically).
CORE_MUTATORS: dict[str, MutatorFn] = {
    "jwt.alg_none": _alg_none,
    "jwt.alg_None": _alg_None,
    "jwt.alg_NONE": _alg_NONE,
    "jwt.alg_none_empty_sig": mutate_alg_none_empty_sig,
    "jwt.alg_empty": mutate_alg_empty,
    "jwt.alg_missing": mutate_alg_missing,
    "jwt.alg_unknown": mutate_alg_unknown,
    "jwt.invalid_signature": mutate_invalid_signature,
    "jwt.missing_signature": mutate_missing_signature,
    "jwt.empty_payload": mutate_empty_payload,
    "jwt.empty_header": mutate_empty_header,
    "jwt.corrupted_b64": mutate_corrupted_b64,
    "jwt.remove_exp": _remove_exp,
    "jwt.exp_far_future": mutate_exp_far_future,
    "jwt.exp_past": mutate_exp_past,
    "jwt.remove_nbf": _remove_nbf,
    "jwt.remove_iss": _remove_iss,
    "jwt.remove_aud": _remove_aud,
    "jwt.modify_sub": mutate_modify_sub,
    "jwt.elevate_role": mutate_elevate_role,
    "jwt.duplicate_claim_role": mutate_duplicate_claim_role,
    "jwt.invalid_kid": mutate_invalid_kid,
    "jwt.empty_kid": mutate_empty_kid,
    "jwt.huge_kid": mutate_huge_kid,
}


def apply_mutation(
    ctx: TokenContext,
    test_id: str,
    *,
    config: Optional[dict[str, Any]] = None,
) -> MutatedToken:
    """
    Purpose:
        Apply a suite test_id mutation to the token context.
    Input:
        ctx — TokenContext
        test_id — e.g. jwt.alg_none or jwt.alg_degrade.rs256_to_hs256
        config — optional binding config (claim_elevation map)
    Output:
        MutatedToken
    Side effects: None.
    Raises:
        KeyError if test_id unknown / not parseable as degradation.
    """
    cfg = config or {}
    if test_id in CORE_MUTATORS:
        fn = CORE_MUTATORS[test_id]
        if test_id == "jwt.elevate_role" and "claim_elevation" in cfg:
            return mutate_elevate_role(ctx, elevation_map=cfg["claim_elevation"])
        return fn(ctx)

    # Algorithm degradation: jwt.alg_degrade.<from>_to_<to>
    prefix = "jwt.alg_degrade."
    if test_id.startswith(prefix):
        rest = test_id[len(prefix):]
        if "_to_" not in rest:
            raise KeyError(f"unknown auth-session test_id: {test_id}")
        _from_part, to_part = rest.rsplit("_to_", 1)
        # Reject pure none targets (core owns none).
        to_norm = to_part.lower()
        if to_norm in {"none", "empty", "missing", "unknown"}:
            raise KeyError(
                f"degradation must not target {to_part!r}; use core suite rows"
            )
        # Reconstruct display alg (HS256 style) from normalized id.
        target_display = _display_alg(to_part)
        return mutate_alg_degrade(ctx, target_display, test_id=test_id)

    raise KeyError(f"unknown auth-session test_id: {test_id}")


def _display_alg(norm: str) -> str:
    """
    Purpose:
        Map normalized alg id (hs256) to conventional display (HS256).
        Unknown norms returned uppercased.
    """
    known = {
        "hs256": "HS256",
        "hs384": "HS384",
        "hs512": "HS512",
        "rs256": "RS256",
        "rs384": "RS384",
        "rs512": "RS512",
        "es256": "ES256",
        "es384": "ES384",
        "es512": "ES512",
        "ps256": "PS256",
        "ps384": "PS384",
        "ps512": "PS512",
        "none": "none",
    }
    key = (norm or "").lower()
    return known.get(key, (norm or "UNKNOWN").upper())
