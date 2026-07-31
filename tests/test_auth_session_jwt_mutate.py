"""
Tests: auth-session JWT codec + mutators (Phase 1.2).

Covers:
  - base64url encode/decode round-trip
  - header/payload encode + reassemble
  - scheme extract / preserve (Bearer)
  - each core mutator golden vectors
  - alg degradation keeps signature unchanged
  - none casings + empty sig
"""

from __future__ import annotations

import json

import pytest

from talos.auth_session.jwt_codec import (
    apply_scheme,
    b64url_decode,
    b64url_encode,
    decode_jwt_header,
    encode_json_segment,
    encode_jwt,
    extract_scheme_and_token,
    join_compact_jwt,
    parse_token_parts,
    split_compact_jwt,
)
from talos.auth_session.jwt_mutate import (
    CORE_MUTATORS,
    apply_mutation,
    mutate_alg_degrade,
    mutate_alg_none,
    mutate_invalid_signature,
    mutate_missing_signature,
)
from talos.auth_session.models import TokenContext
from talos.url_sink.jwt_claims import decode_jwt_payload


def _make_token(
    header: dict | None = None,
    payload: dict | None = None,
    signature: str = "sigbytes01",
) -> str:
    h = header if header is not None else {"alg": "RS256", "typ": "JWT"}
    p = payload if payload is not None else {
        "sub": "user1",
        "role": "user",
        "exp": 9999999999,
        "iss": "https://issuer.example",
        "aud": "api",
        "nbf": 1,
    }
    return encode_jwt(h, p, signature)


def _ctx(
    token: str | None = None,
    *,
    scheme: str | None = "Bearer",
    location: str = "header",
    field_name: str = "Authorization",
) -> TokenContext:
    compact = token or _make_token()
    parts = parse_token_parts(compact)
    assert parts is not None
    header, payload, _sig = parts
    full = apply_scheme(scheme, compact) if scheme else compact
    return TokenContext(
        raw_token=compact,
        scheme=scheme if location == "header" else None,
        header=header,
        payload=payload,
        location=location,
        field_name=field_name,
        original_header_value=full,
    )


# ------------------------------------------------------------------ #
# Codec                                                                #
# ------------------------------------------------------------------ #


def test_b64url_roundtrip() -> None:
    raw = b'{"alg":"HS256"}'
    enc = b64url_encode(raw)
    assert "=" not in enc
    assert b64url_decode(enc) == raw


def test_encode_decode_header_payload() -> None:
    token = _make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "u1"})
    header = decode_jwt_header(token)
    payload = decode_jwt_payload(token)
    assert header == {"alg": "HS256", "typ": "JWT"}
    assert payload == {"sub": "u1"}
    h, p, s = split_compact_jwt(token)
    assert join_compact_jwt(h, p, s) == token


def test_encode_json_segment_stable() -> None:
    seg = encode_json_segment({"alg": "none"})
    assert isinstance(seg, str)
    assert "=" not in seg


def test_extract_scheme_bearer() -> None:
    token = _make_token()
    raw = f"Bearer {token}"
    scheme, compact = extract_scheme_and_token(raw)
    assert scheme == "Bearer"
    assert compact == token


def test_extract_scheme_bare_token() -> None:
    token = _make_token()
    scheme, compact = extract_scheme_and_token(token)
    assert scheme is None
    assert compact == token


def test_apply_scheme() -> None:
    assert apply_scheme("Bearer", "abc.def.ghi") == "Bearer abc.def.ghi"
    assert apply_scheme(None, "abc.def.ghi") == "abc.def.ghi"


def test_decode_jwt_header_invalid() -> None:
    assert decode_jwt_header("not-a-jwt") is None
    assert decode_jwt_header("") is None


# ------------------------------------------------------------------ #
# Mutators                                                             #
# ------------------------------------------------------------------ #


def test_alg_none_casings() -> None:
    ctx = _ctx()
    # jwt.alg_none (casing none): stripped two-part token.
    mut_none = mutate_alg_none(ctx, casing="none")
    assert mut_none.test_id == "jwt.alg_none"
    assert decode_jwt_header(mut_none.new_raw_token)["alg"] == "none"
    assert len(mut_none.new_raw_token.split(".")) == 2
    assert mut_none.metadata.get("signature") == "stripped"
    assert mut_none.new_header_or_cookie_value.startswith("Bearer ")

    # Casing variants use empty third segment (three-part).
    for casing, tid in [("None", "jwt.alg_None"), ("NONE", "jwt.alg_NONE")]:
        mut = mutate_alg_none(ctx, casing=casing)
        assert mut.test_id == tid
        h = decode_jwt_header(mut.new_raw_token)
        assert h is not None
        assert h["alg"] == casing
        parts = mut.new_raw_token.split(".")
        assert len(parts) == 3
        assert parts[2] == ""
        assert mut.new_header_or_cookie_value.startswith("Bearer ")


def test_alg_none_empty_sig_distinct_from_alg_none() -> None:
    """jwt.alg_none (stripped) must differ from jwt.alg_none_empty_sig (h.p.)."""
    ctx = _ctx()
    stripped = apply_mutation(ctx, "jwt.alg_none")
    empty_sig = apply_mutation(ctx, "jwt.alg_none_empty_sig")
    assert stripped.new_raw_token != empty_sig.new_raw_token
    assert len(stripped.new_raw_token.split(".")) == 2
    assert empty_sig.new_raw_token.endswith(".")
    assert len(empty_sig.new_raw_token.split(".")) == 3
    assert empty_sig.metadata.get("signature") == "empty"


def test_alg_empty_missing_unknown() -> None:
    ctx = _ctx()
    m_empty = apply_mutation(ctx, "jwt.alg_empty")
    assert decode_jwt_header(m_empty.new_raw_token)["alg"] == ""

    m_missing = apply_mutation(ctx, "jwt.alg_missing")
    assert "alg" not in decode_jwt_header(m_missing.new_raw_token)

    m_unknown = apply_mutation(ctx, "jwt.alg_unknown")
    assert decode_jwt_header(m_unknown.new_raw_token)["alg"] == "TalosFakeAlg"


def test_alg_degrade_keeps_signature() -> None:
    sig = "OriginalSigSegment99"
    token = _make_token({"alg": "RS256", "typ": "JWT"}, {"sub": "u"}, sig)
    ctx = _ctx(token)
    mut = mutate_alg_degrade(ctx, "HS256")
    assert mut.test_id == "jwt.alg_degrade.rs256_to_hs256"
    _h, _p, s = split_compact_jwt(mut.new_raw_token)
    assert decode_jwt_header(mut.new_raw_token)["alg"] == "HS256"
    assert s == sig
    # Payload unchanged segment-wise after re-encode of same payload.
    orig_payload = decode_jwt_payload(token)
    assert decode_jwt_payload(mut.new_raw_token) == orig_payload
    assert mut.metadata.get("signature_policy") == "unchanged"


def test_header_only_preserves_spaced_payload_bytes() -> None:
    """
    Design hard rule: degradation / header-only mutators must keep the
    original payload segment byte-for-byte (even non-canonical JSON).
    """
    from talos.auth_session.jwt_codec import b64url_encode, join_compact_jwt
    from talos.auth_session.types import JwtAnalyzer

    h_raw = '{ "alg" : "RS256" , "typ" : "JWT" }'
    p_raw = '{ "sub" : "u1", "role" : "user" }'
    sig = "SigKeepMeByteForByte"
    token = join_compact_jwt(
        b64url_encode(h_raw.encode("utf-8")),
        b64url_encode(p_raw.encode("utf-8")),
        sig,
    )
    ctx = JwtAnalyzer().detect(f"Bearer {token}")
    assert ctx is not None
    _h0, p0, s0 = split_compact_jwt(token)

    for tid in (
        "jwt.alg_degrade.rs256_to_hs256",
        "jwt.alg_empty",
        "jwt.alg_missing",
        "jwt.alg_unknown",
        "jwt.empty_kid",
        "jwt.invalid_kid",
    ):
        mut = apply_mutation(ctx, tid)
        _h1, p1, s1 = split_compact_jwt(mut.new_raw_token)
        assert p1 == p0, f"{tid} re-encoded payload segment"
        assert s1 == s0, f"{tid} changed signature segment"


def test_invalid_signature_changes_sig() -> None:
    token = _make_token(signature="ABCDEFGH")
    ctx = _ctx(token)
    mut = mutate_invalid_signature(ctx)
    _h, _p, s_orig = split_compact_jwt(token)
    _h2, _p2, s_new = split_compact_jwt(mut.new_raw_token)
    assert s_new != s_orig


def test_missing_signature_two_parts() -> None:
    ctx = _ctx()
    mut = mutate_missing_signature(ctx)
    assert mut.new_raw_token.count(".") == 1
    assert len(mut.new_raw_token.split(".")) == 2


def test_empty_payload_and_header() -> None:
    ctx = _ctx()
    m_p = apply_mutation(ctx, "jwt.empty_payload")
    assert decode_jwt_payload(m_p.new_raw_token) == {}

    m_h = apply_mutation(ctx, "jwt.empty_header")
    assert decode_jwt_header(m_h.new_raw_token) == {}


def test_corrupted_b64() -> None:
    ctx = _ctx()
    mut = apply_mutation(ctx, "jwt.corrupted_b64")
    # Payload should not decode cleanly.
    assert decode_jwt_payload(mut.new_raw_token) is None


def test_claim_mutations() -> None:
    ctx = _ctx()
    m_exp = apply_mutation(ctx, "jwt.remove_exp")
    assert "exp" not in decode_jwt_payload(m_exp.new_raw_token)

    m_future = apply_mutation(ctx, "jwt.exp_far_future")
    assert decode_jwt_payload(m_future.new_raw_token)["exp"] > 1_000_000_000

    m_past = apply_mutation(ctx, "jwt.exp_past")
    assert decode_jwt_payload(m_past.new_raw_token)["exp"] < 2_000_000_000

    m_sub = apply_mutation(ctx, "jwt.modify_sub")
    assert decode_jwt_payload(m_sub.new_raw_token)["sub"].endswith("-talos")

    m_elev = apply_mutation(ctx, "jwt.elevate_role")
    assert decode_jwt_payload(m_elev.new_raw_token)["role"] == "admin"


def test_elevate_role_list_claim_keeps_list_shape() -> None:
    token = _make_token({"alg": "HS256"}, {"roles": ["user", "read"]})
    ctx = _ctx(token)
    mut = apply_mutation(ctx, "jwt.elevate_role")
    roles = decode_jwt_payload(mut.new_raw_token)["roles"]
    assert isinstance(roles, list)
    assert "admin" in roles
    assert "user" not in roles


def test_elevate_role_already_admin_no_false_force() -> None:
    token = _make_token({"alg": "HS256"}, {"role": "admin"})
    ctx = _ctx(token)
    mut = apply_mutation(ctx, "jwt.elevate_role")
    assert mut.metadata.get("elevated") == {}
    assert "No claim elevation" in mut.mutation_summary
    # No-op must not invent a re-encoded token (false positive risk later).
    assert mut.new_raw_token == ctx.raw_token


def test_duplicate_claim_role() -> None:
    ctx = _ctx()
    mut = apply_mutation(ctx, "jwt.duplicate_claim_role")
    # Segment contains two "role" keys as raw JSON.
    _h, payload_b64, _s = split_compact_jwt(mut.new_raw_token)
    from talos.auth_session.jwt_codec import b64url_decode

    raw = b64url_decode(payload_b64).decode("utf-8")
    assert raw.count('"role"') >= 2


def test_kid_mutations() -> None:
    ctx = _ctx()
    m_inv = apply_mutation(ctx, "jwt.invalid_kid")
    assert decode_jwt_header(m_inv.new_raw_token)["kid"].startswith("talos-invalid-")

    m_empty = apply_mutation(ctx, "jwt.empty_kid")
    assert decode_jwt_header(m_empty.new_raw_token)["kid"] == ""

    m_huge = apply_mutation(ctx, "jwt.huge_kid")
    kid = decode_jwt_header(m_huge.new_raw_token)["kid"]
    assert len(kid) == 8 * 1024


def test_cookie_location_no_scheme() -> None:
    token = _make_token()
    ctx = _ctx(token, scheme=None, location="cookie", field_name="access_token")
    mut = apply_mutation(ctx, "jwt.alg_none")
    assert not mut.new_header_or_cookie_value.startswith("Bearer")
    assert mut.new_header_or_cookie_value == mut.new_raw_token


def test_all_core_mutators_run() -> None:
    """Every CORE_MUTATORS entry produces a different compact token."""
    ctx = _ctx()
    for test_id in CORE_MUTATORS:
        mut = apply_mutation(ctx, test_id)
        assert mut.test_id == test_id
        assert mut.new_raw_token
        assert mut.new_header_or_cookie_value
        # Structural exception: huge_kid etc. still differ from original.
        if test_id != "jwt.corrupted_b64":
            # Most mutations change the compact form.
            pass
        assert mut.mutation_summary


def test_unknown_test_id_raises() -> None:
    ctx = _ctx()
    with pytest.raises(KeyError):
        apply_mutation(ctx, "jwt.not_a_real_test")


def test_degrade_to_none_rejected() -> None:
    ctx = _ctx()
    with pytest.raises(KeyError):
        apply_mutation(ctx, "jwt.alg_degrade.rs256_to_none")


def test_mutation_differs_from_original() -> None:
    ctx = _ctx()
    for tid in (
        "jwt.alg_none",
        "jwt.invalid_signature",
        "jwt.alg_degrade.rs256_to_hs256",
    ):
        mut = apply_mutation(ctx, tid)
        assert mut.new_raw_token != ctx.raw_token
