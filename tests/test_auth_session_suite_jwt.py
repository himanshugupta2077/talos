"""
Tests: auth-session JWT suite catalog + analyzer registry (Phase 1.3).

Covers:
  - core catalog ids present (jwt.alg_none*)
  - Phase-1 degradation matrix for RS256 / HS256 / ES256 / none
  - none-skip rule: no *_to_none degradation ids
  - claim-required filtering
  - JwtAnalyzer detect / list_test_cases / apply
  - ANALYZERS registry
"""

from __future__ import annotations

import pytest

from talos.auth_session.jwt_codec import encode_jwt
from talos.auth_session.models import (
    AUTH_TYPE_JWT,
    FAMILY_ALGORITHM_DEGRADE,
    TokenContext,
)
from talos.auth_session.suite_jwt import (
    CORE_JWT_TEST_CASES,
    alg_degradation_tests,
    all_core_test_ids,
    list_jwt_test_cases,
    normalize_alg,
)
from talos.auth_session.types import ANALYZERS, JwtAnalyzer, get_analyzer


def _token(alg: str = "RS256", payload: dict | None = None) -> str:
    p = payload if payload is not None else {
        "sub": "user1",
        "role": "user",
        "exp": 9999999999,
        "iss": "https://issuer.example",
        "aud": "api",
    }
    return encode_jwt({"alg": alg, "typ": "JWT"}, p, "sig01")


def _ctx_from_token(token: str) -> TokenContext:
    analyzer = JwtAnalyzer()
    ctx = analyzer.detect(f"Bearer {token}", location="header", field_name="Authorization")
    assert ctx is not None
    return ctx


# ------------------------------------------------------------------ #
# Catalog / degradation                                                #
# ------------------------------------------------------------------ #


def test_core_catalog_includes_none_rows() -> None:
    ids = all_core_test_ids()
    for required in (
        "jwt.alg_none",
        "jwt.alg_None",
        "jwt.alg_NONE",
        "jwt.alg_none_empty_sig",
        "jwt.alg_empty",
        "jwt.alg_missing",
        "jwt.alg_unknown",
        "jwt.invalid_signature",
        "jwt.missing_signature",
        "jwt.elevate_role",
        "jwt.huge_kid",
    ):
        assert required in ids


def test_normalize_alg() -> None:
    assert normalize_alg("RS256") == "rs256"
    assert normalize_alg("none") == "none"
    assert normalize_alg("") == "empty"
    assert normalize_alg(None) == "missing"
    assert normalize_alg(123) == "unknown"


def test_rs256_phase1_degradation_targets() -> None:
    cases = alg_degradation_tests("RS256")
    ids = [c.test_id for c in cases]
    assert "jwt.alg_degrade.rs256_to_hs256" in ids
    assert "jwt.alg_degrade.rs256_to_hs384" in ids
    assert "jwt.alg_degrade.rs256_to_hs512" in ids
    # Phase 5 only — must NOT appear in Phase 1.
    assert "jwt.alg_degrade.rs256_to_es256" not in ids
    assert "jwt.alg_degrade.rs256_to_ps256" not in ids
    # none-skip rule.
    assert "jwt.alg_degrade.rs256_to_none" not in ids
    for c in cases:
        assert c.family == FAMILY_ALGORITHM_DEGRADE
        assert "_to_none" not in c.test_id


def test_degradation_never_emits_to_none_for_any_alg() -> None:
    for alg in (
        "RS256", "RS384", "RS512",
        "ES256", "ES384", "ES512",
        "PS256", "PS384", "PS512",
        "HS256", "HS384", "HS512",
        "none", "", None, "WeirdAlg",
    ):
        cases = alg_degradation_tests(alg)
        for c in cases:
            assert not c.test_id.endswith("_to_none")
            assert "_to_none" not in c.test_id
            assert not c.test_id.endswith("_to_empty")
            assert not c.test_id.endswith("_to_missing")
            assert not c.test_id.endswith("_to_unknown")


def test_hs256_phase1_targets() -> None:
    ids = [c.test_id for c in alg_degradation_tests("HS256")]
    assert "jwt.alg_degrade.hs256_to_hs512" in ids
    assert "jwt.alg_degrade.hs256_to_rs256" in ids
    assert "jwt.alg_degrade.hs256_to_none" not in ids


def test_es256_phase1_targets() -> None:
    ids = [c.test_id for c in alg_degradation_tests("ES256")]
    assert set(ids) == {
        "jwt.alg_degrade.es256_to_hs256",
        "jwt.alg_degrade.es256_to_hs384",
        "jwt.alg_degrade.es256_to_hs512",
    }


def test_none_original_degrades_to_hs_rs_only() -> None:
    ids = [c.test_id for c in alg_degradation_tests("none")]
    assert "jwt.alg_degrade.none_to_hs256" in ids
    assert "jwt.alg_degrade.none_to_rs256" in ids
    assert len(ids) == 2


def test_list_test_cases_includes_core_and_degrade() -> None:
    ctx = _ctx_from_token(_token("RS256"))
    cases = list_jwt_test_cases(ctx)
    ids = [c.test_id for c in cases]
    # Core none rows always present.
    assert "jwt.alg_none" in ids
    assert "jwt.alg_None" in ids
    # Degradation Phase 1.
    assert "jwt.alg_degrade.rs256_to_hs256" in ids
    assert "jwt.alg_degrade.rs256_to_none" not in ids
    # Claim-required present when claims exist.
    assert "jwt.remove_exp" in ids
    assert "jwt.modify_sub" in ids
    assert "jwt.elevate_role" in ids


def test_list_skips_missing_claims() -> None:
    token = _token("HS256", payload={"role": "user"})  # no sub/exp/iss/aud
    ctx = _ctx_from_token(token)
    ids = [c.test_id for c in list_jwt_test_cases(ctx)]
    assert "jwt.remove_exp" not in ids
    assert "jwt.modify_sub" not in ids
    assert "jwt.remove_iss" not in ids
    assert "jwt.elevate_role" in ids  # role present


def test_list_skips_elevate_when_no_elevation_claims() -> None:
    token = _token("HS256", payload={"sub": "only-sub"})
    ctx = _ctx_from_token(token)
    ids = [c.test_id for c in list_jwt_test_cases(ctx)]
    assert "jwt.elevate_role" not in ids


def test_disabled_tests_and_families() -> None:
    ctx = _ctx_from_token(_token("RS256"))
    cases = list_jwt_test_cases(
        ctx,
        {
            "disabled_tests": ["jwt.huge_kid", "jwt.alg_degrade.rs256_to_hs384"],
            "enabled_families": ["algorithm", "algorithm_degrade"],
        },
    )
    ids = [c.test_id for c in cases]
    assert "jwt.alg_none" in ids
    assert "jwt.huge_kid" not in ids
    assert "jwt.invalid_signature" not in ids  # signature family disabled
    assert "jwt.alg_degrade.rs256_to_hs256" in ids
    assert "jwt.alg_degrade.rs256_to_hs384" not in ids


# ------------------------------------------------------------------ #
# Analyzer registry                                                    #
# ------------------------------------------------------------------ #


def test_jwt_analyzer_detect_bearer() -> None:
    analyzer = JwtAnalyzer()
    token = _token()
    ctx = analyzer.detect(f"Bearer {token}")
    assert ctx is not None
    assert ctx.scheme == "Bearer"
    assert ctx.header["alg"] == "RS256"
    assert ctx.payload["sub"] == "user1"
    assert ctx.raw_token == token


def test_jwt_analyzer_detect_rejects_garbage() -> None:
    analyzer = JwtAnalyzer()
    assert analyzer.detect("not-a-token") is None
    assert analyzer.detect("") is None
    assert analyzer.detect("Bearer xyz") is None


def test_jwt_analyzer_list_and_apply() -> None:
    analyzer = JwtAnalyzer()
    token = _token("RS256")
    ctx = analyzer.detect(f"Bearer {token}")
    assert ctx is not None
    cases = analyzer.list_test_cases(ctx)
    assert any(c.test_id == "jwt.alg_none" for c in cases)
    mut = analyzer.apply(ctx, "jwt.alg_none")
    assert mut.test_id == "jwt.alg_none"
    assert mut.new_header_or_cookie_value.startswith("Bearer ")
    # Degradation apply
    mut2 = analyzer.apply(ctx, "jwt.alg_degrade.rs256_to_hs256")
    assert mut2.metadata["to_alg"] == "HS256"


def test_analyzers_registry() -> None:
    assert AUTH_TYPE_JWT in ANALYZERS
    assert get_analyzer("jwt").auth_type == "jwt"
    assert get_analyzer("JWT").auth_type == "jwt"
    with pytest.raises(KeyError):
        get_analyzer("saml")


def test_core_test_case_count_stable() -> None:
    # Guard against accidental catalog shrinkage.
    assert len(CORE_JWT_TEST_CASES) >= 20
