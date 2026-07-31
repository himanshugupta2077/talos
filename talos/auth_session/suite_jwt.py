"""
Module: talos.auth_session.suite_jwt

Purpose:
    JWT test suite catalog for auth-session. Defines core fixed test cases
    and the full algorithm-degradation matrix expansion relative to the
    observed header ``alg`` (KD15; Phase 5 completes the product matrix).

    Product rule: degradation **never** emits pure ``to_none`` / empty /
    missing / unknown targets — core ``jwt.alg_none*`` rows own those probes.

Dependencies: models, jwt_mutate
Data flow: TokenContext + config → list[TestCaseDef]; apply via jwt_mutate
Side effects: None.
"""

from __future__ import annotations

from typing import Any, Optional

from talos.auth_session.jwt_mutate import apply_mutation, default_claim_elevation_map
from talos.auth_session.models import (
    FAMILY_ALGORITHM,
    FAMILY_ALGORITHM_DEGRADE,
    FAMILY_CLAIMS,
    FAMILY_KID,
    FAMILY_SIGNATURE,
    FAMILY_STRUCTURE,
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_LOW,
    RISK_MEDIUM,
    MutatedToken,
    TestCaseDef,
    TokenContext,
)

# ------------------------------------------------------------------ #
# Core catalog (fixed rows)                                            #
# ------------------------------------------------------------------ #

CORE_JWT_TEST_CASES: tuple[TestCaseDef, ...] = (
    TestCaseDef(
        test_id="jwt.alg_none",
        title="alg=none (stripped signature)",
        family=FAMILY_ALGORITHM,
        description=(
            "Set header alg to 'none' and strip the signature segment "
            "(two-part token h.p). Classic none attack variant."
        ),
        risk_hint=RISK_CRITICAL,
    ),
    TestCaseDef(
        test_id="jwt.alg_None",
        title="alg=None (casing)",
        family=FAMILY_ALGORITHM,
        description="Set header alg to 'None' casing variant; empty third segment.",
        risk_hint=RISK_CRITICAL,
    ),
    TestCaseDef(
        test_id="jwt.alg_NONE",
        title="alg=NONE (casing)",
        family=FAMILY_ALGORITHM,
        description="Set header alg to 'NONE' casing variant; empty third segment.",
        risk_hint=RISK_CRITICAL,
    ),
    TestCaseDef(
        test_id="jwt.alg_none_empty_sig",
        title="alg=none empty signature",
        family=FAMILY_ALGORITHM,
        description=(
            "alg=none with empty signature segment (three-part h.p.). "
            "Distinct from jwt.alg_none which strips the segment entirely."
        ),
        risk_hint=RISK_CRITICAL,
    ),
    TestCaseDef(
        test_id="jwt.alg_empty",
        title="alg empty string",
        family=FAMILY_ALGORITHM,
        description="Set alg to empty string; original signature kept.",
        risk_hint=RISK_HIGH,
    ),
    TestCaseDef(
        test_id="jwt.alg_missing",
        title="alg header missing",
        family=FAMILY_ALGORITHM,
        description="Delete alg header claim; original signature kept.",
        risk_hint=RISK_HIGH,
    ),
    TestCaseDef(
        test_id="jwt.alg_unknown",
        title="alg unknown",
        family=FAMILY_ALGORITHM,
        description="Set alg to non-standard string TalosFakeAlg.",
        risk_hint=RISK_MEDIUM,
    ),
    TestCaseDef(
        test_id="jwt.invalid_signature",
        title="Invalid signature",
        family=FAMILY_SIGNATURE,
        description="Corrupt trailing signature characters.",
        risk_hint=RISK_HIGH,
    ),
    TestCaseDef(
        test_id="jwt.missing_signature",
        title="Missing signature segment",
        family=FAMILY_STRUCTURE,
        description="Emit two-part token header.payload only.",
        risk_hint=RISK_HIGH,
    ),
    TestCaseDef(
        test_id="jwt.empty_payload",
        title="Empty payload",
        family=FAMILY_STRUCTURE,
        description="Replace payload with empty JSON object.",
        risk_hint=RISK_MEDIUM,
    ),
    TestCaseDef(
        test_id="jwt.empty_header",
        title="Empty header",
        family=FAMILY_STRUCTURE,
        description="Replace header with empty JSON object.",
        risk_hint=RISK_MEDIUM,
    ),
    TestCaseDef(
        test_id="jwt.corrupted_b64",
        title="Corrupted base64url payload",
        family=FAMILY_STRUCTURE,
        description="Insert illegal characters into payload segment.",
        risk_hint=RISK_MEDIUM,
    ),
    TestCaseDef(
        test_id="jwt.remove_exp",
        title="Remove exp claim",
        family=FAMILY_CLAIMS,
        description="Delete payload exp claim.",
        risk_hint=RISK_MEDIUM,
        requires_claims=("exp",),
    ),
    TestCaseDef(
        test_id="jwt.exp_far_future",
        title="exp far future",
        family=FAMILY_CLAIMS,
        description="Set exp to far-future unix timestamp.",
        risk_hint=RISK_LOW,
    ),
    TestCaseDef(
        test_id="jwt.exp_past",
        title="exp past",
        family=FAMILY_CLAIMS,
        description="Set exp to past unix timestamp (often SECURE; useful signal).",
        risk_hint=RISK_LOW,
    ),
    TestCaseDef(
        test_id="jwt.remove_nbf",
        title="Remove nbf claim",
        family=FAMILY_CLAIMS,
        description="Delete payload nbf claim.",
        risk_hint=RISK_LOW,
        requires_claims=("nbf",),
    ),
    TestCaseDef(
        test_id="jwt.remove_iss",
        title="Remove iss claim",
        family=FAMILY_CLAIMS,
        description="Delete payload iss claim.",
        risk_hint=RISK_MEDIUM,
        requires_claims=("iss",),
    ),
    TestCaseDef(
        test_id="jwt.remove_aud",
        title="Remove aud claim",
        family=FAMILY_CLAIMS,
        description="Delete payload aud claim.",
        risk_hint=RISK_MEDIUM,
        requires_claims=("aud",),
    ),
    TestCaseDef(
        test_id="jwt.modify_sub",
        title="Modify sub claim",
        family=FAMILY_CLAIMS,
        description="Change sub claim (append -talos or replace).",
        risk_hint=RISK_HIGH,
        requires_claims=("sub",),
    ),
    TestCaseDef(
        test_id="jwt.elevate_role",
        title="Claim elevation",
        family=FAMILY_CLAIMS,
        description="Elevate role/admin/scope-style claims via built-in or config map.",
        risk_hint=RISK_CRITICAL,
    ),
    TestCaseDef(
        test_id="jwt.duplicate_claim_role",
        title="Duplicate role claim",
        family=FAMILY_CLAIMS,
        description="Craft JSON payload with duplicated role key.",
        risk_hint=RISK_MEDIUM,
    ),
    TestCaseDef(
        test_id="jwt.invalid_kid",
        title="Invalid kid",
        family=FAMILY_KID,
        description="Set header kid to a random value.",
        risk_hint=RISK_MEDIUM,
    ),
    TestCaseDef(
        test_id="jwt.empty_kid",
        title="Empty kid",
        family=FAMILY_KID,
        description="Set header kid to empty string.",
        risk_hint=RISK_MEDIUM,
    ),
    TestCaseDef(
        test_id="jwt.huge_kid",
        title="Huge kid",
        family=FAMILY_KID,
        description="Set header kid to ~8 KiB string (size capped).",
        risk_hint=RISK_LOW,
    ),
)

# Targets that degradation must never emit (core owns none/empty/missing/unknown).
_DEGRADE_FORBIDDEN_TARGETS: frozenset[str] = frozenset({
    "none",
    "empty",
    "missing",
    "unknown",
})

# Full product algorithm-degradation matrix (Phase 5 complete).
# Values are display-form target algs (HS256, …). Rules (design catalog):
#   - HS* confusion always for asymmetric originals
#   - Same-family full downgrade chains when stronger (RS512→RS384→RS256, …)
#   - Cross-family edges (RS↔ES↔PS at 256-bit class; HS→RS256/ES256 upgrade)
#   - never emits none/empty/missing/unknown targets (KD15)
#   - none/empty/missing/unknown/other originals: force HS256 + RS256 only
_FULL_DEGRADE_TARGETS: dict[str, tuple[str, ...]] = {
    # RS family: HS* + same-family downgrade + ES256/PS256 cross-family
    "rs256": ("HS256", "HS384", "HS512", "ES256", "PS256"),
    "rs384": ("HS256", "HS384", "HS512", "RS256", "ES256", "PS256"),
    "rs512": ("HS256", "HS384", "HS512", "RS384", "RS256", "ES256", "PS256"),
    # ES family: HS* + same-family downgrade + RS256/PS256 cross-family
    "es256": ("HS256", "HS384", "HS512", "RS256", "PS256"),
    "es384": ("HS256", "HS384", "HS512", "ES256", "RS256", "PS256"),
    "es512": ("HS256", "HS384", "HS512", "ES384", "ES256", "RS256", "PS256"),
    # PS family: parity with RS (HS* + same-family downgrade + RS256/ES256)
    "ps256": ("HS256", "HS384", "HS512", "RS256", "ES256"),
    "ps384": ("HS256", "HS384", "HS512", "PS256", "RS256", "ES256"),
    "ps512": ("HS256", "HS384", "HS512", "PS384", "PS256", "RS256", "ES256"),
    # HS family: wrong HS strength + upgrade-to-asymmetric (RS256 / ES256)
    "hs256": ("HS384", "HS512", "RS256", "ES256"),
    "hs384": ("HS256", "HS512", "RS256", "ES256"),
    "hs512": ("HS256", "HS384", "RS256", "ES256"),
    # none / empty / missing / unknown / other → force non-none algs only
    "none": ("HS256", "RS256"),
    "empty": ("HS256", "RS256"),
    "missing": ("HS256", "RS256"),
    "unknown": ("HS256", "RS256"),
    "other": ("HS256", "RS256"),
}

# Back-compat alias (tests / importers that still reference Phase-1 name).
_PHASE1_DEGRADE_TARGETS = _FULL_DEGRADE_TARGETS


def normalize_alg(alg: Any) -> str:
    """
    Purpose:
        Normalize observed JWT alg for matrix lookup.
    Input:
        alg — header value (str preferred)
    Output:
        lowercase alnum id, or 'unknown' / 'empty' / 'missing'
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


def alg_degradation_tests(original_alg: Any) -> list[TestCaseDef]:
    """
    Purpose:
        Expand observed original alg into full product degradation TestCaseDefs
        (Phase 5 matrix: same-family downgrades + cross-family edges).
        Never emits pure none/empty/missing/unknown *targets* (KD15).
    Input:
        original_alg — JWT header alg value
    Output:
        list of TestCaseDef with test_id jwt.alg_degrade.<from>_to_<to>
    Side effects: None.
    """
    from_norm = normalize_alg(original_alg)
    targets = _FULL_DEGRADE_TARGETS.get(from_norm)
    if targets is None:
        # Other / non-standard original → HS256 + RS256 only.
        # Keep computed from_norm in test_ids (e.g. customalg_to_hs256).
        targets = _FULL_DEGRADE_TARGETS["other"]

    cases: list[TestCaseDef] = []
    for target in targets:
        to_norm = normalize_alg(target)
        if to_norm in _DEGRADE_FORBIDDEN_TARGETS:
            continue  # hard none-skip rule
        if to_norm == from_norm:
            continue  # no self-swap
        test_id = f"jwt.alg_degrade.{from_norm}_to_{to_norm}"
        cases.append(
            TestCaseDef(
                test_id=test_id,
                title=f"alg degrade {from_norm} → {to_norm}",
                family=FAMILY_ALGORITHM_DEGRADE,
                description=(
                    f"Rewrite header alg from {original_alg!r} to {target!r}; "
                    "keep original signature segment unchanged."
                ),
                risk_hint=RISK_CRITICAL,
            )
        )
    return cases


def _elevation_claims_present(
    payload: dict[str, Any],
    config: Optional[dict[str, Any]],
) -> bool:
    """True if at least one elevation-map claim exists in payload."""
    elev = (config or {}).get("claim_elevation") or default_claim_elevation_map()
    return any(claim in payload for claim in elev)


def list_jwt_test_cases(
    ctx: TokenContext,
    config: Optional[dict[str, Any]] = None,
) -> list[TestCaseDef]:
    """
    Purpose:
        Deterministic suite for a token: core rows (claim-filtered) +
        full algorithm degradation matrix for observed alg.
    Input:
        ctx — TokenContext
        config — binding config (enabled_families, disabled_tests, claim_elevation)
    Output:
        ordered list of TestCaseDef
    Side effects: None.
    """
    cfg = config or {}
    enabled_families = cfg.get("enabled_families")
    if enabled_families is not None:
        enabled = set(enabled_families)
    else:
        enabled = None  # all families

    disabled = set(cfg.get("disabled_tests") or [])

    out: list[TestCaseDef] = []
    for case in CORE_JWT_TEST_CASES:
        if enabled is not None and case.family not in enabled:
            continue
        if case.test_id in disabled:
            continue
        if case.requires_claims:
            if not all(c in ctx.payload for c in case.requires_claims):
                continue
        # elevate_role: skip when no elevation claims present (generate-time skip).
        if case.test_id == "jwt.elevate_role":
            if not _elevation_claims_present(ctx.payload, cfg):
                continue
        out.append(case)

    # Algorithm degradation family.
    if enabled is None or FAMILY_ALGORITHM_DEGRADE in enabled:
        observed = ctx.header.get("alg")
        for case in alg_degradation_tests(observed):
            if case.test_id in disabled:
                continue
            out.append(case)

    return out


def apply_jwt_test(
    ctx: TokenContext,
    test_id: str,
    config: Optional[dict[str, Any]] = None,
) -> MutatedToken:
    """
    Purpose:
        Apply one suite test_id via jwt_mutate.apply_mutation.
    Input / Output / Side effects: see apply_mutation.
    """
    return apply_mutation(ctx, test_id, config=config)


def all_core_test_ids() -> list[str]:
    """Stable list of core catalog test_ids (no degradation expansion)."""
    return [c.test_id for c in CORE_JWT_TEST_CASES]
