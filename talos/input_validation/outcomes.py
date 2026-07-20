"""
Module: talos.input_validation.outcomes

Purpose:
    Shared validation-outcome vocabulary, IV profile schema version constants,
    and best-effort outcome classification from response fingerprints
    (Module 1 — Evidence Foundations).

    Outcomes describe **how the application treated an input mutation**, not
    exploit success.  Later modules store these labels inside versioned
    parameter / endpoint / application profiles.

Validation outcome vocabulary
    accepted   — response matches baseline (probe did not change behaviour).
    modified   — same success class, body/headers/schema differ.
    encoded    — value appears transformed via encoding (reflection hint).
    normalized — value appears canonicalized (case/trim/etc. reflection hint).
    truncated  — success class retained but body substantially shorter or
                 length-limit style delta.
    rejected   — clear validation/auth failure vs baseline (4xx/5xx, error sig).
    ignored    — request appears accepted but parameter effect absent
                 (status/body match baseline despite mutation; optional hint).
    unknown    — insufficient or conflicting signal.

Schema versioning (profiles — Module 2+ will embed these)
    Every stored IV profile JSON must include at least:
        schema_version, engine_version, profile_version, updated_at
    Bump IV_PROFILE_SCHEMA_VERSION only on breaking shape changes.

Classification confidence
    The classifier itself reports confidence 0–100 and human-readable reasons.
    Consumers should treat classification as a hypothesis attached to evidence
    flow ids, not ground truth.

Limitations
    - Without reflection_hints, accepted vs ignored is hard to separate when
      the body is identical to baseline (both map toward accepted/ignored).
    - SPA and A/B noise can flip body_hash and produce false modified.
    - Truncation vs modified is heuristic (relative length drop).
    - encoded / normalized require reflection_hints from analysis phases.

Dependencies: talos.input_validation.fingerprint
Data flow:
    baseline + probe ResponseFingerprint [+ reflection_hints]
        → classify_outcome() → {outcome, confidence, reasons, delta}
Side effects: None.
"""

from __future__ import annotations

from typing import Any

from talos.input_validation.fingerprint import (
    ResponseFingerprint,
    compare_fingerprints,
)


# ---------------------------------------------------------------------------
# Profile schema contracts (Module 1 exports; Module 2 profile.py embeds these)
# ---------------------------------------------------------------------------

# Bump only on breaking profile JSON shape changes; document migrations in
# docs/architecture.md and docs/updates.md.
IV_PROFILE_SCHEMA_VERSION = 1

# Engine tag embedded in profiles so synthesizers know which fingerprint /
# outcome rules produced the data.  Not the same as Talos package version.
IV_ENGINE_VERSION = "iv-evidence-2"

# Profile document version starts at 1; increments when a parameter's profile
# is rewritten (Module 2+).  Constant is the initial value for new profiles.
IV_PROFILE_VERSION_INITIAL = 1


def profile_envelope(
    *,
    engine_version: str = IV_ENGINE_VERSION,
    profile_version: int = IV_PROFILE_VERSION_INITIAL,
    updated_at: str | None = None,
) -> dict[str, Any]:
    """
    Purpose:
        Minimal versioning envelope required on every IV profile JSON.
        ``talos.input_validation.profile`` merges this with observed/inferred
        fields via empty_param_profile / ensure_profile_shape.

    Input:
        engine_version  — IV engine tag (default IV_ENGINE_VERSION).
        profile_version — monotonic rewrite counter for this profile key.
        updated_at      — ISO-8601 UTC string; omitted from result when None
                          so callers can fill after their clock helper runs.

    Output:
        dict with schema_version, engine_version, profile_version, and
        optionally updated_at.

    Side effects: None.
    """
    envelope: dict[str, Any] = {
        "schema_version": IV_PROFILE_SCHEMA_VERSION,
        "engine_version": engine_version,
        "profile_version": profile_version,
    }
    if updated_at is not None:
        envelope["updated_at"] = updated_at
    return envelope


# ---------------------------------------------------------------------------
# Outcome vocabulary
# ---------------------------------------------------------------------------

OUTCOME_ACCEPTED = "accepted"
OUTCOME_MODIFIED = "modified"
OUTCOME_ENCODED = "encoded"
OUTCOME_NORMALIZED = "normalized"
OUTCOME_TRUNCATED = "truncated"
OUTCOME_REJECTED = "rejected"
OUTCOME_IGNORED = "ignored"
OUTCOME_UNKNOWN = "unknown"

VALIDATION_OUTCOMES: frozenset[str] = frozenset({
    OUTCOME_ACCEPTED,
    OUTCOME_MODIFIED,
    OUTCOME_ENCODED,
    OUTCOME_NORMALIZED,
    OUTCOME_TRUNCATED,
    OUTCOME_REJECTED,
    OUTCOME_IGNORED,
    OUTCOME_UNKNOWN,
})

# Relative body-length drop vs baseline that suggests truncation (not mere edit).
_TRUNCATION_REL_DROP = 0.35
# Absolute drop that also suggests truncation on medium/large bodies.
_TRUNCATION_ABS_DROP = 200


# ---------------------------------------------------------------------------
# Public classifier
# ---------------------------------------------------------------------------

def classify_outcome(
    baseline: ResponseFingerprint,
    probe: ResponseFingerprint,
    reflection_hints: dict | None = None,
) -> dict[str, Any]:
    """
    Purpose:
        Map baseline vs probe fingerprint delta (plus optional reflection
        analysis hints) to a validation outcome label with confidence.

    Input:
        baseline         — fingerprint of the unmutated (or reference) response.
        probe            — fingerprint of the probe response.
        reflection_hints — optional dict from reflection/transform analysis:
            reflected (bool) — payload (or transform) seen in response body.
            encoding (str)   — raw | html_encoded | url_encoded | …
            transforms (list[str]) — e.g. trim, lowercase, uppercase.
            payload_in_body (bool) — explicit presence flag if available.
            parameter_effect (bool|None) — False when analyst/synthesizer
                already knows the parameter did not affect the response.

    Output:
        dict:
            outcome     — one of VALIDATION_OUTCOMES.
            confidence  — 0–100 integer (classifier confidence, not param conf).
            reasons     — list[str] human-readable decision trail.
            delta       — compare_fingerprints(baseline, probe) result.

    Side effects: None.
    """
    hints = reflection_hints or {}
    delta = compare_fingerprints(baseline, probe)
    reasons: list[str] = []

    # --- Hard rejects: error class vs successful baseline -----------------
    if _is_reject_transition(baseline, probe, reasons):
        return _result(OUTCOME_REJECTED, _clamp_confidence(88 + (5 if probe.error_signature else 0)), reasons, delta)

    # --- Reflection-driven: encoded / normalized -------------------------
    encoding = (hints.get("encoding") or "").strip().lower()
    transforms = [str(t).lower() for t in (hints.get("transforms") or [])]
    reflected = bool(hints.get("reflected") or hints.get("payload_in_body"))

    if reflected and encoding and encoding not in ("", "raw"):
        reasons.append(f"reflection encoding={encoding}")
        return _result(OUTCOME_ENCODED, 85, reasons, delta)

    norm_transforms = {"trim", "lowercase", "uppercase", "normalize", "canonical"}
    if reflected and any(t in norm_transforms for t in transforms):
        reasons.append(f"reflection transforms={transforms}")
        return _result(OUTCOME_NORMALIZED, 80, reasons, delta)

    # --- Identical fingerprints ------------------------------------------
    if delta["identical"]:
        if hints.get("parameter_effect") is False:
            reasons.append("fingerprint identical; parameter_effect=false")
            return _result(OUTCOME_IGNORED, 75, reasons, delta)
        if reflected:
            reasons.append("fingerprint identical to baseline; payload reflected")
            return _result(OUTCOME_ACCEPTED, 90, reasons, delta)
        reasons.append("fingerprint identical to baseline")
        # Without reflection we cannot prove the app used the value.
        return _result(OUTCOME_ACCEPTED, 70, reasons, delta)

    # --- Truncation heuristic --------------------------------------------
    if _looks_truncated(baseline, probe, delta, reasons):
        conf = 78 if _same_success_class(baseline, probe) else 65
        return _result(OUTCOME_TRUNCATED, conf, reasons, delta)

    # --- Modified: same success class, content differs -------------------
    if _same_success_class(baseline, probe):
        reasons.append(
            "success class retained; changed=" + ",".join(delta["changed"])
        )
        conf = 72
        if delta.get("body_hash_changed") and delta.get("json_schema_changed"):
            conf = 80
            reasons.append("body hash and JSON schema both changed")
        elif delta.get("body_hash_changed"):
            conf = 75
        if reflected:
            conf = min(95, conf + 10)
            reasons.append("payload reflected with content delta")
        return _result(OUTCOME_MODIFIED, conf, reasons, delta)

    # --- Status-class change that is not a clean reject ------------------
    if baseline.status_code is not None and probe.status_code is not None:
        reasons.append(
            f"status class change {baseline.status_code}→{probe.status_code}; "
            f"changed={','.join(delta['changed'])}"
        )
        # 2xx → 3xx often means redirect-on-validation or auth bounce.
        if _status_class(baseline.status_code) == 2 and _status_class(probe.status_code) == 3:
            return _result(OUTCOME_MODIFIED, 60, reasons, delta)
        # 3xx → 2xx or other oddities
        return _result(OUTCOME_UNKNOWN, 45, reasons, delta)

    reasons.append("insufficient status/body signal; changed=" + ",".join(delta["changed"]))
    return _result(OUTCOME_UNKNOWN, 40, reasons, delta)


def is_valid_outcome(label: str) -> bool:
    """
    Purpose: Guard for profile writers — True when label is in vocabulary.
    Side effects: None.
    """
    return label in VALIDATION_OUTCOMES


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _result(
    outcome: str,
    confidence: int,
    reasons: list[str],
    delta: dict[str, Any],
) -> dict[str, Any]:
    return {
        "outcome": outcome,
        "confidence": _clamp_confidence(confidence),
        "reasons": list(reasons),
        "delta": delta,
    }


def _clamp_confidence(value: int) -> int:
    return max(0, min(100, int(value)))


def _status_class(code: int | None) -> int | None:
    if code is None:
        return None
    return code // 100


def _same_success_class(a: ResponseFingerprint, b: ResponseFingerprint) -> bool:
    """
    Purpose:
        True when both statuses are in the same broad class (2xx/3xx/4xx/5xx)
        or both missing.  Used to distinguish modified vs rejected.
    Side effects: None.
    """
    ca, cb = _status_class(a.status_code), _status_class(b.status_code)
    if ca is None or cb is None:
        return a.status_code == b.status_code
    return ca == cb


def _is_reject_transition(
    baseline: ResponseFingerprint,
    probe: ResponseFingerprint,
    reasons: list[str],
) -> bool:
    """
    Purpose:
        Detect validation/auth rejection: baseline success-like, probe error-like.
    Side effects: Appends to reasons when True.
    """
    b_class = _status_class(baseline.status_code)
    p_class = _status_class(probe.status_code)

    # 2xx/3xx → 4xx/5xx
    if b_class in (2, 3) and p_class in (4, 5):
        reasons.append(
            f"status reject transition {baseline.status_code}→{probe.status_code}"
        )
        if probe.error_signature:
            reasons.append(f"error_signature={probe.error_signature}")
        return True

    # New error signature while status stayed 2xx (app-level error payload)
    if (
        b_class == 2
        and p_class == 2
        and probe.error_signature
        and probe.error_signature != baseline.error_signature
        and baseline.error_signature is None
    ):
        # Only treat as reject when body clearly gained error keys and changed.
        if "keys:" in (probe.error_signature or ""):
            reasons.append(
                f"success status with new error payload ({probe.error_signature})"
            )
            return True

    return False


def _looks_truncated(
    baseline: ResponseFingerprint,
    probe: ResponseFingerprint,
    delta: dict[str, Any],
    reasons: list[str],
) -> bool:
    """
    Purpose:
        Heuristic: body got much shorter while staying in the same success
        class, suggesting length limits / field truncation rather than a full
        alternate page.
    Side effects: Appends to reasons when True.
    """
    if not _same_success_class(baseline, probe):
        return False
    length = delta.get("body_length")
    if not length:
        return False
    drop = -int(length.get("delta") or 0)
    if drop <= 0:
        return False
    base_len = baseline.body_length or 0
    rel = (drop / base_len) if base_len > 0 else 0.0
    if drop >= _TRUNCATION_ABS_DROP and rel >= _TRUNCATION_REL_DROP:
        reasons.append(
            f"body length drop delta={-drop} rel={rel:.2f} (truncation heuristic)"
        )
        return True
    # Probe much shorter absolute body on non-tiny baselines
    if base_len >= 100 and probe.body_length <= max(16, int(base_len * 0.15)):
        reasons.append(
            f"probe body_length={probe.body_length} << baseline={base_len}"
        )
        return True
    return False
