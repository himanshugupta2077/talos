"""
Module: talos.input_validation.profile

Purpose:
    Canonical Input Validation **profile data model** (Module 2).

    Defines the versioned JSON shape stored for parameter-, endpoint-, and
    application/host-level intelligence.  Profiles hold observed measurements,
    inferred hypotheses, confidence/uncertainty, negative evidence, mutation
    history, capability flags, parser fingerprints, normalization pipeline,
    and attack candidates (scored in Module 11 ``candidates.py``).

    This module is pure: no HTTP, no scheduler jobs, no probe volume change.
    Persistence lives in ``talos.input_validation.db`` (tables
    ``iv_param_profiles``, ``iv_endpoint_profiles``, ``iv_app_profiles``).

Why separate tables (not ``iv_param_cache`` phase ``profile``)
    - ``iv_param_cache`` is keyed by (host, location, param_name, **phase**)
      for per-analysis resume; overloading it would mix cache status with
      consumer-facing intelligence documents.
    - Multi-level profiles need different primary keys (param_uuid /
      endpoint_id / host).
    - Profile rewrites bump ``profile_version`` independently of phase
      completion status.

Dependencies:
    talos.input_validation.outcomes (profile_envelope, schema version constants)
Data flow:
    empty_*_profile() / ensure_profile_shape() → synthesize (M3) / callers
        → db.upsert_*_profile() → SQLite JSON blob
Side effects: None (pure helpers only).
"""

from __future__ import annotations

import copy
import json
from typing import Any

from talos.input_validation.outcomes import (
    IV_ENGINE_VERSION,
    IV_PROFILE_SCHEMA_VERSION,
    IV_PROFILE_VERSION_INITIAL,
    profile_envelope,
)


# ---------------------------------------------------------------------------
# Bounded history / budget defaults
# ---------------------------------------------------------------------------

# Max mutation-history rows retained per profile (oldest dropped first).
MAX_ATTEMPTS = 50

# Planner budget tiers (Module 5 fills request counts; stored for handoff).
BUDGET_QUICK = "quick"
BUDGET_STANDARD = "standard"
BUDGET_DEEP = "deep"
BUDGET_EXHAUSTIVE = "exhaustive"

BUDGET_TIERS: frozenset[str] = frozenset({
    BUDGET_QUICK,
    BUDGET_STANDARD,
    BUDGET_DEEP,
    BUDGET_EXHAUSTIVE,
})

DEFAULT_BUDGET_TIER = BUDGET_STANDARD

# Characteristic uncertainty labels (consumer guidance in Section 0.4).
UNCERTAINTY_NONE = "none"
UNCERTAINTY_LOW = "low"
UNCERTAINTY_HIGH = "high"

UNCERTAINTY_LEVELS: frozenset[str] = frozenset({
    UNCERTAINTY_NONE,
    UNCERTAINTY_LOW,
    UNCERTAINTY_HIGH,
})

# Generic characteristic state vocabulary (reflection, length, etc.).
STATE_UNKNOWN = "unknown"
STATE_CONFLICTING = "conflicting"

# Reflection context labels (Module 9 may refine further).
REFLECTION_CONTEXTS: frozenset[str] = frozenset({
    "html",
    "attribute",
    "js",
    "css",
    "url",
    "json",
    "xml",
    "header",
    "other",
})

# Character taxonomy class labels (Module 6 stores under observed.acceptance.classes).
# Probe selection and representatives live in talos.input_validation.taxonomy.
CHARSET_CLASSES: frozenset[str] = frozenset({
    "alpha",
    "digit",
    "alnum",
    "whitespace",
    "control",
    "quote",
    "delimiter",
    "operator",
    "comment",
    "path",
    "separator",
    "unicode",
    "null",
    "markup",
    "encoding_meta",
})

# Capability flags for attack modules (Module 11 derives flags + scores candidates).
# Stored as a list of strings on the profile; filled by capabilities.py / synthesizer.
CAPABILITY_REFLECTIVE_INPUT = "reflective_input"
# Value observed in some in-scope response (same-request and/or cross-flow).
# Prefer showing CAPABILITY_STORED_REFLECTION + sinks when stored-only.
CAPABILITY_STORED_REFLECTION = "stored_reflection"
CAPABILITY_HTML_CONTEXT = "html_context"
CAPABILITY_JSON_CONTEXT = "json_context"
CAPABILITY_URL_CONTEXT = "url_context"
CAPABILITY_JS_CONTEXT = "js_context"
CAPABILITY_JSON_PARSER = "json_parser"
CAPABILITY_XML_BODY = "xml_body"
CAPABILITY_UNICODE_SUPPORT = "unicode_support"
CAPABILITY_STRICT_LENGTH = "strict_length"
CAPABILITY_DUPLICATE_PARAMETER = "duplicate_parameter"
CAPABILITY_HEADER_INJECTION_SURFACE = "header_injection_surface"
CAPABILITY_PATH_PARAMETER = "path_parameter"
CAPABILITY_MULTIPART_FILENAME = "multipart_filename"
CAPABILITY_GRAPHQL_VARIABLE = "graphql_variable"
CAPABILITY_REDIRECT_LIKE = "redirect_like"
CAPABILITY_URL_LIKE_VALUE = "url_like_value"
# URL Sink Discovery Phase 4 — unified network resource sink capabilities.
# Confidence / accepts_* detail lives on observed.url_sink (not on the flag).
CAPABILITY_NETWORK_RESOURCE_SINK = "network_resource_sink"
CAPABILITY_REDIRECT_SINK = "redirect_sink"
CAPABILITY_FETCH_SINK = "fetch_sink"
CAPABILITY_WEBHOOK_SINK = "webhook_sink"
# Optional detail flag when protocol variants were accepted (http/https/ftp/…).
CAPABILITY_PROTOCOL_SUPPORT = "protocol_support"

KNOWN_CAPABILITIES: frozenset[str] = frozenset({
    CAPABILITY_REFLECTIVE_INPUT,
    CAPABILITY_STORED_REFLECTION,
    CAPABILITY_HTML_CONTEXT,
    CAPABILITY_JSON_CONTEXT,
    CAPABILITY_URL_CONTEXT,
    CAPABILITY_JS_CONTEXT,
    CAPABILITY_JSON_PARSER,
    CAPABILITY_XML_BODY,
    CAPABILITY_UNICODE_SUPPORT,
    CAPABILITY_STRICT_LENGTH,
    CAPABILITY_DUPLICATE_PARAMETER,
    CAPABILITY_HEADER_INJECTION_SURFACE,
    CAPABILITY_PATH_PARAMETER,
    CAPABILITY_MULTIPART_FILENAME,
    CAPABILITY_GRAPHQL_VARIABLE,
    CAPABILITY_REDIRECT_LIKE,
    CAPABILITY_URL_LIKE_VALUE,
    CAPABILITY_NETWORK_RESOURCE_SINK,
    CAPABILITY_REDIRECT_SINK,
    CAPABILITY_FETCH_SINK,
    CAPABILITY_WEBHOOK_SINK,
    CAPABILITY_PROTOCOL_SUPPORT,
})

# Profile level identifiers (multi-level inheritance — Module 10).
LEVEL_PARAMETER = "parameter"
LEVEL_ENDPOINT = "endpoint"
LEVEL_APPLICATION = "application"

PROFILE_LEVELS: frozenset[str] = frozenset({
    LEVEL_PARAMETER,
    LEVEL_ENDPOINT,
    LEVEL_APPLICATION,
})


# ---------------------------------------------------------------------------
# Characteristic helpers
# ---------------------------------------------------------------------------

def empty_characteristic(
    *,
    state: str = STATE_UNKNOWN,
    confidence: int = 0,
    uncertainty: str = UNCERTAINTY_HIGH,
    evidence_flow_ids: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Purpose:
        Build a standard confidence-bearing characteristic object.

    Input:
        state             — domain-specific state string (e.g. reflected).
        confidence        — 0–100 integer.
        uncertainty       — none | low | high.
        evidence_flow_ids — flow UUIDs supporting this characteristic.
        extra             — optional additional keys merged into the result
                            (e.g. contexts for reflection).

    Output:
        dict with state, confidence, uncertainty, evidence_flow_ids [+ extra].

    Side effects: None.
    """
    char: dict[str, Any] = {
        "state": state,
        "confidence": _clamp_confidence(confidence),
        "uncertainty": uncertainty if uncertainty in UNCERTAINTY_LEVELS else UNCERTAINTY_HIGH,
        "evidence_flow_ids": list(evidence_flow_ids or []),
    }
    if extra:
        for key, value in extra.items():
            if key not in char:
                char[key] = value
    return char


def empty_observed_block() -> dict[str, Any]:
    """
    Purpose:
        Default ``observed`` subtree for a parameter profile skeleton.
        Measured fields start empty / unknown; Module 3+ fills from probes.

    Output: observed dict (never None).
    Side effects: None.
    """
    return {
        "baseline_fingerprint": {},
        "reflection": empty_characteristic(
            state=STATE_UNKNOWN,
            confidence=0,
            uncertainty=UNCERTAINTY_HIGH,
            extra={"contexts": []},
        ),
        "acceptance": {
            "classes": {},
            "chars": {},
        },
        "length": empty_characteristic(state=STATE_UNKNOWN),
        "types": {},
        "semantic": {},  # Module 7 validation/semantic family outcomes
        "parser": {},  # Module 8: duplicate_query, json_null, array_*, …
        "url_sink": {},  # URL Sink Discovery Phase 3: active canary characterization
        # Passive EI copy (Phase 4 consumers); may be empty until synthesize/load.
        "url_features": {},
        "timing": {
            "samples_ms": [],
        },
    }


def empty_inferred_block() -> dict[str, Any]:
    """
    Purpose:
        Default ``inferred`` subtree (hypotheses; may change without re-probe).
    Output: empty dict placeholder for Module 3+.
    Side effects: None.
    """
    return {}


# ---------------------------------------------------------------------------
# Skeleton builders
# ---------------------------------------------------------------------------

def empty_param_profile(
    *,
    param_uuid: str = "",
    host: str = "",
    location: str = "",
    name: str = "",
    engine_version: str = IV_ENGINE_VERSION,
    profile_version: int = IV_PROFILE_VERSION_INITIAL,
    budget_tier: str = DEFAULT_BUDGET_TIER,
    updated_at: str | None = None,
) -> dict[str, Any]:
    """
    Purpose:
        Canonical **parameter-level** profile skeleton (schema_version=1).

    Schema (code-as-truth; see also docs/architecture.md):
        {
          schema_version, engine_version, profile_version, updated_at?,
          level, param_uuid, host, location, name,
          observed { baseline_fingerprint, reflection, acceptance, length,
                     types, timing },
          inferred {},
          tested {},           # negative evidence map
          attempts [],         # bounded mutation history
          capabilities [],     # capability flag strings (capabilities.py)
          candidates [],       # Module 11: {attack, score, confidence, reasons, evidence_flow_ids}
          parser {},           # Module 8 fingerprint (mirrors observed.parser)
          normalization_pipeline [],  # Module 8 ordered stages
          requests_used, budget_tier
        }

    Input:
        Identity fields and versioning overrides for the new document.

    Output:
        Fresh profile dict with all required keys present.

    Side effects: None.
    """
    envelope = profile_envelope(
        engine_version=engine_version,
        profile_version=profile_version,
        updated_at=updated_at,
    )
    tier = budget_tier if budget_tier in BUDGET_TIERS else DEFAULT_BUDGET_TIER
    return {
        **envelope,
        "level": LEVEL_PARAMETER,
        "param_uuid": param_uuid,
        "host": host,
        "location": location,
        "name": name,
        "observed": empty_observed_block(),
        "inferred": empty_inferred_block(),
        "tested": {},
        "attempts": [],
        "capabilities": [],
        "candidates": [],
        "parser": {},
        "normalization_pipeline": [],
        "requests_used": 0,
        "budget_tier": tier,
    }


def empty_endpoint_profile(
    *,
    endpoint_id: str = "",
    host: str = "",
    method: str = "",
    path: str = "",
    engine_version: str = IV_ENGINE_VERSION,
    profile_version: int = IV_PROFILE_VERSION_INITIAL,
    updated_at: str | None = None,
) -> dict[str, Any]:
    """
    Purpose:
        Endpoint-level profile stub (shared middleware / validation defaults).
        Module 10 (``learning.aggregate_endpoint_from_params``) fills
        tested / parser / param_defaults from completed parameter profiles.

    Output: endpoint profile dict with observed/inferred + capabilities.
    Side effects: None.
    """
    envelope = profile_envelope(
        engine_version=engine_version,
        profile_version=profile_version,
        updated_at=updated_at,
    )
    return {
        **envelope,
        "level": LEVEL_ENDPOINT,
        "endpoint_id": endpoint_id,
        "host": host,
        "method": method,
        "path": path,
        "observed": {},
        "inferred": {},
        "tested": {},
        "attempts": [],
        "capabilities": [],
        "candidates": [],
        "parser": {},
        "normalization_pipeline": [],
        "param_defaults": {},
        "requests_used": 0,
        "budget_tier": DEFAULT_BUDGET_TIER,
    }


def empty_app_profile(
    *,
    host: str = "",
    engine_version: str = IV_ENGINE_VERSION,
    profile_version: int = IV_PROFILE_VERSION_INITIAL,
    updated_at: str | None = None,
) -> dict[str, Any]:
    """
    Purpose:
        Application / host-level profile stub (inherit defaults for new params).
    Output: app profile dict.
    Side effects: None.
    """
    envelope = profile_envelope(
        engine_version=engine_version,
        profile_version=profile_version,
        updated_at=updated_at,
    )
    return {
        **envelope,
        "level": LEVEL_APPLICATION,
        "host": host,
        "observed": {},
        "inferred": {},
        "tested": {},
        "attempts": [],
        "capabilities": [],
        "candidates": [],
        "parser": {},
        "normalization_pipeline": [],
        "param_defaults": {},
        "endpoint_defaults": {},
        "requests_used": 0,
        "budget_tier": DEFAULT_BUDGET_TIER,
    }


# ---------------------------------------------------------------------------
# Shape enforcement / serialize
# ---------------------------------------------------------------------------

# Keys that must exist on every parameter profile after ensure_profile_shape.
_PARAM_REQUIRED_TOP = (
    "schema_version",
    "engine_version",
    "profile_version",
    "level",
    "param_uuid",
    "host",
    "location",
    "name",
    "observed",
    "inferred",
    "tested",
    "attempts",
    "capabilities",
    "candidates",
    "parser",
    "normalization_pipeline",
    "requests_used",
    "budget_tier",
)

_ENDPOINT_REQUIRED_TOP = (
    "schema_version",
    "engine_version",
    "profile_version",
    "level",
    "endpoint_id",
    "host",
    "method",
    "path",
    "observed",
    "inferred",
    "tested",
    "attempts",
    "capabilities",
    "candidates",
    "parser",
    "normalization_pipeline",
    "param_defaults",
    "requests_used",
    "budget_tier",
)

_APP_REQUIRED_TOP = (
    "schema_version",
    "engine_version",
    "profile_version",
    "level",
    "host",
    "observed",
    "inferred",
    "tested",
    "attempts",
    "capabilities",
    "candidates",
    "parser",
    "normalization_pipeline",
    "param_defaults",
    "endpoint_defaults",
    "requests_used",
    "budget_tier",
)


def ensure_profile_shape(
    profile: dict[str, Any] | None,
    *,
    level: str = LEVEL_PARAMETER,
) -> dict[str, Any]:
    """
    Purpose:
        Normalize a profile dict so required keys always exist.
        Missing sections are filled from the empty skeleton for ``level``.
        Does **not** strip unknown keys (forward-compatible).

    Input:
        profile — partial or full profile dict (None → full empty skeleton).
        level   — parameter | endpoint | application.

    Output:
        Deep-copied profile with required keys present; schema_version set.

    Side effects: None (returns a new dict).
    """
    if level == LEVEL_ENDPOINT:
        base = empty_endpoint_profile()
        required = _ENDPOINT_REQUIRED_TOP
    elif level == LEVEL_APPLICATION:
        base = empty_app_profile()
        required = _APP_REQUIRED_TOP
    else:
        base = empty_param_profile()
        required = _PARAM_REQUIRED_TOP
        level = LEVEL_PARAMETER

    if not profile:
        return base

    out = copy.deepcopy(profile)

    # Envelope defaults
    if "schema_version" not in out or out["schema_version"] is None:
        out["schema_version"] = IV_PROFILE_SCHEMA_VERSION
    if "engine_version" not in out or not out["engine_version"]:
        out["engine_version"] = IV_ENGINE_VERSION
    if "profile_version" not in out or out["profile_version"] is None:
        out["profile_version"] = IV_PROFILE_VERSION_INITIAL

    out["level"] = level

    for key in required:
        if key not in out or out[key] is None:
            out[key] = copy.deepcopy(base[key])

    # Nested observed defaults for parameter profiles only.
    if level == LEVEL_PARAMETER:
        observed = out.get("observed")
        if not isinstance(observed, dict):
            out["observed"] = empty_observed_block()
        else:
            skeleton = empty_observed_block()
            for ok, ov in skeleton.items():
                if ok not in observed or observed[ok] is None:
                    observed[ok] = copy.deepcopy(ov)
            out["observed"] = observed

    if not isinstance(out.get("inferred"), dict):
        out["inferred"] = {}
    if not isinstance(out.get("tested"), dict):
        out["tested"] = {}
    if not isinstance(out.get("attempts"), list):
        out["attempts"] = []
    if not isinstance(out.get("capabilities"), list):
        out["capabilities"] = []
    if not isinstance(out.get("candidates"), list):
        out["candidates"] = []
    if not isinstance(out.get("parser"), dict):
        out["parser"] = {}
    if not isinstance(out.get("normalization_pipeline"), list):
        out["normalization_pipeline"] = []

    # Cap attempts length
    if len(out["attempts"]) > MAX_ATTEMPTS:
        out["attempts"] = out["attempts"][-MAX_ATTEMPTS:]

    if out.get("budget_tier") not in BUDGET_TIERS:
        out["budget_tier"] = DEFAULT_BUDGET_TIER

    try:
        out["requests_used"] = int(out.get("requests_used") or 0)
    except (TypeError, ValueError):
        out["requests_used"] = 0

    try:
        out["schema_version"] = int(out["schema_version"])
    except (TypeError, ValueError):
        out["schema_version"] = IV_PROFILE_SCHEMA_VERSION

    try:
        out["profile_version"] = int(out["profile_version"])
    except (TypeError, ValueError):
        out["profile_version"] = IV_PROFILE_VERSION_INITIAL

    return out


def serialize_profile(profile: dict[str, Any]) -> str:
    """
    Purpose:
        JSON-encode a profile for DB storage (stable key order not required).
    Input: profile dict (will be shape-ensured as parameter if level missing).
    Output: JSON string.
    Side effects: None.
    """
    level = profile.get("level") if isinstance(profile, dict) else None
    if level not in PROFILE_LEVELS:
        level = LEVEL_PARAMETER
    shaped = ensure_profile_shape(profile, level=level)  # type: ignore[arg-type]
    return json.dumps(shaped, ensure_ascii=False, separators=(",", ":"))


def deserialize_profile(
    raw: str | dict[str, Any] | None,
    *,
    level: str = LEVEL_PARAMETER,
) -> dict[str, Any]:
    """
    Purpose:
        Parse a stored profile JSON (or accept a dict) and ensure shape.

    Input:
        raw   — JSON string, already-parsed dict, or None.
        level — expected profile level when not present in the payload.

    Output:
        Profile dict with required keys (empty skeleton if raw is empty/invalid).

    Side effects: None.
    """
    if raw is None or raw == "":
        return ensure_profile_shape(None, level=level)

    if isinstance(raw, dict):
        detected = raw.get("level") if raw.get("level") in PROFILE_LEVELS else level
        return ensure_profile_shape(raw, level=detected)  # type: ignore[arg-type]

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return ensure_profile_shape(None, level=level)

    if not isinstance(data, dict):
        return ensure_profile_shape(None, level=level)

    detected = data.get("level") if data.get("level") in PROFILE_LEVELS else level
    return ensure_profile_shape(data, level=detected)  # type: ignore[arg-type]


def profile_has_required_envelope(profile: dict[str, Any]) -> bool:
    """
    Purpose:
        Quick guard: schema_version, engine_version, profile_version present
        and observed/inferred are dicts.
    Side effects: None.
    """
    if not isinstance(profile, dict):
        return False
    if "schema_version" not in profile:
        return False
    if "engine_version" not in profile:
        return False
    if "profile_version" not in profile:
        return False
    if not isinstance(profile.get("observed"), dict):
        return False
    if not isinstance(profile.get("inferred"), dict):
        return False
    return True


# ---------------------------------------------------------------------------
# Mutation history / negative evidence mutators (in-memory)
# ---------------------------------------------------------------------------

def append_attempt(
    profile: dict[str, Any],
    *,
    payload: str,
    hypothesis: str,
    result: str,
    confidence: int = 0,
    flow_id: str | None = None,
    fingerprint_delta: str | dict | None = None,
    max_attempts: int = MAX_ATTEMPTS,
) -> dict[str, Any]:
    """
    Purpose:
        Append one mutation-history entry and trim to ``max_attempts``.
        Returns the same profile dict (mutated in place) for chaining.

    Input:
        profile           — profile dict (must have attempts list after ensure).
        payload           — probe value string.
        hypothesis        — e.g. charset.quote_accepted.
        result            — validation outcome label or free-form result.
        confidence        — 0–100.
        flow_id           — evidence flow UUID.
        fingerprint_delta — compact delta summary or compare_fingerprints dict.
        max_attempts      — retention bound (default MAX_ATTEMPTS).

    Output: profile (same object).
    Side effects: Mutates profile["attempts"].
    """
    if not isinstance(profile.get("attempts"), list):
        profile["attempts"] = []

    entry: dict[str, Any] = {
        "payload": payload,
        "hypothesis": hypothesis,
        "result": result,
        "confidence": _clamp_confidence(confidence),
        "flow_id": flow_id,
        "fingerprint_delta": fingerprint_delta,
    }
    profile["attempts"].append(entry)
    if len(profile["attempts"]) > max_attempts:
        profile["attempts"] = profile["attempts"][-max_attempts:]
    return profile


def set_tested(
    profile: dict[str, Any],
    key: str,
    *,
    outcome: str,
    confidence: int = 0,
    evidence_flow_ids: list[str] | None = None,
) -> dict[str, Any]:
    """
    Purpose:
        Record negative (or positive) evidence under ``tested[key]``.
        Example: tested.unicode = {outcome: rejected, confidence: 88}.

    Output: profile (same object, mutated).
    Side effects: Mutates profile["tested"].
    """
    if not isinstance(profile.get("tested"), dict):
        profile["tested"] = {}
    entry: dict[str, Any] = {
        "outcome": outcome,
        "confidence": _clamp_confidence(confidence),
    }
    if evidence_flow_ids is not None:
        entry["evidence_flow_ids"] = list(evidence_flow_ids)
    profile["tested"][key] = entry
    return profile


def add_capability(profile: dict[str, Any], capability: str) -> dict[str, Any]:
    """
    Purpose:
        Append a capability flag if not already present (deduped, order-stable).
    Side effects: Mutates profile["capabilities"].
    """
    if not isinstance(profile.get("capabilities"), list):
        profile["capabilities"] = []
    if capability and capability not in profile["capabilities"]:
        profile["capabilities"].append(capability)
    return profile


def bump_profile_version(profile: dict[str, Any]) -> dict[str, Any]:
    """
    Purpose:
        Increment profile_version when rewriting a stored document.
    Side effects: Mutates profile["profile_version"].
    """
    try:
        current = int(profile.get("profile_version") or 0)
    except (TypeError, ValueError):
        current = 0
    profile["profile_version"] = current + 1
    return profile


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _clamp_confidence(value: int) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0
