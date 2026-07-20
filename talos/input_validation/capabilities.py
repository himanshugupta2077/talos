"""
Module: talos.input_validation.capabilities

Purpose:
    Module 11 — **central capability derivation** from parameter profiles.

    Turns observed/inferred intelligence (reflection, acceptance classes,
    types, surface, parser, length) into a stable list of capability flags
    that attack modules and the candidate scorer consume without re-reading
    raw probe tables.

    This is characterization only: flags mean "surface / behaviour looks
    relevant", not "vulnerability confirmed".

What this module does
    - derive_capabilities(profile) → ordered unique flag list
    - apply_capabilities(profile) → write flags onto profile["capabilities"]
    - Replaces the ad-hoc rules previously living only in synthesize

What this module does **not** do
    - Score attack candidates (see candidates.py)
    - Send HTTP or invent evidence

Dependencies:
    talos.input_validation.profile (capability constants, add_capability)
    talos.input_validation.outcomes (soft-accept outcomes)
    talos.input_validation.surface (surface kind labels)
Data flow:
    profile (observed|tested|parser|location) → derive_capabilities → flags
Side effects: apply_capabilities mutates profile["capabilities"]; derive is pure.
"""

from __future__ import annotations

from typing import Any

from talos.input_validation.outcomes import (
    OUTCOME_ACCEPTED,
    OUTCOME_ENCODED,
    OUTCOME_MODIFIED,
    OUTCOME_NORMALIZED,
)
from talos.input_validation.profile import (
    CAPABILITY_DUPLICATE_PARAMETER,
    CAPABILITY_GRAPHQL_VARIABLE,
    CAPABILITY_HEADER_INJECTION_SURFACE,
    CAPABILITY_HTML_CONTEXT,
    CAPABILITY_JS_CONTEXT,
    CAPABILITY_JSON_CONTEXT,
    CAPABILITY_JSON_PARSER,
    CAPABILITY_MULTIPART_FILENAME,
    CAPABILITY_PATH_PARAMETER,
    CAPABILITY_REDIRECT_LIKE,
    CAPABILITY_REFLECTIVE_INPUT,
    CAPABILITY_STRICT_LENGTH,
    CAPABILITY_UNICODE_SUPPORT,
    CAPABILITY_URL_CONTEXT,
    CAPABILITY_URL_LIKE_VALUE,
    CAPABILITY_XML_BODY,
    KNOWN_CAPABILITIES,
    add_capability,
)
from talos.input_validation.surface import (
    SURFACE_GRAPHQL_VARIABLE,
    SURFACE_HEADER,
    SURFACE_MULTIPART_FIELD,
    SURFACE_MULTIPART_FILENAME,
    SURFACE_XML_LEAF,
    detect_surface_kind,
)

# Outcomes that count as "input was not hard-rejected" for capability flags.
_SOFT_ACCEPT: frozenset[str] = frozenset({
    OUTCOME_ACCEPTED,
    OUTCOME_MODIFIED,
    OUTCOME_ENCODED,
    OUTCOME_NORMALIZED,
})

# Stable derivation order (deterministic, human-friendly).
_CAPABILITY_ORDER: tuple[str, ...] = (
    CAPABILITY_REFLECTIVE_INPUT,
    CAPABILITY_HTML_CONTEXT,
    CAPABILITY_JSON_CONTEXT,
    CAPABILITY_JS_CONTEXT,
    CAPABILITY_URL_CONTEXT,
    CAPABILITY_XML_BODY,
    CAPABILITY_JSON_PARSER,
    CAPABILITY_UNICODE_SUPPORT,
    CAPABILITY_STRICT_LENGTH,
    CAPABILITY_DUPLICATE_PARAMETER,
    CAPABILITY_HEADER_INJECTION_SURFACE,
    CAPABILITY_PATH_PARAMETER,
    CAPABILITY_MULTIPART_FILENAME,
    CAPABILITY_GRAPHQL_VARIABLE,
    CAPABILITY_REDIRECT_LIKE,
    CAPABILITY_URL_LIKE_VALUE,
)


def derive_capabilities(profile: dict[str, Any] | None) -> list[str]:
    """
    Purpose:
        Derive capability flags from a parameter (or endpoint-shaped) profile
        without mutating it.

    Input:
        profile — intelligence document with observed / tested / location.

    Output:
        Ordered unique list of known capability strings. Unknown custom flags
        already on the profile are preserved at the end (order-stable).

    Side effects: None.
    """
    if not profile or not isinstance(profile, dict):
        return []

    found: set[str] = set()
    obs = profile.get("observed") or {}
    if not isinstance(obs, dict):
        obs = {}
    tested = profile.get("tested") or {}
    if not isinstance(tested, dict):
        tested = {}
    location = str(profile.get("location") or "").lower()

    refl = obs.get("reflection") or {}
    if not isinstance(refl, dict):
        refl = {}
    acceptance = (obs.get("acceptance") or {}).get("classes") or {}
    if not isinstance(acceptance, dict):
        acceptance = {}
    types = obs.get("types") or {}
    if not isinstance(types, dict):
        types = {}
    length = obs.get("length") or {}
    if not isinstance(length, dict):
        length = {}
    baseline_fp = obs.get("baseline_fingerprint") or {}
    if not isinstance(baseline_fp, dict):
        baseline_fp = {}
    surface_obs = obs.get("surface") or {}
    if not isinstance(surface_obs, dict):
        surface_obs = {}
    parser_obs = obs.get("parser") or profile.get("parser") or {}
    if not isinstance(parser_obs, dict):
        parser_obs = {}

    # --- Reflection / context ------------------------------------------------
    contexts = list(refl.get("contexts") or [])
    if str(refl.get("state") or "").lower() == "reflected":
        found.add(CAPABILITY_REFLECTIVE_INPUT)
        for ctx in contexts:
            c = str(ctx).lower()
            if c == "html":
                found.add(CAPABILITY_HTML_CONTEXT)
            elif c == "json":
                found.add(CAPABILITY_JSON_CONTEXT)
            elif c in ("js", "javascript"):
                found.add(CAPABILITY_JS_CONTEXT)
            elif c == "url":
                found.add(CAPABILITY_URL_CONTEXT)
            elif c == "xml":
                found.add(CAPABILITY_XML_BODY)

    # --- Content-type / baseline --------------------------------------------
    ct = str(baseline_fp.get("content_type") or "").lower()
    if ct == "json":
        found.add(CAPABILITY_JSON_PARSER)
    if ct == "xml":
        found.add(CAPABILITY_XML_BODY)
    if ct == "html" and str(refl.get("state") or "").lower() == "reflected":
        found.add(CAPABILITY_HTML_CONTEXT)

    # --- Location / surface -------------------------------------------------
    if location == "path":
        found.add(CAPABILITY_PATH_PARAMETER)
    if location == "header":
        found.add(CAPABILITY_HEADER_INJECTION_SURFACE)

    kind = str(surface_obs.get("kind") or "")
    if not kind:
        kind = detect_surface_kind(
            location=location,
            param_name=str(profile.get("name") or ""),
            content_type=str(ct or ""),
            semantic_type="",
        )
    if kind == SURFACE_MULTIPART_FILENAME:
        found.add(CAPABILITY_MULTIPART_FILENAME)
    if kind == SURFACE_GRAPHQL_VARIABLE:
        found.add(CAPABILITY_GRAPHQL_VARIABLE)
    if kind == SURFACE_XML_LEAF:
        found.add(CAPABILITY_XML_BODY)
    if kind == SURFACE_HEADER:
        found.add(CAPABILITY_HEADER_INJECTION_SURFACE)
    # SURFACE_MULTIPART_FIELD has no dedicated flag beyond body (by design).
    _ = SURFACE_MULTIPART_FIELD

    # --- Acceptance / types / length ----------------------------------------
    unicode_entry = acceptance.get("unicode") or tested.get("unicode")
    if _is_soft_accept_entry(unicode_entry):
        found.add(CAPABILITY_UNICODE_SUPPORT)

    if str(length.get("state") or "").lower() in ("bounded", "truncated"):
        found.add(CAPABILITY_STRICT_LENGTH)

    url_type = types.get("url")
    if _is_soft_accept_entry(url_type):
        found.add(CAPABILITY_URL_LIKE_VALUE)
    summary = types.get("_summary")
    if isinstance(summary, dict) and str(summary.get("primary") or "").lower() == "url":
        found.add(CAPABILITY_URL_LIKE_VALUE)

    if baseline_fp.get("redirect"):
        found.add(CAPABILITY_REDIRECT_LIKE)

    # Name/semantic hints already on profile (passive or inferred).
    name = str(profile.get("name") or "").lower()
    semantic = ""
    if isinstance(types.get("_summary"), dict):
        semantic = str(types["_summary"].get("passive") or types["_summary"].get("semantic") or "")
    inferred = profile.get("inferred") or {}
    if isinstance(inferred, dict):
        passive = (inferred.get("passive") or {}) if isinstance(inferred.get("passive"), dict) else {}
        semantic = semantic or str(passive.get("semantic_type") or "")
    if not semantic and isinstance(obs.get("types"), dict):
        # Common passive field mirrored under observed by some synthesizers.
        pass
    if _name_looks_url_or_redirect(name) or str(semantic).lower() in (
        "url", "uri", "redirect", "callback",
    ):
        # Soft capability: name alone does not force url_like_value unless type
        # evidence exists; still useful for redirect_like when baseline redirects.
        if CAPABILITY_URL_LIKE_VALUE in found or CAPABILITY_REDIRECT_LIKE in found:
            pass  # already set from measured evidence
        # Do not invent url_like from name alone — candidate scorer uses name.

    # --- Parser (Module 8) --------------------------------------------------
    for key in ("duplicate_query", "duplicate_form", "array_repeat"):
        entry = parser_obs.get(key) or {}
        if not isinstance(entry, dict):
            continue
        behavior = str(entry.get("behavior") or entry.get("state") or "")
        if behavior in ("first_wins", "last_wins", "join"):
            found.add(CAPABILITY_DUPLICATE_PARAMETER)
            break
    if any(
        k in parser_obs
        for k in ("json_null", "json_empty", "json_omit", "json_duplicate_key")
    ):
        found.add(CAPABILITY_JSON_PARSER)

    # Preserve any pre-existing known flags already on the profile (e.g. set by
    # parser_intel apply) that our rules might have missed.
    existing = profile.get("capabilities") or []
    if isinstance(existing, list):
        for cap in existing:
            if isinstance(cap, str) and cap in KNOWN_CAPABILITIES:
                found.add(cap)

    ordered = [c for c in _CAPABILITY_ORDER if c in found]
    # Append unknown custom flags last (stable).
    if isinstance(existing, list):
        for cap in existing:
            if isinstance(cap, str) and cap and cap not in found and cap not in ordered:
                ordered.append(cap)
    return ordered


def apply_capabilities(profile: dict[str, Any]) -> dict[str, Any]:
    """
    Purpose:
        Recompute and write ``profile["capabilities"]`` from observed/inferred.

    Input:
        profile — mutable parameter intelligence document.

    Output:
        The same profile object (mutated).

    Side effects: Overwrites profile["capabilities"] with derived list.
    """
    if not isinstance(profile, dict):
        return profile
    flags = derive_capabilities(profile)
    profile["capabilities"] = list(flags)
    return profile


def merge_capability(profile: dict[str, Any], capability: str) -> dict[str, Any]:
    """
    Purpose:
        Append one capability flag (wrapper around profile.add_capability).
    Side effects: Mutates profile["capabilities"].
    """
    return add_capability(profile, capability)


def has_capability(profile: dict[str, Any] | None, capability: str) -> bool:
    """
    Purpose: True when the profile lists the given capability flag.
    Side effects: None.
    """
    if not profile or not isinstance(profile, dict):
        return False
    caps = profile.get("capabilities") or []
    return isinstance(caps, list) and capability in caps


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _is_soft_accept_entry(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    return str(entry.get("outcome") or "").lower() in _SOFT_ACCEPT


def _name_looks_url_or_redirect(name: str) -> bool:
    n = (name or "").lower().replace("-", "_")
    needles = (
        "url", "uri", "redirect", "return_url", "returnurl", "next",
        "callback", "continue", "dest", "destination", "goto", "target",
        "webhook", "fetch", "href", "link", "site",
    )
    return any(x in n for x in needles)
