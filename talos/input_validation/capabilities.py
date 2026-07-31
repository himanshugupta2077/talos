"""
Module: talos.input_validation.capabilities

Purpose:
    Module 11 — **central capability derivation** from parameter profiles.

    Turns observed/inferred intelligence (reflection, acceptance classes,
    types, surface, parser, length, URL sink features) into a stable list of
    capability flags that attack modules and the candidate scorer consume
    without re-reading raw probe tables.

    This is characterization only: flags mean "surface / behaviour looks
    relevant", not "vulnerability confirmed".

What this module does
    - derive_capabilities(profile) → ordered unique flag list
    - apply_capabilities(profile) → write flags onto profile["capabilities"]
    - resolve_url_features / resolve_url_sink helpers for candidates (Phase 4)
    - Replaces the ad-hoc rules previously living only in synthesize

What this module does **not** do
    - Score attack candidates (see candidates.py)
    - Send HTTP or invent evidence

Dependencies:
    talos.input_validation.profile (capability constants, add_capability)
    talos.input_validation.outcomes (soft-accept outcomes)
    talos.input_validation.surface (surface kind labels)
    talos.url_sink (optional; name classify when passive features missing)
Data flow:
    profile (observed|tested|parser|location|url_features) → derive_capabilities → flags
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
    CAPABILITY_FETCH_SINK,
    CAPABILITY_GRAPHQL_VARIABLE,
    CAPABILITY_HEADER_INJECTION_SURFACE,
    CAPABILITY_HTML_CONTEXT,
    CAPABILITY_JS_CONTEXT,
    CAPABILITY_JSON_CONTEXT,
    CAPABILITY_JSON_PARSER,
    CAPABILITY_MULTIPART_FILENAME,
    CAPABILITY_NETWORK_RESOURCE_SINK,
    CAPABILITY_PATH_PARAMETER,
    CAPABILITY_PROTOCOL_SUPPORT,
    CAPABILITY_REDIRECT_LIKE,
    CAPABILITY_REDIRECT_SINK,
    CAPABILITY_REFLECTIVE_INPUT,
    CAPABILITY_STORED_REFLECTION,
    CAPABILITY_STRICT_LENGTH,
    CAPABILITY_UNICODE_SUPPORT,
    CAPABILITY_URL_CONTEXT,
    CAPABILITY_URL_LIKE_VALUE,
    CAPABILITY_WEBHOOK_SINK,
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

# Minimum passive score / active confidence to raise network_resource_sink.
_NRS_PASSIVE_SCORE_FLOOR = 45
_NRS_ACTIVE_CONFIDENCE_FLOOR = 35
# url_like_value alias when NRS is present with at least this confidence
# (active url_sink.confidence or passive url_features.score).
_URL_LIKE_ALIAS_CONFIDENCE = 45

# Categories that strongly imply a network resource sink when combined with
# URL-shaped evidence (value or accept).
_SINK_NAME_CATEGORIES: frozenset[str] = frozenset({
    "redirect",
    "webhook",
    "remote_fetch",
    "remote_asset",
    "import_metadata",
    "infrastructure",
    "network_probe",
    "oauth",
})

# Stable derivation order (deterministic, human-friendly).
# stored_reflection sits immediately after reflective_input (cross-flow design §7).
# URL sink flags after classic redirect/url_like (compat + Phase 4).
_CAPABILITY_ORDER: tuple[str, ...] = (
    CAPABILITY_REFLECTIVE_INPUT,
    CAPABILITY_STORED_REFLECTION,
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
    CAPABILITY_NETWORK_RESOURCE_SINK,
    CAPABILITY_REDIRECT_SINK,
    CAPABILITY_FETCH_SINK,
    CAPABILITY_WEBHOOK_SINK,
    CAPABILITY_PROTOCOL_SUPPORT,
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
    # Nested modes (same_request / cross_flow) from stored-reflection merge.
    same_req = refl.get("same_request") if isinstance(refl.get("same_request"), dict) else {}
    cross_flow = refl.get("cross_flow") if isinstance(refl.get("cross_flow"), dict) else {}

    top_state = str(refl.get("state") or "").lower()
    same_state = str(same_req.get("state") or "").lower()
    cross_state = str(cross_flow.get("state") or "").lower()

    # reflective_input = value observed in some in-scope response body
    # (same-request and/or cross-flow). Not "this endpoint echoes the param".
    reflected = (
        top_state == "reflected"
        or same_state == "reflected"
        or cross_state == "reflected"
    )
    if reflected:
        found.add(CAPABILITY_REFLECTIVE_INPUT)

    # stored_reflection: durable source→sink evidence on another flow/page.
    if cross_state == "reflected":
        found.add(CAPABILITY_STORED_REFLECTION)

    # Context flags from union of top-level + same_request + cross_flow sinks.
    contexts: list[str] = []
    for src in (refl, same_req, cross_flow):
        if not isinstance(src, dict):
            continue
        for ctx in src.get("contexts") or []:
            c = str(ctx).lower()
            if c == "javascript":
                c = "js"
            if c and c not in contexts:
                contexts.append(c)
    for sink in (cross_flow.get("sinks") or []) if isinstance(cross_flow, dict) else []:
        if not isinstance(sink, dict):
            continue
        c = str(sink.get("context") or sink.get("sink_context") or "").lower()
        if c == "javascript":
            c = "js"
        if c and c not in contexts:
            contexts.append(c)

    if reflected:
        for c in contexts:
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
    if ct == "html" and reflected:
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
    type_url_soft = _is_soft_accept_entry(url_type)
    if type_url_soft:
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
        semantic = str(
            types["_summary"].get("passive")
            or types["_summary"].get("semantic")
            or ""
        )
    inferred = profile.get("inferred") or {}
    if isinstance(inferred, dict):
        passive = (
            (inferred.get("passive") or {})
            if isinstance(inferred.get("passive"), dict)
            else {}
        )
        semantic = semantic or str(passive.get("semantic_type") or "")
        if not semantic and inferred.get("passive_type"):
            semantic = str(inferred.get("passive_type") or "")
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

    # --- URL Sink Discovery Phase 4 -----------------------------------------
    uf = resolve_url_features(profile)
    us = resolve_url_sink(profile)
    name_cats = _name_categories_from(uf, name=str(profile.get("name") or ""))
    nrs_conf = network_resource_sink_confidence(
        url_features=uf,
        url_sink=us,
        type_url_soft=type_url_soft or CAPABILITY_URL_LIKE_VALUE in found,
        semantic=str(semantic or ""),
        name_categories=name_cats,
    )
    if nrs_conf > 0:
        found.add(CAPABILITY_NETWORK_RESOURCE_SINK)
        # Compat alias for one release: scorers/tests that still check
        # url_like_value keep working when NRS confidence is solid.
        if nrs_conf >= _URL_LIKE_ALIAS_CONFIDENCE:
            found.add(CAPABILITY_URL_LIKE_VALUE)

    if _is_redirect_sink(us=us, name_cats=name_cats, baseline_redirect=bool(baseline_fp.get("redirect"))):
        found.add(CAPABILITY_REDIRECT_SINK)
        if CAPABILITY_REDIRECT_LIKE not in found and (
            us.get("redirect_behavior") is True or "redirect" in name_cats or "oauth" in name_cats
        ):
            # Align redirect_like when active redirect_behavior is present.
            if us.get("redirect_behavior") is True:
                found.add(CAPABILITY_REDIRECT_LIKE)

    if _is_fetch_sink(us=us, name_cats=name_cats, nrs=nrs_conf > 0):
        found.add(CAPABILITY_FETCH_SINK)

    if _is_webhook_sink(us=us, name_cats=name_cats, nrs=nrs_conf > 0, type_url_soft=type_url_soft):
        found.add(CAPABILITY_WEBHOOK_SINK)

    accepted_protocols = us.get("accepted_protocols") if isinstance(us, dict) else None
    if us.get("accepts_protocol") is True or (
        isinstance(accepted_protocols, list) and len(accepted_protocols) > 0
    ):
        found.add(CAPABILITY_PROTOCOL_SUPPORT)

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
# URL sink / features resolvers (shared with candidates.py)
# ---------------------------------------------------------------------------

def resolve_url_features(profile: dict[str, Any] | None) -> dict[str, Any]:
    """
    Purpose:
        Best-effort passive ``url_features`` document from a profile.

        Sources (first non-empty wins, then merge name categories from name):
            1. observed.url_features
            2. top-level profile["url_features"]
            3. inferred.url_features / inferred.passive.url_features
            4. compose from parameter name when still empty

    Output: dict (may be empty).
    Side effects: None (does not mutate profile).
    """
    if not profile or not isinstance(profile, dict):
        return {}

    candidates: list[Any] = []
    obs = profile.get("observed")
    if isinstance(obs, dict):
        candidates.append(obs.get("url_features"))
    candidates.append(profile.get("url_features"))
    inferred = profile.get("inferred")
    if isinstance(inferred, dict):
        candidates.append(inferred.get("url_features"))
        passive = inferred.get("passive")
        if isinstance(passive, dict):
            candidates.append(passive.get("url_features"))

    uf: dict[str, Any] = {}
    for c in candidates:
        parsed = _as_url_features_dict(c)
        if parsed and (parsed.get("score") or parsed.get("name_category")
                       or parsed.get("name_categories")
                       or parsed.get("possible_network_resource")
                       or parsed.get("evidence")):
            uf = parsed
            break
        if parsed and not uf:
            uf = parsed

    # Ensure name categories when missing but name is known.
    name = str(profile.get("name") or "")
    if name and not (uf.get("name_category") or uf.get("name_categories")):
        try:
            from talos.url_sink.features import compose_url_features

            composed = compose_url_features(name=name, value=None)
            if not uf:
                uf = composed
            else:
                uf = dict(uf)
                uf["name_category"] = composed.get("name_category")
                uf["name_categories"] = list(composed.get("name_categories") or [])
                # Modest name-only score if value score absent.
                if int(uf.get("score") or 0) == 0 and int(composed.get("score") or 0):
                    uf["score"] = composed.get("score")
                    uf["possible_network_resource"] = composed.get(
                        "possible_network_resource", False
                    )
                evidence = list(uf.get("evidence") or [])
                for e in composed.get("evidence") or []:
                    if e not in evidence:
                        evidence.append(e)
                uf["evidence"] = evidence
        except Exception:
            pass

    return uf if isinstance(uf, dict) else {}


def resolve_url_sink(profile: dict[str, Any] | None) -> dict[str, Any]:
    """
    Purpose:
        Return ``observed.url_sink`` block (active Phase 3 characterization).
    Output: dict (may be empty).
    Side effects: None.
    """
    if not profile or not isinstance(profile, dict):
        return {}
    obs = profile.get("observed")
    if not isinstance(obs, dict):
        return {}
    us = obs.get("url_sink")
    return dict(us) if isinstance(us, dict) else {}


def network_resource_sink_confidence(
    *,
    url_features: dict[str, Any] | None = None,
    url_sink: dict[str, Any] | None = None,
    type_url_soft: bool = False,
    semantic: str = "",
    name_categories: set[str] | frozenset[str] | None = None,
) -> int:
    """
    Purpose:
        0–100 confidence that this parameter is a network resource sink.
        Used to decide CAPABILITY_NETWORK_RESOURCE_SINK and alias url_like_value.

    Rules (max of contributing signals):
        - type url soft-accept / primary url → ≥ 70
        - active accepts_url / hostname / ip / protocol → ≥ 75–90
        - fetch / redirect / DNS behavior → ≥ 70
        - passive possible_network_resource / score ≥ 45 → score-ish
        - strong name category alone → 0 (name does not invent sink)

    Side effects: None.
    """
    uf = url_features if isinstance(url_features, dict) else {}
    us = url_sink if isinstance(url_sink, dict) else {}
    cats = set(name_categories or ())
    conf = 0

    if type_url_soft:
        conf = max(conf, 75)

    sem = (semantic or "").lower()
    if sem in ("url", "uri"):
        conf = max(conf, 55)

    try:
        passive_score = int(uf.get("score") or 0)
    except (TypeError, ValueError):
        passive_score = 0
    if uf.get("possible_network_resource") is True or passive_score >= _NRS_PASSIVE_SCORE_FLOOR:
        conf = max(conf, min(95, max(passive_score, _NRS_PASSIVE_SCORE_FLOOR)))

    if any(
        us.get(k) is True
        for k in (
            "accepts_url",
            "accepts_hostname",
            "accepts_ip",
            "accepts_protocol",
            "accepts_unc",
        )
    ):
        conf = max(conf, 85)
    if us.get("accepts_path") is True and conf < 50:
        conf = max(conf, 50)

    if us.get("fetch_behavior") is True:
        conf = max(conf, 80)
    if us.get("redirect_behavior") is True:
        conf = max(conf, 75)
    if us.get("dns_resolution_detected") is True:
        conf = max(conf, 78)

    try:
        active_conf = int(us.get("confidence") or 0)
    except (TypeError, ValueError):
        active_conf = 0
    if active_conf >= _NRS_ACTIVE_CONFIDENCE_FLOOR and (
        us.get("error_classes")
        or us.get("per_probe")
        or us.get("validation_behavior")
        or active_conf >= 50
    ):
        # Soft active evidence without hard accepts still raises NRS modestly.
        conf = max(conf, min(70, active_conf))

    # Strong name + any URL-shaped value flag (without inventing from name alone).
    if cats & _SINK_NAME_CATEGORIES and (
        uf.get("possible_url_value")
        or uf.get("possible_hostname")
        or uf.get("possible_ip")
        or type_url_soft
        or conf > 0
    ):
        conf = max(conf, 50)

    return max(0, min(100, int(conf)))


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


def _as_url_features_dict(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    if isinstance(raw, str) and raw.strip():
        try:
            import json
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}
    return {}


def _name_categories_from(
    url_features: dict[str, Any],
    *,
    name: str = "",
) -> set[str]:
    cats: set[str] = set()
    primary = url_features.get("name_category")
    if primary:
        cats.add(str(primary).lower())
    for c in url_features.get("name_categories") or []:
        if c:
            cats.add(str(c).lower())
    if name and not cats:
        try:
            from talos.url_sink.name_classify import classify_name

            nf = classify_name(name)
            if nf.name_category:
                cats.add(str(nf.name_category).lower())
            for c in nf.name_categories or ():
                cats.add(str(c).lower())
        except Exception:
            pass
    return cats


def _is_redirect_sink(
    *,
    us: dict[str, Any],
    name_cats: set[str],
    baseline_redirect: bool,
) -> bool:
    if us.get("redirect_behavior") is True:
        return True
    if "redirect" in name_cats or "oauth" in name_cats:
        # Category alone is a soft sink label when baseline redirects or
        # active characterization ran; still allow category-only for operator
        # prioritization when NRS also present (checked by consumer).
        if baseline_redirect or us.get("accepts_url") is True or int(us.get("confidence") or 0) > 0:
            return True
        # Name category redirect/oauth without behavior: still flag as
        # redirect_sink for candidate bias (characterization, not vuln).
        return True
    if baseline_redirect and (
        us.get("accepts_url") is True
        or us.get("accepts_hostname") is True
        or us.get("accepts_path") is True
    ):
        return True
    return False


def _is_fetch_sink(
    *,
    us: dict[str, Any],
    name_cats: set[str],
    nrs: bool,
) -> bool:
    if us.get("fetch_behavior") is True:
        return True
    if us.get("dns_resolution_detected") is True:
        return True
    err = {str(e).lower() for e in (us.get("error_classes") or []) if e}
    if err & {
        "timeout",
        "connection_refused",
        "dns_lookup_failed",
        "unable_to_fetch",
        "host_unreachable",
    }:
        return True
    fetch_cats = {
        "remote_fetch",
        "remote_asset",
        "import_metadata",
        "infrastructure",
        "network_probe",
        "webhook",
    }
    if nrs and (name_cats & fetch_cats):
        return True
    return False


def _is_webhook_sink(
    *,
    us: dict[str, Any],
    name_cats: set[str],
    nrs: bool,
    type_url_soft: bool,
) -> bool:
    if "webhook" not in name_cats:
        return False
    if us.get("fetch_behavior") is True:
        return True
    if type_url_soft or nrs or us.get("accepts_url") is True:
        return True
    # Name is webhook/callback — soft flag for candidate family bias.
    return True
