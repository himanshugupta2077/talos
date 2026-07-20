"""
Module: talos.input_validation.learning

Purpose:
    Multi-level learning for Input Validation (Module 10).

    Aggregates completed parameter intelligence into **endpoint** and
    **application/host** profiles, then provides inheritance priors so a new
    parameter can skip redundant probes under standard/quick budgets.

    Design principles (Section 0.4 multi-level profiles):
        - Parameter is the primary unit of observed evidence.
        - Endpoint profiles capture shared middleware/validation defaults.
        - Application (host) profiles capture host-wide defaults.
        - Inheritance is **inferred** priors only — never written into
          ``observed`` or local ``tested`` as if measured on this param.
        - Local observed always wins over inherited when both exist.
        - Inherited confidence is capped (default 75) until local confirm.

Scope (in):
        - Aggregate tested negatives, parser fingerprints, acceptance class
          rejections, capabilities, timing baselines, normalization stages.
        - Inheritance merge with confidence decay.
        - Planner-facing priors (suppress control/null/deep-ish probes under
          standard when host/endpoint already rejected them).

Scope (out):
        - Cross-project learning.
        - Automatic controller clustering (optional path-prefix group only as
          a light heuristic on endpoint.path for future M11 consumers).

Dependencies:
    copy, dataclasses, statistics, typing
    talos.input_validation.outcomes (OUTCOME_*)
    talos.input_validation.profile (empty_*, LEVEL_*, set_tested helpers shape)
Data flow:
    param profiles → aggregate_endpoint_profile / aggregate_app_profile
        → upsert via db → build_inheritance_priors → planner PlanContext
Side effects: None (pure). Persistence is the caller's responsibility.
"""

from __future__ import annotations

import copy
import statistics
from dataclasses import dataclass, field
from typing import Any

from talos.input_validation.outcomes import (
    OUTCOME_REJECTED,
    OUTCOME_ACCEPTED,
)
from talos.input_validation.profile import (
    LEVEL_APPLICATION,
    LEVEL_ENDPOINT,
    LEVEL_PARAMETER,
    empty_app_profile,
    empty_endpoint_profile,
    ensure_profile_shape,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Inherited confidence never exceeds this until local evidence confirms.
INHERITED_CONFIDENCE_CAP = 75

# Minimum source confidence to promote a tested/parser fact into a parent.
MIN_AGGREGATE_CONFIDENCE = 60

# Minimum number of agreeing param profiles when multiple exist.
# With a single completed param on the endpoint, that param still seeds
# the endpoint profile (count >= 1).
MIN_PARAM_SUPPORT = 1

# Charset / validation families suppressed under standard when inherited reject.
CONTROL_RELATED_CLASSES: frozenset[str] = frozenset({
    "control",
    "null",
})

# tested{} keys that map to "control-like" suppression (host-level reject).
CONTROL_RELATED_TESTED_KEYS: frozenset[str] = frozenset({
    "control",
    "null",
    "null_byte",
    "charset.control",
    "charset.null",
})

# Validation / semantic payload_type labels suppressed when tested family rejects.
PAYLOAD_TYPE_TO_TESTED_FAMILY: dict[str, str] = {
    "null_byte": "null",
    "whitespace": "whitespace",
    "html_injection": "markup",
    "special_chars": "comment",
    "very_long": "length_limit",
    "empty": "empty",
    "negative_int": "negative_int",
    "float": "float",
    "crlf": "crlf",
    "enum_outside": "enum_outside",
    "zero": "zero",
    "huge_int": "huge_int",
    "null_str": "null_str",
    "unicode": "unicode",
    "control": "control",
}

# Source labels for inferred.inheritance / tested provenance metadata.
SOURCE_ENDPOINT = "inherited_endpoint"
SOURCE_APPLICATION = "inherited_application"
SOURCE_MERGED = "inherited_merged"


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class InheritancePriors:
    """
    Planner-facing priors for one parameter that has not (yet) local evidence
    for the listed facts.  All confidences are already decayed/capped.

    Fields:
        tested              — family → {outcome, confidence, source}
        rejected_classes    — charset taxonomy classes rejected at parent level
        accepted_classes    — charset classes accepted (skip re-probe under std)
        parser              — aggregated parser fingerprint (read-only hint)
        parser_known        — True when parent has usable parser fingerprint
        capabilities        — parent capability flags (M11 handoff)
        normalization_pipeline — ordered stages when shared
        suppress_control_probes — True when control/null rejected at host/ep
        suppress_parser_probes  — True when parser known at parent (std only)
        source_levels       — which levels contributed (endpoint / application)
        endpoint_id         — optional endpoint key used
        host                — optional host key used
        reduced_request_estimate — how many HTTP slots inheritance can save
                                  (planner unit tests assert this > 0 when
                                  priors apply under standard)
    """

    tested: dict[str, dict[str, Any]] = field(default_factory=dict)
    rejected_classes: frozenset[str] = field(default_factory=frozenset)
    accepted_classes: frozenset[str] = field(default_factory=frozenset)
    parser: dict[str, Any] = field(default_factory=dict)
    parser_known: bool = False
    capabilities: tuple[str, ...] = ()
    normalization_pipeline: tuple[str, ...] = ()
    suppress_control_probes: bool = False
    suppress_parser_probes: bool = False
    source_levels: tuple[str, ...] = ()
    endpoint_id: str = ""
    host: str = ""
    reduced_request_estimate: int = 0

    def is_active(self) -> bool:
        """True when any inheritance signal is present."""
        return bool(
            self.tested
            or self.rejected_classes
            or self.accepted_classes
            or self.parser_known
            or self.suppress_control_probes
            or self.suppress_parser_probes
        )

    def known_class_outcomes(self, *, budget_tier: str = "standard") -> dict[str, str]:
        """
        Purpose:
            Map for taxonomy.char_probes_for_strategy skip_known.

            Under deep/exhaustive, control/null classes are **not** skipped from
            inheritance so those budgets re-confirm host-level control rejects.
        Output: class → outcome (rejected or accepted).
        Side effects: None.
        """
        tier = (budget_tier or "standard").lower().strip()
        out: dict[str, str] = {}
        for c in self.rejected_classes:
            if tier in ("deep", "exhaustive") and c in CONTROL_RELATED_CLASSES:
                continue
            out[c] = OUTCOME_REJECTED
        for c in self.accepted_classes:
            if c not in out:
                out[c] = OUTCOME_ACCEPTED
        return out

    def to_inferred_block(self) -> dict[str, Any]:
        """
        Purpose:
            Serializable ``inferred.inheritance`` document (not observed).
        Side effects: None.
        """
        return {
            "source": SOURCE_MERGED if len(self.source_levels) > 1 else (
                self.source_levels[0] if self.source_levels else SOURCE_MERGED
            ),
            "source_levels": list(self.source_levels),
            "endpoint_id": self.endpoint_id,
            "host": self.host,
            "tested": copy.deepcopy(self.tested),
            "rejected_classes": sorted(self.rejected_classes),
            "accepted_classes": sorted(self.accepted_classes),
            "parser_known": self.parser_known,
            "suppress_control_probes": self.suppress_control_probes,
            "suppress_parser_probes": self.suppress_parser_probes,
            "reduced_request_estimate": self.reduced_request_estimate,
            "capabilities": list(self.capabilities),
            "confidence_cap": INHERITED_CONFIDENCE_CAP,
            "note": (
                "Inherited priors only — not local observed evidence. "
                "Local probe outcomes always win when present."
            ),
        }


# ---------------------------------------------------------------------------
# Confidence helpers
# ---------------------------------------------------------------------------

def decay_inherited_confidence(
    confidence: int,
    *,
    cap: int = INHERITED_CONFIDENCE_CAP,
) -> int:
    """
    Purpose:
        Cap inherited confidence so consumers treat it as "verify lightly"
        until local confirmation (Section 0.4: 60–89 band).
    Input:
        confidence — source confidence 0–100.
        cap        — max allowed for inherited facts (default 75).
    Output: clamped integer 0–cap.
    Side effects: None.
    """
    try:
        c = int(confidence)
    except (TypeError, ValueError):
        return 0
    return max(0, min(int(cap), c))


def _clamp_conf(value: Any) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# Aggregation: parameter → endpoint
# ---------------------------------------------------------------------------

def aggregate_endpoint_from_params(
    param_profiles: list[dict[str, Any]],
    *,
    endpoint_id: str = "",
    host: str = "",
    method: str = "",
    path: str = "",
) -> dict[str, Any]:
    """
    Purpose:
        Build an endpoint-level profile from completed parameter profiles
        on that endpoint (parser, common normalization, common rejected
        classes, timing baselines, shared tested negatives).

    Input:
        param_profiles — list of parameter profile dicts (observed filled).
        endpoint_id / host / method / path — identity fields.

    Output:
        Shaped endpoint profile dict (level=endpoint).  Empty-capable when
        no usable param profiles.

    Side effects: None (pure; does not write DB).
    """
    usable = [p for p in param_profiles if _param_profile_usable(p)]
    profile = empty_endpoint_profile(
        endpoint_id=endpoint_id,
        host=host or _first_host(usable),
        method=method,
        path=path,
    )

    if not usable:
        profile["inferred"] = {
            "aggregation": {
                "param_count": 0,
                "source": "none",
            },
        }
        return ensure_profile_shape(profile, level=LEVEL_ENDPOINT)

    tested = _aggregate_tested(usable)
    parser = _aggregate_parser(usable)
    pipeline = _aggregate_normalization_pipeline(usable)
    classes_rej, classes_acc = _aggregate_class_outcomes(usable)
    caps = _aggregate_capabilities(usable)
    timing = _aggregate_timing(usable)

    profile["tested"] = tested
    profile["parser"] = parser
    profile["normalization_pipeline"] = pipeline
    profile["capabilities"] = caps
    profile["observed"] = {
        "acceptance": {
            "rejected_classes": sorted(classes_rej),
            "accepted_classes": sorted(classes_acc),
        },
        "timing": timing,
        "param_count": len(usable),
    }
    profile["param_defaults"] = {
        "tested": copy.deepcopy(tested),
        "parser": copy.deepcopy(parser),
        "rejected_classes": sorted(classes_rej),
        "accepted_classes": sorted(classes_acc),
        "normalization_pipeline": list(pipeline),
    }
    profile["inferred"] = {
        "aggregation": {
            "param_count": len(usable),
            "source": "param_profiles",
            "param_uuids": [
                str(p.get("param_uuid") or "")
                for p in usable
                if p.get("param_uuid")
            ][:50],
        },
    }
    # Sum requests across params for operator visibility (not a hard budget).
    profile["requests_used"] = sum(
        int(p.get("requests_used") or 0) for p in usable
    )
    return ensure_profile_shape(profile, level=LEVEL_ENDPOINT)


def aggregate_app_from_endpoints(
    endpoint_profiles: list[dict[str, Any]],
    *,
    host: str = "",
) -> dict[str, Any]:
    """
    Purpose:
        Build an application/host-level profile from endpoint profiles.

    Input:
        endpoint_profiles — list of endpoint profile dicts.
        host              — application host key.

    Output:
        Shaped application profile dict.

    Side effects: None.
    """
    usable = [
        p for p in endpoint_profiles
        if isinstance(p, dict) and (
            p.get("tested") or p.get("parser") or p.get("param_defaults")
        )
    ]
    profile = empty_app_profile(host=host or _first_host(usable))

    if not usable:
        profile["inferred"] = {
            "aggregation": {"endpoint_count": 0, "source": "none"},
        }
        return ensure_profile_shape(profile, level=LEVEL_APPLICATION)

    # Treat each endpoint's tested / param_defaults as a "source profile".
    pseudo_params: list[dict[str, Any]] = []
    for ep in usable:
        defaults = ep.get("param_defaults") if isinstance(ep.get("param_defaults"), dict) else {}
        tested = defaults.get("tested") or ep.get("tested") or {}
        parser = defaults.get("parser") or ep.get("parser") or {}
        pipeline = (
            defaults.get("normalization_pipeline")
            or ep.get("normalization_pipeline")
            or []
        )
        obs = ep.get("observed") if isinstance(ep.get("observed"), dict) else {}
        acc = obs.get("acceptance") if isinstance(obs.get("acceptance"), dict) else {}
        # Build a synthetic param-like shape for reuse of aggregators.
        classes: dict[str, dict[str, Any]] = {}
        for c in acc.get("rejected_classes") or defaults.get("rejected_classes") or []:
            classes[str(c)] = {"outcome": OUTCOME_REJECTED, "confidence": 70}
        for c in acc.get("accepted_classes") or defaults.get("accepted_classes") or []:
            if str(c) not in classes:
                classes[str(c)] = {"outcome": OUTCOME_ACCEPTED, "confidence": 70}
        pseudo_params.append({
            "tested": tested if isinstance(tested, dict) else {},
            "parser": parser if isinstance(parser, dict) else {},
            "normalization_pipeline": pipeline if isinstance(pipeline, list) else [],
            "capabilities": list(ep.get("capabilities") or []),
            "observed": {
                "acceptance": {"classes": classes},
                "timing": obs.get("timing") or {},
            },
            "param_uuid": ep.get("endpoint_id") or "",
            "requests_used": int(ep.get("requests_used") or 0),
        })

    tested = _aggregate_tested(pseudo_params)
    parser = _aggregate_parser(pseudo_params)
    pipeline = _aggregate_normalization_pipeline(pseudo_params)
    classes_rej, classes_acc = _aggregate_class_outcomes(pseudo_params)
    caps = _aggregate_capabilities(pseudo_params)
    timing = _aggregate_timing(pseudo_params)

    profile["tested"] = tested
    profile["parser"] = parser
    profile["normalization_pipeline"] = pipeline
    profile["capabilities"] = caps
    profile["observed"] = {
        "acceptance": {
            "rejected_classes": sorted(classes_rej),
            "accepted_classes": sorted(classes_acc),
        },
        "timing": timing,
        "endpoint_count": len(usable),
    }
    profile["param_defaults"] = {
        "tested": copy.deepcopy(tested),
        "parser": copy.deepcopy(parser),
        "rejected_classes": sorted(classes_rej),
        "accepted_classes": sorted(classes_acc),
        "normalization_pipeline": list(pipeline),
    }
    profile["endpoint_defaults"] = {
        "endpoint_ids": [
            str(ep.get("endpoint_id") or "")
            for ep in usable
            if ep.get("endpoint_id")
        ][:100],
    }
    profile["inferred"] = {
        "aggregation": {
            "endpoint_count": len(usable),
            "source": "endpoint_profiles",
        },
    }
    profile["requests_used"] = sum(int(p.get("requests_used") or 0) for p in pseudo_params)
    return ensure_profile_shape(profile, level=LEVEL_APPLICATION)


# ---------------------------------------------------------------------------
# Inheritance merge
# ---------------------------------------------------------------------------

def build_inheritance_priors(
    *,
    endpoint_profile: dict[str, Any] | None = None,
    app_profile: dict[str, Any] | None = None,
    local_profile: dict[str, Any] | None = None,
    budget_tier: str = "standard",
) -> InheritancePriors:
    """
    Purpose:
        Merge application then endpoint priors into planner-facing inheritance.
        Local observed / tested always wins (those keys are **excluded** from
        the inherited maps so the planner does not double-count).

    Input:
        endpoint_profile — endpoint-level intelligence or None.
        app_profile      — host-level intelligence or None.
        local_profile    — parameter profile (if any local tested/parser).
        budget_tier      — quick|standard|deep|exhaustive (affects suppress).

    Output:
        InheritancePriors (possibly inactive).

    Side effects: None.
    """
    tier = (budget_tier or "standard").lower().strip()
    local_tested = _local_tested_keys(local_profile)
    local_classes = _local_class_keys(local_profile)
    local_parser_known = _local_parser_known(local_profile)

    # App first, then endpoint overlays (more specific wins on conflict).
    merged_tested: dict[str, dict[str, Any]] = {}
    rejected: set[str] = set()
    accepted: set[str] = set()
    parser: dict[str, Any] = {}
    pipeline: list[str] = []
    caps: list[str] = []
    levels: list[str] = []
    endpoint_id = ""
    host = ""

    if app_profile and isinstance(app_profile, dict):
        _absorb_parent(
            app_profile,
            source=SOURCE_APPLICATION,
            merged_tested=merged_tested,
            rejected=rejected,
            accepted=accepted,
            parser_out=parser,
            pipeline_out=pipeline,
            caps_out=caps,
            local_tested=local_tested,
            local_classes=local_classes,
        )
        host = str(app_profile.get("host") or host)
        levels.append(LEVEL_APPLICATION)

    if endpoint_profile and isinstance(endpoint_profile, dict):
        _absorb_parent(
            endpoint_profile,
            source=SOURCE_ENDPOINT,
            merged_tested=merged_tested,
            rejected=rejected,
            accepted=accepted,
            parser_out=parser,
            pipeline_out=pipeline,
            caps_out=caps,
            local_tested=local_tested,
            local_classes=local_classes,
        )
        endpoint_id = str(endpoint_profile.get("endpoint_id") or "")
        host = str(endpoint_profile.get("host") or host)
        if LEVEL_ENDPOINT not in levels:
            levels.append(LEVEL_ENDPOINT)

    # Host-level control-char rejection suppresses control/null re-probes
    # under quick/standard (not deep/exhaustive — acceptance criterion).
    suppress_control = False
    if tier in ("quick", "standard"):
        suppress_control = _has_control_rejection(merged_tested, rejected)
        if suppress_control:
            # Ensure taxonomy classes are marked rejected for skip maps.
            rejected.update(CONTROL_RELATED_CLASSES)

    parser_known = bool(parser) and not local_parser_known
    # Under standard/quick, skip parser re-fingerprint when parent knows it.
    suppress_parser = False
    if tier in ("quick", "standard") and parser_known:
        suppress_parser = True
    if local_parser_known:
        parser_known = False
        suppress_parser = False

    reduced = estimate_request_savings(
        tested=merged_tested,
        rejected_classes=frozenset(rejected),
        suppress_control=suppress_control,
        suppress_parser=suppress_parser,
        budget_tier=tier,
    )

    return InheritancePriors(
        tested=merged_tested,
        rejected_classes=frozenset(rejected),
        accepted_classes=frozenset(accepted - rejected),
        parser=copy.deepcopy(parser),
        parser_known=parser_known,
        capabilities=tuple(caps),
        normalization_pipeline=tuple(pipeline),
        suppress_control_probes=suppress_control,
        suppress_parser_probes=suppress_parser,
        source_levels=tuple(levels),
        endpoint_id=endpoint_id,
        host=host,
        reduced_request_estimate=reduced,
    )


def estimate_request_savings(
    *,
    tested: dict[str, dict[str, Any]],
    rejected_classes: frozenset[str],
    suppress_control: bool,
    suppress_parser: bool,
    budget_tier: str = "standard",
) -> int:
    """
    Purpose:
        Conservative estimate of HTTP requests saved when inheritance applies
        under the given budget tier (for unit assertions + operator UX).
    Side effects: None.
    """
    tier = (budget_tier or "standard").lower().strip()
    if tier in ("deep", "exhaustive"):
        # Deep still re-confirms; inheritance only soft-skips some chars.
        saved = 0
        if suppress_control:
            saved += 1  # may skip a control representative on deep skip-rejected
        return saved

    saved = 0
    # Each inherited rejected validation family ≈ 1 skipped probe under standard.
    for key, entry in tested.items():
        if not isinstance(entry, dict):
            continue
        if str(entry.get("outcome") or "").lower() != OUTCOME_REJECTED:
            continue
        if _clamp_conf(entry.get("confidence")) < CONFIDENCE_VERIFY_LIGHT:
            continue
        saved += 1
    # Class skips (control/null/unicode etc.) — count unique classes.
    saved += len(rejected_classes)
    if suppress_parser:
        saved += 3  # typical standard parser_probes wave
    if suppress_control and "control" not in rejected_classes:
        saved += 1
    return saved


# Align with planner CONFIDENCE_VERIFY without importing planner (cycle-safe).
CONFIDENCE_VERIFY_LIGHT = 60


def merge_local_over_inherited(
    local_tested: dict[str, Any] | None,
    inherited_tested: dict[str, Any] | None,
) -> dict[str, Any]:
    """
    Purpose:
        View helper: combine maps for display with local winning.
        Does **not** mutate either input; does not write local keys into
        inherited storage.

    Output:
        Merged dict where each entry has ``provenance``: local | inherited_*.
    Side effects: None.
    """
    out: dict[str, Any] = {}
    for key, entry in (inherited_tested or {}).items():
        if not isinstance(entry, dict):
            continue
        row = copy.deepcopy(entry)
        row.setdefault("provenance", entry.get("source") or SOURCE_MERGED)
        out[str(key)] = row
    for key, entry in (local_tested or {}).items():
        if not isinstance(entry, dict):
            continue
        row = copy.deepcopy(entry)
        row["provenance"] = "local_observed"
        out[str(key)] = row  # local wins
    return out


def filter_probes_by_inheritance(
    probes: list[tuple[str, str | None]],
    priors: InheritancePriors | None,
    *,
    budget_tier: str = "standard",
    allow_deep_override: bool = True,
) -> list[tuple[str, str | None]]:
    """
    Purpose:
        Drop probe (payload_type, value) pairs already rejected by inherited
        tested families.  Deep/exhaustive re-include control-related probes
        unless allow_deep_override is False.

    Input:
        probes     — candidate list from type/semantic/char expansion.
        priors     — InheritancePriors or None.
        budget_tier — current planner tier.
        allow_deep_override — when True, deep/exhaustive keep control probes.

    Output:
        Filtered probe list (may be empty).
    Side effects: None.
    """
    if not priors or not priors.is_active():
        return list(probes)
    tier = (budget_tier or "standard").lower().strip()
    deep = tier in ("deep", "exhaustive")

    out: list[tuple[str, str | None]] = []
    for ptype, value in probes:
        family = _tested_family_for_payload_type(str(ptype))
        # Char probes use payload_type "character" — skip via class map separately.
        if str(ptype) == "character":
            out.append((ptype, value))
            continue
        if family and family in priors.tested:
            entry = priors.tested[family]
            if (
                str(entry.get("outcome") or "").lower() == OUTCOME_REJECTED
                and _clamp_conf(entry.get("confidence")) >= CONFIDENCE_VERIFY_LIGHT
            ):
                # Host-level control rejection: suppress under std; deep re-probes.
                if family in CONTROL_RELATED_TESTED_KEYS or family in CONTROL_RELATED_CLASSES:
                    if deep and allow_deep_override:
                        out.append((ptype, value))
                    continue
                # Other inherited rejects: skip under quick/standard only.
                if not deep:
                    continue
        out.append((ptype, value))
    return out


def should_skip_parser_probes(
    priors: InheritancePriors | None,
    *,
    budget_tier: str = "standard",
    local_parser_known: bool = False,
) -> bool:
    """
    Purpose:
        True when planner/engine should not schedule parser_probes because
        endpoint/app already fingerprinted the parser (standard/quick only).
    Side effects: None.
    """
    if local_parser_known:
        return False
    if not priors or not priors.suppress_parser_probes:
        return False
    tier = (budget_tier or "standard").lower().strip()
    return tier in ("quick", "standard")


def format_endpoint_intel_lines(profile: dict[str, Any] | None) -> list[str]:
    """
    Purpose:
        Human-readable summary lines for endpoint intelligence (CLI).
    Side effects: None.
    """
    if not profile or not isinstance(profile, dict):
        return ["(no endpoint profile)"]
    lines: list[str] = []
    lines.append(
        f"level=endpoint  id={profile.get('endpoint_id', '?')}  "
        f"host={profile.get('host', '?')}  "
        f"method={profile.get('method') or '?'}  "
        f"path={profile.get('path') or '?'}"
    )
    lines.append(
        f"schema_v{profile.get('schema_version', '?')}  "
        f"profile_v{profile.get('profile_version', '?')}  "
        f"requests_used={profile.get('requests_used', 0)}"
    )
    tested = profile.get("tested") or {}
    if tested:
        rej = [
            k for k, v in tested.items()
            if isinstance(v, dict) and str(v.get("outcome")).lower() == OUTCOME_REJECTED
        ]
        if rej:
            lines.append(f"Rejected tested: {', '.join(sorted(rej)[:20])}")
    obs = profile.get("observed") or {}
    acc = obs.get("acceptance") or {}
    if acc.get("rejected_classes"):
        lines.append(
            f"Rejected classes: {', '.join(acc['rejected_classes'][:20])}"
        )
    if acc.get("accepted_classes"):
        lines.append(
            f"Accepted classes: {', '.join(acc['accepted_classes'][:20])}"
        )
    parser = profile.get("parser") or {}
    if parser:
        lines.append(f"Parser keys: {', '.join(sorted(parser.keys())[:15])}")
    caps = profile.get("capabilities") or []
    if caps:
        lines.append(f"Capabilities: {', '.join(caps[:20])}")
    # Module 11: endpoint-level capabilities inform attack prioritization;
    # per-parameter candidates live on param profiles (see candidates.py).
    if caps:
        lines.append(
            "Note: attack candidates are scored per parameter; "
            "endpoint capabilities are shared priors (not confirmed vulns)."
        )
    agg = (profile.get("inferred") or {}).get("aggregation") or {}
    if agg:
        lines.append(
            f"Aggregation: param_count={agg.get('param_count', '?')}  "
            f"source={agg.get('source', '?')}"
        )
    return lines


def format_app_intel_lines(profile: dict[str, Any] | None) -> list[str]:
    """
    Purpose:
        Human-readable summary lines for application/host intelligence (CLI).
    Side effects: None.
    """
    if not profile or not isinstance(profile, dict):
        return ["(no application profile)"]
    lines: list[str] = []
    lines.append(
        f"level=application  host={profile.get('host', '?')}"
    )
    lines.append(
        f"schema_v{profile.get('schema_version', '?')}  "
        f"profile_v{profile.get('profile_version', '?')}  "
        f"requests_used={profile.get('requests_used', 0)}"
    )
    tested = profile.get("tested") or {}
    if tested:
        rej = [
            k for k, v in tested.items()
            if isinstance(v, dict) and str(v.get("outcome")).lower() == OUTCOME_REJECTED
        ]
        if rej:
            lines.append(f"Host rejected tested: {', '.join(sorted(rej)[:20])}")
    obs = profile.get("observed") or {}
    acc = obs.get("acceptance") or {}
    if acc.get("rejected_classes"):
        lines.append(
            f"Host rejected classes: {', '.join(acc['rejected_classes'][:20])}"
        )
    parser = profile.get("parser") or {}
    if parser:
        lines.append(f"Parser keys: {', '.join(sorted(parser.keys())[:15])}")
    caps = profile.get("capabilities") or []
    if caps:
        lines.append(f"Capabilities: {', '.join(caps[:20])}")
    agg = (profile.get("inferred") or {}).get("aggregation") or {}
    if agg:
        lines.append(
            f"Aggregation: endpoint_count={agg.get('endpoint_count', '?')}  "
            f"source={agg.get('source', '?')}"
        )
    return lines


# ---------------------------------------------------------------------------
# Internal aggregators
# ---------------------------------------------------------------------------

def _param_profile_usable(p: dict[str, Any] | None) -> bool:
    if not p or not isinstance(p, dict):
        return False
    # Skip pure surface-skip stubs with no probe evidence.
    if p.get("status") == "skipped" and not p.get("tested") and not (
        (p.get("observed") or {}).get("acceptance") or {}
    ).get("classes"):
        return False
    tested = p.get("tested") or {}
    obs = p.get("observed") or {}
    if tested:
        return True
    if isinstance(obs.get("parser"), dict) and obs.get("parser"):
        return True
    if p.get("parser"):
        return True
    classes = ((obs.get("acceptance") or {}).get("classes") or {})
    if classes:
        return True
    # Synthesized with at least some requests.
    if int(p.get("requests_used") or 0) > 0 and (
        obs.get("reflection") or obs.get("length") or obs.get("types")
    ):
        return True
    return False


def _first_host(profiles: list[dict[str, Any]]) -> str:
    for p in profiles:
        h = p.get("host")
        if h:
            return str(h)
    return ""


def _aggregate_tested(params: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Majority / single-source consensus for tested families.
    Outcome must agree; confidence = min of supporters (not yet decayed).
    """
    # key → list of (outcome, confidence)
    buckets: dict[str, list[tuple[str, int]]] = {}
    for p in params:
        tested = p.get("tested") or {}
        if not isinstance(tested, dict):
            continue
        for key, entry in tested.items():
            if not isinstance(entry, dict):
                continue
            outcome = str(entry.get("outcome") or "").lower()
            conf = _clamp_conf(entry.get("confidence"))
            if not outcome or conf < MIN_AGGREGATE_CONFIDENCE:
                continue
            buckets.setdefault(str(key), []).append((outcome, conf))

    out: dict[str, Any] = {}
    for key, votes in buckets.items():
        if len(votes) < MIN_PARAM_SUPPORT:
            continue
        # Require unanimous outcome among voters.
        outcomes = {o for o, _ in votes}
        if len(outcomes) != 1:
            continue
        outcome = next(iter(outcomes))
        conf = min(c for _, c in votes)
        out[key] = {
            "outcome": outcome,
            "confidence": conf,
            "support": len(votes),
            "source": "aggregated",
        }
    return out


def _aggregate_parser(params: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Intersection-style parser fingerprint: keep keys where majority share
    the same state/behavior string.
    """
    # key → list of fingerprint entry dicts
    buckets: dict[str, list[dict[str, Any]]] = {}
    for p in params:
        parser = p.get("parser") or (p.get("observed") or {}).get("parser") or {}
        if not isinstance(parser, dict):
            continue
        for key, entry in parser.items():
            if isinstance(entry, dict) and (entry.get("state") or entry.get("behavior")):
                buckets.setdefault(str(key), []).append(entry)

    out: dict[str, Any] = {}
    n = max(1, len(params))
    for key, entries in buckets.items():
        if len(entries) < MIN_PARAM_SUPPORT:
            continue
        # Prefer keys seen on at least half of params when n > 1.
        if n > 1 and len(entries) < max(1, (n + 1) // 2):
            continue
        # Pick first as representative; attach support count.
        rep = copy.deepcopy(entries[0])
        rep["support"] = len(entries)
        rep["source"] = "aggregated"
        out[key] = rep
    return out


def _aggregate_normalization_pipeline(params: list[dict[str, Any]]) -> list[str]:
    """
    Longest common ordered pipeline prefix across params that have one.
    """
    pipelines: list[list[str]] = []
    for p in params:
        pipe = p.get("normalization_pipeline")
        if isinstance(pipe, list) and pipe:
            pipelines.append([str(s) for s in pipe])
    if not pipelines:
        return []
    if len(pipelines) == 1:
        return list(pipelines[0])
    # Longest common prefix.
    prefix: list[str] = []
    for parts in zip(*pipelines):
        if len(set(parts)) == 1:
            prefix.append(parts[0])
        else:
            break
    return prefix


def _aggregate_class_outcomes(
    params: list[dict[str, Any]],
) -> tuple[set[str], set[str]]:
    """
    Classes rejected/accepted across params (consensus).
    """
    rej_votes: dict[str, int] = {}
    acc_votes: dict[str, int] = {}
    for p in params:
        classes = (
            ((p.get("observed") or {}).get("acceptance") or {}).get("classes") or {}
        )
        if not isinstance(classes, dict):
            continue
        for name, entry in classes.items():
            if not isinstance(entry, dict):
                continue
            outcome = str(entry.get("outcome") or "").lower()
            conf = _clamp_conf(entry.get("confidence"))
            if conf < MIN_AGGREGATE_CONFIDENCE and conf != 0:
                # Multiprobe may omit confidence; still count if outcome set.
                if not outcome:
                    continue
            if outcome == OUTCOME_REJECTED:
                rej_votes[str(name)] = rej_votes.get(str(name), 0) + 1
            elif outcome in (OUTCOME_ACCEPTED, "encoded", "normalized", "modified"):
                acc_votes[str(name)] = acc_votes.get(str(name), 0) + 1

    rejected = {k for k, v in rej_votes.items() if v >= MIN_PARAM_SUPPORT}
    accepted = {
        k for k, v in acc_votes.items()
        if v >= MIN_PARAM_SUPPORT and k not in rejected
    }
    return rejected, accepted


def _aggregate_capabilities(params: list[dict[str, Any]]) -> list[str]:
    """
    Capabilities present on a majority of usable params (stable order).
    """
    counts: dict[str, int] = {}
    for p in params:
        for cap in p.get("capabilities") or []:
            if cap:
                counts[str(cap)] = counts.get(str(cap), 0) + 1
    n = len(params)
    threshold = 1 if n == 1 else max(1, (n + 1) // 2)
    return sorted(k for k, v in counts.items() if v >= threshold)


def _aggregate_timing(params: list[dict[str, Any]]) -> dict[str, Any]:
    samples: list[float] = []
    for p in params:
        timing = (p.get("observed") or {}).get("timing") or {}
        for s in timing.get("samples_ms") or []:
            try:
                samples.append(float(s))
            except (TypeError, ValueError):
                continue
    if not samples:
        return {"samples_ms": [], "baseline_ms": None}
    # Cap stored samples; report median as baseline.
    capped = samples[:200]
    try:
        baseline = float(statistics.median(capped))
    except statistics.StatisticsError:
        baseline = capped[0]
    return {
        "samples_ms": capped[:50],
        "baseline_ms": baseline,
        "sample_count": len(capped),
    }


def _absorb_parent(
    parent: dict[str, Any],
    *,
    source: str,
    merged_tested: dict[str, dict[str, Any]],
    rejected: set[str],
    accepted: set[str],
    parser_out: dict[str, Any],
    pipeline_out: list[str],
    caps_out: list[str],
    local_tested: set[str],
    local_classes: set[str],
) -> None:
    defaults = parent.get("param_defaults") if isinstance(parent.get("param_defaults"), dict) else {}
    tested = defaults.get("tested") or parent.get("tested") or {}
    if isinstance(tested, dict):
        for key, entry in tested.items():
            if not isinstance(entry, dict):
                continue
            if str(key) in local_tested:
                continue  # local observed wins — do not inherit over it
            outcome = str(entry.get("outcome") or "").lower()
            conf = decay_inherited_confidence(entry.get("confidence") or 0)
            if not outcome:
                continue
            if conf < CONFIDENCE_VERIFY_LIGHT:
                continue
            # Endpoint overlays app: overwrite same key.
            merged_tested[str(key)] = {
                "outcome": outcome,
                "confidence": conf,
                "source": source,
                "inherited": True,
            }

    obs = parent.get("observed") if isinstance(parent.get("observed"), dict) else {}
    acc = obs.get("acceptance") if isinstance(obs.get("acceptance"), dict) else {}
    for c in acc.get("rejected_classes") or defaults.get("rejected_classes") or []:
        if str(c) not in local_classes:
            rejected.add(str(c))
    for c in acc.get("accepted_classes") or defaults.get("accepted_classes") or []:
        if str(c) not in local_classes:
            accepted.add(str(c))

    parser = defaults.get("parser") or parent.get("parser") or {}
    if isinstance(parser, dict):
        for k, v in parser.items():
            # Later parent (endpoint) overwrites app.
            parser_out[str(k)] = copy.deepcopy(v) if isinstance(v, dict) else v

    pipe = defaults.get("normalization_pipeline") or parent.get("normalization_pipeline") or []
    if isinstance(pipe, list) and pipe:
        pipeline_out.clear()
        pipeline_out.extend(str(s) for s in pipe)

    for cap in parent.get("capabilities") or []:
        if cap and cap not in caps_out:
            caps_out.append(str(cap))


def _local_tested_keys(profile: dict[str, Any] | None) -> set[str]:
    if not profile or not isinstance(profile, dict):
        return set()
    tested = profile.get("tested") or {}
    if not isinstance(tested, dict):
        return set()
    return {str(k) for k in tested.keys()}


def _local_class_keys(profile: dict[str, Any] | None) -> set[str]:
    if not profile or not isinstance(profile, dict):
        return set()
    classes = (
        ((profile.get("observed") or {}).get("acceptance") or {}).get("classes") or {}
    )
    if not isinstance(classes, dict):
        return set()
    return {str(k) for k in classes.keys()}


def _local_parser_known(profile: dict[str, Any] | None) -> bool:
    if not profile or not isinstance(profile, dict):
        return False
    parser = profile.get("parser") or (profile.get("observed") or {}).get("parser") or {}
    pipeline = profile.get("normalization_pipeline") or []
    if isinstance(pipeline, list) and pipeline:
        return True
    if isinstance(parser, dict) and any(
        isinstance(v, dict) and (v.get("state") or v.get("behavior"))
        for v in parser.values()
    ):
        return True
    return False


def _has_control_rejection(
    tested: dict[str, dict[str, Any]],
    rejected_classes: set[str],
) -> bool:
    if rejected_classes & CONTROL_RELATED_CLASSES:
        return True
    for key in CONTROL_RELATED_TESTED_KEYS:
        entry = tested.get(key)
        if not isinstance(entry, dict):
            continue
        if (
            str(entry.get("outcome") or "").lower() == OUTCOME_REJECTED
            and _clamp_conf(entry.get("confidence")) >= CONFIDENCE_VERIFY_LIGHT
        ):
            return True
    return False


def _tested_family_for_payload_type(payload_type: str) -> str:
    p = (payload_type or "").lower().strip()
    if p in PAYLOAD_TYPE_TO_TESTED_FAMILY:
        return PAYLOAD_TYPE_TO_TESTED_FAMILY[p]
    # type:integer style keys from synthesizer
    if p.startswith("type:"):
        return p
    if p.startswith("parser:"):
        return p
    return p


# ---------------------------------------------------------------------------
# Orchestration (DB I/O) — called after parameter synthesize
# ---------------------------------------------------------------------------

def refresh_endpoint_profile(
    db_path: Any,
    endpoint_id: str,
    *,
    bump_version: bool = True,
) -> dict[str, Any] | None:
    """
    Purpose:
        Re-aggregate parameter profiles on ``endpoint_id`` and upsert
        ``iv_endpoint_profiles``.
    Input:
        db_path     — project SQLite path.
        endpoint_id — endpoints.id.
        bump_version — increment profile_version on rewrite.
    Output:
        Stored endpoint profile, or None when endpoint_id empty / unknown.
    Side effects: DB read/write.
    """
    from pathlib import Path

    from talos.input_validation import db as iv_db

    if not endpoint_id:
        return None
    path = Path(db_path)
    meta = iv_db.get_endpoint_meta(path, endpoint_id)
    if meta is None:
        return None
    params = iv_db.list_param_profiles_for_endpoint(path, endpoint_id)
    aggregated = aggregate_endpoint_from_params(
        params,
        endpoint_id=endpoint_id,
        host=meta.get("host") or "",
        method=meta.get("method") or "",
        path=meta.get("path") or "",
    )
    return iv_db.upsert_endpoint_profile(
        path,
        endpoint_id=endpoint_id,
        host=meta.get("host") or "",
        method=meta.get("method") or "",
        path=meta.get("path") or "",
        profile=aggregated,
        bump_version=bump_version,
    )


def refresh_app_profile(
    db_path: Any,
    host: str,
    *,
    bump_version: bool = True,
) -> dict[str, Any] | None:
    """
    Purpose:
        Re-aggregate endpoint profiles for ``host`` and upsert
        ``iv_app_profiles``.
    Output: Stored app profile, or None when host empty.
    Side effects: DB read/write.
    """
    from pathlib import Path

    from talos.input_validation import db as iv_db

    if not host:
        return None
    path = Path(db_path)
    endpoints = iv_db.list_endpoint_profiles(path, host=host)
    aggregated = aggregate_app_from_endpoints(endpoints, host=host)
    return iv_db.upsert_app_profile(
        path,
        host=host,
        profile=aggregated,
        bump_version=bump_version,
    )


def refresh_multi_level(
    db_path: Any,
    *,
    endpoint_id: str = "",
    host: str = "",
    bump_version: bool = True,
) -> dict[str, Any]:
    """
    Purpose:
        Refresh endpoint profile (if endpoint_id) then app profile (if host).
        Call after parameter profile synthesize so parent levels stay current.
    Output:
        Summary dict: endpoint (profile|None), app (profile|None).
    Side effects: DB read/write.
    """
    ep = None
    app = None
    resolved_host = host
    if endpoint_id:
        ep = refresh_endpoint_profile(
            db_path, endpoint_id, bump_version=bump_version,
        )
        if ep and not resolved_host:
            resolved_host = str(ep.get("host") or "")
    if resolved_host:
        app = refresh_app_profile(
            db_path, resolved_host, bump_version=bump_version,
        )
    return {"endpoint": ep, "app": app, "host": resolved_host or host}


def load_inheritance_priors(
    db_path: Any,
    *,
    host: str,
    endpoint_id: str = "",
    local_profile: dict[str, Any] | None = None,
    budget_tier: str = "standard",
) -> InheritancePriors:
    """
    Purpose:
        Load endpoint + app profiles from DB and build inheritance priors
        for planner / probe expansion.
    Side effects: Read-only DB.
    """
    from pathlib import Path

    from talos.input_validation import db as iv_db

    path = Path(db_path)
    ep = iv_db.get_endpoint_profile(path, endpoint_id) if endpoint_id else None
    app = iv_db.get_app_profile(path, host) if host else None
    return build_inheritance_priors(
        endpoint_profile=ep,
        app_profile=app,
        local_profile=local_profile,
        budget_tier=budget_tier,
    )
