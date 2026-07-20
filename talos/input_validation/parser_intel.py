"""
Module: talos.input_validation.parser_intel

Purpose:
    Module 8 — Normalization pipeline detection and parser fingerprinting.

    Characterizes **how** the server normalizes reflected input (trim, case,
    URL-decode, optional deep unicode/double-encoding) and **how** structured
    parsers treat duplicates, arrays, and null/empty/omitted fields.

    Pure computation only — no HTTP, no SQLite.  The engine expands selected
    probes; the synthesizer folds probe outcomes into ``observed.parser``,
    ``normalization_pipeline``, capabilities, and ``tested{}``.

Design goals (Module 8 brief):
    - Small normalization probe set; deep tier adds unicode/double-encode.
    - Parser probes are location/content-type aware (query vs JSON body).
    - Quick tier skips most parser probes; standard runs a cost-controlled set.
    - Negative evidence when parser rejects duplicates / structural variants.
    - Capabilities: ``duplicate_parameter``, ``json_parser``, etc.
    - Fingerprint only — no HPP/mass-assignment exploitation.

Dependencies: secrets (canary entropy), dataclasses, typing, urllib.parse
Data flow:
    planner parser_probes → select_parser_probes() / select_normalization_probes()
    engine expands → scheduler → prepare_iv_probe(injection_mode)
    synthesize → synthesize_parser_state / synthesize_normalization_pipeline
Side effects: None.
"""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from talos.input_validation.outcomes import (
    OUTCOME_ACCEPTED,
    OUTCOME_MODIFIED,
    OUTCOME_NORMALIZED,
    OUTCOME_REJECTED,
    OUTCOME_UNKNOWN,
)
from talos.input_validation.profile import (
    CAPABILITY_DUPLICATE_PARAMETER,
    CAPABILITY_JSON_PARSER,
    UNCERTAINTY_HIGH,
    UNCERTAINTY_LOW,
    UNCERTAINTY_NONE,
    empty_characteristic,
    set_tested,
)


# ---------------------------------------------------------------------------
# Constants — sentinels, stages, modes
# ---------------------------------------------------------------------------

# Fixed dual-value sentinels for first_wins / last_wins detection (stable resume).
SENTINEL_FIRST = "TlFrstA7k2m9"
SENTINEL_LAST = "TlLastB3x8q1"

# Separator when packing two values into a single payload string for jobs.
DUP_PAYLOAD_SEP = "\x1f"

# Soft accept outcomes for synthesis.
_SOFT_ACCEPT: frozenset[str] = frozenset({
    OUTCOME_ACCEPTED,
    OUTCOME_MODIFIED,
    OUTCOME_NORMALIZED,
    "encoded",
    "normalized",
})

# Normalization stage vocabulary (ordered pipeline candidates).
STAGE_URL_DECODE = "url_decode"
STAGE_UNICODE_NORMALIZE = "unicode_normalize"
STAGE_TRIM = "trim"
STAGE_CASE_FOLD = "case_fold"
STAGE_VALIDATE = "validate"
STAGE_STORE = "store"
STAGE_REFLECT = "reflect"

KNOWN_NORM_STAGES: frozenset[str] = frozenset({
    STAGE_URL_DECODE,
    STAGE_UNICODE_NORMALIZE,
    STAGE_TRIM,
    STAGE_CASE_FOLD,
    STAGE_VALIDATE,
    STAGE_STORE,
    STAGE_REFLECT,
})

# Canonical stage order for inferred pipeline (pre-reflect processing).
STAGE_ORDER: tuple[str, ...] = (
    STAGE_URL_DECODE,
    STAGE_UNICODE_NORMALIZE,
    STAGE_TRIM,
    STAGE_CASE_FOLD,
    STAGE_VALIDATE,
    STAGE_STORE,
    STAGE_REFLECT,
)

# Duplicate-key / multi-value behaviours.
DUP_FIRST_WINS = "first_wins"
DUP_LAST_WINS = "last_wins"
DUP_JOIN = "join"
DUP_REJECT = "reject"
DUP_UNKNOWN = "unknown"

DUP_BEHAVIORS: frozenset[str] = frozenset({
    DUP_FIRST_WINS,
    DUP_LAST_WINS,
    DUP_JOIN,
    DUP_REJECT,
    DUP_UNKNOWN,
})

# Injection modes consumed by phases.prepare_iv_probe.
MODE_VALUE = "value"
MODE_DUP_QUERY = "dup_query"
MODE_DUP_FORM = "dup_form"
MODE_JSON_NULL = "json_null"
MODE_JSON_EMPTY = "json_empty"
MODE_JSON_OMIT = "json_omit"
MODE_JSON_DUP_KEY = "json_dup_key"
MODE_ARRAY_BRACKET = "array_bracket"
MODE_ARRAY_REPEAT = "array_repeat"
MODE_ARRAY_DOT = "array_dot"

# Payload-type → injection mode.
PAYLOAD_TYPE_MODE: dict[str, str] = {
    "norm:trim": MODE_VALUE,
    "norm:case": MODE_VALUE,
    "norm:url_decode": MODE_VALUE,
    "norm:double_encode": MODE_VALUE,
    "norm:unicode": MODE_VALUE,
    "parser:dup_query": MODE_DUP_QUERY,
    "parser:dup_form": MODE_DUP_FORM,
    "parser:json_null": MODE_JSON_NULL,
    "parser:json_empty": MODE_JSON_EMPTY,
    "parser:json_omit": MODE_JSON_OMIT,
    "parser:json_dup_key": MODE_JSON_DUP_KEY,
    "parser:array_bracket": MODE_ARRAY_BRACKET,
    "parser:array_repeat": MODE_ARRAY_REPEAT,
    "parser:array_dot": MODE_ARRAY_DOT,
}

# Probe caps by budget tier (normalization + parser combined).
_PARSER_PROBE_CAP: dict[str, int] = {
    "quick": 1,
    "standard": 5,
    "deep": 10,
    "exhaustive": 14,
}

# tested{} family keys for parser / normalization negatives.
TESTED_PARSER_KEYS: dict[str, str] = {
    "parser:dup_query": "parser:duplicate",
    "parser:dup_form": "parser:duplicate",
    "parser:json_dup_key": "parser:json_duplicate",
    "parser:json_null": "parser:json_null",
    "parser:json_empty": "parser:json_empty",
    "parser:json_omit": "parser:json_omit",
    "parser:array_bracket": "parser:array_bracket",
    "parser:array_repeat": "parser:array_repeat",
    "parser:array_dot": "parser:array_dot",
    "norm:trim": "norm:trim",
    "norm:case": "norm:case",
    "norm:url_decode": "norm:url_decode",
    "norm:double_encode": "norm:double_encode",
    "norm:unicode": "norm:unicode",
}


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ParserProbeSpec:
    """
    One normalization or parser fingerprint probe.

    Fields:
        payload_type    — stable label (norm:trim, parser:dup_query, …).
        payload         — string stored on the job (value or packed dual).
        injection_mode  — how prepare_iv_probe mutates the request.
        hypothesis      — planner hypothesis fragment.
        family          — norm | parser (for filtering / synthesis).
    """

    payload_type: str
    payload: str
    injection_mode: str
    hypothesis: str
    family: str = "parser"


@dataclass(frozen=True)
class ParserProbePlan:
    """
    Selected Module 8 probes for one parameter.

    Fields:
        probes   — ordered ParserProbeSpec list.
        reason   — human-readable selection summary.
        skipped  — labels intentionally omitted (tier / location).
    """

    probes: tuple[ParserProbeSpec, ...]
    reason: str = ""
    skipped: tuple[str, ...] = ()


@dataclass
class NormalizationStage:
    """One ordered pipeline stage with confidence."""

    stage: str
    confidence: int = 0
    evidence: str = ""  # short note (e.g. "reflected trimmed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "confidence": max(0, min(100, int(self.confidence))),
            "evidence": self.evidence,
        }


@dataclass
class ParserSynthesisResult:
    """
    Aggregated parser + normalization intelligence.

    Fields:
        parser              — observed.parser map (duplicate_query, json_*, …).
        normalization_pipeline — ordered stage dicts.
        parser_family       — optional light inferred family string.
        capabilities        — flags to add.
        tested_updates      — key → {outcome, confidence} for tested{}.
        confidence          — overall parser fingerprint confidence.
        uncertainty         — none | low | high.
    """

    parser: dict[str, Any] = field(default_factory=dict)
    normalization_pipeline: list[dict[str, Any]] = field(default_factory=list)
    parser_family: str = ""
    capabilities: list[str] = field(default_factory=list)
    tested_updates: dict[str, dict[str, Any]] = field(default_factory=dict)
    confidence: int = 0
    uncertainty: str = UNCERTAINTY_HIGH


# ---------------------------------------------------------------------------
# Payload helpers
# ---------------------------------------------------------------------------

def pack_dup_payload(first: str = SENTINEL_FIRST, last: str = SENTINEL_LAST) -> str:
    """Pack two sentinels into a single job payload string."""
    return f"{first}{DUP_PAYLOAD_SEP}{last}"


def unpack_dup_payload(payload: str) -> tuple[str, str]:
    """
    Purpose:
        Split a dual-value payload.  Falls back to fixed sentinels when
        the separator is missing (legacy / malformed).
    Side effects: None.
    """
    if DUP_PAYLOAD_SEP in (payload or ""):
        a, _, b = payload.partition(DUP_PAYLOAD_SEP)
        return a, b
    return SENTINEL_FIRST, SENTINEL_LAST


def injection_mode_for_payload_type(payload_type: str) -> str:
    """Map payload_type → injection mode (default value inject)."""
    return PAYLOAD_TYPE_MODE.get(payload_type or "", MODE_VALUE)


def build_norm_canary(prefix: str = "TlNorm") -> str:
    """
    Purpose:
        High-entropy canary for normalization probes (avoids collision).
    Side effects: Reads OS entropy.
    """
    return f"{prefix}{secrets.token_hex(6)}"


# ---------------------------------------------------------------------------
# Probe selection
# ---------------------------------------------------------------------------

def select_normalization_probes(
    *,
    strategy: str = "standard",
    reflection_state: str = "unknown",
    max_probes: int | None = None,
) -> list[ParserProbeSpec]:
    """
    Purpose:
        Build normalization-stage probes.  When reflection is clearly
        not_reflected, only a minimal trim probe is kept (stage detection
        needs reflection); deep still may attempt structural-only signals.

    Input:
        strategy         — quick|standard|deep|exhaustive.
        reflection_state — reflected|not_reflected|unknown|conflicting.
        max_probes       — optional hard cap.

    Output:
        Ordered ParserProbeSpec list (family=norm).

    Side effects: May read OS entropy for canaries.
    """
    tier = (strategy or "standard").lower().strip()
    caps = {
        "quick": 0,  # quick skips normalization probes (budget)
        "standard": 3,
        "deep": 5,
        "exhaustive": 5,
    }
    cap = max_probes if max_probes is not None else caps.get(tier, 3)
    cap = max(0, int(cap))
    if cap == 0:
        return []

    # Without reflection, pipeline stages cannot be observed → skip most.
    refl = (reflection_state or "unknown").lower()
    if refl == "not_reflected" and tier in ("quick", "standard"):
        return []

    canary = build_norm_canary()
    mixed = _mixed_case(canary)
    specs: list[ParserProbeSpec] = []

    # trim: leading + trailing spaces around canary
    specs.append(ParserProbeSpec(
        payload_type="norm:trim",
        payload=f"  {canary}  ",
        injection_mode=MODE_VALUE,
        hypothesis="norm.trim_space",
        family="norm",
    ))
    # case: mixed-case body
    specs.append(ParserProbeSpec(
        payload_type="norm:case",
        payload=mixed,
        injection_mode=MODE_VALUE,
        hypothesis="norm.case_fold",
        family="norm",
    ))
    # url_decode: %41 (A) prefix + canary so reflect-of-decoded is
    # distinguishable from the raw percent-encoded string.
    specs.append(ParserProbeSpec(
        payload_type="norm:url_decode",
        payload=f"%41{canary}",  # %41 → A when decoded once
        injection_mode=MODE_VALUE,
        hypothesis="norm.url_decode",
        family="norm",
    ))

    if tier in ("deep", "exhaustive"):
        # double-encoding: %2541 → %41 if single decode, A if double
        specs.append(ParserProbeSpec(
            payload_type="norm:double_encode",
            payload=f"%2541{canary}",
            injection_mode=MODE_VALUE,
            hypothesis="norm.double_encode",
            family="norm",
        ))
        # unicode compatibility (fullwidth Latin 'A' + canary)
        specs.append(ParserProbeSpec(
            payload_type="norm:unicode",
            payload=f"\uff21{canary}",  # fullwidth A
            injection_mode=MODE_VALUE,
            hypothesis="norm.unicode_compat",
            family="norm",
        ))

    return specs[:cap]


def select_parser_fingerprint_probes(
    *,
    location: str = "query",
    content_type: str = "",
    strategy: str = "standard",
    max_probes: int | None = None,
) -> list[ParserProbeSpec]:
    """
    Purpose:
        Build location-aware parser fingerprint probes.

        - query: duplicate key, array styles
        - body + JSON: null / empty / omit / duplicate keys
        - body + form: duplicate form field
        - header/cookie/path: minimal or skip (M9 expands surfaces)

    Side effects: None (fixed sentinels).
    """
    tier = (strategy or "standard").lower().strip()
    caps = {
        "quick": 0,
        "standard": 3,
        "deep": 6,
        "exhaustive": 8,
    }
    cap = max_probes if max_probes is not None else caps.get(tier, 3)
    cap = max(0, int(cap))
    if cap == 0:
        return []

    loc = (location or "query").lower().strip()
    ct = (content_type or "").lower()
    packed = pack_dup_payload()
    specs: list[ParserProbeSpec] = []

    if loc == "query":
        specs.append(ParserProbeSpec(
            payload_type="parser:dup_query",
            payload=packed,
            injection_mode=MODE_DUP_QUERY,
            hypothesis="parser.duplicate_query",
            family="parser",
        ))
        if tier in ("deep", "exhaustive") or cap >= 3:
            specs.append(ParserProbeSpec(
                payload_type="parser:array_bracket",
                payload=SENTINEL_FIRST,
                injection_mode=MODE_ARRAY_BRACKET,
                hypothesis="parser.array_bracket",
                family="parser",
            ))
            specs.append(ParserProbeSpec(
                payload_type="parser:array_repeat",
                payload=packed,
                injection_mode=MODE_ARRAY_REPEAT,
                hypothesis="parser.array_repeat",
                family="parser",
            ))
        if tier in ("deep", "exhaustive"):
            specs.append(ParserProbeSpec(
                payload_type="parser:array_dot",
                payload=SENTINEL_FIRST,
                injection_mode=MODE_ARRAY_DOT,
                hypothesis="parser.array_dot",
                family="parser",
            ))

    elif loc == "body":
        if "json" in ct or not ct:
            # Prefer JSON probes when content-type is JSON or unknown body.
            # Engine may pass content_type from baseline flow.
            form_first = "x-www-form-urlencoded" in ct or "form" in ct
            if form_first and "json" not in ct:
                specs.append(ParserProbeSpec(
                    payload_type="parser:dup_form",
                    payload=packed,
                    injection_mode=MODE_DUP_FORM,
                    hypothesis="parser.duplicate_form",
                    family="parser",
                ))
            else:
                # JSON null / empty / omit are the Module 8 acceptance minimum.
                specs.append(ParserProbeSpec(
                    payload_type="parser:json_null",
                    payload="null",
                    injection_mode=MODE_JSON_NULL,
                    hypothesis="parser.json_null",
                    family="parser",
                ))
                specs.append(ParserProbeSpec(
                    payload_type="parser:json_empty",
                    payload="",
                    injection_mode=MODE_JSON_EMPTY,
                    hypothesis="parser.json_empty",
                    family="parser",
                ))
                if tier in ("standard", "deep", "exhaustive"):
                    specs.append(ParserProbeSpec(
                        payload_type="parser:json_omit",
                        payload="",
                        injection_mode=MODE_JSON_OMIT,
                        hypothesis="parser.json_omit",
                        family="parser",
                    ))
                if tier in ("deep", "exhaustive"):
                    specs.append(ParserProbeSpec(
                        payload_type="parser:json_dup_key",
                        payload=packed,
                        injection_mode=MODE_JSON_DUP_KEY,
                        hypothesis="parser.json_duplicate_key",
                        family="parser",
                    ))
                # If body content-type was empty, also try form dup under deep.
                if not ct and tier in ("deep", "exhaustive"):
                    specs.append(ParserProbeSpec(
                        payload_type="parser:dup_form",
                        payload=packed,
                        injection_mode=MODE_DUP_FORM,
                        hypothesis="parser.duplicate_form",
                        family="parser",
                    ))
        elif "x-www-form-urlencoded" in ct or "form" in ct:
            specs.append(ParserProbeSpec(
                payload_type="parser:dup_form",
                payload=packed,
                injection_mode=MODE_DUP_FORM,
                hypothesis="parser.duplicate_form",
                family="parser",
            ))
            if tier in ("deep", "exhaustive"):
                specs.append(ParserProbeSpec(
                    payload_type="parser:array_bracket",
                    payload=SENTINEL_FIRST,
                    injection_mode=MODE_ARRAY_BRACKET,
                    hypothesis="parser.array_bracket",
                    family="parser",
                ))
        elif "multipart/form-data" in ct:
            # Module 9: multipart field value is first-class; structural dup
            # is not modelled — value-level norm/parser budget stays on inject.
            specs.append(ParserProbeSpec(
                payload_type="parser:multipart_field",
                payload=SENTINEL_FIRST,
                injection_mode=MODE_VALUE,
                hypothesis="parser.multipart_field",
                family="parser",
            ))
        elif "xml" in ct or "soap" in ct:
            specs.append(ParserProbeSpec(
                payload_type="parser:xml_leaf",
                payload=SENTINEL_FIRST,
                injection_mode=MODE_VALUE,
                hypothesis="parser.xml_leaf",
                family="parser",
            ))
        elif "graphql" in ct:
            specs.append(ParserProbeSpec(
                payload_type="parser:graphql_variable",
                payload=SENTINEL_FIRST,
                injection_mode=MODE_VALUE,
                hypothesis="parser.graphql_variable",
                family="parser",
            ))

    elif loc in ("header", "cookie", "path"):
        # Module 9: surfaces are first-class for value/norm inject; no structural
        # duplicate-key probes on these locations.
        if tier in ("deep", "exhaustive") and cap > 0:
            specs.append(ParserProbeSpec(
                payload_type=f"parser:{loc}_value",
                payload=SENTINEL_FIRST,
                injection_mode=MODE_VALUE,
                hypothesis=f"parser.{loc}_value",
                family="parser",
            ))

    return specs[:cap]


def select_parser_probes(
    *,
    location: str = "query",
    content_type: str = "",
    strategy: str = "standard",
    reflection_state: str = "unknown",
    max_probes: int | None = None,
    include_normalization: bool = True,
    include_parser: bool = True,
) -> ParserProbePlan:
    """
    Purpose:
        Combined Module 8 probe plan (normalization + parser fingerprint).

        Quick: almost empty (planner should skip ACTION_PARSER_PROBES).
        Standard: small set (~5 total) cost-controlled.
        Deep: unicode/double-encode + more array/JSON variants.
        Exhaustive: full M8 catalogue for the location.

    Output:
        ParserProbePlan.

    Side effects: May read OS entropy for norm canaries.
    """
    tier = (strategy or "standard").lower().strip()
    total_cap = max_probes if max_probes is not None else _PARSER_PROBE_CAP.get(tier, 5)
    total_cap = max(0, int(total_cap))
    skipped: list[str] = []

    if total_cap == 0 or tier == "quick":
        return ParserProbePlan(
            probes=(),
            reason=f"tier={tier}: parser/normalization skipped",
            skipped=("all",),
        )

    # Budget split: prefer parser fingerprint when both enabled; leave room for norm.
    norm_budget = 0
    parser_budget = total_cap
    if include_normalization and include_parser:
        if tier == "standard":
            norm_budget = min(2, total_cap // 2 + (1 if total_cap >= 3 else 0))
            parser_budget = total_cap - norm_budget
        else:
            norm_budget = min(3 if tier == "deep" else 5, total_cap // 2 + 1)
            parser_budget = total_cap - norm_budget
    elif include_normalization:
        norm_budget = total_cap
        parser_budget = 0
    elif include_parser:
        norm_budget = 0
        parser_budget = total_cap
    else:
        return ParserProbePlan(probes=(), reason="both families disabled", skipped=("all",))

    if (reflection_state or "").lower() == "not_reflected":
        # Stage detection needs reflection; still run parser structural probes.
        if include_normalization and norm_budget:
            skipped.append("norm:*")
        norm_budget = 0
        if include_parser:
            parser_budget = total_cap

    selected: list[ParserProbeSpec] = []
    if include_parser and parser_budget > 0:
        selected.extend(select_parser_fingerprint_probes(
            location=location,
            content_type=content_type,
            strategy=tier,
            max_probes=parser_budget,
        ))
    if include_normalization and norm_budget > 0:
        selected.extend(select_normalization_probes(
            strategy=tier,
            reflection_state=reflection_state,
            max_probes=norm_budget,
        ))

    # Hard cap final list (parser first for acceptance criteria priority).
    selected = selected[:total_cap]
    if not selected:
        skipped.append("empty_selection")

    reason = (
        f"tier={tier}; location={location}; n={len(selected)}; "
        f"ct={content_type or 'n/a'}"
    )
    return ParserProbePlan(
        probes=tuple(selected),
        reason=reason,
        skipped=tuple(skipped),
    )


def estimated_parser_probe_count(
    strategy: str = "standard",
    *,
    location: str = "query",
    content_type: str = "",
    reflection_state: str = "unknown",
) -> int:
    """Planner estimate for parser_probes HTTP count. Side effects: entropy for canaries."""
    plan = select_parser_probes(
        location=location,
        content_type=content_type,
        strategy=strategy,
        reflection_state=reflection_state,
    )
    return len(plan.probes)


# ---------------------------------------------------------------------------
# Injection helpers (used by phases.prepare_iv_probe)
# ---------------------------------------------------------------------------

def apply_parser_injection(
    *,
    injection_mode: str,
    location: str,
    name: str,
    payload: str,
    url: str,
    headers: dict,
    body: bytes | None,
    normalized_path: str = "",
    semantic_type: str = "",
) -> tuple[str, dict, bytes | None]:
    """
    Purpose:
        Apply a structural or value injection for Module 8 probes.

    Input:
        injection_mode — MODE_* constant.
        location/name  — parameter identity.
        payload        — job payload (value or packed dual).
        url/headers/body — base request parts.
        normalized_path / semantic_type — Module 9 surface context for value inject.

    Output:
        (new_url, new_headers, new_body).

    Side effects: None.
    """
    mode = (injection_mode or MODE_VALUE).lower()
    first, last = unpack_dup_payload(payload or "")

    if mode == MODE_VALUE:
        return _inject_simple_value(
            location,
            name,
            payload or "",
            url,
            headers,
            body,
            normalized_path=normalized_path,
            semantic_type=semantic_type,
        )

    if mode == MODE_DUP_QUERY:
        return _inject_dup_query(url, name, first, last), headers, body

    if mode == MODE_DUP_FORM:
        return url, headers, _inject_dup_form(body, name, first, last)

    if mode == MODE_JSON_NULL:
        return url, headers, _inject_json_typed(body, name, None)

    if mode == MODE_JSON_EMPTY:
        return url, headers, _inject_json_typed(body, name, "")

    if mode == MODE_JSON_OMIT:
        return url, headers, _inject_json_omit(body, name)

    if mode == MODE_JSON_DUP_KEY:
        return url, headers, _inject_json_dup_key(body, name, first, last)

    if mode == MODE_ARRAY_BRACKET:
        # name[] = value (query or form)
        if location == "query":
            return _inject_named_query(url, f"{name}[]", payload or first), headers, body
        if location == "body":
            return url, headers, _inject_named_form(body, f"{name}[]", payload or first)
        return url, headers, body

    if mode == MODE_ARRAY_REPEAT:
        if location == "query":
            return _inject_dup_query(url, name, first, last), headers, body
        if location == "body":
            return url, headers, _inject_dup_form(body, name, first, last)
        return url, headers, body

    if mode == MODE_ARRAY_DOT:
        if location == "query":
            return _inject_named_query(url, f"{name}.0", payload or first), headers, body
        if location == "body":
            return url, headers, _inject_named_form(body, f"{name}.0", payload or first)
        return url, headers, body

    return _inject_simple_value(
        location,
        name,
        payload or "",
        url,
        headers,
        body,
        normalized_path=normalized_path,
        semantic_type=semantic_type,
    )


def _inject_simple_value(
    location: str,
    name: str,
    value: str,
    url: str,
    headers: dict,
    body: bytes | None,
    *,
    normalized_path: str = "",
    semantic_type: str = "",
) -> tuple[str, dict, bytes | None]:
    """
    Purpose:
        Surface-aware simple replace (Module 9: path/multipart/GraphQL/XML).
        Delegates to surface.inject_value to avoid circular import with phases.
    Side effects: None.
    """
    from talos.input_validation.surface import inject_value as surface_inject

    return surface_inject(
        location,
        name,
        value,
        url,
        headers,
        body,
        normalized_path=normalized_path,
        semantic_type=semantic_type,
    )


def _inject_named_query(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    found = False
    new_pairs: list[tuple[str, str]] = []
    for k, v in pairs:
        if k == name:
            new_pairs.append((k, value))
            found = True
        else:
            new_pairs.append((k, v))
    if not found:
        new_pairs.append((name, value))
    return urlunparse(parsed._replace(query=urlencode(new_pairs)))


def _inject_dup_query(url: str, name: str, first: str, last: str) -> str:
    """Replace all name occurrences with two ordered values (a=first&a=last)."""
    parsed = urlparse(url)
    pairs = [(k, v) for k, v in parse_qsl(parsed.query, keep_blank_values=True) if k != name]
    pairs.append((name, first))
    pairs.append((name, last))
    return urlunparse(parsed._replace(query=urlencode(pairs)))


def _inject_named_form(body: bytes | None, name: str, value: str) -> bytes:
    text = (body or b"").decode("utf-8", errors="replace")
    pairs = parse_qsl(text, keep_blank_values=True)
    found = False
    new_pairs: list[tuple[str, str]] = []
    for k, v in pairs:
        if k == name:
            new_pairs.append((k, value))
            found = True
        else:
            new_pairs.append((k, v))
    if not found:
        new_pairs.append((name, value))
    return urlencode(new_pairs).encode("utf-8")


def _inject_dup_form(body: bytes | None, name: str, first: str, last: str) -> bytes:
    text = (body or b"").decode("utf-8", errors="replace")
    pairs = [(k, v) for k, v in parse_qsl(text, keep_blank_values=True) if k != name]
    pairs.append((name, first))
    pairs.append((name, last))
    return urlencode(pairs).encode("utf-8")


def _set_nested(obj: object, parts: list[str], value: Any) -> None:
    if not isinstance(obj, dict) or not parts:
        return
    head, *tail = parts
    if not tail:
        obj[head] = value  # type: ignore[index]
    else:
        child = obj.get(head) if head in obj else None  # type: ignore[index]
        if not isinstance(child, dict):
            obj[head] = {}  # type: ignore[index]
        _set_nested(obj[head], tail, value)  # type: ignore[index]


def _inject_json_typed(body: bytes | None, name: str, value: Any) -> bytes:
    """Set a JSON field to a typed value (None → null, str, etc.)."""
    if not body:
        root: dict[str, Any] = {}
    else:
        try:
            parsed = json.loads(body.decode("utf-8", errors="replace"))
        except Exception:
            return body or b"{}"
        if not isinstance(parsed, dict):
            root = {}
        else:
            root = parsed
    parts = name.split(".")
    _set_nested(root, parts, value)
    return json.dumps(root, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _inject_json_omit(body: bytes | None, name: str) -> bytes:
    """Remove a key from the JSON body (omitted field behaviour)."""
    if not body:
        return b"{}"
    try:
        parsed = json.loads(body.decode("utf-8", errors="replace"))
    except Exception:
        return body or b"{}"
    if not isinstance(parsed, dict):
        return body or b"{}"
    parts = name.split(".")
    _delete_nested(parsed, parts)
    return json.dumps(parsed, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _delete_nested(obj: object, parts: list[str]) -> None:
    if not isinstance(obj, dict) or not parts:
        return
    head, *tail = parts
    if not tail:
        obj.pop(head, None)  # type: ignore[arg-type]
        return
    child = obj.get(head)  # type: ignore[index]
    if isinstance(child, dict):
        _delete_nested(child, tail)


def _inject_json_dup_key(
    body: bytes | None,
    name: str,
    first: str,
    last: str,
) -> bytes:
    """
    Purpose:
        Emit a JSON object with a raw duplicate key (not representable via
        json.dumps of a dict).  Other keys from the original body are preserved
        best-effort for top-level keys only.
    """
    other: dict[str, Any] = {}
    if body:
        try:
            parsed = json.loads(body.decode("utf-8", errors="replace"))
            if isinstance(parsed, dict):
                other = {k: v for k, v in parsed.items() if k != name}
        except Exception:
            other = {}
    # Build manually so both keys appear.
    parts: list[str] = []
    for k, v in other.items():
        parts.append(f"{json.dumps(k)}:{json.dumps(v, ensure_ascii=False)}")
    parts.append(f"{json.dumps(name)}:{json.dumps(first)}")
    parts.append(f"{json.dumps(name)}:{json.dumps(last)}")
    return ("{" + ",".join(parts) + "}").encode("utf-8")


# ---------------------------------------------------------------------------
# Synthesis from synthetic / real probe evidence
# ---------------------------------------------------------------------------

def detect_duplicate_behavior(
    response_body: str,
    *,
    first: str = SENTINEL_FIRST,
    last: str = SENTINEL_LAST,
    outcome: str = OUTCOME_UNKNOWN,
    status_code: int | None = None,
) -> tuple[str, int]:
    """
    Purpose:
        Infer first_wins | last_wins | join | reject | unknown from body
        (and optional HTTP outcome).

    Output:
        (behavior, confidence).

    Side effects: None.
    """
    body = response_body or ""
    has_first = first in body if first else False
    has_last = last in body if last else False

    if outcome == OUTCOME_REJECTED or (status_code is not None and int(status_code) >= 400):
        # Reject only when neither sentinel reflected *and* error-class outcome.
        if not has_first and not has_last:
            return DUP_REJECT, 85

    if has_first and has_last:
        return DUP_JOIN, 90
    if has_first and not has_last:
        return DUP_FIRST_WINS, 92
    if has_last and not has_first:
        return DUP_LAST_WINS, 92

    if outcome in _SOFT_ACCEPT:
        # Accepted but neither sentinel visible — parser may strip / not reflect.
        return DUP_UNKNOWN, 40
    if outcome == OUTCOME_REJECTED:
        return DUP_REJECT, 80
    return DUP_UNKNOWN, 30


def detect_normalization_stages_from_reflection(
    payload: str,
    payload_type: str,
    response_body: str,
    *,
    outcome: str = OUTCOME_UNKNOWN,
) -> list[NormalizationStage]:
    """
    Purpose:
        From a single normalization probe's payload + response body, detect
        which stages applied before reflection.

    Side effects: None.
    """
    body = response_body or ""
    stages: list[NormalizationStage] = []
    ptype = payload_type or ""
    payload = payload or ""

    if not body or not payload:
        return stages

    if ptype == "norm:trim":
        stripped = payload.strip()
        if stripped and stripped in body and payload not in body:
            stages.append(NormalizationStage(
                STAGE_TRIM, 90, "reflected without surrounding whitespace",
            ))
        elif payload in body:
            stages.append(NormalizationStage(
                STAGE_TRIM, 20, "raw spaced payload reflected (trim unlikely)",
            ))

    elif ptype == "norm:case":
        if payload in body:
            stages.append(NormalizationStage(
                STAGE_CASE_FOLD, 15, "exact case preserved",
            ))
        elif payload.lower() in body and payload.lower() != payload:
            stages.append(NormalizationStage(
                STAGE_CASE_FOLD, 88, "reflected lowercased",
            ))
        elif payload.upper() in body and payload.upper() != payload:
            stages.append(NormalizationStage(
                STAGE_CASE_FOLD, 88, "reflected uppercased",
            ))

    elif ptype == "norm:url_decode":
        # payload starts with %41 + rest
        rest = payload[3:] if payload.startswith("%41") else payload
        decoded = "A" + rest
        if decoded in body and payload not in body:
            stages.append(NormalizationStage(
                STAGE_URL_DECODE, 92, "%41 decoded to A before reflect",
            ))
        elif payload in body:
            stages.append(NormalizationStage(
                STAGE_URL_DECODE, 20, "percent-encoding preserved (no decode)",
            ))

    elif ptype == "norm:double_encode":
        # %2541 + canary → single decode: %41+canary; double: A+canary
        rest = payload[5:] if payload.startswith("%2541") else ""
        single = "%41" + rest
        double = "A" + rest
        if double in body and single not in body and payload not in body:
            stages.append(NormalizationStage(
                STAGE_URL_DECODE, 85, "double-decoded %2541 → A",
            ))
        elif single in body and payload not in body:
            stages.append(NormalizationStage(
                STAGE_URL_DECODE, 80, "single-decode only (%2541 → %41)",
            ))
        elif payload in body:
            stages.append(NormalizationStage(
                STAGE_URL_DECODE, 25, "double-encoded form preserved",
            ))

    elif ptype == "norm:unicode":
        # fullwidth A (U+FF21) + canary
        if payload and payload[0] == "\uff21":
            rest = payload[1:]
            ascii_form = "A" + rest
            if ascii_form in body and payload not in body:
                stages.append(NormalizationStage(
                    STAGE_UNICODE_NORMALIZE, 85, "fullwidth A → ASCII A",
                ))
            elif payload in body:
                stages.append(NormalizationStage(
                    STAGE_UNICODE_NORMALIZE, 25, "fullwidth form preserved",
                ))

    # Soft accept without reflection → stage unknown, do not invent pipeline.
    _ = outcome
    return stages


def merge_normalization_pipeline(
    stage_lists: list[list[NormalizationStage]],
) -> list[dict[str, Any]]:
    """
    Purpose:
        Merge per-probe stage detections into an ordered pipeline.
        Higher confidence wins per stage key; order follows STAGE_ORDER.

    Output:
        List of stage dicts (non-empty when any positive evidence ≥60 conf).

    Side effects: None.
    """
    best: dict[str, NormalizationStage] = {}
    for stages in stage_lists:
        for st in stages:
            if st.stage not in KNOWN_NORM_STAGES:
                continue
            # Only keep positive evidence (confidence ≥ 50 means stage applied
            # or was tested; low-confidence "unlikely" notes are kept if sole).
            prev = best.get(st.stage)
            if prev is None or st.confidence > prev.confidence:
                best[st.stage] = st

    # Prefer stages that indicate *application* (confidence ≥ 60).
    pipeline: list[dict[str, Any]] = []
    for name in STAGE_ORDER:
        if name == STAGE_REFLECT:
            continue  # appended after positive stages when observed via body
        st = best.get(name)
        if st is None:
            continue
        if st.confidence >= 60:
            pipeline.append(st.to_dict())
    # If we only have weak negative notes, still surface high-signal stages.
    if not pipeline:
        for name in STAGE_ORDER:
            if name == STAGE_REFLECT:
                continue
            st = best.get(name)
            if st is not None and st.confidence >= 80:
                pipeline.append(st.to_dict())
    # Stages were observed via response body → pipeline ends with reflect.
    if pipeline and not any(s.get("stage") == STAGE_REFLECT for s in pipeline):
        pipeline.append({
            "stage": STAGE_REFLECT,
            "confidence": 70,
            "evidence": "stages observed via reflection",
        })
    return pipeline


def synthesize_parser_state(
    probe_rows: list[dict[str, Any]],
    *,
    location: str = "query",
) -> ParserSynthesisResult:
    """
    Purpose:
        Aggregate completed parser/normalization probe summaries into profile
        fields.

    Input:
        probe_rows — list of dicts with keys:
            payload_type, payload, outcome, confidence, body (optional),
            status_code (optional), evidence_flow_ids (optional),
            analysis (optional; should be "parser").

    Output:
        ParserSynthesisResult.

    Side effects: None.
    """
    result = ParserSynthesisResult()
    if not probe_rows:
        return result

    parser: dict[str, Any] = {}
    stage_lists: list[list[NormalizationStage]] = []
    caps: list[str] = []
    tested: dict[str, dict[str, Any]] = {}
    confidences: list[int] = []

    for row in probe_rows:
        ptype = str(row.get("payload_type") or "")
        payload = str(row.get("payload") or "")
        outcome = str(row.get("outcome") or OUTCOME_UNKNOWN)
        conf = int(row.get("confidence") or 0)
        body = str(row.get("body") or "")
        status_code = row.get("status_code")
        flows = row.get("evidence_flow_ids")
        if not isinstance(flows, list):
            flows = []
        if row.get("flow_id") and row["flow_id"] not in flows:
            flows = list(flows) + [row["flow_id"]]

        # ── Normalization ──────────────────────────────────────────────
        if ptype.startswith("norm:"):
            stages = detect_normalization_stages_from_reflection(
                payload, ptype, body, outcome=outcome,
            )
            stage_lists.append(stages)
            confidences.append(max((s.confidence for s in stages), default=conf))
            # Record tested when no stage evidence and rejected.
            if outcome == OUTCOME_REJECTED:
                key = TESTED_PARSER_KEYS.get(ptype, ptype)
                tested[key] = {
                    "outcome": OUTCOME_REJECTED,
                    "confidence": conf or 70,
                    "evidence_flow_ids": flows,
                }
            continue

        # ── Parser fingerprint ─────────────────────────────────────────
        if ptype in ("parser:dup_query", "parser:dup_form", "parser:array_repeat"):
            first, last = unpack_dup_payload(payload)
            behavior, bconf = detect_duplicate_behavior(
                body,
                first=first,
                last=last,
                outcome=outcome,
                status_code=int(status_code) if status_code is not None else None,
            )
            field_name = {
                "parser:dup_query": "duplicate_query",
                "parser:dup_form": "duplicate_form",
                "parser:array_repeat": "array_repeat",
            }[ptype]
            parser[field_name] = empty_characteristic(
                state=behavior,
                confidence=bconf,
                uncertainty=_uncertainty_for_conf(bconf),
                evidence_flow_ids=flows or None,
                extra={"behavior": behavior},
            )
            confidences.append(bconf)
            if behavior in (DUP_FIRST_WINS, DUP_LAST_WINS, DUP_JOIN):
                if CAPABILITY_DUPLICATE_PARAMETER not in caps:
                    caps.append(CAPABILITY_DUPLICATE_PARAMETER)
            if behavior == DUP_REJECT:
                key = TESTED_PARSER_KEYS.get(ptype, "parser:duplicate")
                tested[key] = {
                    "outcome": OUTCOME_REJECTED,
                    "confidence": bconf,
                    "evidence_flow_ids": flows,
                }

        elif ptype == "parser:json_dup_key":
            first, last = unpack_dup_payload(payload)
            behavior, bconf = detect_duplicate_behavior(
                body, first=first, last=last, outcome=outcome,
                status_code=int(status_code) if status_code is not None else None,
            )
            parser["json_duplicate_key"] = empty_characteristic(
                state=behavior,
                confidence=bconf,
                uncertainty=_uncertainty_for_conf(bconf),
                evidence_flow_ids=flows or None,
                extra={"behavior": behavior},
            )
            confidences.append(bconf)
            if CAPABILITY_JSON_PARSER not in caps:
                caps.append(CAPABILITY_JSON_PARSER)
            if behavior == DUP_REJECT:
                tested["parser:json_duplicate"] = {
                    "outcome": OUTCOME_REJECTED,
                    "confidence": bconf,
                    "evidence_flow_ids": flows,
                }

        elif ptype in ("parser:json_null", "parser:json_empty", "parser:json_omit"):
            key_short = ptype.replace("parser:", "")
            state = outcome if outcome != OUTCOME_UNKNOWN else "unknown"
            # null vs empty differentiation is the fingerprint itself.
            parser[key_short] = empty_characteristic(
                state=state,
                confidence=conf or 50,
                uncertainty=_uncertainty_for_conf(conf or 50),
                evidence_flow_ids=flows or None,
                extra={"outcome": outcome},
            )
            confidences.append(conf or 50)
            if CAPABILITY_JSON_PARSER not in caps:
                caps.append(CAPABILITY_JSON_PARSER)
            if outcome == OUTCOME_REJECTED:
                tested[TESTED_PARSER_KEYS.get(ptype, ptype)] = {
                    "outcome": OUTCOME_REJECTED,
                    "confidence": conf or 70,
                    "evidence_flow_ids": flows,
                }

        elif ptype in ("parser:array_bracket", "parser:array_dot"):
            key_short = ptype.replace("parser:", "")
            # Accepted with sentinel in body → syntax supported.
            first = unpack_dup_payload(payload)[0] if DUP_PAYLOAD_SEP in payload else (
                payload or SENTINEL_FIRST
            )
            supported = first in body if first and body else outcome in _SOFT_ACCEPT
            state = "accepted" if supported and outcome != OUTCOME_REJECTED else (
                "rejected" if outcome == OUTCOME_REJECTED else "unknown"
            )
            bconf = conf or (75 if supported else 40)
            parser[key_short] = empty_characteristic(
                state=state,
                confidence=bconf,
                uncertainty=_uncertainty_for_conf(bconf),
                evidence_flow_ids=flows or None,
            )
            confidences.append(bconf)
            if state == "rejected":
                tested[TESTED_PARSER_KEYS.get(ptype, ptype)] = {
                    "outcome": OUTCOME_REJECTED,
                    "confidence": bconf,
                    "evidence_flow_ids": flows,
                }

    pipeline = merge_normalization_pipeline(stage_lists)

    overall = int(sum(confidences) / len(confidences)) if confidences else 0
    result.parser = parser
    result.normalization_pipeline = pipeline
    result.capabilities = caps
    result.tested_updates = tested
    result.confidence = overall
    result.uncertainty = _uncertainty_for_conf(overall)
    result.parser_family = infer_parser_family(parser, location=location)
    return result


def infer_parser_family(
    parser: dict[str, Any],
    *,
    location: str = "query",
) -> str:
    """
    Purpose:
        Optional light inference of middleware/parser family from fingerprints.
        Intentionally weak — not full framework identification (out of scope).

    Output:
        Short family tag or empty string.

    Side effects: None.
    """
    if not parser:
        return ""
    dup = (parser.get("duplicate_query") or parser.get("duplicate_form") or {})
    behavior = ""
    if isinstance(dup, dict):
        behavior = str(dup.get("behavior") or dup.get("state") or "")

    json_null = parser.get("json_null") or {}
    has_json = bool(
        parser.get("json_null")
        or parser.get("json_empty")
        or parser.get("json_duplicate_key")
    )

    # Very light heuristics (documented as low-certainty).
    if has_json and behavior == DUP_LAST_WINS:
        return "json_body_last_wins"
    if has_json and behavior == DUP_FIRST_WINS:
        return "json_body_first_wins"
    if location == "query" and behavior == DUP_LAST_WINS:
        return "query_last_wins"  # common in PHP / some frameworks
    if location == "query" and behavior == DUP_FIRST_WINS:
        return "query_first_wins"  # common in some Java / Go stacks
    if location == "query" and behavior == DUP_JOIN:
        return "query_join"  # e.g. some ASP.NET / multi-value styles
    if behavior == DUP_REJECT:
        return "strict_no_duplicate"
    if has_json:
        return "json_body"
    return ""


def apply_parser_synthesis_to_profile(
    profile: dict[str, Any],
    synth: ParserSynthesisResult,
) -> dict[str, Any]:
    """
    Purpose:
        Write synthesis result into a parameter profile document.

    Side effects: Mutates profile (observed.parser, parser, pipeline, tested, …).
    """
    if not isinstance(profile.get("observed"), dict):
        profile["observed"] = {}
    if synth.parser:
        profile["observed"]["parser"] = dict(synth.parser)
        # Keep top-level parser in sync (M2 skeleton key).
        profile["parser"] = dict(synth.parser)

    if synth.normalization_pipeline:
        profile["normalization_pipeline"] = list(synth.normalization_pipeline)

    if not isinstance(profile.get("inferred"), dict):
        profile["inferred"] = {}
    if synth.parser_family:
        profile["inferred"]["parser_family"] = synth.parser_family

    for key, entry in (synth.tested_updates or {}).items():
        set_tested(
            profile,
            key,
            outcome=str(entry.get("outcome") or OUTCOME_REJECTED),
            confidence=int(entry.get("confidence") or 0),
            evidence_flow_ids=entry.get("evidence_flow_ids"),
        )

    caps = profile.get("capabilities")
    if not isinstance(caps, list):
        profile["capabilities"] = []
        caps = profile["capabilities"]
    for c in synth.capabilities:
        if c and c not in caps:
            caps.append(c)

    return profile


def tested_key_for_parser_payload(payload_type: str) -> str:
    """Normalize parser/norm payload_type → tested{} key."""
    return TESTED_PARSER_KEYS.get(payload_type or "", payload_type or "unknown")


def is_parser_payload_type(payload_type: str) -> bool:
    """True when payload_type is a Module 8 norm/parser probe label."""
    pt = payload_type or ""
    return pt.startswith("norm:") or pt.startswith("parser:")


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

def _mixed_case(s: str) -> str:
    """Alternate case for case-fold detection."""
    out = []
    for i, ch in enumerate(s):
        out.append(ch.upper() if i % 2 == 0 else ch.lower())
    return "".join(out)


def _uncertainty_for_conf(confidence: int) -> str:
    if confidence >= 90:
        return UNCERTAINTY_NONE
    if confidence >= 60:
        return UNCERTAINTY_LOW
    return UNCERTAINTY_HIGH
