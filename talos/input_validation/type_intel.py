"""
Module: talos.input_validation.type_intel

Purpose:
    Module 7 — Types, semantic validation, and negative-evidence discipline.

    Passive-first type characterization and lightweight semantic (business-rule)
    probes, plus helpers that force every failed family into ``tested{}``.

    Design goals (Module 7 brief):
        - Prune the fixed ~12-type matrix using passive ``semantic_type`` +
          examples + name hints (integer-like → 2–4 confirms, not 12).
        - Prefer URL-shaped confirms for URL/name-hint parameters.
        - Record type outcomes with confidence; detect conflicts
          (e.g. integer examples but UUID accepted).
        - Semantic probes: enum-outside, numeric range, empty/null — not
          full workflow testing.
        - Default validation core excludes exploit-shaped SQLi/XSS strings;
          those stay deep/exhaustive ``edge`` only.
        - Every rejected family writes ``tested.<family>`` with confidence.

Pure computation only — no HTTP, no SQLite.

Dependencies: outcomes, phases probe catalogues
Data flow:
    planner type_confirm / semantic_rules → select_*_probes()
    engine expands probes → scheduler → synthesize fills types + tested
Side effects: None.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from talos.input_validation.outcomes import (
    OUTCOME_ACCEPTED,
    OUTCOME_MODIFIED,
    OUTCOME_REJECTED,
    OUTCOME_UNKNOWN,
)
from talos.input_validation.phases import IV_TYPE_PROBES, IV_VALIDATION_PROBES
from talos.input_validation.profile import (
    STATE_CONFLICTING,
    STATE_UNKNOWN,
    UNCERTAINTY_HIGH,
    UNCERTAINTY_LOW,
    UNCERTAINTY_NONE,
    empty_characteristic,
    set_tested,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SOFT_ACCEPT: frozenset[str] = frozenset({
    OUTCOME_ACCEPTED,
    OUTCOME_MODIFIED,
    "encoded",
    "normalized",
})

# Full type catalogue keyed by probe label (from phases.IV_TYPE_PROBES).
TYPE_PROBE_MAP: dict[str, str] = {name: value for name, value in IV_TYPE_PROBES}

# Passive semantic_type values we understand for pruning.
KNOWN_SEMANTIC_TYPES: frozenset[str] = frozenset({
    "uuid", "jwt", "email", "objectid", "url", "ip", "hash",
    "timestamp", "filename", "boolean", "integer", "float",
    "array", "string", "unknown",
})

# Name-token hints → semantic type (mirrors passive name heuristics lightly).
_NAME_URL_TOKENS: frozenset[str] = frozenset({
    "url", "redirect", "callback", "next", "return_url", "returnurl",
    "href", "link", "uri", "target", "dest", "destination",
})
_NAME_INT_TOKENS: frozenset[str] = frozenset({
    "count", "limit", "offset", "page", "size", "qty", "quantity",
    "amount", "num", "number", "age", "port", "index",
})
_NAME_EMAIL_TOKENS: frozenset[str] = frozenset({"email", "mail", "e_mail"})
_NAME_BOOL_TOKENS: frozenset[str] = frozenset({
    "enabled", "disabled", "active", "is_", "has_", "can_", "flag",
})

# Max probes for type_confirm by tier (before passive pruning further reduces).
_TYPE_CONFIRM_CAP: dict[str, int] = {
    "quick": 2,
    "standard": 4,
    "deep": 8,
    "exhaustive": 12,
}

# Max semantic / validation-core probes by tier.
_SEMANTIC_PROBE_CAP: dict[str, int] = {
    "quick": 2,
    "standard": 5,
    "deep": 8,
    "exhaustive": 12,
}

# Core validation families (characterization, not exploit spray).
VALIDATION_CORE_LABELS: frozenset[str] = frozenset({
    "empty",
    "whitespace",
    "null_byte",
    "very_long",
    "negative_int",
    "float",
})

# Exploit-shaped strings — deep / exhaustive edge only (Module 7 philosophy).
VALIDATION_EDGE_LABELS: frozenset[str] = frozenset({
    "special_chars",   # SQLi-shaped
    "html_injection",  # XSS-shaped
    "crlf",
})

# Map validation / semantic payload_type → tested[] family key.
TESTED_FAMILY_KEYS: dict[str, str] = {
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
    "missing": "missing",
    "unicode": "unicode",
}


# ---------------------------------------------------------------------------
# Data contracts
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TypeProbePlan:
    """
    Selected type-confirm probes for one parameter.

    Fields:
        probes       — (payload_type, value) pairs to enqueue.
        hypothesis   — planner hypothesis string.
        passive_type — resolved passive semantic type used for pruning.
        pruned_from  — full matrix size before pruning (usually 12).
        reason       — short human-readable selection reason.
    """

    probes: tuple[tuple[str, str], ...]
    hypothesis: str
    passive_type: str
    pruned_from: int = 12
    reason: str = ""


@dataclass(frozen=True)
class SemanticProbePlan:
    """
    Selected semantic / validation-core probes.

    Fields:
        probes     — (payload_type, value) pairs.
        hypothesis — planner hypothesis.
        reason     — selection summary.
        skipped    — labels intentionally skipped (e.g. very_long when bound known).
    """

    probes: tuple[tuple[str, str], ...]
    hypothesis: str
    reason: str = ""
    skipped: tuple[str, ...] = ()


@dataclass
class TypeSynthesisResult:
    """
    Aggregated type intelligence from type-phase probe outcomes.

    Fields:
        per_type     — map type label → {outcome, confidence, evidence_flow_ids}.
        primary      — best-accepted type label or passive hypothesis.
        state        — accepted | conflicting | unknown.
        confidence   — 0–100.
        uncertainty  — none | low | high.
        conflict_note — optional explanation when state is conflicting.
        passive_type — passive semantic_type used for comparison.
    """

    per_type: dict[str, Any] = field(default_factory=dict)
    primary: str = "unknown"
    state: str = STATE_UNKNOWN
    confidence: int = 0
    uncertainty: str = UNCERTAINTY_HIGH
    conflict_note: str = ""
    passive_type: str = "unknown"


# ---------------------------------------------------------------------------
# Passive type resolution
# ---------------------------------------------------------------------------

def resolve_passive_type(
    semantic_type: str | None = None,
    examples: list[str] | None = None,
    param_name: str | None = None,
) -> str:
    """
    Purpose:
        Resolve the best passive type hypothesis from Endpoint Intelligence
        fields (semantic_type, example_values, parameter name).
    Input:
        semantic_type — parameters.semantic_type or empty.
        examples      — observed example values (strings).
        param_name    — parameter name for URL/int/email hints.
    Output:
        One of KNOWN_SEMANTIC_TYPES (defaults to ``unknown``).
    Side effects: None.
    """
    st = (semantic_type or "").strip().lower()
    if st and st in KNOWN_SEMANTIC_TYPES and st not in ("unknown", "string", "array"):
        return st

    # Re-infer from examples when passive type is weak.
    for ex in examples or []:
        if not isinstance(ex, str) or not ex:
            continue
        inferred = _infer_type_from_value(ex)
        if inferred and inferred not in ("unknown", "string"):
            return inferred

    hint = _name_type_hint(param_name or "")
    if hint:
        return hint

    if st in ("string", "array"):
        return st
    return "unknown"


def _name_type_hint(name: str) -> str:
    """Lightweight name → type hint for probe prioritization."""
    low = (name or "").lower().replace("-", "_").replace(".", "_")
    if not low:
        return ""
    if any(t in low for t in _NAME_URL_TOKENS):
        return "url"
    if any(t in low for t in _NAME_EMAIL_TOKENS):
        return "email"
    if low.endswith("_id") or low.startswith("id_") or "uuid" in low:
        return "uuid"
    if any(t in low for t in _NAME_INT_TOKENS):
        return "integer"
    if any(low.startswith(t) or t in low for t in _NAME_BOOL_TOKENS):
        return "boolean"
    if "date" in low or "time" in low or low.endswith("_at"):
        return "timestamp"
    if "email" in low:
        return "email"
    return ""


def _infer_type_from_value(value: str) -> str:
    """Pattern-match a single example value to a type label."""
    v = value.strip()
    if not v:
        return "unknown"
    if re.fullmatch(
        r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        v,
    ):
        return "uuid"
    if re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", v):
        return "email"
    if re.match(r"^https?://", v, re.I) or re.match(r"^//", v):
        return "url"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v):
        return "ip"
    if v.lower() in {"true", "false", "yes", "no"}:
        return "boolean"
    if re.fullmatch(r"-?\d+", v):
        return "integer"
    if re.fullmatch(r"-?\d+\.\d+", v):
        return "float"
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}([T ].*)?", v):
        return "timestamp"
    if re.fullmatch(r"\d{10,13}", v):
        return "timestamp"
    if len(v) in (32, 40, 64) and re.fullmatch(r"[0-9a-fA-F]+", v):
        return "hash"
    return "string"


# ---------------------------------------------------------------------------
# Type probe selection (passive-first pruning)
# ---------------------------------------------------------------------------

def select_type_probes(
    *,
    semantic_type: str | None = None,
    examples: list[str] | None = None,
    param_name: str | None = None,
    strategy: str = "standard",
    max_probes: int | None = None,
) -> TypeProbePlan:
    """
    Purpose:
        Choose a minimal set of type confirm/deny probes from passive intel.

        Integer-like params get ~2–4 probes (not the full 12-type matrix).
        URL/name-hint params prioritize URL-shaped confirms first.
        Exhaustive strategy returns the full IV_TYPE_PROBES matrix.

    Input:
        semantic_type / examples / param_name — passive Endpoint Intelligence.
        strategy   — quick|standard|deep|exhaustive.
        max_probes — optional hard cap (overrides tier default).

    Output:
        TypeProbePlan with ordered (label, value) pairs.

    Side effects: None.
    """
    tier = (strategy or "standard").lower().strip()
    passive = resolve_passive_type(semantic_type, examples, param_name)
    full = list(IV_TYPE_PROBES)
    cap = max_probes if max_probes is not None else _TYPE_CONFIRM_CAP.get(tier, 4)
    cap = max(1, int(cap))

    if tier == "exhaustive":
        return TypeProbePlan(
            probes=tuple(full),
            hypothesis="types.exhaustive_matrix",
            passive_type=passive,
            pruned_from=len(full),
            reason="exhaustive: full type matrix",
        )

    ordered_labels = _priority_labels_for_type(passive, param_name)
    # Always include empty as a lightweight deny/accept signal under deep.
    if tier == "deep" and "empty" not in ordered_labels:
        ordered_labels.append("empty")

    selected: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label in ordered_labels:
        if label in seen:
            continue
        if label not in TYPE_PROBE_MAP:
            continue
        value = TYPE_PROBE_MAP[label]
        seen.add(label)
        selected.append((label, value))
        if len(selected) >= cap:
            break

    # Guarantee at least one probe.
    if not selected:
        selected = [("string", TYPE_PROBE_MAP["string"])]
        if cap >= 2:
            selected.append(("integer", TYPE_PROBE_MAP["integer"]))

    hypothesis = f"types.confirm.{passive}"
    reason = (
        f"passive={passive}; selected {len(selected)}/{len(full)} "
        f"(tier={tier}, cap={cap})"
    )
    return TypeProbePlan(
        probes=tuple(selected),
        hypothesis=hypothesis,
        passive_type=passive,
        pruned_from=len(full),
        reason=reason,
    )


def _priority_labels_for_type(passive: str, param_name: str | None) -> list[str]:
    """
    Purpose:
        Ordered type probe labels: confirm first, then useful denies.
    Side effects: None.
    """
    # Name-hint can elevate URL even when passive is weak.
    if passive in ("unknown", "string") and _name_type_hint(param_name or "") == "url":
        passive = "url"

    confirm_deny: dict[str, list[str]] = {
        "integer": ["integer", "float", "string", "empty"],
        "float": ["float", "integer", "string", "empty"],
        "boolean": ["boolean", "integer", "string", "empty"],
        "uuid": ["uuid", "integer", "string", "empty"],
        "email": ["email", "string", "url", "empty"],
        "url": ["url", "string", "email", "empty"],
        "ip": ["string", "integer", "url", "empty"],  # no dedicated ip probe
        "hash": ["hash_md5", "string", "integer", "empty"],
        "timestamp": ["timestamp", "iso_date", "integer", "string"],
        "filename": ["string", "url", "empty", "integer"],
        "jwt": ["string", "integer", "empty", "boolean"],
        "objectid": ["string", "integer", "uuid", "empty"],
        "array": ["string", "integer", "empty", "boolean"],
        "string": ["string", "integer", "boolean", "empty"],
        "unknown": ["string", "integer", "boolean", "uuid"],
    }
    labels = list(confirm_deny.get(passive, confirm_deny["unknown"]))

    # URL prioritization: ensure url is first when name or passive says so.
    if passive == "url" and labels and labels[0] != "url":
        labels = ["url"] + [x for x in labels if x != "url"]
    return labels


def estimated_type_probe_count(
    strategy: str = "standard",
    semantic_type: str | None = None,
    param_name: str | None = None,
) -> int:
    """
    Purpose:
        Planner estimate for type_confirm HTTP count (no examples needed).
    Side effects: None.
    """
    plan = select_type_probes(
        semantic_type=semantic_type,
        param_name=param_name,
        strategy=strategy,
    )
    return len(plan.probes)


# ---------------------------------------------------------------------------
# Semantic + validation-core probes
# ---------------------------------------------------------------------------

def validation_probes_for_strategy(strategy: str = "standard") -> list[tuple[str, str]]:
    """
    Purpose:
        Split legacy IV_VALIDATION_PROBES into core (default) vs edge
        (deep/exhaustive only).  Default validation does **not** require
        SQLi/XSS-shaped strings.
    Output: (payload_type, value) list.
    Side effects: None.
    """
    tier = (strategy or "standard").lower().strip()
    core = [(n, v) for n, v in IV_VALIDATION_PROBES if n in VALIDATION_CORE_LABELS]
    if tier in ("deep", "exhaustive"):
        edge = [(n, v) for n, v in IV_VALIDATION_PROBES if n in VALIDATION_EDGE_LABELS]
        # Legacy list already has special_chars + html_injection; add CRLF for deep+.
        edge_extra = [("crlf", "\r\nX-Talos:1")]
        # Avoid duplicate labels.
        seen = {n for n, _ in core + edge}
        for item in edge_extra:
            if item[0] not in seen:
                edge.append(item)
                seen.add(item[0])
        if tier == "exhaustive":
            # Full legacy list order preference: core + edge + any leftover.
            leftover = [
                (n, v) for n, v in IV_VALIDATION_PROBES
                if n not in VALIDATION_CORE_LABELS and n not in VALIDATION_EDGE_LABELS
            ]
            return core + edge + leftover
        return core + edge
    return core


def select_semantic_probes(
    *,
    semantic_type: str | None = None,
    examples: list[str] | None = None,
    param_name: str | None = None,
    location: str = "query",
    strategy: str = "standard",
    max_accepted_length: int | None = None,
    max_probes: int | None = None,
    include_core_validation: bool = True,
) -> SemanticProbePlan:
    """
    Purpose:
        Build lightweight semantic + core-validation probes.

        - enum-like: value outside observed set when examples form a small enum
        - numeric range: negative / zero / huge when examples are small ints
        - empty / null_str where location allows
        - skip very_long when max_accepted is already known (M6 handoff)
        - exclude exploit-shaped strings from standard core

    Input:
        Passive type fields, location, strategy, optional length bound.
        include_core_validation — merge core validation families (empty, null…).

    Output:
        SemanticProbePlan.

    Side effects: None.
    """
    tier = (strategy or "standard").lower().strip()
    passive = resolve_passive_type(semantic_type, examples, param_name)
    cap = max_probes if max_probes is not None else _SEMANTIC_PROBE_CAP.get(tier, 5)
    cap = max(1, int(cap))
    examples = [e for e in (examples or []) if isinstance(e, str)]

    selected: list[tuple[str, str]] = []
    skipped: list[str] = []
    seen: set[str] = set()

    def _add(label: str, value: str) -> None:
        if label in seen or len(selected) >= cap:
            return
        seen.add(label)
        selected.append((label, value))

    # ── Semantic business-rule probes (shallow) ───────────────────────────
    if passive in ("integer", "float") or _examples_look_numeric(examples):
        _add("negative_int", "-999999")
        _add("zero", "0")
        if _examples_small_positive_ints(examples):
            _add("huge_int", "999999999999999")
        if passive == "float" or any(_looks_float(e) for e in examples):
            _add("float", "9.9999999")

    if passive == "boolean" or _examples_look_boolean(examples):
        _add("integer", "2")  # outside typical bool set
        _add("string", "notabool")

    # Enum-like: small closed set of non-numeric string examples.
    if not _examples_look_numeric(examples):
        enum_outside = _enum_outside_value(examples)
        if enum_outside is not None:
            _add("enum_outside", enum_outside)

    # Empty / null characterization (locations that can carry empty values).
    if location in ("query", "body", "header", "cookie", "path"):
        _add("empty", "")
        _add("null_str", "null")

    # ── Core validation (non-exploit) ─────────────────────────────────────
    if include_core_validation:
        for label, value in validation_probes_for_strategy(tier):
            if label == "very_long" and max_accepted_length is not None:
                # Bound already known from length search — skip pointless 10k probe.
                skipped.append("very_long")
                continue
            if label in seen:
                continue
            # Prefer not to re-add duplicates already selected as semantic.
            _add(label, value)

    # Deep+: optional CRLF characterization (not in legacy list by default).
    if tier in ("deep", "exhaustive") and "crlf" not in seen:
        _add("crlf", "\r\nX-Talos:1")

    if not selected:
        # Absolute minimum characterization.
        selected = [("empty", "")]

    reason_parts = [
        f"passive={passive}",
        f"n={len(selected)}",
        f"tier={tier}",
    ]
    if skipped:
        reason_parts.append(f"skipped={','.join(skipped)}")
    return SemanticProbePlan(
        probes=tuple(selected[:cap]),
        hypothesis=f"semantic.rules.{passive}",
        reason="; ".join(reason_parts),
        skipped=tuple(skipped),
    )


def estimated_semantic_probe_count(
    strategy: str = "standard",
    *,
    semantic_type: str | None = None,
    max_accepted_length: int | None = None,
) -> int:
    """
    Purpose:
        Planner estimate for semantic_rules / validation-core HTTP count.
    Side effects: None.
    """
    plan = select_semantic_probes(
        semantic_type=semantic_type,
        strategy=strategy,
        max_accepted_length=max_accepted_length,
    )
    return len(plan.probes)


def _examples_look_numeric(examples: list[str]) -> bool:
    if not examples:
        return False
    return all(re.fullmatch(r"-?\d+(\.\d+)?", e.strip()) for e in examples if e.strip())


def _examples_small_positive_ints(examples: list[str]) -> bool:
    vals: list[int] = []
    for e in examples:
        if re.fullmatch(r"\d+", e.strip()):
            try:
                vals.append(int(e.strip()))
            except ValueError:
                return False
    if not vals:
        return False
    return all(0 <= v < 10_000 for v in vals)


def _looks_float(value: str) -> bool:
    return bool(re.fullmatch(r"-?\d+\.\d+", (value or "").strip()))


def _examples_look_boolean(examples: list[str]) -> bool:
    if not examples:
        return False
    allowed = {"true", "false", "yes", "no", "0", "1"}
    return all(e.strip().lower() in allowed for e in examples if e.strip())


def _enum_outside_value(examples: list[str]) -> str | None:
    """
    Purpose:
        If examples form a small distinct set (2–8 values), return a value
        clearly outside that set for enum-like semantic probing.
    Side effects: None.
    """
    cleaned = [e.strip() for e in examples if e and e.strip()]
    if len(cleaned) < 2:
        return None
    unique = list(dict.fromkeys(cleaned))  # stable unique
    if not (2 <= len(unique) <= 8):
        return None
    # All short token-like values (enum-ish).
    if not all(len(u) <= 64 and "\n" not in u for u in unique):
        return None
    # Prefer a stable outside token that is unlikely in APIs.
    candidate = "__talos_enum_outside__"
    if candidate not in unique:
        return candidate
    return "__talos_enum_outside_2__"


# ---------------------------------------------------------------------------
# Type synthesis + conflict handling
# ---------------------------------------------------------------------------

def synthesize_type_state(
    type_outcomes: dict[str, dict[str, Any]],
    *,
    passive_type: str = "unknown",
    evidence_flow_ids: list[str] | None = None,
) -> TypeSynthesisResult:
    """
    Purpose:
        Aggregate per-type probe outcomes into primary type + conflict state.

        Conflict example: passive ``integer`` but ``uuid`` probe accepted and
        ``integer`` rejected → state=conflicting, high uncertainty.

    Input:
        type_outcomes — map label → {outcome, confidence, evidence_flow_ids?}.
        passive_type  — resolved passive hypothesis.

    Output:
        TypeSynthesisResult.

    Side effects: None.
    """
    result = TypeSynthesisResult(
        per_type=dict(type_outcomes),
        passive_type=passive_type or "unknown",
    )
    if not type_outcomes:
        result.state = STATE_UNKNOWN
        result.confidence = 0
        result.uncertainty = UNCERTAINTY_HIGH
        result.primary = passive_type or "unknown"
        return result

    accepted: list[tuple[str, int]] = []
    rejected: list[tuple[str, int]] = []
    for label, entry in type_outcomes.items():
        if not isinstance(entry, dict):
            continue
        outcome = str(entry.get("outcome") or OUTCOME_UNKNOWN)
        conf = int(entry.get("confidence") or 0)
        if outcome in _SOFT_ACCEPT:
            accepted.append((label, conf))
        elif outcome == OUTCOME_REJECTED:
            rejected.append((label, conf))

    accepted.sort(key=lambda x: -x[1])
    passive = (passive_type or "unknown").lower()

    # Map type probe labels to semantic families for conflict checks.
    passive_probe = _passive_to_probe_label(passive)

    if accepted:
        primary = accepted[0][0]
        conf = accepted[0][1]
        result.primary = primary
        result.confidence = conf

        # Conflict: passive confirms one family; a different family accepted
        # while the passive probe was rejected.
        conflict = False
        note = ""
        if passive_probe and passive not in ("unknown", "string"):
            passive_entry = type_outcomes.get(passive_probe) or {}
            passive_out = str(passive_entry.get("outcome") or "")
            if primary != passive_probe and primary not in _compatible_types(passive):
                if passive_out == OUTCOME_REJECTED:
                    conflict = True
                    note = (
                        f"passive={passive} rejected but {primary} accepted"
                    )
                elif passive_out in _SOFT_ACCEPT and primary != passive_probe:
                    # Both accepted — mild conflict / multi-type surface.
                    if conf >= 60 and int(passive_entry.get("confidence") or 0) >= 60:
                        # Prefer higher confidence; flag low uncertainty multi-accept.
                        if primary not in _compatible_types(passive):
                            conflict = True
                            note = (
                                f"both {passive_probe} and {primary} accepted"
                            )

        if conflict:
            result.state = STATE_CONFLICTING
            result.uncertainty = UNCERTAINTY_HIGH
            result.confidence = min(result.confidence, 55)
            result.conflict_note = note
        else:
            result.state = "typed"
            if conf >= 90:
                result.uncertainty = UNCERTAINTY_NONE
            elif conf >= 60:
                result.uncertainty = UNCERTAINTY_LOW
            else:
                result.uncertainty = UNCERTAINTY_HIGH
    else:
        result.primary = passive if passive != "unknown" else "unknown"
        result.state = STATE_UNKNOWN
        result.confidence = 30 if passive != "unknown" else 0
        result.uncertainty = UNCERTAINTY_HIGH

    return result


def _passive_to_probe_label(passive: str) -> str:
    """Map semantic_type → IV type probe label when 1:1."""
    mapping = {
        "integer": "integer",
        "float": "float",
        "boolean": "boolean",
        "uuid": "uuid",
        "email": "email",
        "url": "url",
        "timestamp": "timestamp",
        "hash": "hash_md5",
        "string": "string",
    }
    return mapping.get(passive, "")


def _compatible_types(passive: str) -> frozenset[str]:
    """Probe labels compatible with a passive type (not conflicts)."""
    compat: dict[str, frozenset[str]] = {
        "integer": frozenset({"integer", "float", "timestamp", "empty"}),
        "float": frozenset({"float", "integer", "empty"}),
        "boolean": frozenset({"boolean", "integer", "empty"}),
        "uuid": frozenset({"uuid", "string", "empty"}),
        "email": frozenset({"email", "string", "empty"}),
        "url": frozenset({"url", "string", "empty"}),
        "timestamp": frozenset({"timestamp", "iso_date", "integer", "empty"}),
        "hash": frozenset({"hash_md5", "string", "empty"}),
        "string": frozenset(set(TYPE_PROBE_MAP.keys())),
    }
    return compat.get(passive, frozenset({passive}))


# ---------------------------------------------------------------------------
# Negative evidence discipline
# ---------------------------------------------------------------------------

def tested_key_for_payload_type(payload_type: str) -> str:
    """
    Purpose:
        Normalize a probe payload_type into a ``tested{}`` family key.
    Side effects: None.
    """
    pt = (payload_type or "").strip()
    if pt.startswith("type:"):
        return pt
    if pt in TESTED_FAMILY_KEYS:
        return TESTED_FAMILY_KEYS[pt]
    # Type probes use bare labels (integer, uuid, …).
    if pt in TYPE_PROBE_MAP:
        return f"type:{pt}"
    return pt or "unknown"


def record_tested_outcome(
    profile: dict[str, Any],
    payload_type: str,
    *,
    outcome: str,
    confidence: int = 0,
    evidence_flow_ids: list[str] | None = None,
    always: bool = False,
) -> dict[str, Any]:
    """
    Purpose:
        Write ``tested.<family>`` for a probe outcome.

        By default records rejects and non-accept outcomes (negative evidence
        discipline).  When ``always=True``, also records accepts (useful for
        semantic families operators may want to see either way).

    Output: profile (mutated).
    Side effects: Mutates profile["tested"].
    """
    if not always and outcome in _SOFT_ACCEPT:
        # Positives live in observed.types / acceptance; tested is primarily
        # negative.  Exception: always=True for validation mapping.
        return profile
    key = tested_key_for_payload_type(payload_type)
    set_tested(
        profile,
        key,
        outcome=outcome,
        confidence=confidence,
        evidence_flow_ids=evidence_flow_ids,
    )
    return profile


def merge_type_tested(
    profile: dict[str, Any],
    type_outcomes: dict[str, dict[str, Any]],
) -> None:
    """
    Purpose:
        Ensure every **rejected** type family is present under tested.type:*.
    Side effects: Mutates profile["tested"].
    """
    for label, entry in type_outcomes.items():
        if not isinstance(entry, dict):
            continue
        if label.startswith("_"):
            continue
        outcome = str(entry.get("outcome") or "")
        if outcome != OUTCOME_REJECTED:
            continue
        flows = entry.get("evidence_flow_ids")
        if not isinstance(flows, list):
            flows = []
        record_tested_outcome(
            profile,
            label if label.startswith("type:") else f"type:{label}",
            outcome=OUTCOME_REJECTED,
            confidence=int(entry.get("confidence") or 0),
            evidence_flow_ids=flows or None,
            always=True,
        )


def types_summary_block(synth: TypeSynthesisResult) -> dict[str, Any]:
    """
    Purpose:
        Build observed.types meta + per-type map for the profile document.
        Keeps per-type entries and adds a ``_summary`` characteristic.
    Side effects: None.
    """
    out: dict[str, Any] = dict(synth.per_type)
    summary = empty_characteristic(
        state=synth.state if synth.state != "typed" else synth.primary,
        confidence=synth.confidence,
        uncertainty=synth.uncertainty,
    )
    summary["primary"] = synth.primary
    summary["passive_type"] = synth.passive_type
    if synth.conflict_note:
        summary["conflict_note"] = synth.conflict_note
    out["_summary"] = summary
    return out


def is_url_prioritized(
    semantic_type: str | None = None,
    param_name: str | None = None,
    examples: list[str] | None = None,
) -> bool:
    """
    Purpose:
        True when type_confirm should prioritize URL-shaped probes.
    Side effects: None.
    """
    passive = resolve_passive_type(semantic_type, examples, param_name)
    return passive == "url"


def looks_like_url_value(value: str) -> bool:
    """Heuristic: value is URL-shaped (for tests and call-sites)."""
    v = (value or "").strip()
    if not v:
        return False
    if re.match(r"^https?://", v, re.I):
        return True
    try:
        p = urlparse(v if "://" in v else f"http://{v}")
        return bool(p.netloc) and "." in p.netloc
    except Exception:
        return False
