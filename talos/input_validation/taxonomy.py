"""
Module: talos.input_validation.taxonomy

Purpose:
    Module 6 — Character taxonomy map and class-tier probe selection.

    Attack modules consume **class labels** (quote, delimiter, operator…),
    not that character #17 was tested.  This module:

        - Maps each CHARSET_CLASSES label → representative chars + drill-down sets
        - Selects which classes to probe by budget tier / reflection signal
        - Builds the character probe list used by planner ``char_drilldown``
        - Aggregates per-char outcomes into class-level acceptance entries

    Pure computation only — no HTTP, no SQLite.

Design (Section 0.4 + Module 6 brief)
    Core classes          — always when string-like (standard+)
    Injection-relevant    — when reflection or string-like (standard+)
    Structure / control   — deep+ only (control, null, unicode)
    Exhaustive            — full legacy IV_TEST_CHARS list

Dependencies: profile.CHARSET_CLASSES
Data flow:
    planner emits char_drilldown → engine.char_probes_for_strategy()
    synthesize: char_to_classes() + aggregate_class_outcomes()
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from talos.input_validation.outcomes import (
    OUTCOME_ACCEPTED,
    OUTCOME_ENCODED,
    OUTCOME_MODIFIED,
    OUTCOME_NORMALIZED,
    OUTCOME_REJECTED,
    OUTCOME_UNKNOWN,
)
from talos.input_validation.profile import CHARSET_CLASSES


# ---------------------------------------------------------------------------
# Class tiers
# ---------------------------------------------------------------------------

# Always tested (if characters analysis on and string-like).
CORE_CLASSES: tuple[str, ...] = (
    "alpha",
    "digit",
    "separator",
    "whitespace",
)

# Injection-relevant: when reflection or string type is plausible.
INJECTION_CLASSES: tuple[str, ...] = (
    "quote",
    "delimiter",
    "operator",
    "markup",
    "path",
    "encoding_meta",
    "comment",
)

# Structure / control: deep and exhaustive only.
STRUCTURE_CLASSES: tuple[str, ...] = (
    "control",
    "null",
    "unicode",
)

# Soft-accept outcomes for class aggregation.
_SOFT_ACCEPT: frozenset[str] = frozenset({
    OUTCOME_ACCEPTED,
    OUTCOME_MODIFIED,
    OUTCOME_ENCODED,
    OUTCOME_NORMALIZED,
})


# ---------------------------------------------------------------------------
# Taxonomy map: class → representatives + optional drill-down chars
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ClassSpec:
    """
    One taxonomy class definition.

    Fields:
        class_name    — CHARSET_CLASSES label.
        representatives — chars always tried first (typically one).
        drilldown     — extra chars when deep / class accepted / uncertain.
    """

    class_name: str
    representatives: tuple[str, ...]
    drilldown: tuple[str, ...] = ()


# Canonical map.  Representatives align with multiprobe DEFAULT_CLASS_SAMPLES
# so multiprobe and drill-down share the same class anchors.
CLASS_SPECS: dict[str, ClassSpec] = {
    "alpha": ClassSpec("alpha", ("a",), ("z", "A")),
    "digit": ClassSpec("digit", ("7",), ("0", "1", "9")),
    "alnum": ClassSpec("alnum", ("a", "7"), ()),  # derived; rarely probed alone
    "whitespace": ClassSpec("whitespace", (" ",), ("\t", "\n")),
    "control": ClassSpec("control", ("\x01",), ("\x1f", "\x7f")),
    "quote": ClassSpec("quote", ("'",), ('"', "`")),
    "delimiter": ClassSpec("delimiter", (";",), (",", ":", "(", ")", "[", "]")),
    "operator": ClassSpec("operator", ("+",), ("=",)),
    "comment": ClassSpec("comment", ("#",), ()),
    "path": ClassSpec("path", ("/",), ("\\", ".", "-")),
    "separator": ClassSpec("separator", ("_",), ("-", ".", "@")),
    "unicode": ClassSpec("unicode", ("é",), ("中",)),
    "null": ClassSpec("null", ("\x00",), ()),
    "markup": ClassSpec("markup", ("<",), (">", "{", "}")),
    "encoding_meta": ClassSpec("encoding_meta", ("%",), ("+", "&", "?")),
}

# Single-char → primary taxonomy classes (for synthesis aggregation).
# First label is the primary class used in attempt hypotheses.
_CHAR_TO_CLASSES: dict[str, tuple[str, ...]] = {}


def _build_char_to_classes() -> dict[str, tuple[str, ...]]:
    """Invert CLASS_SPECS into char → class tuple map. Side effects: None."""
    mapping: dict[str, list[str]] = {}
    for cls_name, spec in CLASS_SPECS.items():
        if cls_name == "alnum":
            continue  # filled via alpha/digit membership below
        for ch in (*spec.representatives, *spec.drilldown):
            mapping.setdefault(ch, [])
            if cls_name not in mapping[ch]:
                mapping[ch].append(cls_name)
    # alnum is secondary for alpha/digit chars
    for ch, classes in list(mapping.items()):
        if "alpha" in classes or "digit" in classes:
            if "alnum" not in classes:
                classes.append("alnum")
    # Legacy IV_TEST_CHARS extras not already listed
    legacy_extras: dict[str, tuple[str, ...]] = {
        "1": ("digit", "alnum"),
        "a": ("alpha", "alnum"),
        ",": ("delimiter",),
        ":": ("delimiter",),
        "(": ("delimiter",),
        ")": ("delimiter",),
        "[": ("delimiter",),
        "]": ("delimiter",),
        "{": ("delimiter", "markup"),
        "}": ("delimiter", "markup"),
        ">": ("markup", "operator"),
        "<": ("markup", "operator"),
        "\\": ("path", "separator"),
        ".": ("separator", "path"),
        "-": ("separator", "path"),
        "@": ("separator",),
        "&": ("delimiter", "encoding_meta"),
        "?": ("delimiter", "path"),
        "=": ("operator",),
        "+": ("operator", "encoding_meta"),
        "%": ("encoding_meta",),
        "#": ("comment", "operator"),
        " ": ("whitespace",),
        "_": ("separator",),
        "/": ("path", "separator"),
        "'": ("quote",),
        '"': ("quote",),
        "`": ("quote",),
        ";": ("delimiter",),
        "\x00": ("null",),
    }
    for ch, classes in legacy_extras.items():
        existing = mapping.setdefault(ch, [])
        for c in classes:
            if c not in existing:
                existing.append(c)
    return {ch: tuple(cs) for ch, cs in mapping.items()}


_CHAR_TO_CLASSES = _build_char_to_classes()

# Full extended character list for exhaustive mode (legacy 30 + structure).
# Order stable for resume/cache payload_index stability when possible.
EXHAUSTIVE_TEST_CHARS: tuple[str, ...] = (
    "a", "1", "_", "-", ".", " ", ",", ":", ";",
    "'", '"', "`", "<", ">", "(", ")", "[", "]",
    "{", "}", "/", "\\", "%", "+", "=", "#", "@", "&", "?",
    "\x00", "\x01", "é",
)


# ---------------------------------------------------------------------------
# Public API — class selection
# ---------------------------------------------------------------------------

def classes_for_tier(
    strategy: str,
    *,
    reflection_state: str = "unknown",
    include_injection: bool | None = None,
) -> list[str]:
    """
    Purpose:
        Select taxonomy class labels to probe under a budget tier.

    Input:
        strategy         — quick|standard|deep|exhaustive.
        reflection_state — reflected|not_reflected|unknown|conflicting.
        include_injection — override; default: True unless not_reflected on quick.

    Output:
        Ordered unique class names (subset of CHARSET_CLASSES).

    Side effects: None.
    """
    tier = (strategy or "standard").lower().strip()
    if include_injection is None:
        # Injection classes still useful when not reflected (filter behavior),
        # but quick skips them to stay within budget.
        include_injection = not (
            tier == "quick" and reflection_state == "not_reflected"
        )

    selected: list[str] = []

    def _add(names: tuple[str, ...]) -> None:
        for n in names:
            if n in CHARSET_CLASSES and n not in selected and n != "alnum":
                selected.append(n)

    if tier == "quick":
        _add(CORE_CLASSES)
        return selected

    _add(CORE_CLASSES)
    if include_injection:
        _add(INJECTION_CLASSES)

    if tier in ("deep", "exhaustive"):
        _add(STRUCTURE_CLASSES)

    return selected


def chars_for_classes(
    class_names: list[str] | tuple[str, ...],
    *,
    drilldown: bool = False,
    skip_known: dict[str, str] | None = None,
) -> list[str]:
    """
    Purpose:
        Expand class labels to unique representative (and optional drill-down)
        characters.  Optionally skip classes already known with high certainty
        from multiprobe (outcome accepted/rejected).

    Input:
        class_names — taxonomy labels to expand.
        drilldown   — include ClassSpec.drilldown chars.
        skip_known  — optional class → outcome map; skip class if outcome is
                      accepted or rejected (already characterized).

    Output:
        Ordered unique single-character strings.

    Side effects: None.
    """
    skip = skip_known or {}
    seen: set[str] = set()
    out: list[str] = []
    for name in class_names:
        if name not in CLASS_SPECS:
            continue
        outcome = (skip.get(name) or "").lower()
        if outcome in (OUTCOME_ACCEPTED, OUTCOME_REJECTED, "encoded", "normalized"):
            # Still allow drill-down for accepted injection classes when asked.
            if not (drilldown and name in INJECTION_CLASSES and outcome in _SOFT_ACCEPT):
                if not drilldown or outcome == OUTCOME_REJECTED:
                    continue
        spec = CLASS_SPECS[name]
        for ch in spec.representatives:
            if ch not in seen:
                seen.add(ch)
                out.append(ch)
        if drilldown:
            for ch in spec.drilldown:
                if ch not in seen:
                    seen.add(ch)
                    out.append(ch)
    return out


def char_probes_for_strategy(
    strategy: str,
    *,
    reflection_state: str = "unknown",
    known_class_outcomes: dict[str, str] | None = None,
    force_full: bool = False,
    max_chars: int | None = None,
) -> list[tuple[str, str]]:
    """
    Purpose:
        Build (payload_type, char) pairs for character / char_drilldown jobs.

        Standard path: one representative per selected class (not full 30-char
        list).  Deep: representatives + drill-down for injection classes.
        Exhaustive: extended character list (legacy matrix + structure).

    Input:
        strategy             — budget tier name.
        reflection_state     — planner reflection signal.
        known_class_outcomes — multiprobe-derived class → outcome (skip known).
        force_full           — True → exhaustive list regardless of strategy.
        max_chars            — hard cap on number of chars returned.

    Output:
        list of ("character", char) pairs (empty when no work).

    Side effects: None.
    """
    tier = (strategy or "standard").lower().strip()
    if force_full or tier == "exhaustive":
        chars = list(EXHAUSTIVE_TEST_CHARS)
    else:
        classes = classes_for_tier(tier, reflection_state=reflection_state)
        drilldown = tier == "deep"
        # Under standard, skip classes multiprobe already settled.
        skip = known_class_outcomes if tier in ("quick", "standard") else None
        # Deep still drills representatives for all selected classes; skip only
        # when class was rejected (no point probing more of a blocked class).
        if tier == "deep" and known_class_outcomes:
            skip = {
                k: v for k, v in known_class_outcomes.items()
                if (v or "").lower() == OUTCOME_REJECTED
            }
        chars = chars_for_classes(classes, drilldown=drilldown, skip_known=skip)

    if max_chars is not None and max_chars > 0:
        chars = chars[: int(max_chars)]

    return [("character", c) for c in chars]


def estimated_char_probe_count(
    strategy: str,
    *,
    reflection_state: str = "unknown",
    known_class_outcomes: dict[str, str] | None = None,
) -> int:
    """
    Purpose:
        Planner estimate for char_drilldown estimated_requests.
    Side effects: None.
    """
    return len(
        char_probes_for_strategy(
            strategy,
            reflection_state=reflection_state,
            known_class_outcomes=known_class_outcomes,
        )
    )


# ---------------------------------------------------------------------------
# Public API — char → classes + aggregation
# ---------------------------------------------------------------------------

def char_to_classes(char: str) -> list[str]:
    """
    Purpose:
        Map a single character (or short payload) to charset taxonomy labels.
        Non-single-char payloads return [] (except explicit null byte).

    Output: list of known CHARSET_CLASSES labels (may be empty).
    Side effects: None.
    """
    if char == "\x00":
        return ["null"]
    if not char or len(char) != 1:
        return []
    classes = list(_CHAR_TO_CLASSES.get(char, ()))
    if not classes:
        code = ord(char)
        if char.isalpha():
            classes = ["alpha", "alnum"]
        elif char.isdigit():
            classes = ["digit", "alnum"]
        elif char.isspace():
            classes = ["whitespace"]
        elif code < 32 or code == 127:
            classes = ["control"]
        elif code > 127:
            classes = ["unicode"]
        else:
            classes = ["separator"]
    return [c for c in classes if c in CHARSET_CLASSES]


def aggregate_class_outcomes(
    observations: list[tuple[str, str, int, str]],
) -> dict[str, dict[str, Any]]:
    """
    Purpose:
        Fold (class, outcome, confidence, flow_id) rows into class acceptance
        entries suitable for observed.acceptance.classes.

    Input:
        observations — list of (class_name, outcome, confidence, flow_id).

    Output:
        class_name → {outcome, confidence, evidence_flow_ids, ...}

    Side effects: None.
    """
    buckets: dict[str, list[tuple[str, int, str]]] = {}
    for cls, outcome, conf, flow_id in observations:
        if not cls or cls not in CHARSET_CLASSES:
            continue
        buckets.setdefault(str(cls), []).append(
            (str(outcome or OUTCOME_UNKNOWN), int(conf or 0), str(flow_id or ""))
        )
    result: dict[str, dict[str, Any]] = {}
    for cls, rows in buckets.items():
        result[cls] = _majority_class_entry(rows)
    return result


def _majority_class_entry(
    outcomes: list[tuple[str, int, str]],
) -> dict[str, Any]:
    """Pick majority outcome; confidence = max among majority voters."""
    if not outcomes:
        return {
            "outcome": OUTCOME_UNKNOWN,
            "confidence": 0,
            "evidence_flow_ids": [],
        }
    counts: dict[str, int] = {}
    conf_by: dict[str, int] = {}
    flows: list[str] = []
    for outcome, conf, flow in outcomes:
        counts[outcome] = counts.get(outcome, 0) + 1
        conf_by[outcome] = max(conf_by.get(outcome, 0), conf)
        if flow and flow not in flows:
            flows.append(flow)
    # Prefer soft-accept if tied with unknown; prefer rejected when clear.
    best = max(counts.keys(), key=lambda o: (counts[o], conf_by.get(o, 0)))
    return {
        "outcome": best,
        "confidence": conf_by.get(best, 0),
        "evidence_flow_ids": flows[:20],
    }


def multiprobe_default_samples() -> tuple[tuple[str, str], ...]:
    """
    Purpose:
        Representative (class, sample) pairs for multiprobe payloads.
        Samples must be single-char and free of multiprobe separators.
    Output: ordered tuple for multiprobe.DEFAULT_CLASS_SAMPLES alignment.
    Side effects: None.
    """
    # Prefer multiprobe-safe classes (no '=' in sample; null is allowed).
    order = (
        "alpha", "digit", "whitespace", "quote", "delimiter", "operator",
        "markup", "path", "separator", "encoding_meta", "comment", "null",
    )
    out: list[tuple[str, str]] = []
    for name in order:
        spec = CLASS_SPECS.get(name)
        if not spec or not spec.representatives:
            continue
        sample = spec.representatives[0]
        if sample == "=":
            continue
        out.append((name, sample))
    return tuple(out)


# Re-export soft-accept set for synthesizer length/class logic.
TAXONOMY_SOFT_ACCEPT = _SOFT_ACCEPT
"""Outcomes treated as acceptance for taxonomy aggregation."""
