"""
Module: talos.url_sink.name_classify

Purpose:
    Pure parameter-name → sink category classifier.
    Normalizes camelCase / snake_case / kebab-case / dotted paths, then matches
    against the categorized catalog. Returns primary + all matching categories.

    Nested leaf names use only the final segment for catalog match
    (e.g. config.oauth.metadata → leaf "metadata"), while the full path is
    retained for evidence.

Dependencies: re, dataclasses, talos.url_sink.catalog
Data flow: param name → NameClassification
Side effects: None.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from talos.url_sink.catalog import (
    NAME_CATEGORIES,
    primary_category,
)

# Split camelCase / PascalCase boundaries.
_CAMEL_RE = re.compile(
    r"([a-z0-9])([A-Z])"  # aB → a_B
)
_CAMEL_ACRONYM_RE = re.compile(
    r"([A-Z]+)([A-Z][a-z])"  # HTTPSRedirect → HTTPS_Redirect
)
# Non-identifier separators → underscore
_SEP_RE = re.compile(r"[\s\-./]+")
# Collapse repeated underscores
_MULTI_US_RE = re.compile(r"_+")


@dataclass(frozen=True, slots=True)
class NameClassification:
    """
    Purpose:
        Immutable name-side sink classification for one parameter.
    Fields:
        raw_name          — original parameter name (may be dotted path).
        leaf_name         — final segment used for catalog match.
        normalized        — normalized leaf token (snake_case lower).
        name_category     — primary category or None.
        name_categories   — all matching categories (stable priority order).
        evidence          — machine-readable tokens (e.g. name:callback_url).
        score_hint        — modest 0–35 score contribution from name alone.
    Side effects: None.
    """

    raw_name: str
    leaf_name: str
    normalized: str
    name_category: str | None
    name_categories: tuple[str, ...]
    evidence: tuple[str, ...]
    score_hint: int = 0

    def to_dict(self) -> dict:
        """Serialize for tests / merge."""
        return {
            "raw_name": self.raw_name,
            "leaf_name": self.leaf_name,
            "normalized": self.normalized,
            "name_category": self.name_category,
            "name_categories": list(self.name_categories),
            "evidence": list(self.evidence),
            "score_hint": self.score_hint,
        }


def leaf_param_name(name: str) -> str:
    """
    Purpose:
        Extract the leaf segment from a dotted / bracketed parameter path.
    Input:
        name — e.g. "config.oauth.metadata", "variables.user.avatar_url",
               "items[].url".
    Output:
        Leaf string (last non-empty segment after splitting on '.').
    Side effects: None.
    """
    if not name:
        return ""
    # Strip array markers for matching: items[].url → items / url
    cleaned = name.replace("[]", "")
    parts = [p for p in cleaned.split(".") if p]
    if not parts:
        return name
    return parts[-1]


def normalize_param_name(name: str) -> str:
    """
    Purpose:
        Normalize a parameter name (or leaf) for catalog lookup.
        camelCase / PascalCase → snake; hyphens/dots/spaces → underscore;
        lowercased; non-alnum stripped to underscore.
    Input:
        name — raw or leaf name.
    Output:
        Normalized snake_case token (may be empty).
    Side effects: None.
    """
    if not name:
        return ""
    s = str(name).strip()
    # Acronyms then camelCase
    s = _CAMEL_ACRONYM_RE.sub(r"\1_\2", s)
    s = _CAMEL_RE.sub(r"\1_\2", s)
    s = _SEP_RE.sub("_", s)
    s = re.sub(r"[^A-Za-z0-9_]", "_", s)
    s = _MULTI_US_RE.sub("_", s)
    s = s.strip("_").lower()
    return s


def classify_name(name: str | None) -> NameClassification:
    """
    Purpose:
        Classify a parameter name into zero or more sink categories.
    Input:
        name — full parameter name (may be dotted path).
    Output:
        NameClassification (empty categories when no catalog hit).
    Side effects: None.
    """
    raw = str(name or "")
    leaf = leaf_param_name(raw)
    normalized = normalize_param_name(leaf)
    if not normalized:
        return NameClassification(
            raw_name=raw,
            leaf_name=leaf,
            normalized="",
            name_category=None,
            name_categories=(),
            evidence=(),
            score_hint=0,
        )

    matches: list[str] = []
    # Exact normalized match against each category set.
    for category, names in NAME_CATEGORIES.items():
        if normalized in names:
            matches.append(category)
            continue
        # Also try compact form without underscores (returnUrl → returnurl).
        compact = normalized.replace("_", "")
        if compact and compact in names:
            matches.append(category)
            continue
        # Token-contains for multi-word: image_url matches via exact image_url
        # already; also match when normalized equals a catalog key after
        # stripping trailing _url / _uri / _href.
        for suffix in ("_url", "_uri", "_href", "_link", "_path"):
            if normalized.endswith(suffix):
                stem = normalized[: -len(suffix)]
                if stem and stem in names:
                    matches.append(category)
                    break

    # Deduplicate preserving first-seen order, then reorder by primary priority.
    matches = list(dict.fromkeys(matches))
    primary = primary_category(matches)
    if primary and primary in matches:
        ordered = [primary] + [c for c in matches if c != primary]
    else:
        ordered = matches

    evidence: list[str] = []
    if ordered:
        evidence.append(f"name:{leaf}" if leaf else f"name:{normalized}")
        for cat in ordered:
            evidence.append(f"name_category:{cat}")

    # Name-only modest score: stronger for oauth/webhook/redirect/remote_fetch.
    score_hint = 0
    if ordered:
        if primary in ("oauth", "webhook", "redirect"):
            score_hint = 30
        elif primary in ("remote_fetch", "remote_asset", "import_metadata"):
            score_hint = 25
        elif primary in ("infrastructure", "network_probe"):
            score_hint = 22
        elif primary == "path_like":
            score_hint = 18
        else:
            score_hint = 15

    return NameClassification(
        raw_name=raw,
        leaf_name=leaf,
        normalized=normalized,
        name_category=primary,
        name_categories=tuple(ordered),
        evidence=tuple(evidence),
        score_hint=score_hint,
    )
