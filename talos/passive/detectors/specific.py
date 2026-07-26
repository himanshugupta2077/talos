"""
Module: talos.passive.detectors.specific

Purpose:
    Stage 1 — rule-driven provider / structured secret patterns.

    Flow per document:
        1. Keyword prefilter (any rule keyword present in text, case-insensitive)
        2. Run compiled regex only for rules that pass the prefilter
           (or rules with empty keywords — always run)
        3. Emit RawMatch with base confidence metadata from the rule

    Caps matches per document via max_candidates.

Dependencies: talos.passive.detectors.base, rules_loader, models
Data flow: text + RuleIndex → list[RawMatch]
Side effects: None.
"""

from __future__ import annotations

from typing import Optional

from talos.passive.detectors.base import (
    build_raw_match,
    match_value_from_regex,
)
from talos.passive.models import RawMatch, SourceDocument
from talos.passive.rules_loader import CompiledRule, RuleIndex, get_rule_index


class SpecificPatternDetector:
    """
    Purpose:
        Keyword-prefilter + regex detector for YAML provider rules.

    Fields:
        _index — RuleIndex (compiled packs)
        _max_candidates — hard cap on matches emitted per detect() call
    """

    def __init__(
        self,
        index: Optional[RuleIndex] = None,
        *,
        max_candidates: int = 500,
    ) -> None:
        self._index = index if index is not None else get_rule_index()
        self._max_candidates = max(1, int(max_candidates))

    def detect(
        self,
        text: str,
        *,
        document: Optional[SourceDocument] = None,
        encoding_chain: Optional[list[str]] = None,
        decode_depth: int = 0,
    ) -> list[RawMatch]:
        """
        Purpose:
            Run Stage 1 specific rules against text.
        Input:
            text / document / encoding_chain / decode_depth
        Output:
            list[RawMatch] (capped)
        Side effects: None.
        """
        if not text:
            return []

        text_lower = text.lower()
        matches: list[RawMatch] = []
        seen: set[tuple[str, str, int]] = set()  # (rule_id, value, start)

        for rule in self._index.rules:
            if not _rule_prefilter(rule, text, text_lower):
                continue
            for pattern in rule.patterns:
                for m in pattern.finditer(text):
                    value, start, end = match_value_from_regex(m)
                    if not value or not value.strip():
                        continue
                    dedup_key = (rule.id, value, start)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)
                    matches.append(
                        build_raw_match(
                            detector_id=rule.id,
                            detector_family=rule.family,
                            category=rule.category,
                            secret_type=rule.secret_type,
                            raw_value=value,
                            match_start=start,
                            match_end=end,
                            text=text,
                            encoding_chain=encoding_chain,
                            decode_depth=decode_depth,
                            metadata={
                                "rule_name": rule.name,
                                "base_score": rule.confidence_score,
                                "base_level": rule.confidence_level,
                                "case_sensitive": rule.case_sensitive,
                                "finding_title": rule.finding_title,
                                "pack": rule.pack,
                                "stage": "specific",
                            },
                        )
                    )
                    if len(matches) >= self._max_candidates:
                        return matches
        return matches


def _rule_prefilter(rule: CompiledRule, text: str, text_lower: str) -> bool:
    """
    Purpose:
        Cheap gate before regex: require any keyword if the rule lists them.
    Input:
        rule / original text / lowercased text
    Output:
        True when regex should run
    Side effects: None.
    """
    if not rule.keywords:
        return True
    for kw in rule.keywords:
        # Prefer case-sensitive keyword match when keyword has uppercase
        # (e.g. AKIA); fall back to lower for mixed keywords.
        if kw in text or kw.lower() in text_lower:
            return True
    return False
