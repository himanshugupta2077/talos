"""
Module: talos.passive.rules_loader

Purpose:
    Load and validate YAML rule packs from talos/passive/rules/*.yaml.
    Compile regex patterns once; build keyword prefilter indexes.

    Fail closed: a bad rule file is logged and skipped; the worker never
    crashes because one pack is invalid.  Empty pattern lists are allowed
    (documentation / keyword-only packs such as PEM markers).

Rule schema (required fields):
    id, name, family, category, patterns (list; may be empty when disabled)

Optional fields:
    secret_type, confidence_score, confidence_level, keywords, enabled,
    case_sensitive, finding_title, description

Dependencies: pathlib, re, logging, yaml (PyYAML)
Data flow: package rules/ → load_rule_packs() → list[CompiledRule]
Side effects: Reads YAML files from disk; logs warnings on invalid rules.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from talos.passive.constants import (
    CATEGORY_SECRET,
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    CONFIDENCE_LEVELS,
    DETECTOR_FAMILY_PROVIDER,
)

logger = logging.getLogger(__name__)

# Default directory next to this module: talos/passive/rules/
_DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "rules"

# Packs that are not provider regex rules (loaded for metadata / keys only).
_METADATA_PACK_NAMES = frozenset({"generic.yaml"})


@dataclass(frozen=True)
class CompiledRule:
    """
    Purpose:
        One validated, regex-compiled detector rule ready for matching.

    Fields:
        id / name / family / category / secret_type — identity labels
        patterns — compiled re.Pattern list (capture group 1 preferred for value)
        keywords — lowercase prefilter strings (any present → run patterns)
        confidence_score / confidence_level — base score before scoring adjustments
        case_sensitive — fingerprint case policy
        finding_title — Phase 8 title hint
        pack — source YAML filename
        enabled — when False, specific detector skips this rule
    """

    id: str
    name: str
    family: str
    category: str
    secret_type: str
    patterns: tuple[re.Pattern[str], ...]
    keywords: tuple[str, ...] = ()
    confidence_score: int = 90
    confidence_level: str = CONFIDENCE_CONFIRMED_PATTERN
    case_sensitive: bool = True
    finding_title: str = ""
    pack: str = ""
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class GenericRulePack:
    """
    Purpose:
        Parsed generic.yaml content for contextual / entropy detectors.
    """

    sensitive_keys: tuple[str, ...]
    entropy_boost_keywords: tuple[str, ...]


@dataclass
class RuleIndex:
    """
    Purpose:
        In-memory index of all loaded rules + generic pack.

    Fields:
        rules — enabled CompiledRule instances (provider / pem / …)
        all_rules — includes disabled (for CLI list later)
        generic — sensitive key list from generic.yaml
        keyword_to_rule_ids — lowercase keyword → rule ids (prefilter)
        load_errors — (pack, message) pairs from failed closed loads
    """

    rules: list[CompiledRule] = field(default_factory=list)
    all_rules: list[CompiledRule] = field(default_factory=list)
    generic: Optional[GenericRulePack] = None
    keyword_to_rule_ids: dict[str, list[str]] = field(default_factory=dict)
    load_errors: list[tuple[str, str]] = field(default_factory=list)


def default_rules_dir() -> Path:
    """
    Purpose:
        Return the packaged rules directory path.
    Output:
        Path to talos/passive/rules
    Side effects: None.
    """
    return _DEFAULT_RULES_DIR


def load_rule_packs(
    rules_dir: Optional[Path] = None,
    *,
    fail_closed: bool = True,
) -> RuleIndex:
    """
    Purpose:
        Load every *.yaml rule pack from rules_dir, validate, compile regex.

    Input:
        rules_dir   — directory of YAML packs (default: packaged rules/)
        fail_closed — if True (default), invalid packs are skipped with WARNING;
                      if False, re-raise first validation error (tests)

    Output:
        RuleIndex with compiled rules and optional generic pack.

    Side effects:
        Reads YAML files; logs WARNING/ERROR on failures; never raises when
        fail_closed=True (worker-safe).
    """
    directory = Path(rules_dir) if rules_dir is not None else _DEFAULT_RULES_DIR
    index = RuleIndex()

    if not directory.is_dir():
        msg = f"Rules directory missing: {directory}"
        logger.error(msg)
        index.load_errors.append((str(directory), msg))
        return index

    paths = sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml"))
    if not paths:
        logger.warning("No YAML rule packs found in %s", directory)
        return index

    for path in paths:
        try:
            _load_one_pack(path, index)
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "Passive rule pack failed closed — pack=%s error=%s",
                path.name,
                err,
            )
            index.load_errors.append((path.name, err))
            if not fail_closed:
                raise

    # Build keyword → rule id index for enabled rules with patterns or keywords
    for rule in index.rules:
        for kw in rule.keywords:
            key = kw.lower()
            index.keyword_to_rule_ids.setdefault(key, []).append(rule.id)

    logger.info(
        "Passive rules loaded — packs=%d rules=%d enabled=%d errors=%d",
        len(paths),
        len(index.all_rules),
        len(index.rules),
        len(index.load_errors),
    )
    return index


def _load_one_pack(path: Path, index: RuleIndex) -> None:
    """
    Purpose:
        Parse one YAML pack into CompiledRule or GenericRulePack.
    Input:
        path  — YAML file
        index — mutated in place
    Side effects:
        Mutates index; may raise ValueError on schema errors.
    """
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    if data is None:
        return
    if not isinstance(data, dict):
        raise ValueError(f"rule pack root must be a mapping, got {type(data).__name__}")

    if path.name in _METADATA_PACK_NAMES or "sensitive_keys" in data:
        index.generic = _parse_generic_pack(data)
        return

    rules_raw = data.get("rules")
    if rules_raw is None:
        raise ValueError("missing 'rules' list")
    if not isinstance(rules_raw, list):
        raise ValueError("'rules' must be a list")

    for item in rules_raw:
        if not isinstance(item, dict):
            raise ValueError("each rule must be a mapping")
        compiled = _compile_rule(item, pack=path.name)
        index.all_rules.append(compiled)
        if compiled.enabled and compiled.patterns:
            index.rules.append(compiled)
        elif compiled.enabled and not compiled.patterns:
            # Keyword-only / disabled-pattern documentation rules stay in all_rules
            pass


def _parse_generic_pack(data: dict[str, Any]) -> GenericRulePack:
    """
    Purpose:
        Parse generic.yaml sensitive key lists.
    Input:
        data — loaded YAML mapping
    Output:
        GenericRulePack
    Side effects: None.
    """
    keys = data.get("sensitive_keys") or []
    boost = data.get("entropy_boost_keywords") or []
    if not isinstance(keys, list) or not isinstance(boost, list):
        raise ValueError("sensitive_keys and entropy_boost_keywords must be lists")
    return GenericRulePack(
        sensitive_keys=tuple(str(k) for k in keys if k),
        entropy_boost_keywords=tuple(str(k) for k in boost if k),
    )


def _compile_rule(item: dict[str, Any], *, pack: str) -> CompiledRule:
    """
    Purpose:
        Validate one rule mapping and compile its regex patterns.
    Input:
        item — rule dict from YAML
        pack — source filename for diagnostics
    Output:
        CompiledRule
    Side effects: None (raises ValueError on invalid schema / regex).
    """
    rule_id = str(item.get("id") or "").strip()
    name = str(item.get("name") or "").strip()
    family = str(item.get("family") or DETECTOR_FAMILY_PROVIDER).strip()
    category = str(item.get("category") or CATEGORY_SECRET).strip()
    if not rule_id:
        raise ValueError("rule missing required field: id")
    if not name:
        raise ValueError(f"rule {rule_id!r} missing required field: name")
    if not family:
        raise ValueError(f"rule {rule_id!r} missing required field: family")
    if not category:
        raise ValueError(f"rule {rule_id!r} missing required field: category")

    patterns_raw = item.get("patterns")
    if patterns_raw is None:
        raise ValueError(f"rule {rule_id!r} missing required field: patterns")
    if not isinstance(patterns_raw, list):
        raise ValueError(f"rule {rule_id!r} patterns must be a list")

    compiled_patterns: list[re.Pattern[str]] = []
    for i, pat in enumerate(patterns_raw):
        if not isinstance(pat, str) or not pat:
            raise ValueError(f"rule {rule_id!r} pattern[{i}] must be a non-empty string")
        try:
            compiled_patterns.append(re.compile(pat))
        except re.error as exc:
            raise ValueError(
                f"rule {rule_id!r} pattern[{i}] invalid regex: {exc}"
            ) from exc

    keywords_raw = item.get("keywords") or []
    if not isinstance(keywords_raw, list):
        raise ValueError(f"rule {rule_id!r} keywords must be a list")
    keywords = tuple(str(k) for k in keywords_raw if k)

    score = int(item.get("confidence_score") or 90)
    score = max(0, min(100, score))
    level = str(item.get("confidence_level") or "").strip().upper()
    if level not in CONFIDENCE_LEVELS:
        level = _level_from_score(score)

    secret_type = str(item.get("secret_type") or rule_id).strip()
    enabled = bool(item.get("enabled", True))
    case_sensitive = bool(item.get("case_sensitive", True))
    finding_title = str(item.get("finding_title") or name).strip()

    return CompiledRule(
        id=rule_id,
        name=name,
        family=family,
        category=category,
        secret_type=secret_type,
        patterns=tuple(compiled_patterns),
        keywords=keywords,
        confidence_score=score,
        confidence_level=level,
        case_sensitive=case_sensitive,
        finding_title=finding_title,
        pack=pack,
        enabled=enabled,
        metadata={
            "description": str(item.get("description") or ""),
        },
    )


def _level_from_score(score: int) -> str:
    """Map numeric score to confidence level label. Side effects: None."""
    from talos.passive.constants import (
        CONFIDENCE_MEDIUM,
        CONFIDENCE_OBSERVATION_ONLY,
        SCORE_CONFIRMED_PATTERN_MIN,
        SCORE_HIGH_MIN,
        SCORE_MEDIUM_MIN,
    )

    if score >= SCORE_CONFIRMED_PATTERN_MIN:
        return CONFIDENCE_CONFIRMED_PATTERN
    if score >= SCORE_HIGH_MIN:
        return CONFIDENCE_HIGH
    if score >= SCORE_MEDIUM_MIN:
        return CONFIDENCE_MEDIUM
    return CONFIDENCE_OBSERVATION_ONLY


# Module-level cache so workers share one compiled index.
_CACHED_INDEX: Optional[RuleIndex] = None


def get_rule_index(
    rules_dir: Optional[Path] = None,
    *,
    reload: bool = False,
) -> RuleIndex:
    """
    Purpose:
        Return a process-wide RuleIndex (load once unless reload=True).
    Input:
        rules_dir — optional override (bypasses cache when set)
        reload    — force re-read of default packs
    Output:
        RuleIndex
    Side effects:
        May load YAML from disk on first call / reload.
    """
    global _CACHED_INDEX
    if rules_dir is not None:
        return load_rule_packs(rules_dir)
    if _CACHED_INDEX is None or reload:
        _CACHED_INDEX = load_rule_packs()
    return _CACHED_INDEX
