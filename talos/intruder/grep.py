"""
Module: talos.intruder.grep

Purpose:
    Online extract rules for Phase 3: regex capture from body/headers into
    grepped_json columns and optional project pool accumulation.

Dependencies: re, typing
Data flow:
    engine metrics + response → evaluate_grep_rules → {name: [captures]}
Side effects: None (pure).
"""

from __future__ import annotations

import re
from typing import Any, Optional

from talos.intruder.models import DEFAULT_GREP_MAX_MATCHES, ERR_INVALID_GREP


def validate_grep_rule(rule: dict[str, Any]) -> None:
    """
    Raise ValueError with ERR_INVALID_GREP prefix when a rule is malformed.
    """
    if not isinstance(rule, dict):
        raise ValueError(f"{ERR_INVALID_GREP}:rule_not_object")
    name = str(rule.get("name") or "").strip()
    if not name:
        raise ValueError(f"{ERR_INVALID_GREP}:missing_name")
    pattern = rule.get("regex") or rule.get("pattern")
    if not pattern:
        raise ValueError(f"{ERR_INVALID_GREP}:missing_regex:{name}")
    try:
        re.compile(str(pattern))
    except re.error as exc:
        raise ValueError(f"{ERR_INVALID_GREP}:bad_regex:{name}:{exc}") from exc
    group = rule.get("group", 1)
    try:
        int(group)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{ERR_INVALID_GREP}:bad_group:{name}") from exc


def evaluate_grep_rules(
    metrics: dict[str, Any],
    rules: list[dict[str, Any]],
    *,
    response_headers: Optional[dict[str, str]] = None,
) -> tuple[dict[str, list[str]], list[str]]:
    """
    Apply grep/extract rules to response metrics.

    Input:
        metrics — build_metrics_from_response output (uses body_text).
        rules — config grep list; each may include:
            name (required), regex/pattern (required), group (default 1),
            source (body|headers|header:<Name>), ignore_case, max_matches,
            tag_interesting (bool).
        response_headers — raw response headers for header sources.

    Output:
        (grepped_map, interesting_tags)
        grepped_map maps rule name → list of unique capture strings (order preserved).
        interesting_tags lists rule names that matched and have tag_interesting=true.
    """
    if not rules:
        return {}, []

    grepped: dict[str, list[str]] = {}
    tags: list[str] = []
    body = str(metrics.get("body_text") or "")
    headers = response_headers or {}

    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        name = str(rule.get("name") or f"g{i}").strip()
        pattern = rule.get("regex") or rule.get("pattern")
        if not name or not pattern:
            continue
        flags = re.IGNORECASE if rule.get("ignore_case") else 0
        try:
            cre = re.compile(str(pattern), flags)
        except re.error:
            continue

        haystack = _source_text(rule, body, headers)
        if haystack is None:
            continue

        group = int(rule.get("group", 1))
        max_matches = int(rule.get("max_matches") or DEFAULT_GREP_MAX_MATCHES)
        max_matches = max(1, min(max_matches, 1000))

        found: list[str] = []
        seen: set[str] = set()
        for m in cre.finditer(haystack):
            try:
                if group == 0:
                    val = m.group(0)
                else:
                    val = m.group(group)
            except IndexError:
                val = m.group(0)
            if val is None:
                continue
            s = str(val)
            if s in seen:
                continue
            seen.add(s)
            found.append(s)
            if len(found) >= max_matches:
                break

        if found:
            grepped[name] = found
            if rule.get("tag_interesting"):
                tags.append(name)

    return grepped, tags


def _source_text(
    rule: dict[str, Any],
    body: str,
    headers: dict[str, str],
) -> Optional[str]:
    source = str(rule.get("source") or "body").strip().lower()
    if source in ("", "body"):
        return body
    if source == "headers":
        # Flatten header block as "Name: value\\n"
        parts = []
        for k, v in headers.items():
            parts.append(f"{k}: {v}")
        return "\n".join(parts)
    if source.startswith("header:"):
        want = source.split(":", 1)[1].strip().lower()
        for k, v in headers.items():
            if k.lower() == want:
                return str(v)
        return ""
    # Unknown source → body fallback
    return body


def rules_to_pool(
    grepped: dict[str, list[str]],
    rules: list[dict[str, Any]],
) -> dict[str, list[str]]:
    """
    Filter grepped values to those rules that accumulate into pools (default true).

    Output: {pool_name: values} for pool upsert.
    """
    to_pool_names: dict[str, bool] = {}
    for i, rule in enumerate(rules or []):
        if not isinstance(rule, dict):
            continue
        name = str(rule.get("name") or f"g{i}").strip()
        if not name:
            continue
        # to_pool defaults True; explicit false skips
        to_pool_names[name] = bool(rule.get("to_pool", True))

    out: dict[str, list[str]] = {}
    for name, values in (grepped or {}).items():
        if to_pool_names.get(name, True):
            out[name] = list(values)
    return out
