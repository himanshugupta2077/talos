"""
Module: talos.intruder.match

Purpose:
    Online match rules for Phase 1: status, body_contains, regex,
    length_delta_gt, time_gt_ms. Tags interesting results.
"""

from __future__ import annotations

import re
from typing import Any, Optional


def evaluate_match_rules(
    metrics: dict[str, Any],
    rules: list[dict[str, Any]],
    *,
    baseline: Optional[dict[str, Any]] = None,
) -> list[str]:
    """
    Evaluate match rules against attempt metrics.
    Returns list of matching rule tags (or synthetic rule ids).
    """
    if not rules:
        return []
    tags: list[str] = []
    baseline = baseline or {}
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue
        tag = str(rule.get("tag") or rule.get("id") or f"m{i}")
        if _rule_matches(rule, metrics, baseline):
            tags.append(tag)
    return tags


def _rule_matches(
    rule: dict[str, Any],
    metrics: dict[str, Any],
    baseline: dict[str, Any],
) -> bool:
    # status: exact or list
    if "status" in rule and rule["status"] is not None:
        want = rule["status"]
        got = metrics.get("status_code")
        if isinstance(want, list):
            if got not in want:
                return False
        elif got != want:
            return False

    # body_contains
    if rule.get("body_contains") is not None:
        needle = str(rule["body_contains"])
        body = metrics.get("body_text") or ""
        if needle not in body:
            return False

    # regex
    if rule.get("regex"):
        pattern = str(rule["regex"])
        body = metrics.get("body_text") or ""
        flags = re.IGNORECASE if rule.get("ignore_case") else 0
        try:
            if not re.search(pattern, body, flags):
                return False
        except re.error:
            return False

    # length_delta_gt vs baseline body_length
    if rule.get("length_delta_gt") is not None:
        thr = float(rule["length_delta_gt"])
        base_len = baseline.get("body_length")
        if base_len is None:
            base_len = (baseline.get("fingerprint") or {}).get("body_length")
        cur = metrics.get("body_length")
        if base_len is None or cur is None:
            return False
        if abs(int(cur) - int(base_len)) <= thr:
            return False

    # time_gt_ms
    if rule.get("time_gt_ms") is not None:
        thr = float(rule["time_gt_ms"])
        dur = metrics.get("duration_ms")
        if dur is None or float(dur) <= thr:
            return False

    # If rule has no criteria keys, treat as never-match (empty rule).
    criteria = (
        "status",
        "body_contains",
        "regex",
        "length_delta_gt",
        "time_gt_ms",
    )
    if not any(k in rule and rule[k] is not None for k in criteria):
        return False

    return True
