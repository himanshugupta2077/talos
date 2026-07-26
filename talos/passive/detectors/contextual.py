"""
Module: talos.passive.detectors.contextual

Purpose:
    Stage 2 — Family B generic secrets in assignment context.

    Finds sensitive keys (from generic.yaml) assigned via JS/JSON/Python/
    YAML-like operators and extracts the value.  Alone this never runs
    bare substring "password" without assignment.

    Examples that match:
        clientSecret = "A82k…"
        "api_key": "sk_…"
        password: SuperSecret123

    Examples that do not:
        const text = "client secret"   (no sensitive key assignment)
        password = "password"          (suppressed later)

Dependencies: re; rules_loader, detectors.base, constants, models
Data flow: text + sensitive_keys → list[RawMatch]
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Optional

from talos.passive.constants import (
    CATEGORY_SECRET,
    DETECTOR_FAMILY_CONTEXTUAL,
)
from talos.passive.detectors.base import build_raw_match
from talos.passive.models import RawMatch, SourceDocument
from talos.passive.rules_loader import RuleIndex, get_rule_index

# Sensitive key token (word-ish, including camelCase / snake_case)
_KEY_PART = (
    r"(?:password|passwd|secret|client_secret|clientSecret|"
    r"api_key|apiKey|api_secret|apiSecret|"
    r"access_token|accessToken|auth_token|authToken|"
    r"private_key|privateKey|app_secret|appSecret|"
    r"app_key|appKey|token|credentials?)"
)

# Assignment operators across JS / JSON / Python / YAML-ish
_ASSIGN_OPS = r"(?:=|:|=>)"

# Quoted or unquoted value (conservative)
_VALUE = (
    r"(?:"
    r"\"([^\"]{4,256})\""           # double-quoted
    r"|'([^']{4,256})'"             # single-quoted
    r"|`([^`]{4,256})`"             # backtick
    r"|([^\s,;}}\]]{4,256})"        # bare token
    r")"
)

# Full pattern: optional quotes around key, optional const/let/var
_ASSIGNMENT = re.compile(
    rf"(?:(?:const|let|var)\s+)?"
    rf"[\"']?(?P<key>[A-Za-z_][\w]*{_KEY_PART}[\w]*|{_KEY_PART}[\w]*)[\"']?"
    rf"\s*{_ASSIGN_OPS}\s*"
    rf"{_VALUE}",
    re.IGNORECASE,
)

_DETECTOR_ID = "contextual_assignment"
_BASE_SCORE = 40


class ContextualDetector:
    """
    Purpose:
        Detect secrets assigned to sensitive variable / object keys.
    """

    def __init__(
        self,
        index: Optional[RuleIndex] = None,
        *,
        max_candidates: int = 500,
        sensitive_keys: Optional[tuple[str, ...]] = None,
    ) -> None:
        self._index = index if index is not None else get_rule_index()
        self._max_candidates = max(1, int(max_candidates))
        if sensitive_keys is not None:
            self._keys_lower = frozenset(k.lower() for k in sensitive_keys)
        elif self._index.generic is not None:
            self._keys_lower = frozenset(
                k.lower() for k in self._index.generic.sensitive_keys
            )
        else:
            self._keys_lower = frozenset()

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
            Find assignment-context generic secrets.
        Input:
            text / encoding context
        Output:
            list[RawMatch]
        Side effects: None.
        """
        if not text:
            return []
        # Cheap prefilter: any sensitive keyword fragment present
        lower = text.lower()
        if self._keys_lower:
            if not any(k in lower for k in self._keys_lower):
                # Also check core fragments
                if not any(
                    frag in lower
                    for frag in ("password", "secret", "token", "apikey", "api_key", "credential")
                ):
                    return []
        elif not any(
            frag in lower
            for frag in ("password", "secret", "token", "apikey", "api_key")
        ):
            return []

        matches: list[RawMatch] = []
        seen: set[tuple[str, int]] = set()

        for m in _ASSIGNMENT.finditer(text):
            key = m.group("key") or ""
            value, v_start, v_end = _value_from_assignment(m)
            if not value or not key:
                continue
            # Filter: key must look sensitive
            if self._keys_lower and key.lower() not in self._keys_lower:
                # Allow partial: key contains a sensitive key as substring
                if not any(sk in key.lower() for sk in self._keys_lower):
                    continue
            dedup = (value, v_start)
            if dedup in seen:
                continue
            seen.add(dedup)
            matches.append(
                build_raw_match(
                    detector_id=_DETECTOR_ID,
                    detector_family=DETECTOR_FAMILY_CONTEXTUAL,
                    category=CATEGORY_SECRET,
                    secret_type="generic_assignment",
                    raw_value=value,
                    match_start=v_start,
                    match_end=v_end,
                    text=text,
                    matched_key=key,
                    encoding_chain=encoding_chain,
                    decode_depth=decode_depth,
                    metadata={
                        "rule_name": "Contextual Assignment Secret",
                        "base_score": _BASE_SCORE,
                        "base_level": "MEDIUM",
                        "case_sensitive": True,
                        "finding_title": f"Exposed Secret ({key})",
                        "stage": "contextual",
                        "has_assignment": True,
                    },
                )
            )
            if len(matches) >= self._max_candidates:
                break
        return matches


def _value_from_assignment(m: re.Match[str]) -> tuple[str, int, int]:
    """
    Purpose:
        Extract assigned value and its offsets from _ASSIGNMENT match.
    Output:
        (value, start, end) or ("", 0, 0)
    Side effects: None.
    """
    if not m.lastindex:
        return "", 0, 0
    # group 1 is the named 'key' in some Python versions for (?P<key>...);
    # numbered groups for _VALUE follow. Iterate all groups.
    for i in range(1, m.lastindex + 1):
        g = m.group(i)
        if g is None:
            continue
        # Skip the key group (matches key pattern at start of groups)
        if i == m.re.groupindex.get("key"):
            continue
        # Prefer non-key groups that look like values
        if g == m.group("key"):
            continue
        return g, m.start(i), m.end(i)
    return "", 0, 0
