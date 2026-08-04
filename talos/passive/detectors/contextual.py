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
from talos.passive.suppress import (
    is_non_secret_key,
    looks_like_code_expression,
)

# Sensitive key token (word-ish, including camelCase / snake_case).
# Prefer compound secrets (clientSecret, api_key) over bare "token"/"auth"
# which flood minified frontend design-system / HTTP client code.
_KEY_PART = (
    r"(?:password|passwd|secret|client_secret|clientSecret|"
    r"api_key|apiKey|api_secret|apiSecret|"
    r"access_token|accessToken|auth_token|authToken|"
    r"private_key|privateKey|app_secret|appSecret|"
    r"app_key|appKey|client_secret|refresh_token|refreshToken|"
    r"id_token|idToken|bearer|credentials?)"
)

# Bare weak keys only when they are the entire identifier (not withCredentials).
_WEAK_KEY_EXACT = r"(?:token|auth|password|passwd|secret|credentials?)"

# Assignment operators across JS / JSON / Python / YAML-ish
_ASSIGN_OPS = r"(?:=|:|=>)"

# Prefer quoted string values. Bare tokens are accepted only for high-quality
# secret-shaped RHS (no JS expression markers) and are scored/suppressed later.
_VALUE = (
    r"(?:"
    r"\"([^\"]{6,256})\""           # double-quoted
    r"|'([^']{6,256})'"             # single-quoted
    r"|`([^`]{6,256})`"             # backtick
    r"|([A-Za-z0-9+/=_\-.]{8,256})"  # bare secret-shaped only (no braces/parens)
    r")"
)

# Full pattern: optional quotes around key, optional const/let/var.
# Compound keys: *secret*, *password*, apiKey, accessToken, …
# Exact weak keys: token|auth|… as whole identifier (word boundary via
# not consuming leading alnum into the key beyond the identifier start).
_ASSIGNMENT = re.compile(
    rf"(?:(?:const|let|var)\s+)?"
    rf"[\"']?(?P<key>"
    rf"[A-Za-z_][\w]*(?:password|passwd|secret|Secret|token|Token|key|Key|"
    rf"credential|Credential)[\w]*"
    rf"|{_WEAK_KEY_EXACT}"
    rf"|{_KEY_PART}"
    rf")[\"']?"
    rf"\s*{_ASSIGN_OPS}\s*"
    rf"{_VALUE}",
    re.IGNORECASE,
)

_DETECTOR_ID = "contextual_assignment"
_BASE_SCORE = 40

# Known non-secret keys (HTTP client / design tokens / hooks).
_SKIP_KEYS = frozenset({
    "withcredentials",
    "withxsrftoken",
    "canceltoken",
    "usetoken",
    "deprecatedtokens",
    "realtoken",
    "csstoken",
    "designtoken",
    "themetoken",
    "icontoken",
    "fonttoken",
    "colortoken",
    "tokentype",
    "tokencolor",
})


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
            key_l = key.lower()
            key_compact = re.sub(r"[^a-z0-9]", "", key_l)
            if key_compact in _SKIP_KEYS or is_non_secret_key(key):
                continue
            # Filter: key must look sensitive (exact or compound)
            if self._keys_lower and key_l not in self._keys_lower:
                if not any(sk in key_l for sk in self._keys_lower):
                    continue
            # Reject JS expressions / object literals as values
            if looks_like_code_expression(value):
                continue
            # Bare group (unquoted): require secret-shaped alphabet only
            # (regex already restricts charset; double-check no whitespace)
            if any(ch in value for ch in " \t\n\r"):
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
