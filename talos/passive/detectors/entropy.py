"""
Module: talos.passive.detectors.entropy

Purpose:
    Stage 3 — high-entropy string candidates that need a nearby sensitive
    keyword for promotion (never bare random tokens, never assignment-only).

    Assignment-only gating was removed: minified JS is full of ``=`` and
    produced hundreds of false HIGH findings.  Key=value paths belong to
    the contextual assignment detector.

    Does **not** create Base64 / encoding findings.  Pure high-entropy
    blobs without keyword context are ignored.

Dependencies: re; detectors.base, scoring, rules_loader, constants, models
Data flow: text → list[RawMatch] (only context-gated)
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Optional

from talos.passive.constants import (
    CATEGORY_SECRET,
    DETECTOR_FAMILY_ENTROPY,
)
from talos.passive.detectors.base import build_raw_match, shannon_entropy
from talos.passive.models import RawMatch, SourceDocument
from talos.passive.rules_loader import RuleIndex, get_rule_index
from talos.passive.scoring import is_high_entropy
from talos.passive.suppress import (
    looks_like_code_expression,
    looks_like_url_or_hostpath,
)

# Quoted high-entropy-looking tokens (base64 / url-safe / hex-ish).
# Bare (unquoted) candidates deliberately exclude `.` and `=` so minified
# JS property chains (Object.defineProperty, e.unstable_now=…) never match.
_CANDIDATE = re.compile(
    r"(?:"
    r"\"([A-Za-z0-9+/=_\-.]{16,128})\""
    r"|'([A-Za-z0-9+/=_\-.]{16,128})'"
    r"|`([A-Za-z0-9+/=_\-.]{16,128})`"
    r"|(?<![A-Za-z0-9+/=_\-])([A-Za-z0-9+/=_\-]{24,128})(?![A-Za-z0-9+/=_\-])"
    r")"
)

_DETECTOR_ID = "high_entropy_secret"
_BASE_SCORE = 35
_CONTEXT_RADIUS = 80
_MIN_ENTROPY = 4.0
_MIN_LEN_QUOTED = 16
_MIN_LEN_BARE = 24


class EntropyDetector:
    """
    Purpose:
        Emit high-entropy candidates only when gated by keyword/assignment.
    """

    def __init__(
        self,
        index: Optional[RuleIndex] = None,
        *,
        max_candidates: int = 200,
        min_entropy: float = _MIN_ENTROPY,
        min_length: int = _MIN_LEN_QUOTED,
    ) -> None:
        self._index = index if index is not None else get_rule_index()
        self._max_candidates = max(1, int(max_candidates))
        self._min_entropy = float(min_entropy)
        self._min_length = int(min_length)
        if self._index.generic is not None:
            self._boost_keywords = tuple(
                k.lower() for k in self._index.generic.entropy_boost_keywords
            )
        else:
            self._boost_keywords = (
                "password",
                "secret",
                "token",
                "apikey",
                "api_key",
                "access_token",
                "client_secret",
                "private_key",
                "authorization",
                "bearer",
            )

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
            Find high-entropy secrets gated by a nearby sensitive keyword.

        Bare ``=`` assignment context alone is **not** enough — minified JS
        is full of assignments and was flooding HIGH findings.  Contextual
        assignment detector owns ``key = value`` paths.

        Input:
            text / encoding context
        Output:
            list[RawMatch]
        Side effects: None.
        """
        if not text or len(text) < self._min_length:
            return []

        matches: list[RawMatch] = []
        seen: set[tuple[str, int]] = set()

        for m in _CANDIDATE.finditer(text):
            value = None
            v_start = v_end = 0
            quoted = False
            for i in range(1, (m.lastindex or 0) + 1):
                g = m.group(i)
                if g is not None:
                    value = g
                    v_start, v_end = m.start(i), m.end(i)
                    # Groups 1–3 are quoted; group 4 is bare.
                    quoted = i <= 3
                    break
            min_len = self._min_length if quoted else max(self._min_length, _MIN_LEN_BARE)
            if not value or len(value) < min_len:
                continue
            # URLs / host-paths are never secret material for this stage
            # (e.g. //api.github.com/user next to Authorization: token).
            if looks_like_url_or_hostpath(value):
                continue
            if looks_like_code_expression(value):
                continue
            if not is_high_entropy(
                value,
                min_length=min_len,
                min_entropy=self._min_entropy,
            ):
                continue

            window_start = max(0, v_start - _CONTEXT_RADIUS)
            window_end = min(len(text), v_end + _CONTEXT_RADIUS)
            window = text[window_start:window_end]
            window_lower = window.lower()

            # Require a sensitive keyword in the local window.  Assignment
            # alone matches almost every minified statement and is rejected.
            has_keyword = any(k in window_lower for k in self._boost_keywords)
            if not has_keyword:
                continue
            # Prefer keyword that is not only a false friend inside a long
            # identifier far from the value — still accept substring match
            # (api_key_hint, clientSecret) as historically intended.

            dedup = (value, v_start)
            if dedup in seen:
                continue
            seen.add(dedup)

            matches.append(
                build_raw_match(
                    detector_id=_DETECTOR_ID,
                    detector_family=DETECTOR_FAMILY_ENTROPY,
                    category=CATEGORY_SECRET,
                    secret_type="high_entropy",
                    raw_value=value,
                    match_start=v_start,
                    match_end=v_end,
                    text=text,
                    encoding_chain=encoding_chain,
                    decode_depth=decode_depth,
                    metadata={
                        "rule_name": "High Entropy Secret",
                        "base_score": _BASE_SCORE,
                        "base_level": "MEDIUM",
                        "case_sensitive": True,
                        "finding_title": "High-Entropy Secret Candidate",
                        "stage": "entropy",
                        "has_keyword": True,
                        "has_assignment": False,
                        "quoted": quoted,
                        "entropy": shannon_entropy(value),
                    },
                )
            )
            if len(matches) >= self._max_candidates:
                break
        return matches
