"""
Module: talos.passive.detectors.jwt

Purpose:
    Stage 1 companion — compact JWT (JWS) form detection.

    Matches three base64url segments separated by dots:
        header.payload.signature

    Requires a plausible ``eyJ`` header prefix (JSON object base64url) to
    cut noise from random dotted tokens.  Family = jwt; high confidence
    because the shape is structured (not a finding of "valid signed JWT").

Dependencies: re; talos.passive.detectors.base, constants, models
Data flow: text → list[RawMatch]
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Optional

from talos.passive.constants import (
    CATEGORY_SECRET,
    CONFIDENCE_HIGH,
    DETECTOR_FAMILY_JWT,
)
from talos.passive.detectors.base import build_raw_match
from talos.passive.models import RawMatch, SourceDocument

# Compact JWS: three base64url segments. Header almost always starts eyJ
# (base64url of '{"').
_JWT_COMPACT = re.compile(
    r"(?<![A-Za-z0-9_\-])"
    r"(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"
    r"(?![A-Za-z0-9_\-])"
)

_DETECTOR_ID = "jwt_compact"
_SECRET_TYPE = "jwt"
_BASE_SCORE = 80


class JwtDetector:
    """
    Purpose:
        Detect compact JWT strings in source text.
    """

    def __init__(self, *, max_candidates: int = 50) -> None:
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
            Find compact JWT candidates.
        Input:
            text / encoding context
        Output:
            list[RawMatch]
        Side effects: None.
        """
        if not text or "eyJ" not in text or "." not in text:
            return []

        matches: list[RawMatch] = []
        seen: set[tuple[str, int]] = set()
        for m in _JWT_COMPACT.finditer(text):
            value = m.group(1)
            start, end = m.start(1), m.end(1)
            # Segment count sanity
            parts = value.split(".")
            if len(parts) != 3:
                continue
            if any(len(p) < 10 for p in parts):
                continue
            key = (value, start)
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                build_raw_match(
                    detector_id=_DETECTOR_ID,
                    detector_family=DETECTOR_FAMILY_JWT,
                    category=CATEGORY_SECRET,
                    secret_type=_SECRET_TYPE,
                    raw_value=value,
                    match_start=start,
                    match_end=end,
                    text=text,
                    encoding_chain=encoding_chain,
                    decode_depth=decode_depth,
                    metadata={
                        "base_score": _BASE_SCORE,
                        "base_level": CONFIDENCE_HIGH,
                        "case_sensitive": True,
                        "rule_name": "Compact JWT",
                        "finding_title": "Exposed JWT (Unverified)",
                    },
                )
            )
            if len(matches) >= self._max_candidates:
                break
        return matches
