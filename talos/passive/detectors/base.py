"""
Module: talos.passive.detectors.base

Purpose:
    Detector protocol and shared helpers for raw match production.

    Detectors are pure: given text (+ optional encoding context) they
    return list[RawMatch].  Scoring, suppression, and persistence live
    outside individual detectors.

Dependencies: re, typing; talos.passive.constants / models
Data flow: detector.detect(text) → list[RawMatch]
Side effects: None.
"""

from __future__ import annotations

import math
import re
from typing import Optional, Protocol, runtime_checkable

from talos.passive.constants import (
    DEFAULT_CONTEXT_AFTER_CHARS,
    DEFAULT_CONTEXT_BEFORE_CHARS,
)
from talos.passive.models import RawMatch, SourceDocument


@runtime_checkable
class Detector(Protocol):
    """
    Purpose:
        Pluggable detector contract.

    Methods:
        detect(text, *, document=None, encoding_chain=None, decode_depth=0)
            → list[RawMatch]
    """

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
            Find secret-like material in text.
        Input:
            text            — normalized scan text
            document        — optional SourceDocument context
            encoding_chain  — codecs applied if text is decoded
            decode_depth    — nesting depth of decoded text
        Output:
            list[RawMatch] (may be empty)
        Side effects: None (must not write DB or network).
        """
        ...


def extract_context(
    text: str,
    start: int,
    end: int,
    *,
    before: int = DEFAULT_CONTEXT_BEFORE_CHARS,
    after: int = DEFAULT_CONTEXT_AFTER_CHARS,
) -> tuple[str, str]:
    """
    Purpose:
        Slice limited context windows around a match.
    Input:
        text / start / end — match offsets into text
        before / after — character window sizes
    Output:
        (context_before, context_after)
    Side effects: None.
    """
    if not text:
        return "", ""
    s = max(0, int(start))
    e = min(len(text), int(end))
    ctx_before = text[max(0, s - before) : s]
    ctx_after = text[e : min(len(text), e + after)]
    return ctx_before, ctx_after


def match_value_from_regex(match: re.Match[str]) -> tuple[str, int, int]:
    """
    Purpose:
        Prefer capture group 1 as the secret value; fall back to full match.
    Input:
        match — re.Match
    Output:
        (value, start, end) offsets into the original string
    Side effects: None.
    """
    if match.lastindex and match.lastindex >= 1:
        value = match.group(1)
        return value, match.start(1), match.end(1)
    value = match.group(0)
    return value, match.start(0), match.end(0)


def shannon_entropy(value: str) -> float:
    """
    Purpose:
        Shannon entropy (bits per character) of value over observed alphabet.
    Input:
        value — candidate string
    Output:
        Entropy in [0, log2(alphabet)]; 0.0 for empty.
    Side effects: None.
    """
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(value)
    ent = 0.0
    for count in counts.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent


def build_raw_match(
    *,
    detector_id: str,
    detector_family: str,
    category: str,
    secret_type: str,
    raw_value: str,
    match_start: int,
    match_end: int,
    text: str,
    matched_key: Optional[str] = None,
    encoding_chain: Optional[list[str]] = None,
    decode_depth: int = 0,
    metadata: Optional[dict] = None,
    compute_entropy: bool = True,
) -> RawMatch:
    """
    Purpose:
        Construct a RawMatch with context windows and optional entropy.
    Input:
        Identity fields + offsets into text; optional key / encoding metadata.
    Output:
        RawMatch
    Side effects: None.
    """
    ctx_before, ctx_after = extract_context(text, match_start, match_end)
    ent = shannon_entropy(raw_value) if compute_entropy else None
    return RawMatch(
        detector_id=detector_id,
        detector_family=detector_family,
        category=category,
        secret_type=secret_type,
        matched_key=matched_key,
        raw_value=raw_value,
        match_start=match_start,
        match_end=match_end,
        context_before=ctx_before,
        context_after=ctx_after,
        encoding_chain=list(encoding_chain or []),
        decode_depth=int(decode_depth or 0),
        entropy=ent,
        metadata=dict(metadata or {}),
    )
