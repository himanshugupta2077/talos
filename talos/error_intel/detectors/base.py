"""
Module: talos.error_intel.detectors.base

Purpose:
    Shared helpers for Error Intelligence detectors (Phase 2).

    Detectors are pure: given decoded text (+ optional status / headers)
    they return list[RawErrorMatch].  Normalize, fingerprint, classify,
    and persistence live outside individual detectors.

Dependencies: re, typing; talos.error_intel.{constants, models}
Data flow: detector.detect(text, …) → list[RawErrorMatch]
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Optional, Protocol, Union, runtime_checkable

from talos.error_intel.constants import DEFAULT_RAW_SNIPPET_MAX
from talos.error_intel.models import RawErrorMatch

# Soft cap on how many matches a single stage may emit (orchestrator also caps).
DEFAULT_STAGE_MATCH_CAP = 20

# Null-byte density: treat as non-text and skip scan.
_NULL_RATIO_REJECT = 0.02


@runtime_checkable
class ErrorDetector(Protocol):
    """
    Purpose:
        Pluggable Error Intelligence detector contract.
    """

    def detect(
        self,
        text: str,
        *,
        status_code: Optional[int] = None,
        headers: Optional[Mapping[str, str]] = None,
        content_type: Optional[str] = None,
    ) -> list[RawErrorMatch]:
        """
        Purpose:
            Find error-shaped material in decoded response text.
        Input:
            text — UTF-8 (or replace-decoded) body sample
            status_code / headers / content_type — optional context
        Output:
            list[RawErrorMatch] (may be empty)
        Side effects: None (must not write DB or network).
        """
        ...


def decode_body_text(
    body: Optional[Union[str, bytes]],
    *,
    max_bytes: int = 512_000,
) -> str:
    """
    Purpose:
        Decode a response body to text for detector stages.
        Caps length; rejects binary-ish samples (high NUL density).
    Input:
        body — str | bytes | None
        max_bytes — scan budget (bytes before decode for bytes input)
    Output:
        Decoded text, or "" when empty/binary/unusable.
    Side effects: None.
    """
    if body is None:
        return ""
    if isinstance(body, str):
        text = body if len(body) <= max_bytes else body[:max_bytes]
    elif isinstance(body, bytes):
        sample = body[: max(0, int(max_bytes))]
        if not sample:
            return ""
        nulls = sample.count(b"\x00")
        if nulls and nulls / max(len(sample), 1) >= _NULL_RATIO_REJECT:
            return ""
        try:
            text = sample.decode("utf-8", errors="replace")
        except Exception:
            text = sample.decode("latin-1", errors="replace")
    else:
        return ""
    return text


def extract_snippet(
    text: str,
    start: int,
    end: int,
    *,
    max_chars: int = DEFAULT_RAW_SNIPPET_MAX,
    pad_before: int = 120,
    pad_after: int = 400,
) -> str:
    """
    Purpose:
        Bound an evidence snippet around a match span for storage/UI.
        Prefer expanding to nearby newlines so multi-line stacks stay readable.
    Input:
        text / start / end — match offsets
        max_chars — hard cap (default DEFAULT_RAW_SNIPPET_MAX)
        pad_before / pad_after — context padding when span is short
    Output:
        Snippet string (may be truncated with '…' markers).
    Side effects: None.
    """
    if not text:
        return ""
    n = len(text)
    s = max(0, min(int(start), n))
    e = max(s, min(int(end), n))
    # Expand short spans for context
    span_len = e - s
    if span_len < max_chars:
        s = max(0, s - pad_before)
        e = min(n, e + pad_after)
        # Prefer line boundaries
        nl_before = text.rfind("\n", max(0, s - 200), s)
        if nl_before >= 0 and (s - nl_before) < 200:
            s = nl_before + 1
        nl_after = text.find("\n", e, min(n, e + 200))
        if nl_after >= 0 and (nl_after - e) < 200:
            e = nl_after

    if e - s > max_chars:
        # Keep start of span region; truncate tail
        half = max_chars // 2
        mid = (s + e) // 2
        s2 = max(s, mid - half)
        e2 = min(e, s2 + max_chars)
        snippet = text[s2:e2]
        prefix = "…" if s2 > 0 else ""
        suffix = "…" if e2 < n else ""
        return prefix + snippet + suffix

    snippet = text[s:e]
    prefix = "…" if s > 0 else ""
    suffix = "…" if e < n else ""
    return prefix + snippet + suffix


def build_raw_error_match(
    *,
    detector_id: str,
    family: str,
    text: str,
    match_start: int,
    match_end: int,
    exception_type: Optional[str] = None,
    confidence: str = "WEAK",
    category_hint: Optional[str] = None,
    language: Optional[str] = None,
    metadata: Optional[dict[str, Any]] = None,
    raw_snippet: Optional[str] = None,
    snippet_max: int = DEFAULT_RAW_SNIPPET_MAX,
) -> RawErrorMatch:
    """
    Purpose:
        Construct a RawErrorMatch with a bounded evidence snippet.
    Input:
        Identity + offsets into text; optional classification seeds.
    Output:
        RawErrorMatch
    Side effects: None.
    """
    s = max(0, int(match_start))
    e = max(s, int(match_end))
    snippet = (
        raw_snippet
        if raw_snippet is not None
        else extract_snippet(text, s, e, max_chars=snippet_max)
    )
    return RawErrorMatch(
        detector_id=detector_id,
        family=family,
        exception_type=exception_type,
        raw_snippet=snippet,
        match_start=s,
        match_end=e,
        confidence=confidence,
        category_hint=category_hint,
        language=language,
        metadata=dict(metadata or {}),
    )


def first_group(match: re.Match[str], group: int = 1) -> Optional[str]:
    """Return named/numbered group or None. Side effects: None."""
    try:
        if match.lastindex and match.lastindex >= group:
            val = match.group(group)
            return val if val else None
    except IndexError:
        return None
    return None


# Short class names → canonical FQCN for fingerprint merge (BUG-04).
# Only unambiguous, well-known types — app-specific short names stay as-is.
_EXCEPTION_SHORT_TO_FQCN: dict[str, str] = {
    # java.lang
    "NullPointerException": "java.lang.NullPointerException",
    "IllegalArgumentException": "java.lang.IllegalArgumentException",
    "IllegalStateException": "java.lang.IllegalStateException",
    "RuntimeException": "java.lang.RuntimeException",
    "ClassCastException": "java.lang.ClassCastException",
    "IndexOutOfBoundsException": "java.lang.IndexOutOfBoundsException",
    "ArrayIndexOutOfBoundsException": "java.lang.ArrayIndexOutOfBoundsException",
    "NumberFormatException": "java.lang.NumberFormatException",
    "UnsupportedOperationException": "java.lang.UnsupportedOperationException",
    "SecurityException": "java.lang.SecurityException",
    "InterruptedException": "java.lang.InterruptedException",
    "OutOfMemoryError": "java.lang.OutOfMemoryError",
    "StackOverflowError": "java.lang.StackOverflowError",
    "NoSuchMethodError": "java.lang.NoSuchMethodError",
    "NoClassDefFoundError": "java.lang.NoClassDefFoundError",
    "ClassNotFoundException": "java.lang.ClassNotFoundException",
    "NoSuchMethodException": "java.lang.NoSuchMethodException",
    "InstantiationException": "java.lang.InstantiationException",
    "ArithmeticException": "java.lang.ArithmeticException",
    "NegativeArraySizeException": "java.lang.NegativeArraySizeException",
    "StringIndexOutOfBoundsException": "java.lang.StringIndexOutOfBoundsException",
    "ConcurrentModificationException": "java.util.ConcurrentModificationException",
    # java.sql / javax
    "SQLException": "java.sql.SQLException",
    "SQLSyntaxErrorException": "java.sql.SQLSyntaxErrorException",
    "SQLTimeoutException": "java.sql.SQLTimeoutException",
    "SQLIntegrityConstraintViolationException": (
        "java.sql.SQLIntegrityConstraintViolationException"
    ),
    "SQLDataException": "java.sql.SQLDataException",
    "SQLTransientException": "java.sql.SQLTransientException",
    "SQLNonTransientException": "java.sql.SQLNonTransientException",
    "SQLFeatureNotSupportedException": "java.sql.SQLFeatureNotSupportedException",
    "BatchUpdateException": "java.sql.BatchUpdateException",
    "DataAccessException": "org.springframework.dao.DataAccessException",
    # .NET System.*
    "NullReferenceException": "System.NullReferenceException",
    "ArgumentNullException": "System.ArgumentNullException",
    "ArgumentException": "System.ArgumentException",
    "ArgumentOutOfRangeException": "System.ArgumentOutOfRangeException",
    "InvalidOperationException": "System.InvalidOperationException",
    "IndexOutOfRangeException": "System.IndexOutOfRangeException",
    "FormatException": "System.FormatException",
    "TimeoutException": "System.TimeoutException",
    "UnauthorizedAccessException": "System.UnauthorizedAccessException",
    "NotImplementedException": "System.NotImplementedException",
    "NotSupportedException": "System.NotSupportedException",
    "ObjectDisposedException": "System.ObjectDisposedException",
    "KeyNotFoundException": "System.Collections.Generic.KeyNotFoundException",
    "HttpException": "System.Web.HttpException",
    "HttpRequestException": "System.Net.Http.HttpRequestException",
    "AggregateException": "System.AggregateException",
    "ApplicationException": "System.ApplicationException",
    "InvalidCastException": "System.InvalidCastException",
    "OverflowException": "System.OverflowException",
    "DivideByZeroException": "System.DivideByZeroException",
    "IOException": "System.IO.IOException",
    "FileNotFoundException": "System.IO.FileNotFoundException",
    "DirectoryNotFoundException": "System.IO.DirectoryNotFoundException",
    "SocketException": "System.Net.Sockets.SocketException",
    "WebException": "System.Net.WebException",
    "JsonException": "System.Text.Json.JsonException",
    # Python builtins — short names are already canonical
    "ValueError": "ValueError",
    "TypeError": "TypeError",
    "KeyError": "KeyError",
    "IndexError": "IndexError",
    "AttributeError": "AttributeError",
    "RuntimeError": "RuntimeError",
    "NameError": "NameError",
    "ImportError": "ImportError",
    "ModuleNotFoundError": "ModuleNotFoundError",
    "OSError": "OSError",
    "IOError": "IOError",
    "FileNotFoundError": "FileNotFoundError",
    "PermissionError": "PermissionError",
    "TimeoutError": "TimeoutError",
    "StopIteration": "StopIteration",
    "AssertionError": "AssertionError",
    "RecursionError": "RecursionError",
    "MemoryError": "MemoryError",
    "ZeroDivisionError": "ZeroDivisionError",
    "UnicodeError": "UnicodeError",
    "UnicodeDecodeError": "UnicodeDecodeError",
    "ConnectionError": "ConnectionError",
    "BrokenPipeError": "BrokenPipeError",
    "ConnectionResetError": "ConnectionResetError",
    "ConnectionRefusedError": "ConnectionRefusedError",
}

# Trailing "Exception"/"Error" short-name matcher (no dots = not already FQCN).
_SHORT_EXC_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def normalize_exception_type(raw: Optional[str]) -> Optional[str]:
    """
    Purpose:
        Cleanup + canonicalize exception class names for stable fingerprints.

        - Strip trailing punctuation and collapse whitespace
        - Map well-known short JVM / CLR names to FQCN
          (``NullPointerException`` → ``java.lang.NullPointerException``)
        - Already-qualified names (contain ``.``) are kept after cleanup
        - Python builtins stay as short names (canonical form)

    Side effects: None.
    """
    if not raw:
        return None
    text = str(raw).strip().rstrip(".:;,")
    text = re.sub(r"\s+", " ", text)
    if not text:
        return None
    if len(text) > 300:
        text = text[:300]

    # Already FQCN / dotted — keep (light package-case normalize only for known).
    if "." in text:
        return text

    if not _SHORT_EXC_RE.match(text):
        return text

    mapped = _EXCEPTION_SHORT_TO_FQCN.get(text)
    if mapped:
        return mapped
    # Case-insensitive lookup for common mis-casing
    mapped = _EXCEPTION_SHORT_TO_FQCN.get(text[0].upper() + text[1:] if text else text)
    if mapped:
        return mapped
    # Try exact case-insensitive scan for known shorts
    lower_map = {k.lower(): v for k, v in _EXCEPTION_SHORT_TO_FQCN.items()}
    mapped = lower_map.get(text.lower())
    if mapped:
        return mapped
    return text
