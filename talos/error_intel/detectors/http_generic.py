"""
Module: talos.error_intel.detectors.http_generic

Purpose:
    Stage G — generic HTTP / validation errors (lowest priority).

    JSON ``{error, message, code}``, problem+json, HTML title "Bad Request".
    Orchestrator only keeps these when:
        - no stronger stage hit, **and**
        - config.store_generic_http_errors, **or**
        - status is 5xx

Dependencies: json, re; talos.error_intel.{constants, detectors.base, models}
Data flow: text → list[RawErrorMatch]
Side effects: None.
"""

from __future__ import annotations

import json
import re
from typing import Any, Mapping, Optional

from talos.error_intel.constants import (
    CATEGORY_HTTP,
    CATEGORY_VALIDATION,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_WEAK,
    DETECTOR_FAMILY_HTTP,
    LANG_UNKNOWN,
)
from talos.error_intel.detectors.base import (
    DEFAULT_STAGE_MATCH_CAP,
    build_raw_error_match,
    normalize_exception_type,
)
from talos.error_intel.models import RawErrorMatch

_PROBLEM_JSON_CT = re.compile(r"application/(?:problem\+)?json", re.I)

_HTML_TITLE_ERROR = re.compile(
    r"<title>\s*("
    r"\d{3}\s+[^<]{0,80}|"
    r"Bad Request|Unauthorized|Forbidden|Not Found|"
    r"Internal Server Error|Service Unavailable|Gateway Time-?out|"
    r"Error|Exception"
    r")\s*</title>",
    re.I,
)

_HTML_H1_ERROR = re.compile(
    r"<h1[^>]*>\s*("
    r"\d{3}\s+[^<]{0,80}|"
    r"Bad Request|Unauthorized|Forbidden|Not Found|"
    r"Internal Server Error|Service Unavailable"
    r")\s*</h1>",
    re.I,
)

# JSON keys that indicate structured API errors
_ERROR_KEYS = frozenset({
    "error",
    "errors",
    "exception",
    "fault",
    "message",
    "detail",
    "title",
    "code",
    "error_code",
    "errorcode",
    "error_message",
    "errormessage",
    "status",
    "type",
})


class HttpGenericDetector:
    """
    Purpose:
        Stage G — generic HTTP / validation structured errors.
    """

    def __init__(self, *, max_matches: int = DEFAULT_STAGE_MATCH_CAP) -> None:
        self._max = max(1, int(max_matches))

    def detect(
        self,
        text: str,
        *,
        status_code: Optional[int] = None,
        headers: Optional[Mapping[str, str]] = None,
        content_type: Optional[str] = None,
    ) -> list[RawErrorMatch]:
        if not text or not text.strip():
            # Status-only generic (empty body) — still emit if status present
            if status_code is not None and 400 <= int(status_code) <= 599:
                return [
                    build_raw_error_match(
                        detector_id="http_status_only",
                        family=DETECTOR_FAMILY_HTTP,
                        text=str(status_code),
                        match_start=0,
                        match_end=len(str(status_code)),
                        exception_type=None,
                        confidence=CONFIDENCE_WEAK,
                        category_hint=CATEGORY_HTTP,
                        language=LANG_UNKNOWN,
                        metadata={
                            "status_code": int(status_code),
                            "generic": True,
                        },
                        raw_snippet=f"HTTP {status_code}",
                    )
                ]
            return []

        matches: list[RawErrorMatch] = []
        ct = (content_type or "").lower()
        if headers:
            for k, v in headers.items():
                if str(k).lower() == "content-type" and v:
                    ct = str(v).lower()
                    break

        # problem+json / JSON object
        if "json" in ct or text.lstrip().startswith(("{", "[")):
            json_match = self._from_json(text, status_code=status_code, content_type=ct)
            if json_match:
                matches.append(json_match)

        # HTML title / h1
        if not matches or "html" in ct or "<html" in text[:200].lower() or "<title" in text[:500].lower():
            for pattern, det_id in (
                (_HTML_TITLE_ERROR, "http_html_title"),
                (_HTML_H1_ERROR, "http_html_h1"),
            ):
                m = pattern.search(text)
                if not m:
                    continue
                title = (m.group(1) or "").strip()
                cat = CATEGORY_HTTP
                if status_code is not None and 400 <= int(status_code) < 500:
                    cat = CATEGORY_VALIDATION
                matches.append(
                    build_raw_error_match(
                        detector_id=det_id,
                        family=DETECTOR_FAMILY_HTTP,
                        text=text,
                        match_start=m.start(1),
                        match_end=m.end(1),
                        exception_type=None,
                        confidence=CONFIDENCE_WEAK,
                        category_hint=cat,
                        language=LANG_UNKNOWN,
                        metadata={
                            "title": title[:200],
                            "status_code": status_code,
                            "generic": True,
                        },
                    )
                )
                break

        # Plain-text short error line
        if not matches and status_code is not None and 400 <= int(status_code) <= 599:
            first_line = text.strip().splitlines()[0][:300] if text.strip() else ""
            if first_line:
                matches.append(
                    build_raw_error_match(
                        detector_id="http_plain_status_body",
                        family=DETECTOR_FAMILY_HTTP,
                        text=text,
                        match_start=0,
                        match_end=min(len(text), len(first_line)),
                        exception_type=None,
                        confidence=CONFIDENCE_WEAK,
                        category_hint=CATEGORY_HTTP
                        if int(status_code) >= 500
                        else CATEGORY_VALIDATION,
                        language=LANG_UNKNOWN,
                        metadata={
                            "message": first_line,
                            "status_code": int(status_code),
                            "generic": True,
                        },
                        raw_snippet=first_line,
                    )
                )

        return matches[: self._max]

    def _from_json(
        self,
        text: str,
        *,
        status_code: Optional[int],
        content_type: str,
    ) -> Optional[RawErrorMatch]:
        sample = text.strip()
        if len(sample) > 200_000:
            sample = sample[:200_000]
        try:
            data = json.loads(sample)
        except (json.JSONDecodeError, ValueError, TypeError):
            # Partial / trailing garbage — try first object-ish region
            data = _try_loose_json_object(sample)
            if data is None:
                return None

        if not isinstance(data, dict):
            # problem+json can be other shapes; skip arrays of errors for v1
            if isinstance(data, list) and data and isinstance(data[0], dict):
                data = data[0]
            else:
                return None

        keys_lower = {str(k).lower(): k for k in data.keys()}
        hit_keys = [keys_lower[k] for k in keys_lower if k in _ERROR_KEYS]
        if not hit_keys:
            return None

        # Extract best message / type
        message = _first_str(
            data,
            ("message", "detail", "error_message", "errorMessage", "title", "error"),
        )
        err_type = _first_str(
            data,
            ("type", "error", "exception", "error_type", "errorType", "code", "error_code"),
        )
        # If error is an object, dig message
        err_val = data.get("error")
        if isinstance(err_val, dict):
            message = message or _first_str(err_val, ("message", "detail", "title"))
            err_type = err_type or _first_str(err_val, ("type", "code", "name"))

        is_problem = bool(_PROBLEM_JSON_CT.search(content_type)) or (
            "type" in keys_lower and "title" in keys_lower
        )
        cat = CATEGORY_HTTP
        if status_code is not None and 400 <= int(status_code) < 500:
            cat = CATEGORY_VALIDATION
        if is_problem and status_code is not None and int(status_code) < 500:
            cat = CATEGORY_VALIDATION

        conf = CONFIDENCE_MEDIUM if is_problem or message else CONFIDENCE_WEAK
        # Build a stable short identity message for later fingerprinting
        identity = (err_type or message or "json_error")[:200]

        # Find span of first key in raw text for highlight
        start, end = 0, min(len(text), 80)
        for hk in hit_keys:
            needle = f'"{hk}"'
            pos = text.find(needle)
            if pos >= 0:
                start = pos
                end = min(len(text), pos + 120)
                break

        return build_raw_error_match(
            detector_id="http_json_error" if not is_problem else "http_problem_json",
            family=DETECTOR_FAMILY_HTTP,
            text=text,
            match_start=start,
            match_end=end,
            exception_type=normalize_exception_type(str(err_type) if err_type else None),
            confidence=conf,
            category_hint=cat,
            language=LANG_UNKNOWN,
            metadata={
                "message": (message or "")[:500] if message else None,
                "json_keys": [str(k) for k in hit_keys][:12],
                "status_code": status_code,
                "problem_json": is_problem,
                "identity": identity,
                "generic": True,
            },
        )


def _first_str(data: dict[str, Any], keys: tuple[str, ...]) -> Optional[str]:
    lower_map = {str(k).lower(): v for k, v in data.items()}
    for key in keys:
        val = lower_map.get(key.lower())
        if isinstance(val, str) and val.strip():
            return val.strip()
        if isinstance(val, (int, float, bool)):
            return str(val)
    return None


def _try_loose_json_object(text: str) -> Optional[dict[str, Any]]:
    """Best-effort extract first {...} for slightly dirty bodies."""
    start = text.find("{")
    if start < 0:
        return None
    # Balanced scan (naive)
    depth = 0
    for i in range(start, min(len(text), start + 100_000)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(text[start : i + 1])
                except (json.JSONDecodeError, ValueError):
                    return None
                return obj if isinstance(obj, dict) else None
    return None
