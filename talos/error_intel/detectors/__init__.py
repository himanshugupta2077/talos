"""
Package: talos.error_intel.detectors

Purpose:
    Multi-stage Error Intelligence detectors (Phase 2).

    Stages (order matters — specific → structural → generic):
        A  stack_trace   — language exception / stack dumps
        B  database      — SQLSTATE, ORA, vendor engine errors
        C  framework     — Spring/Laravel/Django/ASP.NET chrome
        D  infrastructure— CDN / proxy / ingress / web-server pages
        E  security      — JWT / OAuth / CSRF / CORS / ACL messages
        F  disclosure    — paths / hosts / versions (artifacts-first)
        G  http_generic  — problem+json / generic validation (lowest)

    All detectors are pure: text (+ optional status/headers) →
    list[RawErrorMatch].  No DB, no HTTP, no Findings.

Public:
    ErrorDetectorOrchestrator, detect_errors, ErrorDetectResult
    build_raw_error_match, extract_snippet
"""

from talos.error_intel.detectors.orchestrator import (
    ErrorDetectResult,
    ErrorDetectorOrchestrator,
    detect_errors,
    pick_primary_match,
)
from talos.error_intel.detectors.base import (
    build_raw_error_match,
    decode_body_text,
    extract_snippet,
)

__all__ = [
    "ErrorDetectResult",
    "ErrorDetectorOrchestrator",
    "detect_errors",
    "pick_primary_match",
    "build_raw_error_match",
    "decode_body_text",
    "extract_snippet",
]
