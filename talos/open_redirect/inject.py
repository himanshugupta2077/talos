"""
Module: talos.open_redirect.inject

Purpose:
    Same injectable surfaces as SSRF (query, JSON, form, path, multipart).
"""

from talos.ssrf.inject import (  # noqa: F401
    apply_payload,
    extract_injection_points,
    extract_path_points,
    match_injection_points,
    normalize_param_names,
    parse_headers,
)
from talos.ssrf.models import InjectionPoint

__all__ = [
    "InjectionPoint",
    "apply_payload",
    "extract_injection_points",
    "extract_path_points",
    "match_injection_points",
    "normalize_param_names",
    "parse_headers",
]
