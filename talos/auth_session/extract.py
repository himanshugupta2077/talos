"""
Module: talos.auth_session.extract

Purpose:
    Locate an auth field value on a stored flow and build a TokenContext
    for the bound auth type. Preserves scheme separately from the compact
    token (jwt_codec / analyzer.detect).

Dependencies: json; models; types; jwt_codec helpers
Data flow: flow dict + binding → field value → TokenContext | None
Side effects: None (pure).
"""

from __future__ import annotations

import json
from typing import Any, Optional

from talos.auth_session.models import (
    LOCATION_COOKIE,
    LOCATION_HEADER,
    AuthSessionBinding,
    TokenContext,
)
from talos.auth_session.types import get_analyzer


def _parse_json_object(raw: Any) -> dict[str, Any]:
    """Parse a JSON object from a flow column (str or dict)."""
    if raw is None:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}
    return {}


def _header_value(headers: dict[str, Any], name: str) -> Optional[str]:
    """
    Case-insensitive header lookup. Values may be str or list[str]
    (multi-value headers stored by capture).
    """
    target = name.lower()
    for key, value in headers.items():
        if str(key).lower() != target:
            continue
        if isinstance(value, list):
            if not value:
                return None
            # Prefer first non-empty string.
            for item in value:
                if item is not None and str(item).strip():
                    return str(item)
            return None
        if value is None:
            return None
        text = str(value)
        return text if text.strip() else None
    return None


def _cookie_value(cookies: dict[str, Any], name: str) -> Optional[str]:
    """Cookie name match is case-sensitive (HTTP cookie names)."""
    if name in cookies:
        value = cookies[name]
        if value is None:
            return None
        text = str(value)
        return text if text.strip() else None
    # Fallback: case-insensitive for robustness.
    target = name.lower()
    for key, value in cookies.items():
        if str(key).lower() == target:
            if value is None:
                return None
            text = str(value)
            return text if text.strip() else None
    return None


def get_auth_field_value(
    flow: dict[str, Any],
    location: str,
    name: str,
) -> Optional[str]:
    """
    Purpose:
        Read the bound auth field from a flow's request headers/cookies.
    Input:
        flow — flow dict with request_headers / request_cookies JSON or dict
        location — header | cookie
        name — field name
    Output:
        Raw field value string, or None if absent.
    Side effects: None.
    """
    loc = (location or "").strip().lower()
    field = (name or "").strip()
    if not field:
        return None
    if loc == LOCATION_HEADER:
        headers = _parse_json_object(flow.get("request_headers"))
        return _header_value(headers, field)
    if loc == LOCATION_COOKIE:
        cookies = _parse_json_object(flow.get("request_cookies"))
        # Some captures only put cookies in the Cookie header.
        value = _cookie_value(cookies, field)
        if value is not None:
            return value
        # Parse Cookie header as fallback.
        headers = _parse_json_object(flow.get("request_headers"))
        cookie_header = _header_value(headers, "Cookie")
        if not cookie_header:
            return None
        return _parse_cookie_header(cookie_header, field)
    return None


def _parse_cookie_header(cookie_header: str, name: str) -> Optional[str]:
    """Extract one cookie name from a Cookie request header string."""
    target = name.strip()
    target_lower = target.lower()
    for part in cookie_header.split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        key, _, value = part.partition("=")
        key = key.strip()
        if key == target or key.lower() == target_lower:
            return value.strip() if value.strip() else None
    return None


def extract_token_context(
    flow: dict[str, Any],
    binding: AuthSessionBinding,
) -> tuple[Optional[TokenContext], Optional[str]]:
    """
    Purpose:
        Locate the bound field on the flow and detect the auth type.
    Input:
        flow — flow dict
        binding — AuthSessionBinding
    Output:
        (TokenContext, None) on success
        (None, skip_reason) when field missing or not detectable
    Side effects: None.
    """
    raw = get_auth_field_value(flow, binding.location, binding.name)
    if raw is None:
        return None, "auth_field_absent"
    try:
        analyzer = get_analyzer(binding.auth_type)
    except KeyError:
        return None, f"unsupported_auth_type:{binding.auth_type}"
    ctx = analyzer.detect(
        raw,
        location=binding.location,
        field_name=binding.name,
    )
    if ctx is None:
        return None, "token_not_detectable"
    return ctx, None
