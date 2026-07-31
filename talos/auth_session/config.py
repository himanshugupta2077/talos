"""
Module: talos.auth_session.config

Purpose:
    Defaults and config helpers for the Authentication & Session Testing
    engine. Binding rows store optional JSON overrides; suite constants and
    the built-in claim-elevation map live here / in jwt_mutate.

Dependencies: json, typing; jwt_mutate for default claim elevation
Data flow: CLI / candidates → parse binding config_json → suite filters
Side effects: None (pure helpers).
"""

from __future__ import annotations

import json
from typing import Any, Optional

from talos.auth_session.jwt_mutate import default_claim_elevation_map
from talos.auth_session.models import (
    FAMILY_ALGORITHM,
    FAMILY_ALGORITHM_DEGRADE,
    FAMILY_CLAIMS,
    FAMILY_KID,
    FAMILY_SIGNATURE,
    FAMILY_STRUCTURE,
)

# Methods preferred at generate time (design: safe-method default).
SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})

# Default suite families when binding config omits enabled_families.
DEFAULT_ENABLED_FAMILIES: tuple[str, ...] = (
    FAMILY_SIGNATURE,
    FAMILY_ALGORITHM,
    FAMILY_ALGORITHM_DEGRADE,
    FAMILY_STRUCTURE,
    FAMILY_CLAIMS,
    FAMILY_KID,
)

# Token fingerprint: short display hash (not full token storage).
TOKEN_FINGERPRINT_PREFIX_LEN = 12
TOKEN_FINGERPRINT_HASH_LEN = 10


def parse_binding_config(config_json: str | None) -> dict[str, Any]:
    """
    Purpose:
        Parse binding.config_json into a dict with validated shape.
    Input:
        config_json — JSON text or None / empty → defaults
    Output:
        dict with keys:
            claim_elevation (dict), enabled_families (list|None),
            disabled_tests (list), scheme_preserve (bool)
    Side effects: None.
    """
    raw: dict[str, Any] = {}
    if config_json and str(config_json).strip():
        try:
            parsed = json.loads(config_json)
            if isinstance(parsed, dict):
                raw = parsed
        except (json.JSONDecodeError, TypeError, ValueError):
            raw = {}

    elev = raw.get("claim_elevation")
    if not isinstance(elev, dict) or not elev:
        elev = default_claim_elevation_map()

    families = raw.get("enabled_families")
    if families is not None:
        if not isinstance(families, (list, tuple)):
            families = list(DEFAULT_ENABLED_FAMILIES)
        else:
            families = [str(f) for f in families]
    # None means all families (suite_jwt treats missing key as all).

    disabled = raw.get("disabled_tests") or []
    if not isinstance(disabled, (list, tuple)):
        disabled = []
    disabled = [str(t) for t in disabled]

    scheme_preserve = raw.get("scheme_preserve", True)
    if not isinstance(scheme_preserve, bool):
        scheme_preserve = True

    return {
        "claim_elevation": elev,
        "enabled_families": families,
        "disabled_tests": disabled,
        "scheme_preserve": scheme_preserve,
    }


def suite_config_from_binding(config_json: str | None) -> dict[str, Any]:
    """
    Purpose:
        Build the config dict passed to analyzer.list_test_cases / apply.
    Input:
        config_json — binding row config_json
    Output:
        dict suitable for JwtAnalyzer (claim_elevation, enabled_families,
        disabled_tests). Omits enabled_families when None (all families).
    Side effects: None.
    """
    parsed = parse_binding_config(config_json)
    out: dict[str, Any] = {
        "claim_elevation": parsed["claim_elevation"],
        "disabled_tests": list(parsed["disabled_tests"]),
        "scheme_preserve": parsed["scheme_preserve"],
    }
    if parsed["enabled_families"] is not None:
        out["enabled_families"] = list(parsed["enabled_families"])
    return out


def is_safe_method(method: Optional[str]) -> bool:
    """True when HTTP method is GET / HEAD / OPTIONS (case-insensitive)."""
    if not method:
        return False
    return method.strip().upper() in SAFE_METHODS


def dump_binding_config(config: dict[str, Any] | None) -> str:
    """Serialize a binding config dict to JSON text for storage."""
    if not config:
        return "{}"
    return json.dumps(config, separators=(",", ":"), ensure_ascii=True)
