"""
Module: talos.ai.notes.schema

Purpose:
    Document shape, limits, and allowlisted JSON-patch paths for app notes.
"""

from __future__ import annotations

from typing import Any, Optional

DOC_SCHEMA_VERSION = 1

MAX_DOC_BYTES = 262_144
MAX_HYPOTHESES = 100
MAX_INTERESTING_ENDPOINTS = 200
MAX_FREE_TEXT_CHARS = 4000
MAX_PATCH_OPS = 50

HYPOTHESIS_STATUSES = frozenset({"open", "supported", "refuted"})

# JSON Patch-like paths allowed for notes.app.patch (and CLI structural edits).
# Exact paths or prefixes with trailing segment ids.
ALLOWLISTED_ROOT_KEYS = frozenset(
    {
        "tech_stack",
        "app_class",
        "auth_model",
        "interesting_endpoints",
        "hypotheses",
        "summary",
    }
)


def empty_document() -> dict[str, Any]:
    """Return a fresh schema_version-1 app notes document."""
    return {
        "schema_version": DOC_SCHEMA_VERSION,
        "tech_stack": [],
        "app_class": "",
        "auth_model": "",
        "interesting_endpoints": [],
        "hypotheses": [],
        "summary": "",
        "tainted": False,
    }


def normalize_document(raw: Optional[dict[str, Any]]) -> dict[str, Any]:
    """
    Purpose:
        Coerce a partial/legacy dict into a complete document skeleton.
    """
    base = empty_document()
    if not raw or not isinstance(raw, dict):
        return base
    if "tech_stack" in raw and isinstance(raw["tech_stack"], list):
        base["tech_stack"] = list(raw["tech_stack"])
    if "app_class" in raw and isinstance(raw["app_class"], str):
        base["app_class"] = raw["app_class"]
    if "auth_model" in raw and isinstance(raw["auth_model"], str):
        base["auth_model"] = raw["auth_model"]
    if "interesting_endpoints" in raw and isinstance(
        raw["interesting_endpoints"], list
    ):
        base["interesting_endpoints"] = list(raw["interesting_endpoints"])
    if "hypotheses" in raw and isinstance(raw["hypotheses"], list):
        base["hypotheses"] = list(raw["hypotheses"])
    if "summary" in raw and isinstance(raw["summary"], str):
        base["summary"] = raw["summary"]
    if "tainted" in raw:
        base["tainted"] = bool(raw["tainted"])
    # Preserve unknown non-dangerous keys for forward compatibility (operator edit).
    for key, value in raw.items():
        if key not in base and key != "schema_version":
            if key.startswith("_"):
                continue
            base[key] = value
    base["schema_version"] = DOC_SCHEMA_VERSION
    return base
