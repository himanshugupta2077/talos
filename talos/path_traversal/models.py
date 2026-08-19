"""
Module: talos.path_traversal.models

Purpose:
    Verdicts, technique catalogue metadata, and result dataclasses for
    the path traversal / LFI engine.

Dependencies: dataclasses
Data flow: payloads / engine / CLI / findings_bridge import constants.
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


VERDICT_PATH_TRAVERSAL = "PATH_TRAVERSAL"
"""Probe leaked a well-known file (or PHP-filtered copy) vs baseline."""

VERDICT_SECURE = "SECURE"
"""No path-traversal / LFI file-content signal on this probe."""

VERDICT_UNKNOWN = "UNKNOWN"
"""Probe did not complete (network / store error)."""

PATH_TRAVERSAL_VERDICTS: tuple[str, ...] = (
    VERDICT_PATH_TRAVERSAL,
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
)

ATTACK_MODULE = "path_traversal"
"""Findings attack_module label (cluster PATH_TRAVERSAL:<endpoint_id>)."""

FAMILY_UNIX = "unix"
FAMILY_WINDOWS = "windows"
FAMILY_DOTDOT = "dotdot"
FAMILY_ENCODED = "encoded"
FAMILY_WRAPPER = "wrapper"
FAMILY_NULLBYTE = "nullbyte"
FAMILY_BYPASS = "bypass"

FAMILIES: tuple[str, ...] = (
    FAMILY_UNIX,
    FAMILY_WINDOWS,
    FAMILY_DOTDOT,
    FAMILY_ENCODED,
    FAMILY_WRAPPER,
    FAMILY_NULLBYTE,
    FAMILY_BYPASS,
)

OS_GENERIC = "generic"
OS_UNIX = "unix"
OS_WINDOWS = "windows"
OS_PHP = "php"

INJECT_REPLACE = "replace"
INJECT_SUFFIX = "suffix"

INJECT_MODES: tuple[str, ...] = (INJECT_REPLACE, INJECT_SUFFIX)


@dataclass(frozen=True)
class PathTraversalPayload:
    """
    Purpose:
        One filesystem / LFI payload to send in place of a captured field.

    Fields:
        technique    — unique id (job meta / results).
        family       — unix | windows | dotdot | encoded | wrapper |
                       nullbyte | bypass.
        payload      — string written into the field (replace) or appended
                       after the original (suffix).
        description  — one-line operator explanation.
        os           — intended target (generic | unix | windows | php).
        inject_mode  — replace (default) | suffix.
    """

    technique: str
    family: str
    payload: str
    description: str
    os: str = OS_GENERIC
    inject_mode: str = INJECT_REPLACE

    def to_dict(self) -> dict:
        """Purpose: JSON-ready payload description. Output: dict."""
        return {
            "technique": self.technique,
            "family": self.family,
            "payload": self.payload,
            "description": self.description,
            "os": self.os,
            "inject_mode": self.inject_mode,
        }


@dataclass(frozen=True)
class InjectionPoint:
    """
    Purpose:
        One mutable field on a captured request.

    Fields:
        location         — query | body | path.
        name             — query key, form field, JSON path, path param,
                           or multipart field name.
        original         — captured string value.
        surface_kind     — query | json_body | form_body | path |
                           multipart_filename.
        path_index       — path segment index when location=path.
        normalized_path  — endpoint ``/users/{id}`` template when known.
    """

    location: str
    name: str
    original: str
    surface_kind: str
    path_index: Optional[int] = None
    normalized_path: str = ""

    def to_dict(self) -> dict:
        """Purpose: JSON-ready injection point. Output: dict."""
        out = {
            "location": self.location,
            "name": self.name,
            "original": self.original,
            "surface_kind": self.surface_kind,
        }
        if self.path_index is not None:
            out["path_index"] = self.path_index
        if self.normalized_path:
            out["normalized_path"] = self.normalized_path
        return out


@dataclass
class PathTraversalOutcome:
    """
    Purpose:
        Result of one path-traversal probe (one unique replay flow).
    """

    original_flow_id: str
    replayed_flow_id: Optional[str]
    endpoint_id: Optional[str]
    host: str
    method: str
    path: str
    technique: str
    technique_family: str
    location: str
    param_name: str
    payload_sent: str
    original_value: str
    original_status: Optional[int]
    replay_status: Optional[int]
    elapsed_ms: Optional[int]
    os_hint: Optional[str]
    evidence: str
    verdict: str
    risk_hint: str
    failure_reason: Optional[str] = None
    extra: dict = field(default_factory=dict)
