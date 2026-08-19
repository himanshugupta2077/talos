"""
Module: talos.ssrf.models

Purpose:
    Verdicts, technique catalogue metadata, and result dataclasses for
    the SSRF engine.

Dependencies: dataclasses
Data flow: payloads / engine / CLI / findings_bridge import constants.
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


VERDICT_SSRF = "SSRF"
"""Probe returned a new server-side fetch signature vs baseline."""

VERDICT_SECURE = "SECURE"
"""No in-band SSRF signature on this probe."""

VERDICT_UNKNOWN = "UNKNOWN"
"""Probe did not complete (network / store error)."""

SSRF_VERDICTS: tuple[str, ...] = (
    VERDICT_SSRF,
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
)

ATTACK_MODULE = "ssrf"
"""Findings attack_module label (cluster SSRF:<endpoint_id>)."""

FAMILY_LOOPBACK = "loopback"
FAMILY_CLOUD = "cloud"
FAMILY_PROTOCOL = "protocol"
FAMILY_BYPASS = "bypass"
FAMILY_ENCODED = "encoded"
FAMILY_INTERNAL = "internal"
FAMILY_OAST = "oast"

FAMILIES: tuple[str, ...] = (
    FAMILY_LOOPBACK,
    FAMILY_CLOUD,
    FAMILY_PROTOCOL,
    FAMILY_BYPASS,
    FAMILY_ENCODED,
    FAMILY_INTERNAL,
    FAMILY_OAST,
)

SINK_GENERIC = "generic"
SINK_LOOPBACK = "loopback"
SINK_CLOUD = "cloud"
SINK_FILE = "file"
SINK_SERVICE = "service"
SINK_OAST = "oast"
SINK_INTERNAL = "internal"

INJECT_REPLACE = "replace"
INJECT_SUFFIX = "suffix"

INJECT_MODES: tuple[str, ...] = (INJECT_REPLACE, INJECT_SUFFIX)


@dataclass(frozen=True)
class SsrfPayload:
    """
    Purpose:
        One SSRF payload to send in place of a captured field.

    Fields:
        technique             — unique id (job meta / results).
        family                — loopback | cloud | protocol | bypass |
                                encoded | internal | oast.
        payload               — string written into the field. May contain
                                ``{COLLAB}``, ``{OAST}``, ``{CANARY}``.
        description           — one-line operator explanation.
        sink                  — intended sink class for reporting.
        inject_mode           — replace (default) | suffix.
        requires_collaborator — skip unless --collaborator is set.
    """

    technique: str
    family: str
    payload: str
    description: str
    sink: str = SINK_GENERIC
    inject_mode: str = INJECT_REPLACE
    requires_collaborator: bool = False

    def to_dict(self) -> dict:
        """Purpose: JSON-ready payload description. Output: dict."""
        return {
            "technique": self.technique,
            "family": self.family,
            "payload": self.payload,
            "description": self.description,
            "sink": self.sink,
            "inject_mode": self.inject_mode,
            "requires_collaborator": self.requires_collaborator,
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
class SsrfOutcome:
    """
    Purpose:
        Result of one SSRF probe (one unique replay flow).
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
    sink_hint: Optional[str]
    oast_host: str
    evidence: str
    verdict: str
    risk_hint: str
    failure_reason: Optional[str] = None
    extra: dict = field(default_factory=dict)
