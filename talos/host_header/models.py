"""
Module: talos.host_header.models

Purpose:
    Verdicts, technique catalogue metadata, and result dataclasses for
    the host-header injection engine.

Dependencies: dataclasses
Data flow: payloads / engine / CLI / findings_bridge import constants.
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


VERDICT_HOST_HEADER = "HOST_HEADER"
"""Probe reflected the attacker host in a URL-shaped response sink vs baseline."""

VERDICT_SECURE = "SECURE"
"""No host-header injection signal on this probe."""

VERDICT_UNKNOWN = "UNKNOWN"
"""Probe did not complete (network / store error)."""

HOST_HEADER_VERDICTS: tuple[str, ...] = (
    VERDICT_HOST_HEADER,
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
)

ATTACK_MODULE = "host_header"
"""Findings attack_module label (cluster HOST_HEADER:<endpoint_id>)."""

FAMILY_ABSOLUTE = "absolute"
FAMILY_PORT = "port"
FAMILY_AMBIGUOUS = "ambiguous"
FAMILY_ABSOLUTE_URL = "absolute_url"
FAMILY_ENCODED = "encoded"
FAMILY_BYPASS = "bypass"
FAMILY_CRLF = "crlf"

FAMILIES: tuple[str, ...] = (
    FAMILY_ABSOLUTE,
    FAMILY_PORT,
    FAMILY_AMBIGUOUS,
    FAMILY_ABSOLUTE_URL,
    FAMILY_ENCODED,
    FAMILY_BYPASS,
    FAMILY_CRLF,
)

CANARY_HOST = "talos-hhi.invalid"
"""Default attacker host used in payloads and detection (.invalid TLD)."""

LOCATION_HEADER = "header"
SURFACE_HOST = "host"
SURFACE_OVERRIDE = "host_override"

INJECT_REPLACE = "replace"

INJECT_MODES: tuple[str, ...] = (INJECT_REPLACE,)


@dataclass(frozen=True)
class HostHeaderPayload:
    """
    Purpose:
        One host-header injection payload to write into a request header.

    Fields:
        technique    — unique id (job meta / results).
        family       — absolute | port | ambiguous | absolute_url | encoded |
                       bypass | crlf.
        payload      — header value. May contain {CANARY}, {ORIG},
                       {ORIG_HOST}, {ORIG_PORT}.
        description  — one-line operator explanation.
        headers      — restrict to these header names; empty = every point.
        inject_mode  — replace (only mode in v1).
    """

    technique: str
    family: str
    payload: str
    description: str
    headers: tuple[str, ...] = ()
    inject_mode: str = INJECT_REPLACE

    def to_dict(self) -> dict:
        """Purpose: JSON-ready payload description. Output: dict."""
        return {
            "technique": self.technique,
            "family": self.family,
            "payload": self.payload,
            "description": self.description,
            "headers": list(self.headers),
            "inject_mode": self.inject_mode,
        }


@dataclass(frozen=True)
class InjectionPoint:
    """
    Purpose:
        One mutable host-related header on a captured request.

    Fields:
        location         — always ``header``.
        name             — Host, X-Forwarded-Host, Forwarded, …
        original         — captured value (empty when the header was absent).
        surface_kind     — host | host_override.
        path_index       — unused (kept for scheduler meta parity).
        normalized_path  — endpoint template when known.
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
        if self.normalized_path:
            out["normalized_path"] = self.normalized_path
        return out


@dataclass
class HostHeaderOutcome:
    """
    Purpose:
        Result of one host-header injection probe (one unique replay flow).
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
    reflected_url: str
    evidence: str
    verdict: str
    risk_hint: str
    failure_reason: Optional[str] = None
    extra: dict = field(default_factory=dict)
