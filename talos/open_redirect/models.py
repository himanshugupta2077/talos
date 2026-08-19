"""
Module: talos.open_redirect.models

Purpose:
    Verdicts, technique catalogue metadata, and result dataclasses for
    the open-redirect engine.

Dependencies: dataclasses
Data flow: payloads / engine / CLI / findings_bridge import constants.
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


VERDICT_OPEN_REDIRECT = "OPEN_REDIRECT"
"""Probe issued a new redirect to the attacker canary vs baseline."""

VERDICT_SECURE = "SECURE"
"""No open-redirect signal on this probe."""

VERDICT_UNKNOWN = "UNKNOWN"
"""Probe did not complete (network / store error)."""

OPEN_REDIRECT_VERDICTS: tuple[str, ...] = (
    VERDICT_OPEN_REDIRECT,
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
)

ATTACK_MODULE = "open_redirect"
"""Findings attack_module label (cluster OPEN_REDIRECT:<endpoint_id>)."""

FAMILY_ABSOLUTE = "absolute"
FAMILY_PROTO_REL = "proto_rel"
FAMILY_SLASH = "slash"
FAMILY_ENCODED = "encoded"
FAMILY_USERINFO = "userinfo"
FAMILY_DATA_JS = "data_js"
FAMILY_FRAGMENT = "fragment"
FAMILY_CRLF = "crlf"

FAMILIES: tuple[str, ...] = (
    FAMILY_ABSOLUTE,
    FAMILY_PROTO_REL,
    FAMILY_SLASH,
    FAMILY_ENCODED,
    FAMILY_USERINFO,
    FAMILY_DATA_JS,
    FAMILY_FRAGMENT,
    FAMILY_CRLF,
)

CANARY_HOST = "talos-or.invalid"
"""Default attacker host used in payloads and detection."""

INJECT_REPLACE = "replace"
INJECT_SUFFIX = "suffix"

INJECT_MODES: tuple[str, ...] = (INJECT_REPLACE, INJECT_SUFFIX)


@dataclass(frozen=True)
class OpenRedirectPayload:
    """
    Purpose:
        One open-redirect payload to send in place of a captured field.

    Fields:
        technique    — unique id (job meta / results).
        family       — absolute | proto_rel | slash | encoded | userinfo |
                       data_js | fragment | crlf.
        payload      — string written into the field. May contain {REDIR}.
        description  — one-line operator explanation.
        inject_mode  — replace (default) | suffix.
    """

    technique: str
    family: str
    payload: str
    description: str
    inject_mode: str = INJECT_REPLACE

    def to_dict(self) -> dict:
        """Purpose: JSON-ready payload description. Output: dict."""
        return {
            "technique": self.technique,
            "family": self.family,
            "payload": self.payload,
            "description": self.description,
            "inject_mode": self.inject_mode,
        }


@dataclass
class OpenRedirectOutcome:
    """
    Purpose:
        Result of one open-redirect probe (one unique replay flow).
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
    redirect_url: str
    evidence: str
    verdict: str
    risk_hint: str
    failure_reason: Optional[str] = None
    extra: dict = field(default_factory=dict)
