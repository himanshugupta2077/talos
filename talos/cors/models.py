"""
Module: talos.cors.models

Purpose:
    Verdicts, technique catalogue metadata, and result dataclasses for
    the CORS misconfiguration engine.

Dependencies: dataclasses
Data flow: payloads / engine / CLI / findings_bridge import constants.
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# ------------------------------------------------------------------ #
# Verdicts                                                             #
# ------------------------------------------------------------------ #

VERDICT_CORS_MISCONFIG = "CORS_MISCONFIG"
"""Attacker-controlled Origin was reflected in Access-Control-Allow-Origin."""

VERDICT_SECURE = "SECURE"
"""No attacker origin reflection (includes ACAO:* and ACAC-only responses)."""

VERDICT_UNKNOWN = "UNKNOWN"
"""Probe did not complete (network / store error)."""

CORS_VERDICTS: tuple[str, ...] = (
    VERDICT_CORS_MISCONFIG,
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
)

ATTACK_MODULE = "cors"
"""Findings attack_module label (cluster CORS:<origin>)."""


# ------------------------------------------------------------------ #
# Technique families                                                   #
# ------------------------------------------------------------------ #

FAMILY_BASELINE = "baseline"
FAMILY_ARBITRARY = "arbitrary_origin"
FAMILY_SUBDOMAIN = "subdomain_reflection"
FAMILY_PREFIX_SUFFIX = "prefix_suffix"
FAMILY_PARSER = "regex_parser"
FAMILY_SPECIAL = "special_origin"
FAMILY_SCHEME_PORT = "scheme_port"
FAMILY_PREFLIGHT = "preflight"


# ------------------------------------------------------------------ #
# Payload + outcome                                                    #
# ------------------------------------------------------------------ #

@dataclass(frozen=True)
class CorsPayload:
    """
    Purpose:
        One Origin mutation to send as a distinct probe.

    Fields:
        technique            — stable id (job meta / CLI --technique).
        family               — grouping for UI / reports.
        origin               — Origin header value to send.
        description          — one-line operator explanation.
        attacker_controlled  — True when ACAO echo of this origin is an issue.
        method_override      — if set, send this method instead of baseline
                               (OPTIONS for preflight).
        acr_method           — Access-Control-Request-Method (preflight).
        acr_headers          — Access-Control-Request-Headers (preflight).
    """

    technique: str
    family: str
    origin: str
    description: str
    attacker_controlled: bool
    method_override: Optional[str] = None
    acr_method: Optional[str] = None
    acr_headers: Optional[str] = None

    def to_dict(self) -> dict:
        """Purpose: JSON-ready payload description. Output: dict."""
        return {
            "technique": self.technique,
            "family": self.family,
            "origin": self.origin,
            "description": self.description,
            "attacker_controlled": self.attacker_controlled,
            "method_override": self.method_override,
            "acr_method": self.acr_method,
            "acr_headers": self.acr_headers,
        }


@dataclass
class CorsOutcome:
    """
    Purpose:
        Result of one CORS probe (one unique replay flow).

    Fields:
        original_flow_id  — captured baseline UUID (never overwritten).
        replayed_flow_id  — new flow UUID, or None if nothing was stored.
        endpoint_id       — target endpoint, if known.
        host              — target origin key used for finding cluster.
        technique         — payload technique id.
        technique_family  — payload family.
        origin_sent       — Origin request header that was sent.
        acao / acac       — CORS response headers (may be None).
        reflected         — True when ACAO equals the attacker origin sent.
        credentials       — True when ACAC is the token 'true'.
        wildcard          — True when ACAO is '*'.
        original_status   — baseline HTTP status.
        replay_status     — probe HTTP status, or None on transport error.
        verdict           — CORS_MISCONFIG | SECURE | UNKNOWN.
        risk_hint         — reflected_origin | credentials | null_origin | ''.
        failure_reason    — set on skip / transport / store failure.
    """

    original_flow_id: str
    replayed_flow_id: Optional[str]
    endpoint_id: Optional[str]
    host: str
    technique: str
    technique_family: str
    origin_sent: str
    acao: Optional[str]
    acac: Optional[str]
    reflected: bool
    credentials: bool
    wildcard: bool
    original_status: Optional[int]
    replay_status: Optional[int]
    verdict: str
    risk_hint: str
    failure_reason: Optional[str] = None
    extra_headers: dict = field(default_factory=dict)


# Human catalogue for CLI / Control Panel pickers.
# Keep in sync with generate_cors_payloads() technique ids.
TECHNIQUE_CATALOG: tuple[dict[str, str], ...] = (
    {
        "name": "baseline_origin",
        "family": FAMILY_BASELINE,
        "description": "Replay with the app's own Origin (or a host-synthesized one).",
    },
    {
        "name": "arbitrary_https",
        "family": FAMILY_ARBITRARY,
        "description": "Random https attacker origin on a reserved .invalid domain.",
    },
    {
        "name": "arbitrary_http",
        "family": FAMILY_ARBITRARY,
        "description": "Random http attacker origin on a reserved .invalid domain.",
    },
    {
        "name": "attacker_subdomain",
        "family": FAMILY_ARBITRARY,
        "description": "Subdomain of the random attacker origin.",
    },
    {
        "name": "subdomain_of_target",
        "family": FAMILY_SUBDOMAIN,
        "description": "Attacker-controlled subdomain of the target host.",
    },
    {
        "name": "prefix_bypass",
        "family": FAMILY_PREFIX_SUFFIX,
        "description": "target-host as a prefix of an attacker domain.",
    },
    {
        "name": "suffix_bypass",
        "family": FAMILY_PREFIX_SUFFIX,
        "description": "Attacker label glued onto the target host (endswith bypass).",
    },
    {
        "name": "trusted_plus",
        "family": FAMILY_PREFIX_SUFFIX,
        "description": "Full trusted origin concatenated before an attacker host.",
    },
    {
        "name": "unescaped_dot",
        "family": FAMILY_PARSER,
        "description": "Replace the first dot in the host (regex '.' vs '\\.' ).",
    },
    {
        "name": "encoded_dot",
        "family": FAMILY_PARSER,
        "description": "Percent-encoded dot between target host and attacker domain.",
    },
    {
        "name": "underscore",
        "family": FAMILY_PARSER,
        "description": "Underscore after the target host before the attacker domain.",
    },
    {
        "name": "null_origin",
        "family": FAMILY_SPECIAL,
        "description": "Origin: null (sandboxed iframe / data: / file: classic).",
    },
    {
        "name": "wildcard_origin",
        "family": FAMILY_SPECIAL,
        "description": "Origin: * (observation only — ACAO:* is not a finding).",
    },
    {
        "name": "localhost",
        "family": FAMILY_SPECIAL,
        "description": "https://localhost as Origin.",
    },
    {
        "name": "loopback",
        "family": FAMILY_SPECIAL,
        "description": "http://127.0.0.1 as Origin.",
    },
    {
        "name": "scheme_downgrade",
        "family": FAMILY_SCHEME_PORT,
        "description": "http:// variant of the app origin (observation).",
    },
    {
        "name": "port_443",
        "family": FAMILY_SCHEME_PORT,
        "description": "Attacker origin with an explicit :443 port.",
    },
    {
        "name": "port_80",
        "family": FAMILY_SCHEME_PORT,
        "description": "Attacker origin with an explicit :80 port.",
    },
    {
        "name": "port_8080",
        "family": FAMILY_SCHEME_PORT,
        "description": "Attacker origin with an explicit :8080 port.",
    },
    {
        "name": "preflight",
        "family": FAMILY_PREFLIGHT,
        "description": "OPTIONS preflight with attacker Origin + ACR-Method.",
    },
)

TECHNIQUE_NAMES: tuple[str, ...] = tuple(item["name"] for item in TECHNIQUE_CATALOG)
TECHNIQUE_BY_NAME: dict[str, dict[str, str]] = {
    item["name"]: item for item in TECHNIQUE_CATALOG
}
