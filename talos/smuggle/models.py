"""
Module: talos.smuggle.models

Purpose:
    Verdicts, technique catalogue, and result dataclasses for HTTP
    request smuggling.

Dependencies: dataclasses
Data flow: payloads / engine / CLI / findings_bridge import constants.
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


VERDICT_SMUGGLE = "SMUGGLE"
"""Confirmed front-end / back-end desync (poisoned follow-up or canary)."""

VERDICT_SECURE = "SECURE"
"""No confirmed desync on this technique."""

VERDICT_UNKNOWN = "UNKNOWN"
"""Probe did not complete (connect / NTLM / store error)."""

SMUGGLE_VERDICTS: tuple[str, ...] = (
    VERDICT_SMUGGLE,
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
)

ATTACK_MODULE = "smuggle"
"""Findings attack_module label (cluster SMUGGLE:<origin>)."""

FAMILY_CLTE = "cl_te"
FAMILY_TECL = "te_cl"
FAMILY_TE_OBFUSCATE = "te_obfuscate"
FAMILY_CLCL = "cl_cl"

FAMILIES: tuple[str, ...] = (
    FAMILY_CLTE,
    FAMILY_TECL,
    FAMILY_TE_OBFUSCATE,
    FAMILY_CLCL,
)


@dataclass(frozen=True)
class SmugglePayload:
    """
    Purpose:
        One raw HTTP/1.1 probe (conflicting framing headers + body).

    Fields:
        technique   — stable id (job meta / CLI --technique).
        family      — cl_te | te_cl | te_obfuscate | cl_cl.
        description — one-line operator explanation.
        method      — usually POST.
        headers     — ordered pairs; duplicates are intentional (CL.CL, TE.TE).
        body        — bytes after the header block.
        canary_path — unique path smuggled as the leftover request.
    """

    technique: str
    family: str
    description: str
    method: str
    headers: tuple[tuple[str, str], ...]
    body: bytes
    canary_path: str

    def to_dict(self) -> dict:
        """Purpose: JSON-ready payload description (body omitted)."""
        return {
            "technique": self.technique,
            "family": self.family,
            "description": self.description,
            "method": self.method,
            "headers": [list(pair) for pair in self.headers],
            "body_len": len(self.body),
            "canary_path": self.canary_path,
        }


@dataclass
class SmuggleOutcome:
    """
    Purpose:
        Result of one smuggling probe (one unique replay flow).
    """

    original_flow_id: str
    replayed_flow_id: Optional[str]
    endpoint_id: Optional[str]
    host: str
    method: str
    path: str
    technique: str
    technique_family: str
    canary_path: str
    ntlm_used: bool
    baseline_status: Optional[int]
    probe_status: Optional[int]
    followup_status: Optional[int]
    probe_elapsed_ms: Optional[int]
    followup_elapsed_ms: Optional[int]
    timeout_hit: bool
    desync_signal: str
    evidence: str
    original_status: Optional[int]
    verdict: str
    risk_hint: str
    failure_reason: Optional[str] = None
    extra: dict = field(default_factory=dict)


# Human catalogue for CLI / Control Panel pickers.
# Keep in sync with generate_smuggle_payloads() technique ids.
TECHNIQUE_CATALOG: tuple[dict[str, str], ...] = (
    {
        "name": "cl_te",
        "family": FAMILY_CLTE,
        "description": "Content-Length + Transfer-Encoding: chunked (front CL, back TE).",
    },
    {
        "name": "te_cl",
        "family": FAMILY_TECL,
        "description": "Chunked body with a short Content-Length (front TE, back CL).",
    },
    {
        "name": "te_space",
        "family": FAMILY_TE_OBFUSCATE,
        "description": "Obfuscated TE: 'chunked' with a trailing space.",
    },
    {
        "name": "te_tab",
        "family": FAMILY_TE_OBFUSCATE,
        "description": "Obfuscated TE: tab before 'chunked'.",
    },
    {
        "name": "te_xchunked",
        "family": FAMILY_TE_OBFUSCATE,
        "description": "Obfuscated TE: xchunked (one parser ignores TE).",
    },
    {
        "name": "te_dual",
        "family": FAMILY_TE_OBFUSCATE,
        "description": "Two Transfer-Encoding headers (chunked + identity).",
    },
    {
        "name": "cl_cl",
        "family": FAMILY_CLCL,
        "description": "Two Content-Length headers with conflicting values.",
    },
)

TECHNIQUE_NAMES: tuple[str, ...] = tuple(item["name"] for item in TECHNIQUE_CATALOG)
TECHNIQUE_BY_NAME: dict[str, dict[str, str]] = {
    item["name"]: item for item in TECHNIQUE_CATALOG
}
