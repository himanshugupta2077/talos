"""
Module: talos.sqli.models

Purpose:
    Verdicts, technique catalogue, and result dataclasses for the
    SQL injection engine.

Dependencies: dataclasses
Data flow: payloads / engine / CLI / findings_bridge import constants.
Side effects: None.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


VERDICT_SQLI = "SQLI"
"""Probe produced a DBMS error, UNION leak, or time delay vs baseline."""

VERDICT_SECURE = "SECURE"
"""No SQLi signal on this probe."""

VERDICT_UNKNOWN = "UNKNOWN"
"""Probe did not complete (network / store error)."""

SQLI_VERDICTS: tuple[str, ...] = (
    VERDICT_SQLI,
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
)

ATTACK_MODULE = "sqli"
"""Findings attack_module label (cluster SQLI:<endpoint_id>)."""

FAMILY_ERROR = "error"
FAMILY_UNION = "union"
FAMILY_BOOLEAN = "boolean"
FAMILY_TIME = "time"

FAMILIES: tuple[str, ...] = (
    FAMILY_ERROR,
    FAMILY_UNION,
    FAMILY_BOOLEAN,
    FAMILY_TIME,
)


@dataclass(frozen=True)
class SqliPayload:
    """
    Purpose:
        One SQL payload to append to an injection point.

    Fields:
        technique   — stable id (job meta / CLI --technique).
        family      — error | union | boolean | time.
        payload     — bytes appended to the original field value.
        description — one-line operator explanation.
        delay_s     — expected sleep for time-based probes (0 otherwise).
    """

    technique: str
    family: str
    payload: str
    description: str
    delay_s: float = 0.0

    def to_dict(self) -> dict:
        """Purpose: JSON-ready payload description. Output: dict."""
        return {
            "technique": self.technique,
            "family": self.family,
            "payload": self.payload,
            "description": self.description,
            "delay_s": self.delay_s,
        }


@dataclass(frozen=True)
class InjectionPoint:
    """
    Purpose:
        One mutable field on a captured request.

    Fields:
        location     — query | body (v1 does not mutate headers/cookies).
        name         — query key, form field, or JSON path (``[0]``, ``user.id``).
        original     — captured string value.
        surface_kind — query | json_body | form_body.
    """

    location: str
    name: str
    original: str
    surface_kind: str

    def to_dict(self) -> dict:
        """Purpose: JSON-ready injection point. Output: dict."""
        return {
            "location": self.location,
            "name": self.name,
            "original": self.original,
            "surface_kind": self.surface_kind,
        }


@dataclass
class SqliOutcome:
    """
    Purpose:
        Result of one SQLi probe (one unique replay flow).
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
    dbms: Optional[str]
    evidence: str
    verdict: str
    risk_hint: str
    failure_reason: Optional[str] = None
    extra: dict = field(default_factory=dict)


# Human catalogue for CLI / Control Panel pickers.
# Keep in sync with generate_sqli_payloads() technique ids.
TECHNIQUE_CATALOG: tuple[dict[str, str], ...] = (
    {
        "name": "quote_single",
        "family": FAMILY_ERROR,
        "description": "Append a single quote to break a SQL string.",
    },
    {
        "name": "quote_double",
        "family": FAMILY_ERROR,
        "description": "Append a double quote.",
    },
    {
        "name": "quote_paren",
        "family": FAMILY_ERROR,
        "description": "Close a quoted value and a parenthesis.",
    },
    {
        "name": "comment_dash",
        "family": FAMILY_ERROR,
        "description": "Single quote plus SQL line comment.",
    },
    {
        "name": "stacked_semi",
        "family": FAMILY_ERROR,
        "description": "Stacked-query terminator plus comment.",
    },
    {
        "name": "tautology",
        "family": FAMILY_ERROR,
        "description": "Classic OR 1=1 string tautology (often errors or changes rows).",
    },
    {
        "name": "mssql_convert",
        "family": FAMILY_ERROR,
        "description": "SQL Server CONVERT(int, @@version) error-based leak.",
    },
    {
        "name": "mysql_extractvalue",
        "family": FAMILY_ERROR,
        "description": "MySQL EXTRACTVALUE/XPATH error-based leak.",
    },
    {
        "name": "union_1",
        "family": FAMILY_UNION,
        "description": "UNION SELECT with 1 NULL column.",
    },
    {
        "name": "union_2",
        "family": FAMILY_UNION,
        "description": "UNION SELECT with 2 NULL columns.",
    },
    {
        "name": "union_3",
        "family": FAMILY_UNION,
        "description": "UNION SELECT with 3 NULL columns.",
    },
    {
        "name": "union_4",
        "family": FAMILY_UNION,
        "description": "UNION SELECT with 4 NULL columns.",
    },
    {
        "name": "union_5",
        "family": FAMILY_UNION,
        "description": "UNION SELECT with 5 NULL columns.",
    },
    {
        "name": "bool_true",
        "family": FAMILY_BOOLEAN,
        "description": "Boolean true: AND '1'='1 (observation; finding on error only).",
    },
    {
        "name": "bool_false",
        "family": FAMILY_BOOLEAN,
        "description": "Boolean false: AND '1'='2 (observation; finding on error only).",
    },
    {
        "name": "mssql_waitfor",
        "family": FAMILY_TIME,
        "description": "SQL Server WAITFOR DELAY 5s.",
    },
    {
        "name": "mysql_sleep",
        "family": FAMILY_TIME,
        "description": "MySQL SLEEP(5).",
    },
    {
        "name": "pg_sleep",
        "family": FAMILY_TIME,
        "description": "PostgreSQL pg_sleep(5).",
    },
)

TECHNIQUE_NAMES: tuple[str, ...] = tuple(item["name"] for item in TECHNIQUE_CATALOG)
TECHNIQUE_BY_NAME: dict[str, dict[str, str]] = {
    item["name"]: item for item in TECHNIQUE_CATALOG
}

DEFAULT_PAYLOAD_COUNT = len(TECHNIQUE_CATALOG)
"""Jobs per injection point when the operator runs every technique."""
