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

DB_UNKNOWN = "unknown"
"""Default: multi-vendor payloads plus encoded variants."""

DB_MSSQL = "mssql"
"""Microsoft SQL Server / T-SQL focused set."""

DB_TYPES: tuple[str, ...] = (DB_UNKNOWN, DB_MSSQL)

DB_TYPE_ALIASES: dict[str, str] = {
    "unknown": DB_UNKNOWN,
    "": DB_UNKNOWN,
    "mssql": DB_MSSQL,
    "sqlserver": DB_MSSQL,
    "sql-server": DB_MSSQL,
    "sql_server": DB_MSSQL,
    "microsoft": DB_MSSQL,
    "microsoft_sql_server": DB_MSSQL,
    "microsoft-sql-server": DB_MSSQL,
}

DB_TYPE_CATALOG: tuple[dict[str, str], ...] = (
    {
        "name": DB_UNKNOWN,
        "label": "Unknown",
        "description": (
            "DBMS not known. Send multi-vendor error / UNION / boolean / "
            "time payloads plus URL, double-URL, and IIS unicode encodings "
            "of the syntax breakers."
        ),
    },
    {
        "name": DB_MSSQL,
        "label": "Microsoft SQL Server",
        "description": (
            "T-SQL / SQL Server only: CONVERT/CAST leaks, WAITFOR DELAY, "
            "stacked comments, and integer tautologies."
        ),
    },
)

ENCODING_RAW = "raw"
ENCODING_URL = "url"
ENCODING_DOUBLE_URL = "double_url"
ENCODING_UNICODE = "unicode"

ENCODINGS: tuple[str, ...] = (
    ENCODING_RAW,
    ENCODING_URL,
    ENCODING_DOUBLE_URL,
    ENCODING_UNICODE,
)

DBMS_GENERIC = "generic"
DBMS_MSSQL = "mssql"
DBMS_MYSQL = "mysql"
DBMS_POSTGRES = "postgresql"
DBMS_ORACLE = "oracle"
DBMS_SQLITE = "sqlite"


def normalize_db_type(raw: object) -> str:
    """
    Purpose:
        Map operator --db / Select DB text to a canonical db type.
    Input:
        raw — unknown | mssql | aliases (sqlserver, microsoft, …).
    Output:
        DB_UNKNOWN or DB_MSSQL.
    Side effects: None. Raises ValueError on an unknown token.
    """
    key = str(raw or DB_UNKNOWN).strip().lower().replace(" ", "_")
    mapped = DB_TYPE_ALIASES.get(key)
    if mapped is None:
        raise ValueError(
            f"unknown SQLi database {raw!r}. "
            f"Expected one of: {', '.join(DB_TYPES)}"
        )
    return mapped


@dataclass(frozen=True)
class SqliPayload:
    """
    Purpose:
        One SQL payload to append to an injection point.

    Fields:
        technique      — unique id (job meta / results). Encoded variants
                         use ``{base}__{encoding}``.
        family         — error | union | boolean | time.
        payload        — bytes appended to the original field value.
        description    — one-line operator explanation.
        delay_s        — expected sleep for time-based probes (0 otherwise).
        dbms           — intended vendor (generic | mssql | mysql | …).
        encoding       — raw | url | double_url | unicode.
        base_technique — picker / --technique name (equals technique when raw).
    """

    technique: str
    family: str
    payload: str
    description: str
    delay_s: float = 0.0
    dbms: str = DBMS_GENERIC
    encoding: str = ENCODING_RAW
    base_technique: str = ""

    def to_dict(self) -> dict:
        """Purpose: JSON-ready payload description. Output: dict."""
        base = self.base_technique or self.technique
        return {
            "technique": self.technique,
            "family": self.family,
            "payload": self.payload,
            "description": self.description,
            "delay_s": self.delay_s,
            "dbms": self.dbms,
            "encoding": self.encoding,
            "base_technique": base,
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


# Human catalogue for CLI / Control Panel pickers (base techniques only).
# Encoded variants are generated from encodeable rows when --db unknown.
# Keep in sync with generate_sqli_payloads() base technique ids.
TECHNIQUE_CATALOG: tuple[dict[str, object], ...] = (
    {
        "name": "quote_single",
        "family": FAMILY_ERROR,
        "description": "Append a single quote to break a SQL string.",
        "dbms": DBMS_GENERIC,
        "encodeable": True,
    },
    {
        "name": "quote_double",
        "family": FAMILY_ERROR,
        "description": "Append a double quote.",
        "dbms": DBMS_GENERIC,
        "encodeable": True,
    },
    {
        "name": "quote_paren",
        "family": FAMILY_ERROR,
        "description": "Close a quoted value and a parenthesis.",
        "dbms": DBMS_GENERIC,
        "encodeable": True,
    },
    {
        "name": "comment_dash",
        "family": FAMILY_ERROR,
        "description": "Single quote plus SQL line comment.",
        "dbms": DBMS_GENERIC,
        "encodeable": True,
    },
    {
        "name": "comment_dash_space",
        "family": FAMILY_ERROR,
        "description": "Quote plus -- comment with a trailing space (SQL Server).",
        "dbms": DBMS_MSSQL,
        "encodeable": False,
    },
    {
        "name": "stacked_semi",
        "family": FAMILY_ERROR,
        "description": "Stacked-query terminator plus comment.",
        "dbms": DBMS_GENERIC,
        "encodeable": True,
    },
    {
        "name": "tautology",
        "family": FAMILY_ERROR,
        "description": "Classic OR 1=1 string tautology (often errors or changes rows).",
        "dbms": DBMS_GENERIC,
        "encodeable": True,
    },
    {
        "name": "mssql_tautology",
        "family": FAMILY_ERROR,
        "description": "SQL Server integer tautology: OR 1=1 plus line comment.",
        "dbms": DBMS_MSSQL,
        "encodeable": False,
    },
    {
        "name": "mssql_convert",
        "family": FAMILY_ERROR,
        "description": "SQL Server CONVERT(int, @@version) error-based leak.",
        "dbms": DBMS_MSSQL,
        "encodeable": False,
    },
    {
        "name": "mssql_convert_db",
        "family": FAMILY_ERROR,
        "description": "SQL Server CONVERT(int, DB_NAME()) error-based leak.",
        "dbms": DBMS_MSSQL,
        "encodeable": False,
    },
    {
        "name": "mssql_cast",
        "family": FAMILY_ERROR,
        "description": "SQL Server CAST(@@version AS int) error-based leak.",
        "dbms": DBMS_MSSQL,
        "encodeable": False,
    },
    {
        "name": "mssql_divzero",
        "family": FAMILY_ERROR,
        "description": "SQL Server divide-by-zero error probe.",
        "dbms": DBMS_MSSQL,
        "encodeable": False,
    },
    {
        "name": "mssql_char_or",
        "family": FAMILY_ERROR,
        "description": "SQL Server CHAR() tautology (OR CHAR(49)=CHAR(49)).",
        "dbms": DBMS_MSSQL,
        "encodeable": False,
    },
    {
        "name": "mysql_extractvalue",
        "family": FAMILY_ERROR,
        "description": "MySQL EXTRACTVALUE/XPATH error-based leak.",
        "dbms": DBMS_MYSQL,
        "encodeable": False,
    },
    {
        "name": "pg_cast",
        "family": FAMILY_ERROR,
        "description": "PostgreSQL CAST(version() AS int) error-based leak.",
        "dbms": DBMS_POSTGRES,
        "encodeable": False,
    },
    {
        "name": "oracle_to_number",
        "family": FAMILY_ERROR,
        "description": "Oracle TO_NUMBER error-based leak.",
        "dbms": DBMS_ORACLE,
        "encodeable": False,
    },
    {
        "name": "sqlite_error",
        "family": FAMILY_ERROR,
        "description": "SQLite version comparison that often errors.",
        "dbms": DBMS_SQLITE,
        "encodeable": False,
    },
    {
        "name": "union_1",
        "family": FAMILY_UNION,
        "description": "UNION SELECT with 1 NULL column.",
        "dbms": DBMS_GENERIC,
        "encodeable": False,
    },
    {
        "name": "union_2",
        "family": FAMILY_UNION,
        "description": "UNION SELECT with 2 NULL columns.",
        "dbms": DBMS_GENERIC,
        "encodeable": False,
    },
    {
        "name": "union_3",
        "family": FAMILY_UNION,
        "description": "UNION SELECT with 3 NULL columns.",
        "dbms": DBMS_GENERIC,
        "encodeable": False,
    },
    {
        "name": "union_4",
        "family": FAMILY_UNION,
        "description": "UNION SELECT with 4 NULL columns.",
        "dbms": DBMS_GENERIC,
        "encodeable": False,
    },
    {
        "name": "union_5",
        "family": FAMILY_UNION,
        "description": "UNION SELECT with 5 NULL columns.",
        "dbms": DBMS_GENERIC,
        "encodeable": False,
    },
    {
        "name": "bool_true",
        "family": FAMILY_BOOLEAN,
        "description": "Boolean true: AND '1'='1 (observation; finding on error only).",
        "dbms": DBMS_GENERIC,
        "encodeable": False,
    },
    {
        "name": "bool_false",
        "family": FAMILY_BOOLEAN,
        "description": "Boolean false: AND '1'='2 (observation; finding on error only).",
        "dbms": DBMS_GENERIC,
        "encodeable": False,
    },
    {
        "name": "mssql_bool_true",
        "family": FAMILY_BOOLEAN,
        "description": "SQL Server boolean true: AND 1=1 plus line comment.",
        "dbms": DBMS_MSSQL,
        "encodeable": False,
    },
    {
        "name": "mssql_bool_false",
        "family": FAMILY_BOOLEAN,
        "description": "SQL Server boolean false: AND 1=2 plus line comment.",
        "dbms": DBMS_MSSQL,
        "encodeable": False,
    },
    {
        "name": "mssql_waitfor",
        "family": FAMILY_TIME,
        "description": "SQL Server stacked WAITFOR DELAY 5s.",
        "dbms": DBMS_MSSQL,
        "encodeable": False,
    },
    {
        "name": "mssql_waitfor_inline",
        "family": FAMILY_TIME,
        "description": "SQL Server in-statement WAITFOR DELAY 5s (no stacked query).",
        "dbms": DBMS_MSSQL,
        "encodeable": False,
    },
    {
        "name": "mssql_waitfor_if",
        "family": FAMILY_TIME,
        "description": "SQL Server IF 1=1 WAITFOR DELAY 5s.",
        "dbms": DBMS_MSSQL,
        "encodeable": False,
    },
    {
        "name": "mysql_sleep",
        "family": FAMILY_TIME,
        "description": "MySQL SLEEP(5).",
        "dbms": DBMS_MYSQL,
        "encodeable": False,
    },
    {
        "name": "pg_sleep",
        "family": FAMILY_TIME,
        "description": "PostgreSQL pg_sleep(5).",
        "dbms": DBMS_POSTGRES,
        "encodeable": False,
    },
    {
        "name": "oracle_pipe",
        "family": FAMILY_TIME,
        "description": "Oracle DBMS_PIPE.RECEIVE_MESSAGE 5s delay.",
        "dbms": DBMS_ORACLE,
        "encodeable": False,
    },
)

TECHNIQUE_NAMES: tuple[str, ...] = tuple(str(item["name"]) for item in TECHNIQUE_CATALOG)
TECHNIQUE_BY_NAME: dict[str, dict[str, object]] = {
    str(item["name"]): item for item in TECHNIQUE_CATALOG
}

MSSQL_DBMS = frozenset({DBMS_GENERIC, DBMS_MSSQL})
"""Vendors included when the operator selects Microsoft SQL Server."""

ENCODEABLE_TECHNIQUES: frozenset[str] = frozenset(
    str(item["name"]) for item in TECHNIQUE_CATALOG if item.get("encodeable")
)

DEFAULT_PAYLOAD_COUNT = len(TECHNIQUE_CATALOG)
"""Base technique count (picker). Unknown-mode job count is higher (encodings)."""
