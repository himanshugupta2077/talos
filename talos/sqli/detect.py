"""
Module: talos.sqli.detect

Purpose:
    Decide whether a probe response shows SQL injection.

    Error-based: DBMS signatures present in the probe that were not in
    the captured baseline (so a pre-existing conversion error does not
    by itself become a finding). UNION column-count strings are always
    a hit. Time-based: elapsed >= 80% of the payload delay.

Dependencies: re
Data flow: engine → analyze_sqli_response → verdict
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Optional

from talos.sqli.models import (
    FAMILY_TIME,
    FAMILY_UNION,
    VERDICT_SECURE,
    VERDICT_SQLI,
)

# (regex, dbms_or_None, kind)
# kind: error | union — union hits even when the baseline already had a
# different SQL error (column-count messages are payload-specific).
_SIGNATURES: tuple[tuple[re.Pattern[str], Optional[str], str], ...] = (
    # SQL Server / Microsoft (matches the issue-7 ODBC leak)
    (re.compile(r"Unclosed quotation mark", re.I), "sqlserver", "error"),
    (re.compile(r"Incorrect syntax near", re.I), "sqlserver", "error"),
    (re.compile(r"Conversion failed when converting", re.I), "sqlserver", "error"),
    (re.compile(r"SQLExecDirectW", re.I), "sqlserver", "error"),
    (re.compile(r"\[Microsoft\]\[ODBC Driver", re.I), "sqlserver", "error"),
    (re.compile(r"\[SQL Server\]", re.I), "sqlserver", "error"),
    (re.compile(r"SQLServerException", re.I), "sqlserver", "error"),
    (re.compile(r"SqlException", re.I), "sqlserver", "error"),
    (re.compile(r"OLE DB.*?SQL Server", re.I), "sqlserver", "error"),
    (re.compile(r"\b22007\b"), "sqlserver", "error"),
    (re.compile(r"All queries combined using (?:a )?UNION", re.I), "sqlserver", "union"),
    (re.compile(
        r"must have an equal number of expressions",
        re.I,
    ), None, "union"),
    (re.compile(
        r"SELECTs? to the left and right of UNION",
        re.I,
    ), None, "union"),
    (re.compile(r"The used SELECT statements have a different number of columns", re.I), "mysql", "union"),
    (re.compile(r"each UNION query must have the same number of columns", re.I), "postgresql", "union"),
    # MySQL / MariaDB
    (re.compile(r"You have an error in your SQL syntax", re.I), "mysql", "error"),
    (re.compile(r"XPATH syntax error", re.I), "mysql", "error"),
    (re.compile(r"mysql_fetch|mysqli_|MariaDB server", re.I), "mysql", "error"),
    (re.compile(r"check the manual that corresponds to your MySQL", re.I), "mysql", "error"),
    # PostgreSQL
    (re.compile(r"unterminated quoted string", re.I), "postgresql", "error"),
    (re.compile(r"syntax error at or near", re.I), "postgresql", "error"),
    (re.compile(r"\bPG::\w+", re.I), "postgresql", "error"),
    (re.compile(r"psycopg(?:2)?\.\w*Error", re.I), "postgresql", "error"),
    # Oracle
    (re.compile(r"\bORA-\d{5}\b"), "oracle", "error"),
    (re.compile(r"quoted string not properly terminated", re.I), "oracle", "error"),
    # SQLite
    (re.compile(r"unrecognized token", re.I), "sqlite", "error"),
    (re.compile(r"SQLite3?::", re.I), "sqlite", "error"),
    (re.compile(r"SQLITE_ERROR", re.I), "sqlite", "error"),
    # Generic
    (re.compile(r"SQLSyntaxErrorException", re.I), None, "error"),
    (re.compile(r"SQLSTATE\s*[\[:]", re.I), None, "error"),
    (re.compile(r"sqlalchemy\.exc", re.I), None, "error"),
    (re.compile(r"java\.sql\.SQLException", re.I), None, "error"),
)

TIME_HIT_RATIO = 0.8


def _decode_body(raw: object) -> str:
    """Purpose: Response body to searchable text. Output: str."""
    if raw is None:
        return ""
    if isinstance(raw, (bytes, bytearray)):
        return raw.decode("utf-8", errors="replace")
    return str(raw)


def collect_signatures(text: str) -> list[tuple[str, Optional[str], str]]:
    """
    Purpose:
        Return (pattern, dbms, kind) hits in ``text``.
    Output:
        Deduped list in catalogue order.
    """
    blob = text or ""
    hits: list[tuple[str, Optional[str], str]] = []
    seen: set[str] = set()
    for pattern, dbms, kind in _SIGNATURES:
        if pattern.search(blob):
            key = pattern.pattern
            if key in seen:
                continue
            seen.add(key)
            hits.append((key, dbms, kind))
    return hits


def analyze_sqli_response(
    *,
    baseline_body: object,
    probe_body: object,
    family: str,
    delay_s: float,
    elapsed_s: Optional[float],
) -> tuple[str, str, Optional[str], str]:
    """
    Purpose:
        Classify one probe against the captured baseline.
    Output:
        (verdict, risk_hint, dbms, evidence)
    """
    base_text = _decode_body(baseline_body)
    probe_text = _decode_body(probe_body)
    base_hits = collect_signatures(base_text)
    probe_hits = collect_signatures(probe_text)
    base_keys = {item[0] for item in base_hits}
    new_hits = [item for item in probe_hits if item[0] not in base_keys]
    union_hits = [item for item in probe_hits if item[2] == "union"]

    dbms: Optional[str] = None
    for _pat, vendor, _kind in new_hits + union_hits + probe_hits:
        if vendor:
            dbms = vendor
            break

    if union_hits and (family == FAMILY_UNION or any(h[0] not in base_keys for h in union_hits)):
        evidence = union_hits[0][0][:160]
        return VERDICT_SQLI, "union", dbms, evidence

    if new_hits:
        evidence = new_hits[0][0][:160]
        return VERDICT_SQLI, "error_based", dbms, evidence

    if (
        family == FAMILY_TIME
        and delay_s > 0
        and elapsed_s is not None
        and elapsed_s >= delay_s * TIME_HIT_RATIO
    ):
        return (
            VERDICT_SQLI,
            "time_delay",
            dbms,
            f"elapsed={elapsed_s:.2f}s delay={delay_s:.1f}s",
        )

    return VERDICT_SECURE, "", dbms, ""
