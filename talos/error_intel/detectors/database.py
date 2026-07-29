"""
Module: talos.error_intel.detectors.database

Purpose:
    Stage B — database / SQL / NoSQL engine error detectors.

    Prefer extracting vendor + SQLSTATE/code + short message.  Does not
    store full SQL when it may embed secrets (connection strings left for
    passive secret scan if the body is source-like).

Dependencies: re; talos.error_intel.{constants, detectors.base, models}
Data flow: text → list[RawErrorMatch]
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Mapping, Optional

from talos.error_intel.constants import (
    CATEGORY_DATABASE,
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    DETECTOR_FAMILY_DATABASE,
    LANG_JAVA,
    LANG_PYTHON,
    LANG_UNKNOWN,
)
from talos.error_intel.detectors.base import (
    DEFAULT_STAGE_MATCH_CAP,
    build_raw_error_match,
    normalize_exception_type,
)
from talos.error_intel.models import RawErrorMatch

# SQLSTATE[HY000] / SQLSTATE: 42P01 / SQLSTATE 42000
# Note: no trailing \b after ] — "]:" has no word boundary.
_SQLSTATE = re.compile(
    r"\bSQLSTATE\s*(?:\[([A-Z0-9]+)\]|:?\s*([A-Z0-9]{5}))",
    re.IGNORECASE,
)

# Oracle ORA-00942
_ORA = re.compile(r"\bORA-(\d{5})\b")

# MySQL / MariaDB: ERROR 1064 (42000) or mysql error 1045
_MYSQL_ERR = re.compile(
    r"\b(?:MySQL|MariaDB)?\s*(?:ERROR|error)\s+(\d{4})\b"
    r"(?:\s*\(([A-Z0-9]+)\))?",
    re.IGNORECASE,
)

# PostgreSQL / psycopg
_PG = re.compile(
    r"\b("
    r"psycopg2?\.(?:errors\.)?[A-Za-z]+|"
    r"postgresql(?:\s+error)?|"
    r"PQException|"
    r"relation\s+\"[^\"]+\"\s+does not exist|"
    r"column\s+\"[^\"]+\"\s+does not exist|"
    r"duplicate key value violates unique constraint"
    r")\b",
    re.IGNORECASE,
)

# SQLite
_SQLITE = re.compile(
    r"\b("
    r"sqlite3?\.(?:OperationalError|IntegrityError|DatabaseError|ProgrammingError)|"
    r"SQLite\s+(?:error|exception)|"
    r"no such (?:table|column)\s*:"
    r")\b",
    re.IGNORECASE,
)

# JDBC / ODBC / generic SQLException already partly Stage A; keep vendor cues
_JDBC = re.compile(
    r"\b("
    r"java\.sql\.SQL(?:SyntaxError|IntegrityConstraintViolation|TransientConnection|Timeout|Data)?Exception|"
    r"jdbc:[a-z0-9+]+://|"
    r"\bODBC\b|"
    r"\[Microsoft\]\[ODBC|"
    r"SQLServerException|MySQLSyntaxErrorException|"
    r"PSQLException|OracleDatabaseException"
    r")",
    re.IGNORECASE,
)

# Mongo / Redis
_NOSQL = re.compile(
    r"\b("
    r"Mongo(?:Server)?Error|MongoException|"
    r"E11000\s+duplicate key|"
    r"Redis(?:Error|Exception|CommandError)|"
    r"WRONGTYPE Operation against a key|"
    r"NOAUTH Authentication required"
    r")\b",
    re.IGNORECASE,
)

# Hibernate / JPA SQL wrappers (database-ish even when Java stack also fires)
_HIBERNATE_SQL = re.compile(
    r"\b("
    r"org\.hibernate\.(?:exception\.)?[A-Za-z]+|"
    r"HibernateException|"
    r"JDBCException|"
    r"ConstraintViolationException|"
    r"DataIntegrityViolationException|"
    r"BadSqlGrammarException|"
    r"QuerySyntaxException"
    r")\b",
)


class DatabaseErrorDetector:
    """
    Purpose:
        Stage B — vendor / SQLSTATE / engine error patterns.
    """

    def __init__(self, *, max_matches: int = DEFAULT_STAGE_MATCH_CAP) -> None:
        self._max = max(1, int(max_matches))

    def detect(
        self,
        text: str,
        *,
        status_code: Optional[int] = None,
        headers: Optional[Mapping[str, str]] = None,
        content_type: Optional[str] = None,
    ) -> list[RawErrorMatch]:
        del status_code, headers, content_type
        if not text or not text.strip():
            return []

        matches: list[RawErrorMatch] = []
        seen_keys: set[str] = set()

        def _add(
            *,
            detector_id: str,
            start: int,
            end: int,
            vendor: Optional[str],
            code: Optional[str],
            exception_type: Optional[str],
            confidence: str,
            language: Optional[str] = None,
            extra: Optional[dict] = None,
        ) -> None:
            key = f"{detector_id}|{vendor}|{code}|{exception_type}"
            if key in seen_keys:
                return
            seen_keys.add(key)
            meta = {
                "vendor": vendor,
                "sqlstate": None,
                "error_code": code,
                "database": vendor,
            }
            if extra:
                meta.update(extra)
            # Promote SQLSTATE into dedicated field when present
            if code and re.fullmatch(r"[A-Z0-9]{5}", code, re.I):
                meta["sqlstate"] = code.upper()
            matches.append(
                build_raw_error_match(
                    detector_id=detector_id,
                    family=DETECTOR_FAMILY_DATABASE,
                    text=text,
                    match_start=start,
                    match_end=end,
                    exception_type=normalize_exception_type(exception_type),
                    confidence=confidence,
                    category_hint=CATEGORY_DATABASE,
                    language=language or LANG_UNKNOWN,
                    metadata=meta,
                )
            )

        # SQLSTATE
        for m in _SQLSTATE.finditer(text):
            code = (m.group(1) or m.group(2) or "").upper()
            if not code:
                continue
            vendor = (
                _guess_vendor_from_context(text, m.start())
                or vendor_from_sqlstate(code)
            )
            _add(
                detector_id="db_sqlstate",
                start=m.start(),
                end=m.end(),
                vendor=vendor,
                code=code,
                exception_type=f"SQLSTATE:{code}",
                confidence=CONFIDENCE_CONFIRMED_PATTERN,
                extra={"sqlstate": code},
            )
            if len(matches) >= self._max:
                return matches

        # Oracle
        for m in _ORA.finditer(text):
            code = m.group(1)
            _add(
                detector_id="db_oracle",
                start=m.start(),
                end=m.end(),
                vendor="oracle",
                code=f"ORA-{code}",
                exception_type=f"ORA-{code}",
                confidence=CONFIDENCE_CONFIRMED_PATTERN,
            )
            if len(matches) >= self._max:
                return matches

        # MySQL / MariaDB numbered errors
        for m in _MYSQL_ERR.finditer(text):
            num = m.group(1)
            sqlstate = m.group(2)
            vendor = "mariadb" if re.search(r"mariadb", m.group(0), re.I) else "mysql"
            # Avoid matching generic "error 500" — require 4-digit MySQL range cues
            # or nearby mysql/mariadb/sql tokens
            window = text[max(0, m.start() - 40) : m.end() + 40]
            if not re.search(r"mysql|mariadb|sql|syntax", window, re.I) and not sqlstate:
                # still accept classic MySQL codes in 1xxx–2xxx when ERROR keyword present
                try:
                    n = int(num)
                except ValueError:
                    continue
                if n < 1000 or n > 3999:
                    continue
            _add(
                detector_id="db_mysql",
                start=m.start(),
                end=m.end(),
                vendor=vendor,
                code=num,
                exception_type=f"MySQL:{num}",
                confidence=CONFIDENCE_HIGH if sqlstate else CONFIDENCE_MEDIUM,
                extra={"sqlstate": sqlstate.upper() if sqlstate else None},
            )
            if len(matches) >= self._max:
                return matches

        # PostgreSQL
        for m in _PG.finditer(text):
            token = m.group(1)
            lang = LANG_PYTHON if token.lower().startswith("psycopg") else LANG_UNKNOWN
            _add(
                detector_id="db_postgresql",
                start=m.start(),
                end=m.end(),
                vendor="postgresql",
                code=None,
                exception_type=token if "." in token else "PostgreSQLError",
                confidence=CONFIDENCE_HIGH,
                language=lang,
            )
            if len(matches) >= self._max:
                return matches

        # SQLite
        for m in _SQLITE.finditer(text):
            token = m.group(1)
            _add(
                detector_id="db_sqlite",
                start=m.start(),
                end=m.end(),
                vendor="sqlite",
                code=None,
                exception_type=token if ("Error" in token or "error" in token) else "SQLiteError",
                confidence=CONFIDENCE_HIGH,
                language=LANG_PYTHON if token.lower().startswith("sqlite3") else LANG_UNKNOWN,
            )
            if len(matches) >= self._max:
                return matches

        # JDBC / SQLException class names
        for m in _JDBC.finditer(text):
            token = m.group(1)
            vendor = _vendor_from_jdbc(token, text)
            # Skip bare jdbc: URL-only unless error context nearby (still record as weak disclosure)
            if token.lower().startswith("jdbc:"):
                _add(
                    detector_id="db_jdbc_url",
                    start=m.start(),
                    end=m.end(),
                    vendor=vendor,
                    code=None,
                    exception_type=None,
                    confidence=CONFIDENCE_MEDIUM,
                    language=LANG_JAVA,
                    extra={"jdbc_url_prefix": token[:80], "note": "connection_string_candidate"},
                )
            else:
                _add(
                    detector_id="db_jdbc",
                    start=m.start(),
                    end=m.end(),
                    vendor=vendor,
                    code=None,
                    exception_type=token,
                    confidence=CONFIDENCE_CONFIRMED_PATTERN
                    if "Exception" in token or "exception" in token.lower()
                    else CONFIDENCE_HIGH,
                    language=LANG_JAVA,
                )
            if len(matches) >= self._max:
                return matches

        # Hibernate / Spring DAO (database category hint even with stack_trace sibling)
        for m in _HIBERNATE_SQL.finditer(text):
            token = m.group(1)
            _add(
                detector_id="db_hibernate",
                start=m.start(),
                end=m.end(),
                vendor=_guess_vendor_from_context(text, m.start()) or None,
                code=None,
                exception_type=token,
                confidence=CONFIDENCE_HIGH,
                language=LANG_JAVA,
                extra={"technologies": ["hibernate"]},
            )
            if len(matches) >= self._max:
                return matches

        # NoSQL
        for m in _NOSQL.finditer(text):
            token = m.group(1)
            vendor = "mongodb" if re.search(r"mongo", token, re.I) else "redis"
            _add(
                detector_id=f"db_{vendor}",
                start=m.start(),
                end=m.end(),
                vendor=vendor,
                code="E11000" if "E11000" in token else None,
                exception_type=token.split()[0] if token else vendor,
                confidence=CONFIDENCE_HIGH,
            )
            if len(matches) >= self._max:
                return matches

        return matches


# Well-known SQLSTATE codes → vendor when unambiguous (BUG-11).
# Prefer PostgreSQL letter-subclass codes (position 3 is A–Z).
# Multi-vendor ANSI codes (e.g. 42000, HY000) stay unmapped without context.
_SQLSTATE_CODE_VENDOR: dict[str, str] = {
    "42P01": "postgresql",  # undefined_table
    "42P02": "postgresql",  # undefined_parameter
    "42P07": "postgresql",  # duplicate_table
    "22P02": "postgresql",  # invalid_text_representation
    "28P01": "postgresql",  # invalid_password
    "40P01": "postgresql",  # deadlock_detected
    "3D000": "postgresql",  # invalid_catalog_name
    "42703": "postgresql",  # undefined_column (PG surface)
    "42701": "postgresql",  # duplicate_column
    "42883": "postgresql",  # undefined_function
}


def vendor_from_sqlstate(code: Optional[str]) -> Optional[str]:
    """
    Purpose:
        Map a SQLSTATE code to a database vendor when unambiguous (BUG-11).
    Input:
        code — 5-char SQLSTATE (e.g. ``42P01``, ``42601``)
    Output:
        Vendor string or None when multi-vendor / unknown.
    Side effects: None.
    """
    if not code:
        return None
    c = str(code).strip().upper()
    if not c:
        return None
    if c in _SQLSTATE_CODE_VENDOR:
        return _SQLSTATE_CODE_VENDOR[c]
    # PostgreSQL-specific extensions put a letter in the third position.
    if len(c) == 5 and c[2].isalpha():
        return "postgresql"
    return None


def _guess_vendor_from_context(text: str, pos: int) -> Optional[str]:
    window = text[max(0, pos - 200) : pos + 200].lower()
    for vendor, needles in (
        ("postgresql", ("postgresql", "psycopg", "postgres", "psql")),
        ("mysql", ("mysql", "mariadb", "mysqli")),
        ("oracle", ("oracle", "ora-", "ojdbc")),
        ("sqlserver", ("sql server", "sqlserver", "tds")),
        ("sqlite", ("sqlite",)),
        ("mongodb", ("mongodb", "mongo")),
        ("redis", ("redis",)),
    ):
        if any(n in window for n in needles):
            return vendor
    return None


def _vendor_from_jdbc(token: str, text: str) -> Optional[str]:
    low = token.lower()
    if "mysql" in low:
        return "mysql"
    if "postgres" in low or "psql" in low:
        return "postgresql"
    if "oracle" in low:
        return "oracle"
    if "sqlserver" in low or "microsoft" in low:
        return "sqlserver"
    if "sqlite" in low:
        return "sqlite"
    if low.startswith("jdbc:"):
        # jdbc:postgresql://…
        parts = token.split(":", 2)
        if len(parts) >= 2:
            return parts[1].split("+")[0].lower() or None
    return _guess_vendor_from_context(text, 0)
