"""
Module: talos.passive.detectors.connection_string

Purpose:
    Stage 1 companion — database / service URIs that embed credentials.

    Matches schemes such as:
        postgres://user:pass@host/db
        mysql://…
        mongodb(+srv)://…
        redis://…
        amqp://…
        mssql://… / sqlserver://…

    Family = connection_string.  Userinfo without password is ignored.
    Passwordless host-only URIs are not treated as secrets.

Dependencies: re; talos.passive.detectors.base, constants, models
Data flow: text → list[RawMatch]
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Optional

from talos.passive.constants import (
    CATEGORY_SECRET,
    CONFIDENCE_HIGH,
    DETECTOR_FAMILY_CONNECTION_STRING,
)
from talos.passive.detectors.base import build_raw_match
from talos.passive.models import RawMatch, SourceDocument

# scheme://user:password@host…  (password must be non-empty)
_CONN_URI = re.compile(
    r"(?<![A-Za-z0-9_\-])"
    r"("
    r"(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|"
    r"amqp|amqps|mssql|sqlserver|couchdb|cassandra)"
    r"://"
    r"[^\s\"'<>@:/]+:[^\s\"'<>@]+@"  # user:pass@
    r"[^\s\"'<>]+"  # host + rest until whitespace/quote
    r")",
    re.IGNORECASE,
)

_DETECTOR_ID = "db_connection_uri"
_SECRET_TYPE = "connection_string"
_BASE_SCORE = 88


class ConnectionStringDetector:
    """
    Purpose:
        Detect credential-bearing connection URIs in source text.
    """

    def __init__(self, *, max_candidates: int = 50) -> None:
        self._max_candidates = max(1, int(max_candidates))

    def detect(
        self,
        text: str,
        *,
        document: Optional[SourceDocument] = None,
        encoding_chain: Optional[list[str]] = None,
        decode_depth: int = 0,
    ) -> list[RawMatch]:
        """
        Purpose:
            Find connection strings with embedded credentials.
        Input:
            text / encoding context
        Output:
            list[RawMatch]
        Side effects: None.
        """
        if not text or "://" not in text:
            return []
        # Cheap prefilter
        low = text.lower()
        if not any(
            s in low
            for s in (
                "postgres",
                "mysql",
                "mongo",
                "redis",
                "amqp",
                "mssql",
                "sqlserver",
                "couchdb",
                "cassandra",
                "mariadb",
            )
        ):
            return []

        matches: list[RawMatch] = []
        seen: set[tuple[str, int]] = set()
        for m in _CONN_URI.finditer(text):
            value = m.group(1).rstrip(".,;)")
            # Require non-empty password segment
            try:
                after_scheme = value.split("://", 1)[1]
                userinfo = after_scheme.split("@", 1)[0]
                if ":" not in userinfo:
                    continue
                _user, password = userinfo.split(":", 1)
                if not password or password in ("*", "xxx", "password"):
                    # Weak / placeholder passwords still may match; leave
                    # suppression to suppress.py for password/placeholder.
                    pass
                if not password:
                    continue
            except (IndexError, ValueError):
                continue

            start = m.start(1)
            end = start + len(value)
            key = (value, start)
            if key in seen:
                continue
            seen.add(key)
            matches.append(
                build_raw_match(
                    detector_id=_DETECTOR_ID,
                    detector_family=DETECTOR_FAMILY_CONNECTION_STRING,
                    category=CATEGORY_SECRET,
                    secret_type=_SECRET_TYPE,
                    raw_value=value,
                    match_start=start,
                    match_end=end,
                    text=text,
                    encoding_chain=encoding_chain,
                    decode_depth=decode_depth,
                    metadata={
                        "base_score": _BASE_SCORE,
                        "base_level": CONFIDENCE_HIGH,
                        "case_sensitive": True,
                        "rule_name": "Database Connection URI",
                        "finding_title": "Exposed Database Connection String",
                    },
                )
            )
            if len(matches) >= self._max_candidates:
                break
        return matches
