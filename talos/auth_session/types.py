"""
Module: talos.auth_session.types

Purpose:
    Auth-type analyzer Protocol and registry. JWT is the only v1 analyzer;
    future types (session_cookie, api_key, oauth_access) register here.

Dependencies: models, jwt_codec, suite_jwt, jwt_mutate
Data flow: raw field value → TokenContext → list_test_cases / apply
Side effects: None (pure analysis / mutation construction).
"""

from __future__ import annotations

from typing import Any, Optional, Protocol, runtime_checkable

from talos.auth_session.jwt_codec import (
    decode_jwt_header,
    extract_scheme_and_token,
)
from talos.auth_session.models import (
    AUTH_TYPE_JWT,
    MutatedToken,
    TestCaseDef,
    TokenContext,
)
from talos.auth_session.suite_jwt import apply_jwt_test, list_jwt_test_cases
from talos.url_sink.jwt_claims import decode_jwt_payload


@runtime_checkable
class AuthTypeAnalyzer(Protocol):
    """
    Purpose:
        Pluggable auth-type surface for detect / list_test_cases / apply.
    """

    auth_type: str

    def detect(
        self,
        raw_value: str,
        *,
        location: str = "header",
        field_name: str = "Authorization",
    ) -> TokenContext | None:
        """Return context if value matches this auth type; else None."""
        ...

    def list_test_cases(
        self,
        ctx: TokenContext,
        config: dict[str, Any] | None = None,
    ) -> list[TestCaseDef]:
        """Deterministic suite filtered by config + available claims."""
        ...

    def apply(
        self,
        ctx: TokenContext,
        test_id: str,
        config: dict[str, Any] | None = None,
    ) -> MutatedToken:
        """Produce mutated token; raise if test_id unknown or inapplicable."""
        ...


class JwtAnalyzer:
    """
    Purpose:
        Compact JWS analyzer (v1). Detects Bearer/Token-prefixed or bare JWTs,
        lists Phase-1 suite rows, applies mutations via suite_jwt / jwt_mutate.
    Side effects: None.
    """

    auth_type: str = AUTH_TYPE_JWT

    def detect(
        self,
        raw_value: str,
        *,
        location: str = "header",
        field_name: str = "Authorization",
    ) -> TokenContext | None:
        """
        Purpose:
            Parse a header/cookie value into TokenContext if it is compact JWS.
        Input:
            raw_value — full field value
            location / field_name — binding metadata
        Output:
            TokenContext or None (not a JWT / decode failure / JWE)
        Side effects: None.
        """
        if not raw_value or not isinstance(raw_value, str):
            return None
        scheme, compact = extract_scheme_and_token(raw_value)
        if not compact:
            return None
        # Compact JWS only: reject if we cannot decode both header and payload.
        header = decode_jwt_header(compact)
        payload = decode_jwt_payload(compact)
        if header is None or payload is None:
            return None
        # Reject JWE-shaped (5 segments) already filtered by extract; ensure
        # we did not accept garbage with empty essential structure only.
        return TokenContext(
            raw_token=compact,
            scheme=scheme if location == "header" else None,
            header=header,
            payload=payload,
            location=location,
            field_name=field_name,
            original_header_value=raw_value.strip(),
        )

    def list_test_cases(
        self,
        ctx: TokenContext,
        config: dict[str, Any] | None = None,
    ) -> list[TestCaseDef]:
        """See suite_jwt.list_jwt_test_cases."""
        return list_jwt_test_cases(ctx, config)

    def apply(
        self,
        ctx: TokenContext,
        test_id: str,
        config: dict[str, Any] | None = None,
    ) -> MutatedToken:
        """See suite_jwt.apply_jwt_test."""
        return apply_jwt_test(ctx, test_id, config)


# Registry — extend when new auth types land.
ANALYZERS: dict[str, AuthTypeAnalyzer] = {
    AUTH_TYPE_JWT: JwtAnalyzer(),
}


def get_analyzer(auth_type: str) -> AuthTypeAnalyzer:
    """
    Purpose:
        Look up analyzer by auth_type string.
    Input:
        auth_type — e.g. ``jwt``
    Output:
        AuthTypeAnalyzer instance
    Side effects: None.
    Raises:
        KeyError if type not registered.
    """
    key = (auth_type or "").strip().lower()
    if key not in ANALYZERS:
        raise KeyError(
            f"unsupported auth type {auth_type!r}; "
            f"known: {sorted(ANALYZERS)}"
        )
    return ANALYZERS[key]
