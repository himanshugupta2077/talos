"""
Module: talos.error_intel.detectors.security

Purpose:
    Stage E — security / auth error semantics (not secret scanning).

    JWT decode failures, OAuth exceptions, CSRF validation, CORS rejections,
    ACL/RBAC/IAM denial messages.  Category: security.

Dependencies: re; talos.error_intel.{constants, detectors.base, models}
Data flow: text → list[RawErrorMatch]
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Mapping, Optional

from talos.error_intel.constants import (
    CATEGORY_SECURITY,
    CONFIDENCE_CONFIRMED_PATTERN,
    CONFIDENCE_HIGH,
    CONFIDENCE_MEDIUM,
    DETECTOR_FAMILY_SECURITY,
    LANG_UNKNOWN,
)
from talos.error_intel.detectors.base import (
    DEFAULT_STAGE_MATCH_CAP,
    build_raw_error_match,
    normalize_exception_type,
)
from talos.error_intel.models import RawErrorMatch

# (detector_id, pattern, exception_type, confidence, tech_tag)
_SECURITY_RULES: tuple[tuple[str, re.Pattern[str], str, str, str], ...] = (
    (
        "sec_jwt",
        # Prefer concrete failure phrasing / error codes over "invalid token"
        # in docs/marketing copy ("How to handle invalid token errors in JWT").
        re.compile(
            r"\b(?:"
            r"JWT\s+(?:decode|validation|signature)\s+(?:failed|error|invalid)|"
            r"(?:invalid|expired|malformed)\s+jwt\b|"
            r"jwt\s+(?:expired|invalid|malformed|decode\s+failed)|"
            r"TokenExpiredError|"
            r"JsonWebTokenError|"
            r"Unable to (?:verify|parse) (?:JWT|token)|"
            r"malformed\s+jwt|"
            r"[\"']invalid_token[\"']|"
            r"\binvalid_token\b|"
            r"error_description[\"']?\s*:\s*[\"'][^\"']*token"
            r")",
            re.I,
        ),
        "JWTError",
        CONFIDENCE_HIGH,
        "jwt",
    ),
    (
        "sec_oauth",
        # access_denied alone is common non-OAuth API vocabulary; require
        # OAuth/OIDC grant codes or explicit oauth wording (see _oauth_context_ok).
        re.compile(
            r"\b(?:"
            r"oauth(?:2)?\s+error|"
            r"invalid_grant|"
            r"invalid_client|"
            r"unauthorized_client|"
            r"access_denied|"
            r"invalid_scope|"
            r"unsupported_grant_type|"
            r"OpenID\s+Connect\s+error|"
            r"AADSTS\d+|"
            r"invalid_request.*oauth"
            r")",
            re.I,
        ),
        "OAuthError",
        CONFIDENCE_HIGH,
        "oauth",
    ),
    (
        "sec_csrf",
        re.compile(
            r"\b(?:"
            r"CSRF\s+(?:token\s+)?(?:validation\s+)?(?:failed|mismatch|missing|invalid)|"
            r"invalid\s+csrf|"
            r"CSRFVerificationError|"
            r"Forbidden\s+\(CSRF|"
            r"anti-?forgery"
            r")",
            re.I,
        ),
        "CSRFError",
        CONFIDENCE_CONFIRMED_PATTERN,
        "csrf",
    ),
    (
        "sec_cors",
        re.compile(
            r"\b(?:"
            r"CORS\s+(?:policy|error|rejected|blocked)|"
            r"Access-Control-Allow-Origin|"
            r"No\s+'Access-Control-Allow-Origin'|"
            r"has been blocked by CORS|"
            r"Cross-Origin Request Blocked"
            r")",
            re.I,
        ),
        "CORSError",
        CONFIDENCE_HIGH,
        "cors",
    ),
    (
        "sec_authz",
        re.compile(
            r"\b(?:"
            r"access\s+(?:is\s+)?denied|"
            r"not\s+authorized|"
            r"unauthorized|"
            r"permission\s+denied|"
            r"insufficient\s+(?:permissions|privileges|scope)|"
            r"RBAC\s+(?:denied|forbidden)|"
            r"IAM\s+(?:policy|permission)\s+(?:denied|failed)|"
            r"ACL\s+(?:denied|check failed)|"
            r"Forbidden|"
            r"User is not allowed|"
            r"does not have permission"
            r")",
            re.I,
        ),
        "AuthorizationError",
        CONFIDENCE_MEDIUM,
        "authz",
    ),
    (
        "sec_authn",
        re.compile(
            r"\b(?:"
            r"authentication\s+(?:failed|required|error)|"
            r"invalid\s+(?:credentials|password|username)|"
            r"login\s+failed|"
            r"not\s+authenticated|"
            r"session\s+(?:expired|invalid)|"
            r"WWW-Authenticate"
            r")",
            re.I,
        ),
        "AuthenticationError",
        CONFIDENCE_MEDIUM,
        "authn",
    ),
)


class SecurityErrorDetector:
    """
    Purpose:
        Stage E — AuthN/Z, JWT, CSRF, CORS, policy error semantics.
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
        del content_type
        if not text or not text.strip():
            return self._from_headers(headers, status_code)

        matches: list[RawErrorMatch] = []
        seen: set[str] = set()

        for detector_id, pattern, exc, confidence, tech in _SECURITY_RULES:
            if detector_id in seen:
                continue
            m = pattern.search(text)
            if not m:
                continue
            # Soften bare "unauthorized"/"forbidden" on non-error pages
            if detector_id in ("sec_authz", "sec_authn"):
                if not _auth_context_ok(text, m, status_code):
                    continue
            # JWT docs / tutorials on 2xx without real error chrome
            if detector_id == "sec_jwt":
                if not _jwt_context_ok(text, m, status_code):
                    continue
            # bare access_denied without OAuth vocabulary
            if detector_id == "sec_oauth":
                if not _oauth_context_ok(text, m):
                    continue
            seen.add(detector_id)
            matches.append(
                build_raw_error_match(
                    detector_id=detector_id,
                    family=DETECTOR_FAMILY_SECURITY,
                    text=text,
                    match_start=m.start(),
                    match_end=m.end(),
                    exception_type=normalize_exception_type(exc),
                    confidence=confidence,
                    category_hint=CATEGORY_SECURITY,
                    language=LANG_UNKNOWN,
                    metadata={
                        "technologies": [tech],
                        "security_kind": tech,
                    },
                )
            )
            if len(matches) >= self._max:
                break

        for hm in self._from_headers(headers, status_code):
            if hm.detector_id in seen:
                continue
            seen.add(hm.detector_id)
            matches.append(hm)
            if len(matches) >= self._max:
                break

        return matches

    def _from_headers(
        self,
        headers: Optional[Mapping[str, str]],
        status_code: Optional[int],
    ) -> list[RawErrorMatch]:
        if not headers:
            return []
        lower = {str(k).lower(): str(v) for k, v in headers.items() if k is not None}
        out: list[RawErrorMatch] = []
        if "www-authenticate" in lower:
            val = lower["www-authenticate"]
            out.append(
                build_raw_error_match(
                    detector_id="sec_www_authenticate",
                    family=DETECTOR_FAMILY_SECURITY,
                    text=val,
                    match_start=0,
                    match_end=min(len(val), 80),
                    exception_type="AuthenticationRequired",
                    confidence=CONFIDENCE_HIGH,
                    category_hint=CATEGORY_SECURITY,
                    language=LANG_UNKNOWN,
                    metadata={
                        "technologies": ["authn"],
                        "security_kind": "authn",
                        "from_header": True,
                        "status_code": status_code,
                    },
                    raw_snippet=val[:300],
                )
            )
        return out


def _auth_context_ok(
    text: str,
    match: re.Match[str],
    status_code: Optional[int],
) -> bool:
    """
    Reduce FPs from marketing copy ("unauthorized access is prevented").
    Prefer error status, JSON error keys, or short error-ish bodies.
    """
    if status_code is not None:
        try:
            code = int(status_code)
            if code in (401, 403, 407) or 400 <= code <= 599:
                return True
        except (TypeError, ValueError):
            pass
    window = text[max(0, match.start() - 80) : match.end() + 80].lower()
    if any(
        k in window
        for k in (
            "error",
            "exception",
            "denied",
            "failed",
            "invalid",
            "forbidden",
            "unauthorized",
            "www-authenticate",
            '"code"',
            '"status"',
        )
    ):
        return True
    # Very short body likely an API error payload
    if len(text) < 800:
        return True
    return False


def _is_error_status(status_code: Optional[int]) -> bool:
    if status_code is None:
        return False
    try:
        code = int(status_code)
    except (TypeError, ValueError):
        return False
    return 400 <= code <= 599


def _jwt_context_ok(
    text: str,
    match: re.Match[str],
    status_code: Optional[int],
) -> bool:
    """
    Drop tutorial/docs hits like "How to handle invalid token errors in JWT"
    on healthy 2xx pages. Keep real API failures (error status, JSON codes,
    exception class names, decode/signature failure phrasing).
    """
    if _is_error_status(status_code):
        return True
    span = match.group(0).lower()
    # Strong failure phrases always OK even on 200 error bodies
    if any(
        k in span
        for k in (
            "decode failed",
            "signature",
            "tokenexpirederror",
            "jsonwebtokenerror",
            "unable to verify",
            "unable to parse",
            "malformed jwt",
            "invalid_token",
            "jwt expired",
            "jwt invalid",
            "jwt malformed",
            "jwt decode",
        )
    ):
        return True
    window = text[max(0, match.start() - 100) : match.end() + 100].lower()
    if any(
        k in window
        for k in (
            '"error"',
            '"error_description"',
            "exception",
            "unauthorized",
            "www-authenticate",
            "status\":40",
            "status':40",
        )
    ):
        return True
    # Short JSON-ish API body on 2xx still accepted if it looks like a payload
    if len(text) < 600 and ("{" in text or "invalid_token" in text.lower()):
        return True
    return False


def _oauth_context_ok(text: str, match: re.Match[str]) -> bool:
    """
    ``access_denied`` alone is too common (generic APIs, JSON status fields).
    Require OAuth/OIDC grant vocabulary unless the match is already a grant code.
    """
    span = (match.group(0) or "").lower()
    # Strong OAuth grant / protocol codes — always accept
    if any(
        k in span
        for k in (
            "invalid_grant",
            "invalid_client",
            "unauthorized_client",
            "invalid_scope",
            "unsupported_grant_type",
            "oauth",
            "openid",
            "aadsts",
        )
    ):
        return True
    # bare access_denied → need nearby OAuth vocabulary
    if "access_denied" in span:
        window = text[max(0, match.start() - 160) : match.end() + 160].lower()
        if re.search(
            r"oauth|openid|oidc|grant_type|client_id|redirect_uri|"
            r"authorization_code|bearer|token_type|aadsts|asgardeo|"
            r"error_description|\"error\"\s*:\s*\"access_denied\"",
            window,
            re.I,
        ):
            return True
        return False
    return True
