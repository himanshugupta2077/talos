"""
Module: talos.url_sink.value_classify

Purpose:
    Pure value → URL / hostname / IP / path / UNC / protocol features + score.
    Value dominates name for sink scoring; email addresses are ignored.

    Detection accumulates flags (not exclusive). Score bands (illustrative):
        Absolute URL with scheme     90–100
        IP literal                   70–85
        Hostname / domain            55–75
        Path-only / UNC              40–65
        Protocol-relative //host     80–90
        Email                        0 (not a network resource sink)

Dependencies: dataclasses, ipaddress, re, urllib.parse
Data flow: raw string → UrlValueFeatures
Side effects: None.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Schemes that indicate an absolute network or resource locator.
# mailto / data / blob score lower and do not always imply fetch sinks.
_NETWORK_SCHEMES: frozenset[str] = frozenset({
    "http", "https", "ftp", "ftps", "gopher", "dict",
    "ldap", "ldaps", "ws", "wss", "file", "jar", "sftp",
})
_LOW_WEIGHT_SCHEMES: frozenset[str] = frozenset({
    "mailto", "data", "blob",
})
_ALL_SCHEMES: frozenset[str] = _NETWORK_SCHEMES | _LOW_WEIGHT_SCHEMES

# scheme://… (scheme case-insensitive)
_SCHEME_RE = re.compile(
    r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*)\s*:\s*//",
    re.IGNORECASE,
)
# Opaque schemes without // — mailto:, data:, blob:, jar:form
_OPAQUE_SCHEME_RE = re.compile(
    r"^(?P<scheme>mailto|data|blob|jar)\s*:",
    re.IGNORECASE,
)
# protocol-relative //host[/path]
_PROTO_REL_RE = re.compile(
    r"^//"
    r"(?P<host>"
    r"\[[^\]]+\]"  # IPv6
    r"|[^/?#\s]+"  # hostname / IPv4
    r")"
    r"(?P<rest>[/?#].*)?$",
)
# Email — ignored as network resource sink
_EMAIL_RE = re.compile(
    r"^[^@\s]+@[^@\s]+\.[^@\s]+$",
)
# UNC \\host\share or //host/share (Windows)
_UNC_RE = re.compile(
    r"^(?:"
    r"\\\\(?P<host1>[^\\/]+)(?:\\(?P<share1>.*))?"
    r"|"
    r"//(?P<host2>[^\\/]+)(?:/(?P<share2>.*))?"
    r")$",
)
# Windows drive path C:\… or C:/…
_WIN_PATH_RE = re.compile(
    r"^[A-Za-z]:[\\/]",
)
# Unix absolute path (must look path-like, not a single bare word)
_UNIX_PATH_RE = re.compile(
    r"^/(?:[\w.\-]+/)*[\w.\-]*$",
)
# host:port without scheme
_HOST_PORT_RE = re.compile(
    r"^(?:"
    r"\[(?P<ipv6>[^\]]+)\]"  # [2001:db8::1]
    r"|(?P<host>[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+)"
    r")"
    r":(?P<port>\d{1,5})$",
)
# Hostname / FQDN (at least two labels, TLD letters or known internal)
_HOSTNAME_RE = re.compile(
    r"^(?:"
    r"\*"  # wildcard label optional first
    r"\.)?"
    r"(?:"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"\.)+"
    r"(?:"
    r"[a-zA-Z]{2,63}"  # public TLD-ish
    r"|local|internal|intranet|corp|lan|home|invalid|test"
    r")$",
    re.IGNORECASE,
)
# path with query (no scheme)
_PATH_QUERY_RE = re.compile(
    r"^/[^\s]*\?[^\s]+$",
)
# Bare IPv4 string (full match)
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$",
)

# Last-label "TLDs" that are almost always file extensions, not domains.
# Prevents report.pdf / photo.png / script.js from scoring as hostnames.
_FILE_EXTENSIONS: frozenset[str] = frozenset({
    "7z", "apk", "avi", "bat", "bmp", "bz2", "c", "cfg", "conf", "cpp",
    "css", "csv", "dat", "db", "dll", "doc", "docx", "dmg", "eot", "env",
    "exe", "gif", "go", "gz", "h", "htm", "html", "ico", "ini", "jar",
    "java", "jpeg", "jpg", "js", "json", "jsx", "key", "less", "lock",
    "log", "m3u8", "map", "md", "mjs", "mov", "mp3", "mp4", "otf", "pdf",
    "pem", "php", "pkg", "png", "ppt", "pptx", "ps1", "py", "rar", "rb",
    "rs", "scss", "sh", "so", "svg", "tar", "tgz", "toml", "ts", "tsx",
    "ttf", "txt", "vue", "wasm", "wav", "webm", "webp", "woff", "woff2",
    "xhtml", "xls", "xlsx", "xml", "xz", "yaml", "yml", "zip",
})

# Score threshold for inventory flag possible_network_resource
NETWORK_RESOURCE_SCORE_THRESHOLD: int = 45


# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class UrlValueFeatures:
    """
    Purpose:
        Immutable classification of one scalar string as a potential network
        resource locator.
    Fields:
        possible_url_value / possible_hostname / possible_ip / possible_path /
        possible_domain / possible_unc / possible_protocol — pattern flags.
        protocols_seen — lowercased schemes observed (may be empty).
        looks_like — short labels: url, hostname, ipv4, ipv6, path, unc, …
        score — 0–100 value-only sink strength.
        possible_network_resource — score >= threshold and not email.
        evidence — machine-readable reason tokens.
        is_email — True when value is an email address (ignored for sinks).
    Side effects: None.
    """

    possible_url_value: bool = False
    possible_hostname: bool = False
    possible_ip: bool = False
    possible_path: bool = False
    possible_domain: bool = False
    possible_unc: bool = False
    possible_protocol: bool = False
    protocols_seen: tuple[str, ...] = ()
    looks_like: tuple[str, ...] = ()
    score: int = 0
    possible_network_resource: bool = False
    evidence: tuple[str, ...] = ()
    is_email: bool = False

    def to_dict(self) -> dict:
        """Serialize for url_features merge / tests."""
        return {
            "possible_url_value": self.possible_url_value,
            "possible_hostname": self.possible_hostname,
            "possible_ip": self.possible_ip,
            "possible_path": self.possible_path,
            "possible_domain": self.possible_domain,
            "possible_unc": self.possible_unc,
            "possible_protocol": self.possible_protocol,
            "protocols_seen": list(self.protocols_seen),
            "looks_like": list(self.looks_like),
            "score": self.score,
            "possible_network_resource": self.possible_network_resource,
            "evidence": list(self.evidence),
            "is_email": self.is_email,
        }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def classify_value(value: str | None) -> UrlValueFeatures:
    """
    Purpose:
        Classify a scalar parameter value for network-resource sink signals.
    Input:
        value — raw sample string (may be None/empty).
    Output:
        UrlValueFeatures (score 0 and empty flags when empty/unrelated).
    Side effects: None.
    """
    if value is None:
        return UrlValueFeatures()
    raw = str(value).strip()
    if not raw:
        return UrlValueFeatures()

    # Cap pathological lengths (no recursive bombs; pure classifier).
    if len(raw) > 4096:
        raw = raw[:4096]

    # Email → ignore as network resource sink.
    if _EMAIL_RE.match(raw) and not raw.lower().startswith("mailto:"):
        return UrlValueFeatures(
            is_email=True,
            looks_like=("email",),
            evidence=("email_ignored",),
            score=0,
            possible_network_resource=False,
        )

    flags: dict[str, bool] = {
        "possible_url_value": False,
        "possible_hostname": False,
        "possible_ip": False,
        "possible_path": False,
        "possible_domain": False,
        "possible_unc": False,
        "possible_protocol": False,
    }
    protocols: list[str] = []
    looks: list[str] = []
    evidence: list[str] = []
    score = 0

    # --- 1. Absolute scheme:// -------------------------------------------------
    scheme_m = _SCHEME_RE.match(raw)
    if scheme_m:
        scheme = scheme_m.group("scheme").lower()
        if scheme in _ALL_SCHEMES:
            flags["possible_protocol"] = True
            protocols.append(scheme)
            evidence.append(f"value_scheme:{scheme}")
            if scheme in _NETWORK_SCHEMES:
                flags["possible_url_value"] = True
                looks.append("url")
                score = max(score, 95 if scheme in ("http", "https") else 90)
                # Parse host for extra flags.
                _enrich_from_url(raw, flags, looks, evidence)
            elif scheme == "mailto":
                # Low weight; still protocol but not fetch sink by default.
                looks.append("mailto")
                score = max(score, 10)
            elif scheme in ("data", "blob"):
                looks.append(scheme)
                score = max(score, 15)
        else:
            # Unknown scheme still looks URL-shaped.
            flags["possible_protocol"] = True
            flags["possible_url_value"] = True
            protocols.append(scheme)
            looks.append("url")
            evidence.append(f"value_scheme:{scheme}")
            score = max(score, 85)
    else:
        # Opaque single-colon schemes: mailto:, data:, blob:
        opaque_m = _OPAQUE_SCHEME_RE.match(raw)
        if opaque_m:
            scheme = opaque_m.group("scheme").lower()
            flags["possible_protocol"] = True
            protocols.append(scheme)
            evidence.append(f"value_scheme:{scheme}")
            if scheme == "mailto":
                looks.append("mailto")
                score = max(score, 10)
            else:
                looks.append(scheme)
                score = max(score, 15)

    # --- 2. Protocol-relative //host ------------------------------------------
    if not flags["possible_url_value"] and not flags["possible_protocol"]:
        pr = _PROTO_REL_RE.match(raw)
        if pr and not raw.startswith("///"):
            host = pr.group("host")
            if host and _looks_like_authority(host):
                flags["possible_url_value"] = True
                flags["possible_protocol"] = True  # implicit http(s)
                looks.append("protocol_relative")
                evidence.append("value_protocol_relative")
                score = max(score, 85)
                _classify_host_token(host, flags, looks, evidence)

    # --- 3. IPv4 / IPv6 literals ----------------------------------------------
    # Skip bare-IP detection when we already have a full URL (host handled).
    ip_score = 0
    if not flags["possible_url_value"]:
        ip_score = _try_ip(raw, flags, looks, evidence)
    score = max(score, ip_score)

    # --- 4. UNC ---------------------------------------------------------------
    unc_score = _try_unc(raw, flags, looks, evidence)
    score = max(score, unc_score)

    # --- 5. Filesystem paths --------------------------------------------------
    path_score = _try_path(raw, flags, looks, evidence)
    score = max(score, path_score)

    # --- 6. Hostname / domain -------------------------------------------------
    if not flags["possible_url_value"] and not flags["possible_ip"]:
        host_score = _try_hostname(raw, flags, looks, evidence)
        score = max(score, host_score)

    # --- 7. host:port / path?query fragments ----------------------------------
    if score < 55:
        frag_score = _try_fragments(raw, flags, looks, evidence)
        score = max(score, frag_score)

    # Deduplicate looks / evidence while preserving order.
    looks_t = tuple(dict.fromkeys(looks))
    evidence_t = tuple(dict.fromkeys(evidence))
    protocols_t = tuple(dict.fromkeys(protocols))
    score = max(0, min(100, score))
    possible_nr = score >= NETWORK_RESOURCE_SCORE_THRESHOLD

    return UrlValueFeatures(
        possible_url_value=flags["possible_url_value"],
        possible_hostname=flags["possible_hostname"],
        possible_ip=flags["possible_ip"],
        possible_path=flags["possible_path"],
        possible_domain=flags["possible_domain"],
        possible_unc=flags["possible_unc"],
        possible_protocol=flags["possible_protocol"],
        protocols_seen=protocols_t,
        looks_like=looks_t,
        score=score,
        possible_network_resource=possible_nr,
        evidence=evidence_t,
        is_email=False,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _enrich_from_url(
    raw: str,
    flags: dict[str, bool],
    looks: list[str],
    evidence: list[str],
) -> None:
    """Add host/IP/path flags from a scheme:// URL."""
    try:
        parts = urlsplit(raw)
    except Exception:
        return
    host = parts.hostname or ""
    if host:
        _classify_host_token(host, flags, looks, evidence)
    if parts.path and parts.path not in ("", "/"):
        flags["possible_path"] = True
        if "path" not in looks:
            looks.append("path")


def _classify_host_token(
    host: str,
    flags: dict[str, bool],
    looks: list[str],
    evidence: list[str],
) -> None:
    """Classify a host token as IP, domain, or hostname."""
    h = host.strip().strip("[]")
    if not h:
        return
    # IPv4 / IPv6
    try:
        addr = ipaddress.ip_address(h)
        flags["possible_ip"] = True
        label = "ipv6" if addr.version == 6 else "ipv4"
        if label not in looks:
            looks.append(label)
        evidence.append(f"value_ip:{label}")
        return
    except ValueError:
        pass
    if "." in h or h.lower() in ("localhost",):
        flags["possible_hostname"] = True
        flags["possible_domain"] = True
        if "hostname" not in looks:
            looks.append("hostname")
        evidence.append("value_hostname")
    else:
        flags["possible_hostname"] = True
        if "hostname" not in looks:
            looks.append("hostname")
        evidence.append("value_hostname")


def _looks_like_authority(host: str) -> bool:
    """True if token could be a host authority (not empty garbage)."""
    h = host.strip().strip("[]")
    if not h or " " in h:
        return False
    if _IPV4_RE.match(h):
        return True
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        pass
    if h.lower() == "localhost":
        return True
    # At least one label with alnum
    return bool(re.match(r"^[A-Za-z0-9._\-]+$", h))


def _try_ip(
    raw: str,
    flags: dict[str, bool],
    looks: list[str],
    evidence: list[str],
) -> int:
    """Detect bare IPv4/IPv6 (optional port stripped for IPv4)."""
    candidate = raw
    # Strip trailing :port for IPv4 only
    if _IPV4_RE.match(raw.split(":")[0] if raw.count(":") == 1 else raw):
        if ":" in raw and raw.count(":") == 1:
            host_part, _, port = raw.partition(":")
            if port.isdigit() and 1 <= int(port) <= 65535 and _IPV4_RE.match(host_part):
                candidate = host_part
    # Bracketed IPv6 with optional port [addr]:port
    if raw.startswith("["):
        m = re.match(r"^\[([^\]]+)\](?::(\d{1,5}))?$", raw)
        if m:
            candidate = m.group(1)

    try:
        addr = ipaddress.ip_address(candidate)
    except ValueError:
        # Bare IPv6 without brackets
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            return 0

    flags["possible_ip"] = True
    label = "ipv6" if addr.version == 6 else "ipv4"
    if label not in looks:
        looks.append(label)
    evidence.append(f"value_ip:{label}")
    # Private/loopback still network resources (characterization, not exploit).
    return 80 if addr.version == 4 else 78


def _try_unc(
    raw: str,
    flags: dict[str, bool],
    looks: list[str],
    evidence: list[str],
) -> int:
    """Detect Windows UNC paths."""
    # Prefer backslash form; forward-slash //host/share only when two+ segments
    # and not mistaken for protocol-relative URL we already handled.
    if raw.startswith("\\\\"):
        m = _UNC_RE.match(raw)
        if m:
            flags["possible_unc"] = True
            flags["possible_path"] = True
            looks.append("unc")
            evidence.append("value_unc")
            host = m.group("host1") or ""
            if host:
                _classify_host_token(host, flags, looks, evidence)
            return 60
    return 0


def _try_path(
    raw: str,
    flags: dict[str, bool],
    looks: list[str],
    evidence: list[str],
) -> int:
    """Detect filesystem-looking paths (lower score unless file://)."""
    if flags.get("possible_url_value"):
        return 0
    if _WIN_PATH_RE.match(raw):
        flags["possible_path"] = True
        looks.append("path")
        evidence.append("value_win_path")
        return 50
    # Unix path: require at least one slash beyond root and a multi-segment
    # or known sensitive leaf to avoid flagging "/login".
    if raw.startswith("/") and not raw.startswith("//"):
        if _PATH_QUERY_RE.match(raw):
            flags["possible_path"] = True
            looks.append("path")
            evidence.append("value_path_query")
            return 45
        segs = [s for s in raw.split("/") if s]
        if len(segs) >= 2 and _UNIX_PATH_RE.match(raw):
            flags["possible_path"] = True
            looks.append("path")
            evidence.append("value_unix_path")
            # Sensitive-looking paths score higher within path band.
            sensitive = {
                "etc", "proc", "var", "usr", "windows", "system32",
                "passwd", "shadow", "web-inf", "boot.ini",
            }
            low_segs = {s.lower() for s in segs}
            if low_segs & sensitive:
                return 55
            return 45
    return 0


def _is_likely_filename(value: str) -> bool:
    """
    Purpose:
        True when value looks like a basename with a common file extension
        (e.g. report.pdf, jquery.min.js) rather than a network hostname.
    Input:
        value — candidate string (no path separators expected).
    Output:
        bool
    Side effects: None.
    """
    if not value or "/" in value or "\\" in value or " " in value:
        return False
    if "." not in value:
        return False
    # Reject scheme-like prefixes
    if "://" in value:
        return False
    ext = value.rsplit(".", 1)[-1].lower()
    if not ext or ext not in _FILE_EXTENSIONS:
        return False
    # Must have a non-empty stem; multi-dot (a.b.js) still filename when
    # last label is a known extension.
    stem = value[: -(len(ext) + 1)]
    if not stem or stem.startswith("."):
        return False
    return True


def _try_hostname(
    raw: str,
    flags: dict[str, bool],
    looks: list[str],
    evidence: list[str],
) -> int:
    """Detect bare hostnames / domains (no scheme)."""
    candidate = raw
    # Strip trailing path from hostname/path form: example.com/path
    if "/" in raw and not raw.startswith("/"):
        host_part = raw.split("/", 1)[0]
        if (
            not _is_likely_filename(host_part)
            and (_HOSTNAME_RE.match(host_part) or host_part.lower() == "localhost")
        ):
            candidate = host_part
            flags["possible_path"] = True
            if "path" not in looks:
                looks.append("path")

    # Filenames like report.pdf must not score as hostnames (TLD collision).
    if _is_likely_filename(candidate):
        return 0

    if candidate.lower() == "localhost":
        flags["possible_hostname"] = True
        looks.append("hostname")
        evidence.append("value_hostname")
        return 60

    if _HOSTNAME_RE.match(candidate):
        flags["possible_hostname"] = True
        flags["possible_domain"] = True
        looks.append("hostname")
        looks.append("domain")
        evidence.append("value_hostname")
        # Internal TLDs still count
        return 65

    return 0


def _try_fragments(
    raw: str,
    flags: dict[str, bool],
    looks: list[str],
    evidence: list[str],
) -> int:
    """host:port and path?query fragments without scheme."""
    m = _HOST_PORT_RE.match(raw)
    if m:
        host = m.group("ipv6") or m.group("host") or ""
        port = int(m.group("port"))
        if 1 <= port <= 65535 and host:
            _classify_host_token(host, flags, looks, evidence)
            evidence.append("value_host_port")
            looks.append("host_port")
            return 70
    if _PATH_QUERY_RE.match(raw):
        flags["possible_path"] = True
        looks.append("path")
        evidence.append("value_path_query")
        return 45
    return 0
