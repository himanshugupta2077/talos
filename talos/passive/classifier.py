"""
Module: talos.passive.classifier

Purpose:
    Classify a captured response body (or extracted virtual fragment) into a
    SourceKind so the scan worker, extractors, and config toggles can specialize.

    Classification is deterministic and pure: content-type, path extension /
    hints, then optional cheap magic-byte / text sniff.  Never runs detectors
    or full-body regex.

    Used by:
        SourceScanWorker after dequeue
        is_source_candidate() for consistent allow/deny decisions

Dependencies: re, urllib.parse (stdlib); talos.passive.constants.SourceKind
Data flow: (content_type, path, optional body/text) → SourceKind
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import unquote, urlparse

from talos.passive.constants import SourceKind

# ---------------------------------------------------------------------------
# Content-Type → SourceKind (primary signal when present and specific)
# ---------------------------------------------------------------------------

# Exact media types (after stripping parameters / lowercasing).
_CT_EXACT: dict[str, SourceKind] = {
    "text/html": SourceKind.HTML,
    "application/xhtml+xml": SourceKind.HTML,
    "text/javascript": SourceKind.JAVASCRIPT,
    "application/javascript": SourceKind.JAVASCRIPT,
    "application/x-javascript": SourceKind.JAVASCRIPT,
    "text/ecmascript": SourceKind.JAVASCRIPT,
    "application/ecmascript": SourceKind.JAVASCRIPT,
    "application/json": SourceKind.JSON,
    "text/json": SourceKind.JSON,
    "application/ld+json": SourceKind.JSON,
    "application/manifest+json": SourceKind.JSON,
    "application/xml": SourceKind.XML,
    "text/xml": SourceKind.XML,
    "application/atom+xml": SourceKind.XML,
    "application/rss+xml": SourceKind.XML,
    "text/plain": SourceKind.TEXT,
    "text/csv": SourceKind.TEXT,
    "text/markdown": SourceKind.TEXT,
    "text/css": SourceKind.CSS,
    "application/wasm": SourceKind.WASM,
    "application/pdf": SourceKind.BINARY,
    "application/zip": SourceKind.BINARY,
    "application/gzip": SourceKind.BINARY,
    "application/x-gzip": SourceKind.BINARY,
    "application/x-tar": SourceKind.BINARY,
    "application/octet-stream": SourceKind.UNKNOWN,  # need path/sniff
    "application/force-download": SourceKind.UNKNOWN,
}

# Prefix rules for image/audio/video/font and structured +json/+xml.
_CT_PREFIX_BINARY: tuple[str, ...] = (
    "image/",
    "audio/",
    "video/",
    "font/",
    "application/font-",
    "application/vnd.ms-fontobject",
    "multipart/",
)

# Path extension → SourceKind (path without query; lowercased).
_EXT_KIND: dict[str, SourceKind] = {
    ".html": SourceKind.HTML,
    ".htm": SourceKind.HTML,
    ".xhtml": SourceKind.HTML,
    ".js": SourceKind.JAVASCRIPT,
    ".mjs": SourceKind.JAVASCRIPT,
    ".cjs": SourceKind.JAVASCRIPT,
    ".jsx": SourceKind.JAVASCRIPT,
    ".ts": SourceKind.JAVASCRIPT,  # TS sources often served as text; scan as JS family
    ".tsx": SourceKind.JAVASCRIPT,
    ".json": SourceKind.JSON,
    ".map": SourceKind.SOURCEMAP,
    ".xml": SourceKind.XML,
    ".xsl": SourceKind.XML,
    ".xslt": SourceKind.XML,
    ".svg": SourceKind.XML,  # XML family; extractors may treat as markup later
    ".css": SourceKind.CSS,
    ".txt": SourceKind.TEXT,
    ".text": SourceKind.TEXT,
    ".md": SourceKind.TEXT,
    ".csv": SourceKind.TEXT,
    ".yml": SourceKind.TEXT,
    ".yaml": SourceKind.TEXT,
    ".toml": SourceKind.TEXT,
    ".ini": SourceKind.TEXT,
    ".env": SourceKind.TEXT,
    ".wasm": SourceKind.WASM,
    # Binary / non-source extensions (explicit reject)
    ".png": SourceKind.BINARY,
    ".jpg": SourceKind.BINARY,
    ".jpeg": SourceKind.BINARY,
    ".gif": SourceKind.BINARY,
    ".webp": SourceKind.BINARY,
    ".ico": SourceKind.BINARY,
    ".bmp": SourceKind.BINARY,
    ".tif": SourceKind.BINARY,
    ".tiff": SourceKind.BINARY,
    ".pdf": SourceKind.BINARY,
    ".zip": SourceKind.BINARY,
    ".gz": SourceKind.BINARY,
    ".br": SourceKind.BINARY,
    ".woff": SourceKind.BINARY,
    ".woff2": SourceKind.BINARY,
    ".ttf": SourceKind.BINARY,
    ".otf": SourceKind.BINARY,
    ".eot": SourceKind.BINARY,
    ".mp3": SourceKind.BINARY,
    ".mp4": SourceKind.BINARY,
    ".webm": SourceKind.BINARY,
    ".avi": SourceKind.BINARY,
    ".mov": SourceKind.BINARY,
    ".bin": SourceKind.BINARY,
    ".exe": SourceKind.BINARY,
    ".dll": SourceKind.BINARY,
    ".so": SourceKind.BINARY,
    ".dmg": SourceKind.BINARY,
    ".iso": SourceKind.BINARY,
}

# Path basename / segment hints that imply source-like payloads even when
# Content-Type is generic (octet-stream / empty / text/plain).
_PATH_SOURCE_HINTS: tuple[str, ...] = (
    "env.js",
    "config.js",
    "settings.js",
    "runtime.js",
    "main.js",
    "app.js",
    "bundle.js",
    "chunk.js",
    "vendor.js",
    "swagger",
    "openapi",
    "sourcemap",
    "source.map",
    ".map",
    "webpack",
    "__next",
    "manifest.json",
    "package.json",
)

# Magic prefixes → kind (checked on first bytes only).
_MAGIC: tuple[tuple[bytes, SourceKind], ...] = (
    (b"\x89PNG\r\n\x1a\n", SourceKind.BINARY),
    (b"\xff\xd8\xff", SourceKind.BINARY),  # JPEG
    (b"GIF87a", SourceKind.BINARY),
    (b"GIF89a", SourceKind.BINARY),
    (b"%PDF", SourceKind.BINARY),
    (b"PK\x03\x04", SourceKind.BINARY),  # ZIP / jar / many office
    (b"PK\x05\x06", SourceKind.BINARY),
    (b"\x00asm", SourceKind.WASM),
    (b"wOFF", SourceKind.BINARY),
    (b"wOF2", SourceKind.BINARY),
    (b"OTTO", SourceKind.BINARY),  # OpenType
    (b"\x00\x01\x00\x00", SourceKind.BINARY),  # TrueType often
    (b"RIFF", SourceKind.BINARY),  # WEBP/WAV (refined below for WEBP)
    (b"\x1f\x8b", SourceKind.BINARY),  # gzip
    (b"BZ", SourceKind.BINARY),  # bzip2 (weak; only if not text-like)
)

# Text sniff prefixes (first non-BOM bytes as latin-1 / ascii-safe).
_JS_SNIFF = re.compile(
    r"^\s*(?:"
    r"function\b|var\b|let\b|const\b|import\b|export\b|class\b|"
    r"/\*|//|#!|"
    r"\(\s*function\b|window\.|document\.|self\."
    r")",
    re.IGNORECASE,
)
_HTML_SNIFF = re.compile(
    r"^\s*(?:<!DOCTYPE\s+html\b|<html\b|<!--)",
    re.IGNORECASE,
)
_XML_SNIFF = re.compile(r"^\s*<\?xml\b", re.IGNORECASE)
_CSS_SNIFF = re.compile(
    r"^\s*(?:@charset\b|@import\b|@media\b|@font-face\b|[@.]?[a-zA-Z_-][\w-]*\s*\{)",
)
_SOURCEMAP_SNIFF = re.compile(
    r'^\s*\{\s*"(?:version|sources|mappings|file)"\s*:',
)


def parse_media_type(content_type: Optional[str]) -> str:
    """
    Purpose:
        Extract the bare media type from a Content-Type header value.
    Input:
        content_type — full header or empty (may include charset=…).
    Output:
        Lowercased type/subtype, or "" if missing.
    Side effects: None.
    """
    if not content_type:
        return ""
    primary = str(content_type).split(";", 1)[0].strip().lower()
    return primary


def path_for_classification(path_or_url: Optional[str]) -> str:
    """
    Purpose:
        Normalize a request path or full URL to a lowercased path suitable
        for extension / hint matching (query and fragment stripped).
    Input:
        path_or_url — path ("/static/app.js") or absolute URL.
    Output:
        Lowercased path string (may be empty).
    Side effects: None.
    """
    if not path_or_url:
        return ""
    raw = str(path_or_url).strip()
    if not raw:
        return ""
    # Absolute URL → path only
    if "://" in raw or raw.startswith("//"):
        try:
            parsed = urlparse(raw if "://" in raw else f"https:{raw}")
            raw = parsed.path or ""
        except Exception:
            raw = raw.split("?", 1)[0].split("#", 1)[0]
    else:
        raw = raw.split("?", 1)[0].split("#", 1)[0]
    try:
        raw = unquote(raw)
    except Exception:
        pass
    return raw.lower()


def path_extension(path_or_url: Optional[str]) -> str:
    """
    Purpose:
        Return the file extension including the leading dot, or "".
    Input:
        path_or_url — path or URL.
    Output:
        e.g. ".js", ".map", or "".
    Side effects: None.
    """
    path = path_for_classification(path_or_url)
    if not path:
        return ""
    # basename
    base = path.rsplit("/", 1)[-1]
    if not base or base in (".", ".."):
        return ""
    # multi-dot: prefer last extension; special-case .js.map already handled as .map
    if "." not in base:
        return ""
    return "." + base.rsplit(".", 1)[-1]


def path_has_source_hint(path_or_url: Optional[str]) -> bool:
    """
    Purpose:
        Whether the path contains a known source-like basename/segment hint
        (env.js, swagger, .map, …) even without a clean extension match.
    Input:
        path_or_url — path or URL.
    Output:
        True if a hint matches.
    Side effects: None.
    """
    path = path_for_classification(path_or_url)
    if not path:
        return False
    base = path.rsplit("/", 1)[-1]
    for hint in _PATH_SOURCE_HINTS:
        if hint in path or hint in base:
            return True
    return False


def sniff_magic(body: Optional[bytes]) -> Optional[SourceKind]:
    """
    Purpose:
        Detect well-known binary containers from a short magic prefix.
    Input:
        body — raw response bytes (only first ~16 bytes inspected).
    Output:
        SourceKind.BINARY / WASM, or None if no magic match.
    Side effects: None.
    """
    if not body:
        return None
    head = body[:16]
    # WEBP: RIFF....WEBP
    if head.startswith(b"RIFF") and len(body) >= 12 and body[8:12] == b"WEBP":
        return SourceKind.BINARY
    for magic, kind in _MAGIC:
        if magic == b"RIFF":
            # bare RIFF without WEBP refinement — only claim binary if not
            # printable text (unlikely for real RIFF)
            if head.startswith(b"RIFF") and len(body) >= 12 and body[8:12] != b"WEBP":
                # WAV etc.
                return SourceKind.BINARY
            continue
        if magic == b"BZ":
            # too weak alone; skip generic BZ
            continue
        if head.startswith(magic):
            return kind
    return None


def _sniff_text_kind(sample: str) -> Optional[SourceKind]:
    """Map a short decoded prefix to SourceKind, or None if ambiguous."""
    if not sample or not sample.strip():
        return None
    # Strip UTF-8 BOM for sniff
    if sample.startswith("\ufeff"):
        sample = sample[1:]
    if _HTML_SNIFF.search(sample):
        return SourceKind.HTML
    if _XML_SNIFF.search(sample):
        return SourceKind.XML
    if _SOURCEMAP_SNIFF.search(sample):
        return SourceKind.SOURCEMAP
    stripped = sample.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        # JSON-ish; source maps often start with {"version"
        if _SOURCEMAP_SNIFF.search(sample):
            return SourceKind.SOURCEMAP
        return SourceKind.JSON
    if _JS_SNIFF.search(sample):
        return SourceKind.JAVASCRIPT
    if _CSS_SNIFF.search(sample):
        return SourceKind.CSS
    # Markup-ish without doctype
    if stripped.startswith("<") and any(
        tag in stripped[:200].lower()
        for tag in ("<html", "<head", "<body", "<script", "<div", "<!doctype")
    ):
        return SourceKind.HTML
    return None


def _looks_mostly_text(body: bytes, *, sample_size: int = 512) -> bool:
    """
    Purpose:
        Cheap printable-ratio check for generic Content-Types.
    Output:
        True if sample is predominantly text-like (high printable ratio).
    Side effects: None.
    """
    if not body:
        return False
    sample = body[:sample_size]
    if not sample:
        return False
    # NUL-heavy → binary
    if sample.count(b"\x00") > max(1, len(sample) // 50):
        return False
    printable = 0
    for b in sample:
        if b in (9, 10, 13) or 32 <= b <= 126:
            printable += 1
        elif b >= 0xC0:  # possible UTF-8 lead — count as text-ish
            printable += 1
    return (printable / len(sample)) >= 0.85


def _kind_from_content_type(media_type: str) -> Optional[SourceKind]:
    if not media_type:
        return None
    if media_type in _CT_EXACT:
        return _CT_EXACT[media_type]
    for prefix in _CT_PREFIX_BINARY:
        if media_type.startswith(prefix):
            return SourceKind.BINARY
    if media_type.endswith("+json") or "/json" in media_type:
        return SourceKind.JSON
    if media_type.endswith("+xml"):
        return SourceKind.XML
    if media_type.startswith("text/"):
        if "css" in media_type:
            return SourceKind.CSS
        if "html" in media_type:
            return SourceKind.HTML
        if "javascript" in media_type or "ecmascript" in media_type:
            return SourceKind.JAVASCRIPT
        if "xml" in media_type:
            return SourceKind.XML
        return SourceKind.TEXT
    if "javascript" in media_type or "ecmascript" in media_type:
        return SourceKind.JAVASCRIPT
    if "html" in media_type:
        return SourceKind.HTML
    return None


def classify_source(
    content_type: Optional[str] = None,
    path: Optional[str] = None,
    body: Optional[bytes] = None,
    text: Optional[str] = None,
) -> SourceKind:
    """
    Purpose:
        Decide SourceKind for a response (or virtual document).

    Priority (first decisive signal wins, with path refining generic CT):
        1. Magic bytes on body (PNG/JPEG/PDF/WASM/…)
        2. Specific Content-Type
        3. Path extension / source hints
        4. Text/body sniff (when body or text provided)
        5. UNKNOWN

    Generic CT (octet-stream, empty, force-download) never alone decides
    BINARY — path and sniff get a chance so mislabeled JS/JSON still scan.

    Input:
        content_type — response Content-Type header (may be empty)
        path         — request path or full URL
        body         — optional raw bytes (magic + text sniff)
        text         — optional already-normalized text (sniff only)

    Output:
        SourceKind enum member.

    Side effects: None.
    """
    # 1. Magic — hard reject for known binaries (even if CT lies)
    magic_kind = sniff_magic(body)
    if magic_kind is not None:
        return magic_kind

    media = parse_media_type(content_type)
    ct_kind = _kind_from_content_type(media)
    ext = path_extension(path)
    ext_kind = _EXT_KIND.get(ext) if ext else None
    hinted = path_has_source_hint(path)

    # Path says binary (e.g. .png) → BINARY even if CT missing
    if ext_kind is SourceKind.BINARY:
        return SourceKind.BINARY
    if ext_kind is SourceKind.WASM:
        return SourceKind.WASM

    # Specific CT that is not "generic unknown"
    generic_ct = ct_kind in (None, SourceKind.UNKNOWN)
    if ct_kind is not None and not generic_ct:
        # CT binary/image always wins
        if ct_kind is SourceKind.BINARY:
            return SourceKind.BINARY
        if ct_kind is SourceKind.WASM:
            return SourceKind.WASM
        # Path can upgrade JSON → SOURCEMAP when extension is .map
        if ext_kind is SourceKind.SOURCEMAP:
            return SourceKind.SOURCEMAP
        # Path can refine text/plain → JS/JSON/HTML when extension known
        if ct_kind is SourceKind.TEXT and ext_kind is not None:
            return ext_kind
        return ct_kind

    # 3. Extension / hints when CT empty or generic
    if ext_kind is not None and ext_kind not in (SourceKind.BINARY, SourceKind.WASM):
        return ext_kind
    if hinted:
        # Hint without extension: prefer JS for *.js names already covered;
        # swagger/openapi → JSON; sourcemap → SOURCEMAP
        path_l = path_for_classification(path)
        if ".map" in path_l or "sourcemap" in path_l:
            return SourceKind.SOURCEMAP
        if "swagger" in path_l or "openapi" in path_l or path_l.endswith(".json"):
            return SourceKind.JSON
        return SourceKind.JAVASCRIPT

    # 4. Sniff body/text
    sniff_sample: Optional[str] = None
    if text:
        sniff_sample = text[:512]
    elif body and _looks_mostly_text(body):
        # Best-effort ASCII/UTF-8-ish decode for sniff only (not full normalize)
        try:
            sniff_sample = body[:512].decode("utf-8")
        except UnicodeDecodeError:
            sniff_sample = body[:512].decode("latin-1", errors="replace")

    if sniff_sample:
        sniffed = _sniff_text_kind(sniff_sample)
        if sniffed is not None:
            return sniffed
        # Text-like but no strong structure → TEXT
        if body is None or _looks_mostly_text(body):
            return SourceKind.TEXT

    # Body present and not text-like → binary
    if body is not None and len(body) > 0 and not _looks_mostly_text(body):
        return SourceKind.BINARY

    return SourceKind.UNKNOWN


def is_scannable_kind(kind: SourceKind) -> bool:
    """
    Purpose:
        Whether a SourceKind is in-scope for passive secret scanning by default.
        WASM is not scannable under default config (scan_wasm=False); BINARY and
        UNKNOWN are never scan targets for enqueue.
    Input:
        kind — classified SourceKind
    Output:
        True for html/js/json/xml/text/css/sourcemap
    Side effects: None.
    """
    return kind in {
        SourceKind.HTML,
        SourceKind.JAVASCRIPT,
        SourceKind.JSON,
        SourceKind.XML,
        SourceKind.TEXT,
        SourceKind.CSS,
        SourceKind.SOURCEMAP,
    }
