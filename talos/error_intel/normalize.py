"""
Module: talos.error_intel.normalize

Purpose:
    Error-specific text normalization for fingerprint identity (Phase 4).

    Strips volatile tokens so the same application error (different line
    numbers, request IDs, timestamps) collapses to one cluster.

    Aligned with IV body volatility stripping
    (``talos.input_validation.fingerprint.normalize_body_for_hash``) plus
    error-specific rules: stack line numbers, memory addresses, paths.

Dependencies: re (stdlib)
Data flow: raw snippet / frames / message → normalized strings
Side effects: None.
"""

from __future__ import annotations

import re
from typing import Any, Optional, Sequence

# ---------------------------------------------------------------------------
# Volatility patterns (order matters for overlapping substitutions)
# ---------------------------------------------------------------------------

# JWT-ish (three base64url segments) — before generic long hex / session
_RE_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)

# UUID / GUID
_RE_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)

# ISO timestamps
_RE_ISO_TS = re.compile(
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"
)
_RE_DATE_ONLY = re.compile(r"\b\d{4}-\d{2}-\d{2}\b")
_RE_UNIX_TS_MS = re.compile(r"\b1[6-9]\d{11}\b")
_RE_UNIX_TS_S = re.compile(r"\b1[6-9]\d{8}\b")

# Memory addresses
_RE_ADDR = re.compile(r"\b0x[0-9a-fA-F]{4,16}\b")

# Long hex dumps / IDs (after UUID)
_RE_LONG_HEX = re.compile(r"\b[0-9a-fA-F]{32,}\b")

# Request / correlation / trace IDs (key=value)
_RE_REQID_KV = re.compile(
    r"(?i)\b("
    r"request[_-]?id|correlation[_-]?id|trace[_-]?id|traceid|"
    r"x-request-id|x-correlation-id|cf-ray|span[_-]?id|"
    r"session[_-]?id|sid|jti|rid"
    r")\s*[=:]\s*[\"']?[A-Za-z0-9._:@\-/=+]{6,128}[\"']?"
)

# Session cookies / tokens in messages
_RE_SESSION = re.compile(
    r"(?i)\b("
    r"JSESSIONID|PHPSESSID|ASP\.NET_SessionId|connect\.sid|"
    r"sessionid"
    r")\s*[=:]\s*[A-Za-z0-9+/=._\-]{8,200}"
)

# Ephemeral host:port (keep host shape, scrub port)
_RE_HOST_PORT = re.compile(
    r"(?P<host>"
    r"(?:localhost|127\.0\.0\.1|"
    r"(?:10|192\.168|172\.(?:1[6-9]|2\d|3[0-1]))\.\d{1,3}\.\d{1,3}|"
    r"[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+)"
    r"):(?P<port>\d{2,5})\b"
)

# Stack line numbers — language-family specific then generic
_RE_JAVA_LINE = re.compile(
    r"\(([A-Za-z0-9_./\\$-]+\.(?:java|kt|scala|groovy)):(\d+)\)"
)
_RE_DOTNET_LINE = re.compile(
    r"(?i)(\.cs|\.vb|\.fs):line\s+(\d+)"
)
_RE_PYTHON_LINE = re.compile(
    r'(?i)(File\s+"[^"]+",\s+)line\s+(\d+)'
)
_RE_JS_LINE = re.compile(
    r"(\.(?:js|ts|jsx|tsx|mjs|cjs)):(\d+)(?::(\d+))?"
)
_RE_GENERIC_COLON_LINE = re.compile(
    r"([A-Za-z0-9_./\\$-]+\.(?:py|rb|php|go|rs|java|cs|js|ts))(?::(\d+))+"
)
_RE_PHP_LINE = re.compile(
    r"(?i)\bon\s+line\s+(\d+)\b"
)
_RE_RUBY_FROM_LINE = re.compile(
    r"(from\s+[^\n:]+:)(\d+)"
)

# Unix / Windows home user path scrub
_RE_HOME_USER = re.compile(
    r"(/(?:home|Users)/)([^/\s\"']+)(/[^\s\"']*)?"
)
_RE_WIN_USER = re.compile(
    r"([A-Za-z]:\\Users\\)([^\\]+)((?:\\[^\s\"']*)?)",
    re.IGNORECASE,
)

# Optional high-churn numeric IDs in free-form messages
_RE_STANDALONE_NUM = re.compile(r"\b\d{4,}\b")

_RE_WS = re.compile(r"[ \t]+")
_RE_MULTI_NL = re.compile(r"\n{3,}")


def normalize_error_text(
    text: Optional[str],
    *,
    scrub_numeric_ids: bool = False,
) -> str:
    """
    Purpose:
        Replace volatile tokens in error body / snippet text with placeholders
        so fingerprint identity is stable across requests.

    Input:
        text — raw error text (may be multi-line stack)
        scrub_numeric_ids — when True, also replace long standalone numbers
            with ``<NUM>`` (high-churn messages only; default off)

    Output:
        Normalized string (empty when input empty/None).

    Side effects: None.
    """
    if not text:
        return ""

    out = str(text)

    out = _RE_JWT.sub("<JWT>", out)
    out = _RE_UUID.sub("<UUID>", out)
    out = _RE_ISO_TS.sub("<TS>", out)
    out = _RE_UNIX_TS_MS.sub("<TS>", out)
    out = _RE_UNIX_TS_S.sub("<TS>", out)
    out = _RE_DATE_ONLY.sub("<TS>", out)
    out = _RE_ADDR.sub("<ADDR>", out)
    out = _RE_REQID_KV.sub(
        lambda m: f"{m.group(1)}=<REQID>",
        out,
    )
    out = _RE_SESSION.sub(
        lambda m: f"{m.group(1)}=<SESSION>",
        out,
    )
    out = _RE_LONG_HEX.sub("<HEX>", out)
    out = _RE_HOST_PORT.sub(r"\g<host>:<PORT>", out)

    out = normalize_stack_line_numbers(out)
    out = normalize_path_user_segments(out)

    if scrub_numeric_ids:
        out = _RE_STANDALONE_NUM.sub("<NUM>", out)

    out = _RE_WS.sub(" ", out)
    out = _RE_MULTI_NL.sub("\n\n", out)
    return out.strip()


def normalize_stack_line_numbers(text: str) -> str:
    """
    Purpose:
        Replace line numbers in stack frames with ``<LINE>``.
    Side effects: None.
    """
    if not text:
        return ""
    out = text
    out = _RE_JAVA_LINE.sub(r"(\1:<LINE>)", out)
    out = _RE_DOTNET_LINE.sub(r"\1:line <LINE>", out)
    out = _RE_PYTHON_LINE.sub(r"\1line <LINE>", out)
    out = _RE_JS_LINE.sub(
        lambda m: f"{m.group(1)}:<LINE>" + (":<COL>" if m.group(3) else ""),
        out,
    )
    out = _RE_GENERIC_COLON_LINE.sub(
        lambda m: m.group(1) + (":<LINE>" * max(1, m.group(0).count(":"))),
        out,
    )
    out = _RE_PHP_LINE.sub("on line <LINE>", out)
    out = _RE_RUBY_FROM_LINE.sub(r"\1<LINE>", out)
    out = re.sub(
        r"(\.(?:go|rs))(?::\d+)+",
        r"\1:<LINE>",
        out,
    )
    return out


def normalize_path_user_segments(text: str) -> str:
    """
    Purpose:
        Scrub user home path segments while keeping directory *shape*.
        ``/home/alice/app`` → ``/home/<USER>/app``
    Side effects: None.
    """
    if not text:
        return ""
    out = _RE_HOME_USER.sub(
        lambda m: m.group(1) + "<USER>" + (m.group(3) or ""),
        text,
    )
    out = _RE_WIN_USER.sub(
        lambda m: m.group(1) + "<USER>" + (m.group(3) or ""),
        out,
    )
    return out


def normalize_path_shape(path: str) -> str:
    """
    Purpose:
        Normalize a single filesystem path for artifact / message identity.
    Side effects: None.
    """
    if not path:
        return ""
    return normalize_path_user_segments(normalize_stack_line_numbers(path.strip()))


def normalize_frames(
    frames: Optional[Sequence[Any]],
    *,
    max_frames: int = 8,
) -> str:
    """
    Purpose:
        Build a stable multi-line stack identity from detector frame metadata.

    Input:
        frames — list of dicts (method/file/line) or strings from
            RawErrorMatch.metadata
        max_frames — top-N frames for identity (default 8)

    Output:
        Normalized stack string (empty when no frames).

    Side effects: None.
    """
    if not frames:
        return ""
    lines: list[str] = []
    for frame in list(frames)[: max(1, int(max_frames))]:
        line = _frame_to_line(frame)
        if line:
            lines.append(normalize_error_text(line))
    return "\n".join(lines)


def _frame_to_line(frame: Any) -> str:
    if frame is None:
        return ""
    if isinstance(frame, str):
        return frame.strip()
    if not isinstance(frame, dict):
        return str(frame).strip()
    method = frame.get("method") or frame.get("function") or frame.get("symbol")
    file_ = frame.get("file") or frame.get("filename") or frame.get("source")
    line_no = frame.get("line") or frame.get("lineno")
    raw = frame.get("raw") or frame.get("text")
    if method and file_:
        return (
            f"at {method}({file_}:<LINE>)"
            if line_no is not None
            else f"at {method}({file_})"
        )
    if method:
        return f"at {method}"
    if file_:
        return f"{file_}:<LINE>" if line_no is not None else str(file_)
    if raw:
        return str(raw)
    parts = []
    for k in sorted(frame.keys()):
        if k in {"start", "end", "match_start", "match_end"}:
            continue
        v = frame[k]
        if v is None:
            continue
        if isinstance(v, (str, int, float)):
            parts.append(f"{k}={v}")
    return " ".join(parts)


def extract_message_norm(
    text: Optional[str],
    *,
    exception_type: Optional[str] = None,
    max_chars: int = 240,
) -> str:
    """
    Purpose:
        Derive a short normalized message for cluster.message_norm and
        fingerprint message hash.

    Prefers the message after the exception type when present, otherwise
    the first meaningful line of the snippet.

    Side effects: None.
    """
    if not text:
        return ""
    raw = str(text).strip()
    if not raw:
        return ""

    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if not lines:
        return ""

    message = lines[0]
    if exception_type:
        exc = exception_type.strip()
        for ln in lines[:4]:
            if exc in ln:
                if ":" in ln:
                    after = ln.split(":", 1)[1].strip()
                    if after:
                        message = after
                        break
                message = ln
                break
        else:
            message = lines[0]

    if re.match(r"^(?:at\s+|File\s+|from\s+|#+ )", message):
        for ln in lines[1:6]:
            if not re.match(r"^(?:at\s+|File\s+|from\s+|#+ |\s*$)", ln):
                message = ln
                break

    norm = normalize_error_text(message)
    if len(norm) > max_chars:
        norm = norm[: max_chars - 1] + "…"
    return norm


def extract_normalized_stack_from_match(
    match: Any,
    *,
    max_frames: int = 8,
) -> str:
    """
    Purpose:
        Pull frames from a RawErrorMatch (or similar) and normalize them.
        Falls back to stack-ish lines from raw_snippet when no frames.

    Side effects: None.
    """
    meta = getattr(match, "metadata", None) or {}
    if not isinstance(meta, dict):
        meta = {}
    frames = meta.get("frames")
    stack = normalize_frames(frames, max_frames=max_frames)
    if stack:
        return stack

    snippet = getattr(match, "raw_snippet", None) or ""
    if not snippet:
        return ""
    frame_lines: list[str] = []
    for ln in str(snippet).splitlines():
        s = ln.strip()
        if not s:
            continue
        if re.match(
            r"^(?:at\s+|File\s+|from\s+|#\d+\s+|Caused by:)",
            s,
        ) or re.search(r":\d+(?::\d+)?\s*$", s):
            frame_lines.append(s)
        if len(frame_lines) >= max_frames:
            break
    if frame_lines:
        return normalize_error_text("\n".join(frame_lines))
    return ""
