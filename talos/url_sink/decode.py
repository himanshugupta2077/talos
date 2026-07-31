"""
Module: talos.url_sink.decode

Purpose:
    Best-effort unwrap of base64 / base64url / URL-encoded JSON blobs so
    Endpoint Intelligence can walk nested keys with full dotted paths
    (e.g. form field ``config`` → ``config.oauth.metadata.url``).

    Inventory-only: never decrypts, never fetches, never mutates traffic.
    Caps size, depth, and leaf count to avoid recursive bombs.

Dependencies: base64, binascii, json, re, urllib.parse (stdlib)
Data flow: opaque string value → optional parsed JSON object + evidence chain
Side effects: None.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, unquote_plus

# ---------------------------------------------------------------------------
# Caps (mirror JSON walk depth ≤6; keep decode cheap on hot path)
# ---------------------------------------------------------------------------

# Skip unwrap attempts on tiny or huge values.
MIN_ENCODED_LEN: int = 8
MAX_ENCODED_LEN: int = 64_000

# Nested decode layers (url then base64, or double-url, etc.).
MAX_DECODE_LAYERS: int = 2

# Maximum leaves emitted when walking one unwrapped blob (per outer param).
MAX_LEAVES_PER_BLOB: int = 50

# JSON walk depth for unwrapped structure (same family as parameters._walk_json).
MAX_JSON_DEPTH: int = 6

# Base64-ish character class (standard + url-safe).
_B64_RE = re.compile(r"^[A-Za-z0-9_\-+/]+=*$")
# Looks like percent-encoded JSON start after unquote.
_JSON_START_CHARS = frozenset("{[")


@dataclass(frozen=True, slots=True)
class UnwrapResult:
    """
    Purpose:
        Outcome of a best-effort encoded-JSON unwrap attempt.
    Fields:
        parsed   — JSON object/array/scalar when successful, else None.
        evidence — machine-readable decode chain tokens (e.g. decode:base64).
        raw_text — intermediate decoded text used for json.loads (for tests).
    Side effects: None.
    """

    parsed: Any | None
    evidence: tuple[str, ...]
    raw_text: str = ""


def try_unwrap_json(value: str | None) -> UnwrapResult:
    """
    Purpose:
        Attempt to interpret ``value`` as URL-encoded and/or base64 JSON.
    Input:
        value — raw parameter sample (form/query/JSON leaf/multipart field).
    Output:
        UnwrapResult; ``parsed`` is None when value is not encoded JSON.
    Side effects: None.
    Assumptions:
        - Plain JSON objects already handled by body parsers are not required
          here; this targets *encoded* blobs nested inside scalar strings.
        - First successful JSON parse wins (no multi-object search).
    """
    if value is None:
        return UnwrapResult(parsed=None, evidence=())
    text = value.strip()
    if len(text) < MIN_ENCODED_LEN or len(text) > MAX_ENCODED_LEN:
        return UnwrapResult(parsed=None, evidence=())

    # Fast reject: already plain non-JSON string without encoding markers.
    if (
        not _looks_percent_encoded(text)
        and not _looks_base64(text)
        and text[:1] not in _JSON_START_CHARS
    ):
        return UnwrapResult(parsed=None, evidence=())

    # Try direct JSON first (URL-decoded form fields sometimes land as raw JSON).
    direct = _try_json_loads(text)
    if direct is not None and _is_structured(direct):
        return UnwrapResult(
            parsed=direct,
            evidence=("decode:json",),
            raw_text=text,
        )

    candidates: list[tuple[str, tuple[str, ...]]] = [(text, ())]
    seen: set[str] = set()

    for _layer in range(MAX_DECODE_LAYERS):
        next_round: list[tuple[str, tuple[str, ...]]] = []
        for current, chain in candidates:
            if current in seen:
                continue
            seen.add(current)

            # URL-decode (plus and percent forms).
            if _looks_percent_encoded(current) or "+" in current:
                for decoder, tag in (
                    (unquote_plus, "decode:url"),
                    (unquote, "decode:url"),
                ):
                    try:
                        decoded = decoder(current)
                    except Exception:
                        continue
                    if decoded == current or not decoded:
                        continue
                    parsed = _try_json_loads(decoded)
                    if parsed is not None and _is_structured(parsed):
                        return UnwrapResult(
                            parsed=parsed,
                            evidence=chain + (tag, "decode:json"),
                            raw_text=decoded,
                        )
                    if decoded not in seen and len(decoded) <= MAX_ENCODED_LEN:
                        next_round.append((decoded, chain + (tag,)))

            # Base64 / base64url
            if _looks_base64(current):
                b64_text = _b64_decode_to_text(current)
                if b64_text:
                    tag = "decode:base64"
                    parsed = _try_json_loads(b64_text)
                    if parsed is not None and _is_structured(parsed):
                        return UnwrapResult(
                            parsed=parsed,
                            evidence=chain + (tag, "decode:json"),
                            raw_text=b64_text,
                        )
                    if b64_text not in seen and len(b64_text) <= MAX_ENCODED_LEN:
                        next_round.append((b64_text, chain + (tag,)))

        candidates = next_round
        if not candidates:
            break

    return UnwrapResult(parsed=None, evidence=())


def walk_unwrapped_leaves(
    parsed: Any,
    *,
    prefix: str,
    max_depth: int = MAX_JSON_DEPTH,
    max_leaves: int = MAX_LEAVES_PER_BLOB,
) -> list[tuple[str, str]]:
    """
    Purpose:
        Flatten a parsed JSON structure into (dotted_name, sample_value) leaves.
    Input:
        parsed    — object from try_unwrap_json (dict/list preferred).
        prefix    — outer parameter name (e.g. form field ``config``).
        max_depth / max_leaves — safety caps.
    Output:
        List of (full_dotted_path, scalar_string_value). Arrays record first
        dict element under ``prefix[]`` similar to parameters._walk_json.
    Side effects: None.
    """
    results: list[tuple[str, str]] = []
    _walk(parsed, prefix, results, depth=0, max_depth=max_depth, max_leaves=max_leaves)
    return results


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _is_structured(obj: Any) -> bool:
    """Only treat dict/list as worth expanding (scalars already in inventory)."""
    return isinstance(obj, (dict, list))


def _try_json_loads(text: str) -> Any | None:
    stripped = text.strip()
    if not stripped or stripped[0] not in _JSON_START_CHARS:
        return None
    try:
        return json.loads(stripped)
    except (json.JSONDecodeError, TypeError, ValueError, RecursionError):
        return None


def _looks_percent_encoded(text: str) -> bool:
    return "%" in text and bool(re.search(r"%[0-9A-Fa-f]{2}", text))


def _looks_base64(text: str) -> bool:
    """
    Heuristic: long enough, charset-safe, length multiple of 4 (after pad).
    Rejects obvious URLs and paths.
    """
    s = text.strip()
    if len(s) < 16:
        return False
    if "://" in s or s.startswith("//") or s.startswith("/") or s.startswith("{"):
        return False
    if not _B64_RE.match(s):
        return False
    # Padding-normalized length should be multiple of 4 for strict base64.
    pad_len = (-len(s)) % 4
    if pad_len == 3:
        return False
    return True


def _b64_decode_to_text(text: str) -> str | None:
    """Decode standard or URL-safe base64 to UTF-8 text; None on failure."""
    s = text.strip().replace("\n", "").replace("\r", "")
    pad = (-len(s)) % 4
    if pad:
        s = s + ("=" * pad)
    raw: bytes | None = None
    for decoder in (
        lambda t: base64.b64decode(t, validate=False),
        lambda t: base64.urlsafe_b64decode(t),
    ):
        try:
            raw = decoder(s)
            break
        except (binascii.Error, ValueError):
            continue
    if raw is None or not raw:
        return None
    # Reject binary-looking blobs (high null / control density).
    if raw.count(b"\x00") > 0:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return raw.decode("latin-1")
        except Exception:
            return None


def _walk(
    node: Any,
    prefix: str,
    results: list[tuple[str, str]],
    *,
    depth: int,
    max_depth: int,
    max_leaves: int,
) -> None:
    if depth > max_depth or len(results) >= max_leaves:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if len(results) >= max_leaves:
                return
            if not isinstance(key, str) or not key:
                continue
            full = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                _walk(
                    value, full, results,
                    depth=depth + 1, max_depth=max_depth, max_leaves=max_leaves,
                )
            elif isinstance(value, list):
                if value and isinstance(value[0], dict):
                    _walk(
                        value[0], full + "[]", results,
                        depth=depth + 1, max_depth=max_depth, max_leaves=max_leaves,
                    )
                elif value and not isinstance(value[0], (dict, list)):
                    if len(results) < max_leaves:
                        results.append((full + "[]", str(value[0])))
            elif value is None:
                if len(results) < max_leaves:
                    results.append((full, ""))
            else:
                if len(results) < max_leaves:
                    results.append((full, str(value)))
    elif isinstance(node, list):
        if node and isinstance(node[0], dict):
            _walk(
                node[0], (prefix + "[]") if prefix else "[]", results,
                depth=depth + 1, max_depth=max_depth, max_leaves=max_leaves,
            )
        elif node and not isinstance(node[0], (dict, list)):
            if len(results) < max_leaves:
                name = (prefix + "[]") if prefix else "[]"
                results.append((name, str(node[0])))
