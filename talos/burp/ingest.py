"""
Module: talos.burp.ingest

Purpose:
    Offer a BurpTrace to the Talos Burp extension over localhost so the
    proxied request never carries X-Talos-* headers.

    Burp HTTP history always records the original inbound request
    (Montoya cannot rewrite that view). Grouping therefore happens
    out of band when the extension is loaded.

Dependencies: json, urllib, time; talos.burp.trace
Data flow: maybe_apply_burp_headers → offer_trace → extension /ingest
Side effects: Short HTTP POST to 127.0.0.1; process-level up/down cache.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from pathlib import Path
from talos.burp.trace import BurpTrace

logger = logging.getLogger(__name__)

DEFAULT_PORT = 17384
_HEALTH_PATH = "/health"
_INGEST_PATH = "/ingest"
_TIMEOUT_S = 0.2
_UP_TTL_S = 30.0
_DOWN_TTL_S = 2.0

_available: bool | None = None
_checked_at = 0.0


def reset_ingest_state() -> None:
    """
    Purpose:
        Clear the process ingest cache (tests).
    Side effects: Next offer/health will probe the extension again.
    """
    global _available, _checked_at
    _available = None
    _checked_at = 0.0


def ingest_base_url() -> str:
    """
    Purpose:
        Resolve the extension ingest base URL.
    Output:
        http://127.0.0.1:<port> from ~/.talos/burp-ingest.port or default.
    Side effects: May read the port file.
    """
    port = DEFAULT_PORT
    port_file = Path.home() / ".talos" / "burp-ingest.port"
    try:
        raw = port_file.read_text(encoding="utf-8").strip()
        parsed = int(raw)
        if 1 <= parsed <= 65535:
            port = parsed
    except (OSError, ValueError):
        pass
    return f"http://127.0.0.1:{port}"


def offer_trace(
    trace: BurpTrace,
    *,
    method: str = "",
    host: str = "",
    path: str = "",
) -> bool:
    """
    Purpose:
        POST one trace to the extension. Empty match fields still enqueue
        but are harder to claim.
    Input:
        trace  — grouping metadata.
        method — actual HTTP method of the upcoming request.
        host   — hostname[:port] of the upcoming request.
        path   — path without query of the upcoming request.
    Output:
        True when the extension accepted the trace (do not stamp headers).
    Side effects: Localhost HTTP; updates the up/down cache.
    """
    if not _ingest_available():
        return False
    payload = {
        "engine": trace.engine,
        "group": trace.group,
        "endpoint": trace.endpoint_label,
        "endpoint_id": trace.endpoint_id,
        "host": host or trace.host,
        "param": trace.extras.get("param", ""),
        "location": trace.extras.get("location", ""),
        "analysis": trace.extras.get("analysis", ""),
        "payload_type": trace.extras.get("payload_type", ""),
        "technique": trace.extras.get("technique", ""),
        "variant": trace.extras.get("variant", ""),
        "detail": trace.extras.get("detail", ""),
        "method": (method or "").strip(),
        "path": (path or "").strip(),
        "project_id": trace.project_id,
        "project_name": trace.project_name,
        "record_id": trace.record_id,
    }
    try:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            ingest_base_url() + _INGEST_PATH,
            data=body,
            method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            if 200 <= getattr(resp, "status", 200) < 300:
                _mark(True)
                return True
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        logger.debug("burp ingest offer failed: %s", exc)
    _mark(False)
    return False


def _ingest_available() -> bool:
    global _available, _checked_at
    now = time.monotonic()
    if _available is True and (now - _checked_at) < _UP_TTL_S:
        return True
    if _available is False and (now - _checked_at) < _DOWN_TTL_S:
        return False
    ok = _probe_health()
    _mark(ok)
    return ok


def _probe_health() -> bool:
    try:
        req = urllib.request.Request(ingest_base_url() + _HEALTH_PATH, method="GET")
        with urllib.request.urlopen(req, timeout=_TIMEOUT_S) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return "talos-burp" in raw
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def _mark(up: bool) -> None:
    global _available, _checked_at
    _available = up
    _checked_at = time.monotonic()
