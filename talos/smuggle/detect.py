"""
Module: talos.smuggle.detect

Purpose:
    Decide SMUGGLE / SECURE from a baseline, probe, and follow-up.

    Confirmed only when the follow-up is clearly poisoned (status flip
    to 400/404/405, canary echo, or an extra queued response). A probe
    timeout alone is not a finding.

Dependencies: talos.smuggle.models
Data flow: engine → analyze_smuggle_exchange
Side effects: None.
"""

from __future__ import annotations

from typing import Optional

from talos.smuggle.models import VERDICT_SECURE, VERDICT_SMUGGLE


_POISON_STATUSES = frozenset({400, 404, 405})


def _as_text(body: object) -> str:
    """Purpose: Decode a response body for canary search."""
    if body is None:
        return ""
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def _headers_text(headers: object) -> str:
    """Purpose: Flatten header pairs/maps for canary search."""
    if not headers:
        return ""
    if isinstance(headers, dict):
        return " ".join(f"{k} {v}" for k, v in headers.items())
    if isinstance(headers, (list, tuple)):
        parts: list[str] = []
        for item in headers:
            if isinstance(item, (list, tuple)) and len(item) >= 2:
                parts.append(f"{item[0]} {item[1]}")
            else:
                parts.append(str(item))
        return " ".join(parts)
    return str(headers)


def analyze_smuggle_exchange(
    *,
    canary_path: str,
    baseline_status: Optional[int],
    probe_status: Optional[int],
    followup_status: Optional[int],
    followup_body: object = None,
    followup_headers: object = None,
    probe_timed_out: bool = False,
    extra_response: bool = False,
) -> tuple[str, str, str, str]:
    """
    Purpose:
        Classify one probe + follow-up exchange.
    Output:
        (verdict, desync_signal, evidence, risk_hint)
    """
    canary = (canary_path or "").strip()
    blob = _as_text(followup_body) + " " + _headers_text(followup_headers)
    canary_hit = bool(canary) and canary in blob

    if extra_response:
        return (
            VERDICT_SMUGGLE,
            "extra_response",
            "An extra HTTP response was waiting after the follow-up "
            "(front-end and back-end consumed different request counts).",
            "desync",
        )

    if canary_hit:
        return (
            VERDICT_SMUGGLE,
            "canary_reflected",
            f"Follow-up response mentioned canary path {canary}.",
            "canary",
        )

    if (
        followup_status in _POISON_STATUSES
        and baseline_status is not None
        and followup_status != baseline_status
    ):
        hint = "timeout+poison" if probe_timed_out else "poisoned_followup"
        return (
            VERDICT_SMUGGLE,
            hint,
            (
                f"Follow-up status {followup_status} differs from baseline "
                f"{baseline_status} (probe_status={probe_status})."
            ),
            "desync",
        )

    return VERDICT_SECURE, "", "", ""
