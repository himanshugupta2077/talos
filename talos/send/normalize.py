"""
Module: talos.send.normalize

Purpose:
    Request normalizers applied after draft edits and before send.

    Phase 1 normalizers:
        content_length — ensure Content-Length matches body as sent (Burp default).

    Policy:
        • Default (update_content_length=True): strip any stale Content-Length,
          then set Content-Length to the body byte length when a body is present;
          remove Content-Length when body is absent/empty.
        • update_content_length=False: leave headers untouched (edge / smuggling
          tests). Transfer-Encoding is never silently stripped.

Dependencies: typing
Data flow:
    draft fields → apply_content_length → headers + normalizers list
Side effects: None (returns new structures; does not mutate inputs in place
              when caller passes copies — we mutate the provided headers dict
              for efficiency and document that).
"""

from __future__ import annotations

from typing import Optional


def apply_content_length(
    headers: dict[str, str],
    body: Optional[bytes],
    *,
    enabled: bool = True,
) -> list[str]:
    """
    Purpose:
        Apply the Content-Length normalizer when enabled.
    Input:
        headers — request header map (mutated in place when enabled).
        body    — request body bytes or None.
        enabled — when False, no-op and returns [].
    Output:
        List of normalizer names that ran (e.g. ["content_length"]).
    Side effects:
        May delete/set Content-Length on headers when enabled.
    """
    if not enabled:
        return []

    # Drop any existing Content-Length (any casing).
    keys_to_drop = [k for k in headers if k.lower() == "content-length"]
    for key in keys_to_drop:
        del headers[key]

    body_bytes = body if body is not None else b""
    if body_bytes:
        # Canonical casing used by most clients.
        headers["Content-Length"] = str(len(body_bytes))
    # No body → leave CL absent (correct for GET/HEAD-like requests).

    return ["content_length"]


def strip_content_length(headers: dict[str, str]) -> dict[str, str]:
    """
    Purpose:
        Return a copy of headers without Content-Length (any casing).
        Useful when letting httpx set CL while preserving other headers.
    Input:
        headers — source header map.
    Output:
        New dict without Content-Length keys.
    Side effects: None.
    """
    return {k: v for k, v in headers.items() if k.lower() != "content-length"}
