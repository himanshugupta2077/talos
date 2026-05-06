"""
Module: talos.replay.diff

Purpose:
    Compare an original captured flow against its replay and produce a
    structured diff result with a single verdict.

    This is the core signal for every future attack module.  Without a
    reliable diff, replay results are uninterpretable.

Design rules:
    - Pure function.  No DB access, no I/O.
    - Deterministic.  Same inputs always produce the same verdict.
    - Minimal.  Only the three fields the caller needs are stored.

Verdict rules (evaluated in order — first match wins):
    1. ERROR      — replay has a replay_error value (network/protocol failure).
    2. DIFFERENT  — status code changed between original and replay.
    3. DIFFERENT  — response body length delta exceeds threshold.
    4. DIFFERENT  — both bodies are JSON and top-level key sets differ.
    5. SAME       — none of the above triggered.

Thresholds:
    _LARGE_BODY_DELTA_ABS  — 500 bytes absolute change triggers DIFFERENT.
    _LARGE_BODY_DELTA_REL  — 0.20 (20%) relative change triggers DIFFERENT
                              when original body is non-empty.

Dependencies: json (stdlib only)
Data flow:
    engine._execute_replay → compute_diff(original_flow, replayed_flow) → DiffResult
Side effects: None.
"""

import json
from dataclasses import dataclass
from typing import Optional


# Threshold for "large body delta" branch.
# Absolute: either side changes by more than 500 bytes → DIFFERENT.
# Relative: change exceeds 20% of the original size → DIFFERENT.
_LARGE_BODY_DELTA_ABS = 500
_LARGE_BODY_DELTA_REL = 0.20


# ------------------------------------------------------------------ #
# Public result type                                                   #
# ------------------------------------------------------------------ #

@dataclass
class DiffResult:
    """
    Purpose:
        Carries the outcome of comparing one original flow against one replay.

    Fields:
        verdict        — SAME | DIFFERENT | ERROR.
        status_changed — True when status code differed.
        status_diff    — Human-readable change string (e.g. "200→403"), or None
                         when the status did not change or was absent.
        length_diff    — Signed delta: replay_body_len - original_body_len.
                         0 when neither body exists.
    """
    verdict: str
    status_changed: bool
    status_diff: Optional[str]
    length_diff: int


# ------------------------------------------------------------------ #
# Public entry point                                                   #
# ------------------------------------------------------------------ #

def compute_diff(original_flow: dict, replayed_flow: dict) -> DiffResult:
    """
    Purpose:
        Produce a DiffResult by comparing a captured flow with its replay.
    Input:
        original_flow  — flow dict as returned by replay_db.get_flow_for_replay.
                         Must include: status_code, response_body, content_type.
                         Missing fields are treated as None / empty.
        replayed_flow  — the in-memory replay dict built by _execute_replay
                         before insert_replayed_flow is called.
                         Must include: replay_error, status_code, response_body,
                         content_type.
    Output:
        DiffResult with verdict, status_changed, status_diff, length_diff.
    Side effects: None.
    """
    # Rule 1: ERROR — network or protocol failure prevented a response.
    if replayed_flow.get("replay_error"):
        return DiffResult(
            verdict="ERROR",
            status_changed=False,
            status_diff=None,
            length_diff=0,
        )

    orig_status: Optional[int] = original_flow.get("status_code")
    replay_status: Optional[int] = replayed_flow.get("status_code")

    # Rule 2: status code changed.
    status_changed = orig_status != replay_status
    status_diff: Optional[str] = (
        f"{orig_status}\u2192{replay_status}" if status_changed else None
    )

    # Normalise response bodies to bytes for length comparison.
    orig_body = _to_bytes(original_flow.get("response_body"))
    replay_body = _to_bytes(replayed_flow.get("response_body"))

    length_diff = len(replay_body) - len(orig_body)

    if status_changed:
        return DiffResult(
            verdict="DIFFERENT",
            status_changed=True,
            status_diff=status_diff,
            length_diff=length_diff,
        )

    # Rule 3: large body delta.
    if _is_large_delta(len(orig_body), length_diff):
        return DiffResult(
            verdict="DIFFERENT",
            status_changed=False,
            status_diff=None,
            length_diff=length_diff,
        )

    # Rule 4: JSON structure change (top-level key sets differ).
    orig_ct = original_flow.get("content_type") or ""
    replay_ct = replayed_flow.get("content_type") or ""
    if "json" in orig_ct and "json" in replay_ct:
        if _json_keys_differ(orig_body, replay_body):
            return DiffResult(
                verdict="DIFFERENT",
                status_changed=False,
                status_diff=None,
                length_diff=length_diff,
            )

    # Rule 5: no signal detected.
    return DiffResult(
        verdict="SAME",
        status_changed=False,
        status_diff=None,
        length_diff=length_diff,
    )


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _to_bytes(value: object) -> bytes:
    """
    Purpose: Normalise DB/httpx body values to bytes for size comparison.
    Input:   value — bytes, str, or None.
    Output:  bytes; empty bytes when value is None.
    Side effects: None.
    """
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    # Fallback: encode string representations.
    return str(value).encode("utf-8", errors="replace")


def _is_large_delta(orig_len: int, delta: int) -> bool:
    """
    Purpose:
        Return True when the absolute or relative body length change exceeds
        the configured thresholds.
    Input:
        orig_len — byte length of the original response body.
        delta    — signed difference (replay_len - orig_len).
    Output: bool.
    Side effects: None.
    """
    abs_delta = abs(delta)
    if abs_delta > _LARGE_BODY_DELTA_ABS:
        return True
    if orig_len > 0 and (abs_delta / orig_len) > _LARGE_BODY_DELTA_REL:
        return True
    return False


def _json_keys_differ(orig_body: bytes, replay_body: bytes) -> bool:
    """
    Purpose:
        Compare the top-level key sets of two JSON bodies.
        Returns True when the key sets differ, indicating a structural change.
        Returns False on any parse failure — structure comparison is best-effort.
    Input:
        orig_body   — bytes for the original response body.
        replay_body — bytes for the replay response body.
    Output: bool. False on non-dict JSON or parse error.
    Side effects: None.
    """
    try:
        orig_obj = json.loads(orig_body)
        replay_obj = json.loads(replay_body)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        # Bodies are not valid JSON or could not be decoded — skip structure check.
        return False

    # Only compare dict top-level key sets; arrays and scalars are not compared.
    if not isinstance(orig_obj, dict) or not isinstance(replay_obj, dict):
        return False

    return set(orig_obj.keys()) != set(replay_obj.keys())
