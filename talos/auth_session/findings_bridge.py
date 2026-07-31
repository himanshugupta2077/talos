"""
Module: talos.auth_session.findings_bridge

Purpose:
    Create TRIAGING findings for Authentication & Session Testing when a
    job settles with ``WEAK_VALIDATION`` (KD16 — settle / right-now only;
    never called from deep inside the mutation engine).

    Title formula (Appendix B):
        "{ATTACK_DISPLAY} — {test_id} on {METHOD} {path}"

    Cluster: AUTH_SESSION:<endpoint_id>:<auth_type> via
    create_finding_from_verdict(..., auth_type=..., title=...).

    risk_hint lives in evidence/notes only — findings table has no severity
    column (resolved open question).

Dependencies: findings.creator / model; replay_db for baseline method/path
Data flow:
    scheduler._maybe_create_finding_auth_session
        → maybe_create_auth_session_finding
        → create_finding_from_verdict
    CLI --right-now may call the same helper after success
Side effects: Writes findings + evidence + timeline on WEAK_VALIDATION.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import talos.replay.db as replay_db
from talos.auth_session.models import VERDICT_WEAK_VALIDATION
from talos.findings.creator import create_finding_from_verdict
from talos.findings.model import ATTACK_DISPLAY

_log = logging.getLogger(__name__)

ATTACK_MODULE = "auth_session"


def build_finding_title(
    *,
    test_id: str,
    method: Optional[str],
    path: Optional[str],
) -> str:
    """
    Purpose:
        Deterministic finding title (Appendix B).
    Output:
        e.g. ``Authentication & Session Testing — jwt.alg_none on GET /api/me``
    """
    label = ATTACK_DISPLAY.get(ATTACK_MODULE, "Authentication & Session Testing")
    m = (method or "?").strip() or "?"
    p = (path or "?").strip() or "?"
    return f"{label} — {test_id} on {m} {p}"


def maybe_create_auth_session_finding(
    *,
    db_path: Path,
    project_id: str,
    verdict: str,
    endpoint_id: Optional[str],
    original_flow_id: Optional[str],
    replayed_flow_id: Optional[str],
    test_id: str,
    auth_type: str,
    job_id: Optional[str] = None,
    diff_verdict: Optional[str] = None,
    risk_hint: Optional[str] = None,
    mutation_summary: Optional[str] = None,
    candidate_id: Optional[str] = None,
    binding_id: Optional[str] = None,
) -> Optional[str]:
    """
    Purpose:
        Create a finding when verdict is WEAK_VALIDATION; no-op otherwise.
    Input:
        Standard settle context + test_id / auth_type for title and cluster.
        risk_hint / mutation_summary are stored via variant + creator evidence;
        extra notes are not written here (evidence branch owns result row).
    Output:
        Finding UUID or None (non-trigger / error).
    Side effects:
        Findings DB writes on trigger; errors logged non-fatally.
    """
    if verdict != VERDICT_WEAK_VALIDATION:
        return None
    if not replayed_flow_id:
        _log.debug(
            "[auth_session] skip finding: WEAK_VALIDATION without replay_flow_id"
        )
        return None

    method: Optional[str] = None
    path: Optional[str] = None
    if original_flow_id:
        try:
            flow = replay_db.get_flow_for_replay(db_path, original_flow_id)
            if flow:
                method = flow.get("method")
                path = flow.get("path") or flow.get("url")
        except Exception as exc:  # noqa: BLE001
            _log.debug("[auth_session] baseline flow lookup for title: %s", exc)

    title = build_finding_title(test_id=test_id, method=method, path=path)

    # Pack operator-facing context into variant for timeline; title is separate.
    variant = test_id
    extra_notes_bits: list[str] = []
    if risk_hint:
        extra_notes_bits.append(f"risk_hint={risk_hint}")
    if mutation_summary:
        extra_notes_bits.append(f"mutation={mutation_summary}")
    if candidate_id:
        extra_notes_bits.append(f"candidate={candidate_id[:8]}")
    if binding_id:
        extra_notes_bits.append(f"binding={binding_id[:8]}")

    try:
        finding_id = create_finding_from_verdict(
            db_path=db_path,
            project_id=project_id,
            attack_module=ATTACK_MODULE,
            verdict=verdict,
            endpoint_id=endpoint_id,
            original_flow_id=original_flow_id,
            replayed_flow_id=replayed_flow_id,
            job_id=job_id,
            attack_type="auth_session_attack",
            variant=variant,
            diff_verdict=diff_verdict,
            title=title,
            auth_type=auth_type,
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "[findings] auth_session finding creation error (non-fatal): %s", exc
        )
        return None

    if finding_id and extra_notes_bits:
        # Append risk_hint / mutation context as a free-form note (no severity col).
        try:
            import talos.findings.db as findings_db
            from talos.findings.model import (
                EVIDENCE_TYPE_ANALYST_NOTE,
                TIMELINE_ACTOR_SYSTEM,
            )

            findings_db.add_evidence(
                db_path=db_path,
                finding_id=finding_id,
                evidence_type=EVIDENCE_TYPE_ANALYST_NOTE,
                reference_id=None,
                label="auth_session context",
                data={
                    "text": "; ".join(extra_notes_bits),
                    "risk_hint": risk_hint,
                    "mutation_summary": mutation_summary,
                    "test_id": test_id,
                    "auth_type": auth_type,
                },
            )
            findings_db.add_timeline_event(
                db_path=db_path,
                finding_id=finding_id,
                event=(
                    f"Auth-session context attached: {'; '.join(extra_notes_bits)}"
                ),
                actor=TIMELINE_ACTOR_SYSTEM,
            )
        except Exception as exc:  # noqa: BLE001
            _log.debug("[auth_session] context evidence attach failed: %s", exc)

    return finding_id
