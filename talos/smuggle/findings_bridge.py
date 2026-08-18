"""
Module: talos.smuggle.findings_bridge

Purpose:
    Create TRIAGING findings when a smuggle job settles with SMUGGLE.

    Clustering: SMUGGLE:<scheme://netloc> so every confirmed technique
    on the same origin lands under one PRIMARY (later techniques LINKED).

Dependencies: findings.creator / model / db
Data flow: scheduler settle / CLI --right-now → maybe_create_smuggle_finding
Side effects: findings + evidence + timeline on SMUGGLE.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import talos.findings.db as findings_db
from talos.findings.creator import create_finding_from_verdict
from talos.findings.model import ATTACK_DISPLAY
from talos.smuggle.models import ATTACK_MODULE, VERDICT_SMUGGLE, SmuggleOutcome

_log = logging.getLogger(__name__)


def build_finding_title(
    *,
    technique: str,
    method: Optional[str],
    path: Optional[str],
    host: str,
    is_primary: bool,
) -> str:
    """
    Purpose:
        PRIMARY uses a host-level title; LINKED names the technique + route.
    """
    label = ATTACK_DISPLAY.get(ATTACK_MODULE, "HTTP Request Smuggling")
    if is_primary:
        return f"{label} — desync on {host}"
    m = (method or "?").strip() or "?"
    p = (path or "?").strip() or "?"
    return f"{label} — {technique} on {m} {p}"


def maybe_create_smuggle_finding(
    *,
    db_path: Path,
    project_id: str,
    outcome: SmuggleOutcome,
    job_id: Optional[str] = None,
) -> Optional[str]:
    """
    Purpose:
        Create a finding when the probe confirmed a request desync.
    Output:
        Finding UUID or None (non-trigger / error).
    """
    if outcome.verdict != VERDICT_SMUGGLE:
        return None
    if not outcome.replayed_flow_id:
        _log.debug("[smuggle] skip finding: SMUGGLE without replay_flow_id")
        return None

    cluster_key = findings_db.build_cluster_key(
        ATTACK_MODULE,
        outcome.endpoint_id,
        host=outcome.host,
    )
    existing = (
        findings_db.get_primary_by_cluster(db_path, cluster_key)
        if cluster_key
        else None
    )
    title = build_finding_title(
        technique=outcome.technique,
        method=outcome.method,
        path=outcome.path,
        host=outcome.host or "unknown",
        is_primary=existing is None,
    )

    result_data = {
        "technique": outcome.technique,
        "technique_family": outcome.technique_family,
        "canary_path": outcome.canary_path,
        "desync_signal": outcome.desync_signal,
        "evidence": outcome.evidence,
        "ntlm_used": outcome.ntlm_used,
        "baseline_status": outcome.baseline_status,
        "followup_status": outcome.followup_status,
        "risk_hint": outcome.risk_hint,
        "host": outcome.host,
    }

    try:
        finding_id = create_finding_from_verdict(
            db_path=db_path,
            project_id=project_id,
            attack_module=ATTACK_MODULE,
            verdict=outcome.verdict,
            endpoint_id=outcome.endpoint_id,
            original_flow_id=outcome.original_flow_id,
            replayed_flow_id=outcome.replayed_flow_id,
            job_id=job_id,
            attack_type="smuggle_attack",
            variant=outcome.technique,
            title=title,
            host=outcome.host,
            result_evidence_data=result_data,
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning("[findings] smuggle finding creation error (non-fatal): %s", exc)
        return None
    return finding_id
