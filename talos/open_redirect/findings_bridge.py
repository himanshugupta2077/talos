"""
Module: talos.open_redirect.findings_bridge

Purpose:
    Create TRIAGING findings when an open-redirect job settles with
    OPEN_REDIRECT. Cluster OPEN_REDIRECT:<endpoint_id>.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import talos.findings.db as findings_db
from talos.findings.creator import create_finding_from_verdict
from talos.findings.model import ATTACK_DISPLAY
from talos.open_redirect.models import (
    ATTACK_MODULE,
    VERDICT_OPEN_REDIRECT,
    OpenRedirectOutcome,
)

_log = logging.getLogger(__name__)


def build_finding_title(
    *,
    technique: str,
    method: Optional[str],
    path: Optional[str],
    param_name: str,
    is_primary: bool,
) -> str:
    """Purpose: PRIMARY is endpoint-level; LINKED names the point + technique."""
    label = ATTACK_DISPLAY.get(ATTACK_MODULE, "Open Redirect")
    m = (method or "?").strip() or "?"
    p = (path or "?").strip() or "?"
    if is_primary:
        return f"{label} — {m} {p}"
    point = param_name or "input"
    return f"{label} — {technique} on {point} ({m} {p})"


def maybe_create_open_redirect_finding(
    *,
    db_path: Path,
    project_id: str,
    outcome: OpenRedirectOutcome,
    job_id: Optional[str] = None,
) -> Optional[str]:
    """Purpose: Create a finding when the probe confirmed an open redirect."""
    if outcome.verdict != VERDICT_OPEN_REDIRECT:
        return None
    if not outcome.replayed_flow_id:
        _log.debug("[open_redirect] skip finding: OPEN_REDIRECT without replay_flow_id")
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
        param_name=outcome.param_name,
        is_primary=existing is None,
    )

    result_data = {
        "technique": outcome.technique,
        "technique_family": outcome.technique_family,
        "location": outcome.location,
        "param_name": outcome.param_name,
        "payload_sent": outcome.payload_sent,
        "redirect_url": outcome.redirect_url,
        "evidence": outcome.evidence,
        "risk_hint": outcome.risk_hint,
        "elapsed_ms": outcome.elapsed_ms,
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
            attack_type="open_redirect_attack",
            variant=outcome.technique,
            title=title,
            host=outcome.host,
            result_evidence_data=result_data,
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning(
            "[findings] open-redirect finding creation error (non-fatal): %s",
            exc,
        )
        return None
    return finding_id
