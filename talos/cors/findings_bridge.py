"""
Module: talos.cors.findings_bridge

Purpose:
    Create TRIAGING findings when a CORS job settles with CORS_MISCONFIG.

    Clustering: CORS:<scheme://netloc> so every successful technique on the
    same target origin lands under one PRIMARY (later techniques LINKED).

    ACAC:true / wildcard flags are stored on cors_result evidence — they
    do not create a second finding.

Dependencies: findings.creator / model / db
Data flow: scheduler settle / CLI --right-now → maybe_create_cors_finding
Side effects: findings + evidence + timeline on CORS_MISCONFIG.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import talos.findings.db as findings_db
from talos.cors.models import (
    ATTACK_MODULE,
    VERDICT_CORS_MISCONFIG,
    CorsOutcome,
)
from talos.findings.creator import create_finding_from_verdict
from talos.findings.model import ATTACK_DISPLAY

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
    label = ATTACK_DISPLAY.get(ATTACK_MODULE, "CORS Misconfiguration")
    if is_primary:
        return f"{label} — reflected attacker origin on {host}"
    m = (method or "?").strip() or "?"
    p = (path or "?").strip() or "?"
    return f"{label} — {technique} on {m} {p}"


def maybe_create_cors_finding(
    *,
    db_path: Path,
    project_id: str,
    outcome: CorsOutcome,
    job_id: Optional[str] = None,
    method: Optional[str] = None,
    path: Optional[str] = None,
) -> Optional[str]:
    """
    Purpose:
        Create a finding when the probe reflected an attacker origin.
    Output:
        Finding UUID or None (non-trigger / error).
    Side effects:
        Findings writes on CORS_MISCONFIG; errors logged non-fatally.
    """
    if outcome.verdict != VERDICT_CORS_MISCONFIG:
        return None
    if not outcome.replayed_flow_id:
        _log.debug("[cors] skip finding: CORS_MISCONFIG without replay_flow_id")
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
        method=method,
        path=path,
        host=outcome.host or "unknown",
        is_primary=existing is None,
    )

    result_data = {
        "technique": outcome.technique,
        "technique_family": outcome.technique_family,
        "origin_sent": outcome.origin_sent,
        "acao": outcome.acao,
        "acac": outcome.acac,
        "reflected": outcome.reflected,
        "credentials": outcome.credentials,
        "wildcard": outcome.wildcard,
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
            attack_type="cors_attack",
            variant=outcome.technique,
            title=title,
            host=outcome.host,
            result_evidence_data=result_data,
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning("[findings] cors finding creation error (non-fatal): %s", exc)
        return None
    return finding_id
