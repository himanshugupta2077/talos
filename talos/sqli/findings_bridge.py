"""
Module: talos.sqli.findings_bridge

Purpose:
    Create TRIAGING findings when a SQLi job settles with SQLI.

    Clustering: SQLI:<endpoint_id> so every successful technique on the
    same endpoint lands under one PRIMARY (later techniques LINKED).

Dependencies: findings.creator / model / db
Data flow: scheduler settle / CLI --right-now → maybe_create_sqli_finding
Side effects: findings + evidence + timeline on SQLI.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import talos.findings.db as findings_db
from talos.findings.creator import create_finding_from_verdict
from talos.findings.model import ATTACK_DISPLAY
from talos.sqli.models import ATTACK_MODULE, VERDICT_SQLI, SqliOutcome

_log = logging.getLogger(__name__)


def build_finding_title(
    *,
    technique: str,
    method: Optional[str],
    path: Optional[str],
    param_name: str,
    is_primary: bool,
) -> str:
    """
    Purpose:
        PRIMARY uses an endpoint-level title; LINKED names the point + technique.
    """
    label = ATTACK_DISPLAY.get(ATTACK_MODULE, "SQL Injection")
    m = (method or "?").strip() or "?"
    p = (path or "?").strip() or "?"
    if is_primary:
        return f"{label} — {m} {p}"
    point = param_name or "input"
    return f"{label} — {technique} on {point} ({m} {p})"


def maybe_create_sqli_finding(
    *,
    db_path: Path,
    project_id: str,
    outcome: SqliOutcome,
    job_id: Optional[str] = None,
) -> Optional[str]:
    """
    Purpose:
        Create a finding when the probe confirmed SQL injection.
    Output:
        Finding UUID or None (non-trigger / error).
    """
    if outcome.verdict != VERDICT_SQLI:
        return None
    if not outcome.replayed_flow_id:
        _log.debug("[sqli] skip finding: SQLI without replay_flow_id")
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
        "dbms": outcome.dbms,
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
            attack_type="sqli_attack",
            variant=outcome.technique,
            title=title,
            host=outcome.host,
            result_evidence_data=result_data,
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning("[findings] sqli finding creation error (non-fatal): %s", exc)
        return None
    return finding_id
