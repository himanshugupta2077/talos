"""
Module: talos.intruder.findings_bridge

Purpose:
    Optional Phase 5 bridge from Intruder match/interesting results to the
    Findings subsystem. **Off by default** — operators opt in via
    ``findings.promote`` / ``talos intruder findings set --promote on``.

    Design goals:
        - Never spam: hard ``max_findings`` per session (default 25)
        - Idempotent: skip rows that already have ``finding_id``
        - Cluster: PRIMARY + LINKED under INTRUDER:<session_id>
          (or INTRUDER:<endpoint_id> when cluster_by=endpoint)
        - Fail-soft: promote errors are logged; engine continues

Dependencies:
    logging, pathlib
    talos.findings.db, talos.findings.model
    talos.intruder.models
Data flow:
    engine (online) / CLI findings promote (offline)
        → promote_result / promote_session_results
        → findings tables + intruder_results.finding_id
Side effects:
    Writes findings / evidence / timeline; updates result finding_id.
    Never raises into the engine loop (callers use maybe_* wrappers).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import talos.findings.db as findings_db
from talos.findings.model import (
    ATTACK_DISPLAY,
    EVIDENCE_TYPE_ENDPOINT,
    EVIDENCE_TYPE_INTRUDER_RESULT,
    EVIDENCE_TYPE_MODULE,
    EVIDENCE_TYPE_ORIGINAL_FLOW,
    EVIDENCE_TYPE_REPLAY_FLOW,
    EVIDENCE_TYPE_ROLE,
    TIMELINE_ACTOR_SYSTEM,
)
from talos.intruder import db as intruder_db
from talos.intruder.models import (
    ATTACK_TYPE_INTRUDER,
    CLUSTER_BY_ENDPOINT,
    CLUSTER_BY_SESSION,
    DEFAULT_FINDINGS_MAX,
    DEFAULT_FINDINGS_ONLY_SUCCESS,
    DEFAULT_FINDINGS_PROMOTE,
    FINDINGS_ON_INTERESTING,
    FINDINGS_ON_MATCHED,
    VERDICT_INTRUDER_MATCH,
)

_log = logging.getLogger(__name__)


def findings_config_from(cfg: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize findings block with Phase 5 defaults.

    Output keys: promote, on, max_findings, only_success, cluster_by.
    """
    block = dict(cfg.get("findings") or {})
    promote = block.get("promote", DEFAULT_FINDINGS_PROMOTE)
    if isinstance(promote, str):
        promote = promote.strip().lower() in ("1", "true", "yes", "on")
    else:
        promote = bool(promote)
    on = str(block.get("on") or FINDINGS_ON_INTERESTING).strip().lower()
    if on == FINDINGS_ON_MATCHED:
        on = FINDINGS_ON_INTERESTING
    try:
        max_findings = int(block.get("max_findings", DEFAULT_FINDINGS_MAX))
    except (TypeError, ValueError):
        max_findings = DEFAULT_FINDINGS_MAX
    only_success = block.get("only_success", DEFAULT_FINDINGS_ONLY_SUCCESS)
    if isinstance(only_success, str):
        only_success = only_success.strip().lower() in ("1", "true", "yes", "on")
    else:
        only_success = bool(only_success)
    cluster_by = str(block.get("cluster_by") or CLUSTER_BY_SESSION).strip().lower()
    return {
        "promote": promote,
        "on": on,
        "max_findings": max(0, max_findings),
        "only_success": only_success,
        "cluster_by": cluster_by,
    }


def build_intruder_cluster_key(
    *,
    session_id: str,
    endpoint_id: Optional[str] = None,
    cluster_by: str = CLUSTER_BY_SESSION,
) -> str:
    """
    Cluster identity for Intruder-promoted findings.

    session  → INTRUDER:<session_id>
    endpoint → INTRUDER:<endpoint_id> (falls back to session when missing)
    """
    mode = (cluster_by or CLUSTER_BY_SESSION).strip().lower()
    if mode == CLUSTER_BY_ENDPOINT and endpoint_id:
        return f"INTRUDER:{endpoint_id}"
    return f"INTRUDER:{session_id}"


def _title_for_result(
    *,
    session_name: str,
    attempt_index: int,
    match_tags: list[str],
    status_code: Optional[int],
) -> str:
    label = ATTACK_DISPLAY.get(ATTACK_TYPE_INTRUDER, "Intruder Match")
    tags = ", ".join(match_tags[:4]) if match_tags else "interesting"
    sc = status_code if status_code is not None else "?"
    name = (session_name or "").strip() or "session"
    return f"{label} — {name} #{attempt_index} ({sc}; {tags})"


def result_eligible(
    result: dict[str, Any],
    fcfg: dict[str, Any],
) -> bool:
    """
    Whether a result row should be considered for promotion under fcfg.
    Does not check max_findings or existing finding_id.
    """
    if result.get("finding_id"):
        return False
    if fcfg.get("only_success", True) and not result.get("success"):
        return False
    on = fcfg.get("on") or FINDINGS_ON_INTERESTING
    if on in (FINDINGS_ON_INTERESTING, FINDINGS_ON_MATCHED):
        if result.get("interesting"):
            return True
        tags = result.get("match_tags") or []
        return bool(tags)
    return False


def promote_result(
    db_path: Path,
    project_id: str,
    session: dict[str, Any],
    result: dict[str, Any],
    *,
    fcfg: Optional[dict[str, Any]] = None,
    job_id: Optional[str] = None,
) -> Optional[str]:
    """
    Create one finding from an Intruder result row and link finding_id.

    Input:
        session — session dict (id, name, endpoint_id, base_flow_id, …)
        result  — result dict (attempt_index, match_tags, flow_id, …)
    Output:
        finding UUID if created; None if skipped or on error.
    Side effects:
        findings + evidence + timeline; UPDATE intruder_results.finding_id.
    """
    cfg = fcfg or findings_config_from(session.get("config") or {})
    if not cfg.get("promote"):
        return None
    if not result_eligible(result, cfg):
        return None

    session_id = session["id"]
    endpoint_id = session.get("endpoint_id")
    attempt_index = int(result["attempt_index"])
    match_tags = list(result.get("match_tags") or [])
    status_code = result.get("status_code")
    flow_id = result.get("flow_id")
    result_row_id = result.get("id")

    cluster_key = build_intruder_cluster_key(
        session_id=session_id,
        endpoint_id=endpoint_id,
        cluster_by=str(cfg.get("cluster_by") or CLUSTER_BY_SESSION),
    )
    title = _title_for_result(
        session_name=str(session.get("name") or ""),
        attempt_index=attempt_index,
        match_tags=match_tags,
        status_code=status_code,
    )

    try:
        finding_id = findings_db.create_finding(
            db_path=db_path,
            project_id=project_id,
            attack_type=ATTACK_TYPE_INTRUDER,
            verdict=VERDICT_INTRUDER_MATCH,
            endpoint_id=endpoint_id,
            title=title,
            cluster_key=cluster_key,
        )
    except Exception as exc:  # noqa: BLE001
        _log.error("[intruder.findings] create_finding failed: %s", exc)
        return None

    base_flow_id = session.get("base_flow_id")
    try:
        if base_flow_id:
            findings_db.add_evidence(
                db_path,
                finding_id,
                EVIDENCE_TYPE_ORIGINAL_FLOW,
                base_flow_id,
                "Baseline flow (Intruder template source)",
            )
        if flow_id:
            findings_db.add_evidence(
                db_path,
                finding_id,
                EVIDENCE_TYPE_REPLAY_FLOW,
                flow_id,
                f"Intruder attempt flow #{attempt_index}",
            )
        if endpoint_id:
            findings_db.add_evidence(
                db_path,
                finding_id,
                EVIDENCE_TYPE_ENDPOINT,
                endpoint_id,
                "Target endpoint",
            )
        findings_db.add_evidence(
            db_path,
            finding_id,
            EVIDENCE_TYPE_INTRUDER_RESULT,
            result_row_id,
            f"Intruder result attempt_index={attempt_index}",
            data={
                "session_id": session_id,
                "attempt_index": attempt_index,
                "variables": result.get("variables") or {},
                "match_tags": match_tags,
                "status_code": status_code,
                "body_length": result.get("body_length"),
                "duration_ms": result.get("duration_ms"),
                "body_hash": result.get("body_hash"),
                "grepped": result.get("grepped") or {},
                "job_id": job_id,
            },
        )
        # Role / module from baseline when present
        if base_flow_id:
            flow = intruder_db.load_flow(db_path, base_flow_id)
            if flow:
                if flow.get("role_id"):
                    findings_db.add_evidence(
                        db_path,
                        finding_id,
                        EVIDENCE_TYPE_ROLE,
                        flow["role_id"],
                        "Baseline role",
                    )
                if flow.get("module_id"):
                    findings_db.add_evidence(
                        db_path,
                        finding_id,
                        EVIDENCE_TYPE_MODULE,
                        flow["module_id"],
                        "Baseline module",
                    )
        findings_db.add_timeline_event(
            db_path=db_path,
            finding_id=finding_id,
            event=(
                f"Intruder match promoted (session={session_id[:8]}… "
                f"attempt={attempt_index}, tags={match_tags or ['interesting']})"
            ),
            actor=TIMELINE_ACTOR_SYSTEM,
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning("[intruder.findings] evidence attach failed: %s", exc)

    try:
        if result_row_id:
            intruder_db.set_result_finding_id(
                db_path, result_row_id, finding_id
            )
        else:
            intruder_db.set_result_finding_id_by_attempt(
                db_path, session_id, attempt_index, finding_id
            )
    except Exception as exc:  # noqa: BLE001
        _log.warning("[intruder.findings] link finding_id failed: %s", exc)

    try:
        from talos.burp.snapshot import record_finding

        record_finding(
            project_id=project_id,
            finding_id=finding_id,
            db_path=db_path,
            attack_type=ATTACK_TYPE_INTRUDER,
            title=title,
            flow_id=str(flow_id or base_flow_id or ""),
        )
    except Exception:  # noqa: BLE001
        _log.debug("[intruder.findings] burp snapshot skipped", exc_info=True)

    return finding_id


def maybe_promote_result(
    db_path: Path,
    project_id: str,
    session: dict[str, Any],
    result: dict[str, Any],
    *,
    fcfg: dict[str, Any],
    findings_promoted: int,
    job_id: Optional[str] = None,
) -> tuple[Optional[str], int]:
    """
    Engine helper: promote if enabled, under cap, eligible.

    Returns (finding_id_or_None, updated_findings_promoted_count).
    Never raises.
    """
    if not fcfg.get("promote"):
        return None, findings_promoted
    max_n = int(fcfg.get("max_findings") or 0)
    if max_n <= 0 or findings_promoted >= max_n:
        return None, findings_promoted
    if not result_eligible(result, fcfg):
        return None, findings_promoted
    try:
        fid = promote_result(
            db_path,
            project_id,
            session,
            result,
            fcfg=fcfg,
            job_id=job_id,
        )
    except Exception as exc:  # noqa: BLE001
        _log.error("[intruder.findings] promote failed: %s", exc)
        return None, findings_promoted
    if fid:
        return fid, findings_promoted + 1
    return None, findings_promoted


def promote_session_results(
    db_path: Path,
    project_id: str,
    session: dict[str, Any],
    *,
    fcfg: Optional[dict[str, Any]] = None,
    force_enable: bool = False,
) -> dict[str, Any]:
    """
    Offline promote for existing interesting results without finding_id.

    force_enable: treat promote as on for this call (CLI ``findings promote``).
    """
    cfg = findings_config_from(session.get("config") or {})
    if fcfg:
        cfg = {**cfg, **fcfg}
    if force_enable:
        cfg["promote"] = True
    if not cfg.get("promote"):
        return {
            "promoted": 0,
            "skipped": 0,
            "capped": False,
            "finding_ids": [],
            "reason": "promote_disabled",
        }

    max_n = int(cfg.get("max_findings") or DEFAULT_FINDINGS_MAX)
    already = intruder_db.count_results_with_findings(db_path, session["id"])
    remaining = max(0, max_n - already)
    if remaining <= 0:
        return {
            "promoted": 0,
            "skipped": 0,
            "capped": True,
            "finding_ids": [],
            "reason": "max_findings",
            "already": already,
            "max_findings": max_n,
        }

    # Walk interesting results without finding_id
    candidates = intruder_db.list_results(
        db_path,
        session["id"],
        interesting_only=True,
        limit=10_000,
        unpromoted_only=True,
    )
    promoted_ids: list[str] = []
    skipped = 0
    for row in candidates:
        if len(promoted_ids) >= remaining:
            break
        if not result_eligible(row, cfg):
            skipped += 1
            continue
        fid = promote_result(
            db_path,
            project_id,
            session,
            row,
            fcfg=cfg,
        )
        if fid:
            promoted_ids.append(fid)
        else:
            skipped += 1

    # Refresh progress counter
    total_promoted = already + len(promoted_ids)
    progress = dict(session.get("progress") or {})
    progress["findings_promoted"] = total_promoted
    try:
        intruder_db.update_session(db_path, session["id"], progress=progress)
    except Exception:  # noqa: BLE001
        pass

    return {
        "promoted": len(promoted_ids),
        "skipped": skipped,
        "capped": (already + len(promoted_ids)) >= max_n and len(candidates) > len(promoted_ids),
        "finding_ids": promoted_ids,
        "already": already,
        "max_findings": max_n,
        "findings_promoted_total": total_promoted,
        "reason": "ok",
    }
