"""
Module: talos.findings.creator

Purpose:
    Determine whether an attack verdict triggers a finding, then create
    the finding and attach structured evidence.

    This is the integration point between attack modules and the Findings
    subsystem.  Attack engines call create_finding_from_verdict() after
    producing a verdict; the creator decides whether a finding should be
    created and handles all DB writes.

    Verdict trigger map (defined in model.VERDICT_TRIGGERS):
        bac          → POSSIBLE_BAC    triggers a finding.
        auth_test    → BYPASS          triggers a finding.
        unauth       → BYPASS          triggers a finding.
        auth_session → WEAK_VALIDATION triggers a finding.

    Relationship (PRIMARY / LINKED) is decided here via cluster_key:
        first finding in a cluster → PRIMARY
        later findings             → LINKED under that PRIMARY

    Evidence attached automatically per attack type:
        BAC attack:
            - original_flow   (EVIDENCE_TYPE_ORIGINAL_FLOW)
            - replay_flow     (EVIDENCE_TYPE_REPLAY_FLOW)
            - diff            (EVIDENCE_TYPE_DIFF)
            - scheduler_job   (EVIDENCE_TYPE_SCHEDULER_JOB)
            - endpoint        (EVIDENCE_TYPE_ENDPOINT)
            - attacker_role   (EVIDENCE_TYPE_ATTACKER_ROLE)
            - target_role     (EVIDENCE_TYPE_TARGET_ROLE)
            - bac_result      (EVIDENCE_TYPE_BAC_RESULT)
        Auth-bypass test:
            - original_flow   (EVIDENCE_TYPE_ORIGINAL_FLOW)
            - replay_flow     (EVIDENCE_TYPE_REPLAY_FLOW)
            - diff            (EVIDENCE_TYPE_DIFF)
            - endpoint        (EVIDENCE_TYPE_ENDPOINT)
            - auth_test_result(EVIDENCE_TYPE_AUTH_TEST_RESULT)

Dependencies: pathlib, logging
              talos.findings.db, talos.findings.model
Data flow:
    talos.scheduler.scheduler → create_finding_from_verdict(...)
        → check VERDICT_TRIGGERS
        → create_finding, add_evidence, add_timeline_event
Side effects:
    Writes to findings, finding_evidence, finding_timeline tables.
"""

import logging
import sqlite3
from pathlib import Path
from typing import Optional

import talos.findings.db as findings_db
from talos.findings.model import (
    VERDICT_TRIGGERS,
    ATTACK_DISPLAY,
    FINDING_STATUS_TRIAGING,
    RELATION_TYPE_PRIMARY,
    RELATION_TYPE_LINKED,
    EVIDENCE_TYPE_ORIGINAL_FLOW,
    EVIDENCE_TYPE_REPLAY_FLOW,
    EVIDENCE_TYPE_DIFF,
    EVIDENCE_TYPE_SCHEDULER_JOB,
    EVIDENCE_TYPE_ENDPOINT,
    EVIDENCE_TYPE_ATTACKER_ROLE,
    EVIDENCE_TYPE_TARGET_ROLE,
    EVIDENCE_TYPE_BAC_RESULT,
    EVIDENCE_TYPE_AUTH_TEST_RESULT,
    EVIDENCE_TYPE_UNAUTH_RESULT,
    EVIDENCE_TYPE_AUTH_SESSION_RESULT,
    EVIDENCE_TYPE_CORS_RESULT,
    EVIDENCE_TYPE_SQLI_RESULT,
    EVIDENCE_TYPE_PATH_TRAVERSAL_RESULT,
    EVIDENCE_TYPE_SSRF_RESULT,
    EVIDENCE_TYPE_OPEN_REDIRECT_RESULT,
    EVIDENCE_TYPE_SMUGGLE_RESULT,
    EVIDENCE_TYPE_MODULE,
    EVIDENCE_TYPE_ROLE,
    TIMELINE_ACTOR_SYSTEM,
)

_log = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Read-only lookups used to build a real, timestamp-accurate timeline  #
# ------------------------------------------------------------------ #

def _fetch_flow_summary(db_path: Path, flow_id: Optional[str]) -> Optional[dict]:
    """
    Purpose:
        Fetch the minimal flow fields needed to reconstruct timeline history
        and role/module evidence: when it was captured and which role/module
        produced it.
    Output:
        Dict with keys: id, captured_at, method, path, role_id, module_id.
        None if flow_id is falsy or the row does not exist.
    """
    if not flow_id:
        return None
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT id, captured_at, method, path, role_id, module_id "
            "FROM flows WHERE id = ?",
            (flow_id,),
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:  # noqa: BLE001
        return None


def _fetch_job_times(db_path: Path, job_id: Optional[str]) -> Optional[dict]:
    """
    Purpose:
        Fetch the scheduler job's lifecycle timestamps for timeline reconstruction.
    Output:
        Dict with keys: created_at, started_at, finished_at. None if not found.
    """
    if not job_id:
        return None
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT created_at, started_at, finished_at "
            "FROM scheduler_jobs WHERE job_id = ?",
            (job_id,),
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:  # noqa: BLE001
        return None


def _fetch_name(db_path: Path, table: str, row_id: Optional[str]) -> Optional[str]:
    """Purpose: Fetch a 'name' column value from roles/modules by id."""
    if not row_id:
        return None
    try:
        conn = sqlite3.connect(str(db_path))
        row = conn.execute(f"SELECT name FROM {table} WHERE id = ?", (row_id,)).fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:  # noqa: BLE001
        return None


def create_finding_from_verdict(
    db_path: Path,
    project_id: str,
    attack_module: str,
    verdict: str,
    endpoint_id: Optional[str],
    original_flow_id: Optional[str],
    replayed_flow_id: Optional[str],
    job_id: Optional[str] = None,
    attacker_role_id: Optional[str] = None,
    target_role_id: Optional[str] = None,
    module_id: Optional[str] = None,
    attack_type: Optional[str] = None,
    variant: Optional[str] = None,
    diff_verdict: Optional[str] = None,
    title: Optional[str] = None,
    auth_type: Optional[str] = None,
    host: Optional[str] = None,
    result_evidence_data: Optional[dict] = None,
) -> Optional[str]:
    """
    Purpose:
        Check whether the verdict triggers a finding; if so, create it and
        attach all available evidence.

        Relationship decision (PRIMARY vs LINKED) is owned here — attack
        modules only report successful verdicts.  Cluster identity is
        attack-specific (see findings_db.build_cluster_key):
            unauth       → UNAUTH:<endpoint_id>
            auth_test    → AUTH_TEST:<endpoint_id>
            bac          → BAC:<endpoint_id>:<attacker>:<target>
            auth_session → AUTH_SESSION:<auth_type>
            cors         → CORS:<scheme://netloc>
            sqli            → SQLI:<endpoint_id>
            path_traversal  → PATH_TRAVERSAL:<endpoint_id>
            ssrf            → SSRF:<endpoint_id>
            open_redirect   → OPEN_REDIRECT:<endpoint_id>
            smuggle         → SMUGGLE:<scheme://netloc>

        The first finding in a cluster becomes PRIMARY; later findings in
        the same cluster become LINKED to that PRIMARY.  Every successful
        technique still gets its own finding row (no result deduplication).

    Input:
        db_path         — path to the project's talos.db.
        project_id      — project identifier.
        attack_module   — 'bac' | 'auth_test' | 'unauth' | 'auth_session'.
        verdict         — verdict string produced by the attack engine.
        endpoint_id     — FK to endpoints.id; may be None.
        original_flow_id— UUID of the original captured flow.
        replayed_flow_id— UUID of the attack replay flow; may be None.
        job_id          — scheduler job UUID; may be None.
        attacker_role_id— attacker role UUID (BAC only).
        target_role_id  — target role UUID (BAC only).
        module_id       — access module UUID (BAC only).
        attack_type     — BAC job type constant (e.g. 'bac_session_swap').
        variant         — technique / test_id label for timeline context.
        diff_verdict    — SAME | DIFFERENT | ERROR; may be None.
        title           — optional full title override (auth_session Appendix B).
                          When omitted, uses default "{ATTACK_DISPLAY} — {verdict}
                          ({variant})" builder.
        auth_type       — auth_session only (jwt, …) for cluster key.
        host            — cors / smuggle: target origin key for cluster.
        result_evidence_data — optional extra keys merged into the attack-result
                          evidence JSON (e.g. risk_hint, mutation_summary for
                          auth_session). No severity column on findings.

    Output:
        Finding UUID if a finding was created; None if verdict is not a trigger.

    Side effects:
        Writes finding + evidence + timeline rows on trigger; silent on no-trigger.
        The timeline is reconstructed from real historical timestamps (original
        flow capture time, job start/finish time, replay flow capture time)
        rather than a single batch of "now" events, so 'finding show' reflects
        when each stage of the attack actually happened.
    """
    triggers = VERDICT_TRIGGERS.get(attack_module, frozenset())
    if verdict not in triggers:
        return None

    # Build a readable title for the finding (caller may override fully).
    attack_label = ATTACK_DISPLAY.get(attack_module, attack_module.upper())
    if not title:
        title_parts = [attack_label, f"— {verdict}"]
        if variant:
            title_parts.append(f"({variant})")
        title = " ".join(title_parts)

    # Cluster identity — attack-specific; mutations/variants are intentionally
    # excluded so multiple bypass techniques for the same endpoint cluster.
    cluster_key = findings_db.build_cluster_key(
        attack_module=attack_module,
        endpoint_id=endpoint_id,
        attacker_role_id=attacker_role_id,
        target_role_id=target_role_id,
        auth_type=auth_type,
        host=host,
    )

    try:
        finding_id = findings_db.create_finding(
            db_path=db_path,
            project_id=project_id,
            attack_type=attack_module,
            verdict=verdict,
            endpoint_id=endpoint_id,
            title=title,
            cluster_key=cluster_key,
        )
    except Exception as exc:  # noqa: BLE001
        _log.error("[findings] Failed to create finding: %s", exc)
        return None

    created = findings_db.get_finding(db_path, finding_id)
    relation_type = (created or {}).get("relation_type", RELATION_TYPE_PRIMARY)
    parent_finding_id = (created or {}).get("parent_finding_id")

    # Resolve the original/replay flow's role + module — used both for
    # evidence and for reconstructing an accurate timeline.
    original_flow = _fetch_flow_summary(db_path, original_flow_id)
    replayed_flow = _fetch_flow_summary(db_path, replayed_flow_id)
    job_times = _fetch_job_times(db_path, job_id)

    resolved_role_id = attacker_role_id or (original_flow or {}).get("role_id")
    resolved_module_id = module_id or (original_flow or {}).get("module_id")

    # Attach evidence based on what is available.
    _attach_evidence(
        db_path=db_path,
        finding_id=finding_id,
        attack_module=attack_module,
        original_flow_id=original_flow_id,
        replayed_flow_id=replayed_flow_id,
        job_id=job_id,
        endpoint_id=endpoint_id,
        attacker_role_id=attacker_role_id,
        target_role_id=target_role_id,
        module_id=resolved_module_id,
        role_id=resolved_role_id,
        attack_type=attack_type,
        variant=variant,
        diff_verdict=diff_verdict,
        replayed_flow_id_for_result=replayed_flow_id,
        result_evidence_data=result_evidence_data,
    )

    # --------------------------------------------------------------- #
    # Reconstruct an accurate timeline from real historical timestamps. #
    # Falls back to "now" for any stage whose timestamp is unavailable, #
    # but never invents an ordering — each event uses the actual        #
    # capture/run time it corresponds to.                                #
    # --------------------------------------------------------------- #
    engine_label = attack_type or attack_module

    try:
        if original_flow and original_flow.get("captured_at"):
            findings_db.add_timeline_event(
                db_path=db_path,
                finding_id=finding_id,
                event=(
                    "Baseline flow first appeared — "
                    f"{original_flow.get('method', '?')} {original_flow.get('path', '?')}"
                ),
                actor=TIMELINE_ACTOR_SYSTEM,
                occurred_at=original_flow["captured_at"],
            )

        if job_times and job_times.get("created_at"):
            findings_db.add_timeline_event(
                db_path=db_path,
                finding_id=finding_id,
                event=f"Test case scheduled (engine: {engine_label})",
                actor=TIMELINE_ACTOR_SYSTEM,
                occurred_at=job_times["created_at"],
            )

        run_started_at = (job_times or {}).get("started_at") or (replayed_flow or {}).get("captured_at")
        if run_started_at:
            findings_db.add_timeline_event(
                db_path=db_path,
                finding_id=finding_id,
                event=f"Test case run started (engine: {engine_label})",
                actor=TIMELINE_ACTOR_SYSTEM,
                occurred_at=run_started_at,
            )

        if replayed_flow and replayed_flow.get("captured_at"):
            findings_db.add_timeline_event(
                db_path=db_path,
                finding_id=finding_id,
                event="Attack replay executed against target",
                actor=TIMELINE_ACTOR_SYSTEM,
                occurred_at=replayed_flow["captured_at"],
            )

        diff_time = (replayed_flow or {}).get("captured_at")
        if diff_verdict and diff_time:
            findings_db.add_timeline_event(
                db_path=db_path,
                finding_id=finding_id,
                event=f"Replay diff computed — {diff_verdict}",
                actor=TIMELINE_ACTOR_SYSTEM,
                occurred_at=diff_time,
            )

        verdict_time = (job_times or {}).get("finished_at") or diff_time
        if verdict_time:
            findings_db.add_timeline_event(
                db_path=db_path,
                finding_id=finding_id,
                event=f"Verdict determined: {verdict}" + (f" via {variant}" if variant else ""),
                actor=TIMELINE_ACTOR_SYSTEM,
                occurred_at=verdict_time,
            )

        relation_note = f" as {relation_type}"
        if relation_type == RELATION_TYPE_LINKED and parent_finding_id:
            relation_note += f" under PRIMARY {parent_finding_id}"
        if cluster_key:
            relation_note += f" (cluster: {cluster_key})"

        findings_db.add_timeline_event(
            db_path=db_path,
            finding_id=finding_id,
            event=(
                f"Finding created{relation_note} — {attack_label} engine produced {verdict}"
                + (f" via {variant}" if variant else "")
                + f" (engine: {engine_label})"
            ),
            actor=TIMELINE_ACTOR_SYSTEM,
        )

        if replayed_flow_id:
            findings_db.add_timeline_event(
                db_path=db_path,
                finding_id=finding_id,
                event="Evidence attached: replay flow, original flow"
                + (f", diff ({diff_verdict})" if diff_verdict else ""),
                actor=TIMELINE_ACTOR_SYSTEM,
            )
    except Exception as exc:  # noqa: BLE001
        _log.warning("[findings] Timeline write error (non-fatal): %s", exc)

    _log.info(
        "[findings] Created finding %s  attack=%s  verdict=%s  relation=%s",
        finding_id[:8],
        attack_module,
        verdict,
        relation_type,
    )
    _snapshot_finding_for_burp(
        db_path=db_path,
        project_id=project_id,
        finding_id=finding_id,
        attack_type=attack_module,
        title=title,
        flow_id=replayed_flow_id or original_flow_id or "",
    )
    return finding_id


def _snapshot_finding_for_burp(
    db_path: Path,
    project_id: str,
    finding_id: str,
    attack_type: str,
    title: str,
    flow_id: str,
) -> None:
    """Best-effort Findings tree row for the Burp extension. Never raises."""
    try:
        from talos.burp.snapshot import record_finding

        record_finding(
            project_id=project_id,
            finding_id=finding_id,
            db_path=db_path,
            attack_type=attack_type,
            title=title,
            flow_id=flow_id,
        )
    except Exception:  # noqa: BLE001
        _log.debug("[findings] burp snapshot skipped", exc_info=True)


# ------------------------------------------------------------------ #
# Evidence attachment                                                  #
# ------------------------------------------------------------------ #

def _attach_evidence(
    db_path: Path,
    finding_id: str,
    attack_module: str,
    original_flow_id: Optional[str],
    replayed_flow_id: Optional[str],
    job_id: Optional[str],
    endpoint_id: Optional[str],
    attacker_role_id: Optional[str],
    target_role_id: Optional[str],
    module_id: Optional[str],
    role_id: Optional[str],
    attack_type: Optional[str],
    variant: Optional[str],
    diff_verdict: Optional[str],
    replayed_flow_id_for_result: Optional[str],
    result_evidence_data: Optional[dict] = None,
) -> None:
    """
    Purpose:
        Attach all available evidence items to a newly-created finding.
        Each piece of evidence is a separate row in finding_evidence.
        Failures are non-fatal — they are logged and skipped.
    Side effects:
        Writes to finding_evidence; partial success is acceptable.
    """
    _safe_add = _safe_add_evidence  # local alias for brevity

    if original_flow_id:
        _safe_add(
            db_path, finding_id,
            EVIDENCE_TYPE_ORIGINAL_FLOW, original_flow_id,
            "Original captured flow",
        )

    if replayed_flow_id:
        _safe_add(
            db_path, finding_id,
            EVIDENCE_TYPE_REPLAY_FLOW, replayed_flow_id,
            "Attack replay flow",
        )

    if diff_verdict and replayed_flow_id:
        _safe_add(
            db_path, finding_id,
            EVIDENCE_TYPE_DIFF, replayed_flow_id,
            f"Replay diff — {diff_verdict}",
            {"diff_verdict": diff_verdict},
        )

    if endpoint_id:
        _safe_add(
            db_path, finding_id,
            EVIDENCE_TYPE_ENDPOINT, endpoint_id,
            "Target endpoint",
        )

    if job_id:
        _safe_add(
            db_path, finding_id,
            EVIDENCE_TYPE_SCHEDULER_JOB, job_id,
            f"Scheduler job ({attack_type or attack_module})",
        )

    if module_id:
        module_name = _fetch_name(db_path, "modules", module_id)
        _safe_add(
            db_path, finding_id,
            EVIDENCE_TYPE_MODULE, module_id,
            f"Application module: {module_name or module_id}",
            {"name": module_name},
        )

    if role_id:
        role_name = _fetch_name(db_path, "roles", role_id)
        _safe_add(
            db_path, finding_id,
            EVIDENCE_TYPE_ROLE, role_id,
            f"Role: {role_name or role_id}",
            {"name": role_name},
        )

    if attack_module == "bac":
        if attacker_role_id:
            _safe_add(
                db_path, finding_id,
                EVIDENCE_TYPE_ATTACKER_ROLE, attacker_role_id,
                "Attacker role",
            )
        if target_role_id:
            _safe_add(
                db_path, finding_id,
                EVIDENCE_TYPE_TARGET_ROLE, target_role_id,
                "Target (victim) role",
            )
        if replayed_flow_id_for_result:
            _safe_add(
                db_path, finding_id,
                EVIDENCE_TYPE_BAC_RESULT, replayed_flow_id_for_result,
                "BAC attack result"
                + (f" — variant: {variant}" if variant else ""),
                {"attack_type": attack_type, "variant": variant},
            )

    elif attack_module == "auth_test":
        if replayed_flow_id_for_result:
            _safe_add(
                db_path, finding_id,
                EVIDENCE_TYPE_AUTH_TEST_RESULT, replayed_flow_id_for_result,
                "Auth-bypass test result",
            )

    elif attack_module == "unauth":
        if replayed_flow_id_for_result:
            _safe_add(
                db_path, finding_id,
                EVIDENCE_TYPE_UNAUTH_RESULT, replayed_flow_id_for_result,
                "Unauthenticated-execution attack result"
                + (f" — variant: {variant}" if variant else ""),
                {"variant": variant},
            )

    elif attack_module == "auth_session":
        if replayed_flow_id_for_result:
            as_data: dict = {"variant": variant, "test_id": variant}
            if result_evidence_data:
                as_data.update(result_evidence_data)
            _safe_add(
                db_path, finding_id,
                EVIDENCE_TYPE_AUTH_SESSION_RESULT, replayed_flow_id_for_result,
                "Authentication & Session Testing result"
                + (f" — test: {variant}" if variant else ""),
                as_data,
            )

    elif attack_module == "cors":
        if replayed_flow_id_for_result:
            cors_data: dict = {"variant": variant, "technique": variant}
            if result_evidence_data:
                cors_data.update(result_evidence_data)
            _safe_add(
                db_path, finding_id,
                EVIDENCE_TYPE_CORS_RESULT, replayed_flow_id_for_result,
                "CORS misconfiguration probe"
                + (f" — {variant}" if variant else ""),
                cors_data,
            )

    elif attack_module == "sqli":
        if replayed_flow_id_for_result:
            sqli_data: dict = {"variant": variant, "technique": variant}
            if result_evidence_data:
                sqli_data.update(result_evidence_data)
            _safe_add(
                db_path, finding_id,
                EVIDENCE_TYPE_SQLI_RESULT, replayed_flow_id_for_result,
                "SQL injection probe"
                + (f" — {variant}" if variant else ""),
                sqli_data,
            )

    elif attack_module == "path_traversal":
        if replayed_flow_id_for_result:
            pt_data: dict = {"variant": variant, "technique": variant}
            if result_evidence_data:
                pt_data.update(result_evidence_data)
            _safe_add(
                db_path, finding_id,
                EVIDENCE_TYPE_PATH_TRAVERSAL_RESULT, replayed_flow_id_for_result,
                "Path traversal / LFI probe"
                + (f" — {variant}" if variant else ""),
                pt_data,
            )

    elif attack_module == "ssrf":
        if replayed_flow_id_for_result:
            ssrf_data: dict = {"variant": variant, "technique": variant}
            if result_evidence_data:
                ssrf_data.update(result_evidence_data)
            _safe_add(
                db_path, finding_id,
                EVIDENCE_TYPE_SSRF_RESULT, replayed_flow_id_for_result,
                "SSRF probe"
                + (f" — {variant}" if variant else ""),
                ssrf_data,
            )

    elif attack_module == "open_redirect":
        if replayed_flow_id_for_result:
            or_data: dict = {"variant": variant, "technique": variant}
            if result_evidence_data:
                or_data.update(result_evidence_data)
            _safe_add(
                db_path, finding_id,
                EVIDENCE_TYPE_OPEN_REDIRECT_RESULT, replayed_flow_id_for_result,
                "Open-redirect probe"
                + (f" — {variant}" if variant else ""),
                or_data,
            )

    elif attack_module == "smuggle":
        if replayed_flow_id_for_result:
            smuggle_data: dict = {"variant": variant, "technique": variant}
            if result_evidence_data:
                smuggle_data.update(result_evidence_data)
            _safe_add(
                db_path, finding_id,
                EVIDENCE_TYPE_SMUGGLE_RESULT, replayed_flow_id_for_result,
                "HTTP request smuggling probe"
                + (f" — {variant}" if variant else ""),
                smuggle_data,
            )


def _safe_add_evidence(
    db_path: Path,
    finding_id: str,
    evidence_type: str,
    reference_id: Optional[str],
    label: str,
    data: Optional[dict] = None,
) -> None:
    """
    Purpose:
        Call findings_db.add_evidence and swallow any exception so that
        a single evidence write failure does not abort finding creation.
    """
    try:
        findings_db.add_evidence(
            db_path=db_path,
            finding_id=finding_id,
            evidence_type=evidence_type,
            reference_id=reference_id,
            label=label,
            data=data,
        )
    except Exception as exc:  # noqa: BLE001
        _log.warning("[findings] Evidence attach error (%s): %s", evidence_type, exc)
