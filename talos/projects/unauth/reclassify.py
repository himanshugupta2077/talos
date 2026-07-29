"""
Module: talos.projects.unauth.reclassify

Purpose:
    Offline re-application of unauth-decision-filter.yaml against stored
    unauth_results. Used after an analyst updates the decision filter so that
    historical BYPASS noise can be reclassified to SECURE and linked findings
    auto-rejected as false positives.

Pipeline:
    load filter
        → for each unauth_results row
            → load replay flow response
            → evaluate_response
            → update unauth_results when verdict/match metadata changes
            → if BYPASS → SECURE: reject eligible findings + timeline reason
            → if non-BYPASS → BYPASS: count would_create_finding (v1 report only)

Status policy:
    TRIAGING  → REJECT on BYPASS→SECURE
    CONFIRMED → REJECT only when include_confirmed=True (--force)
    REJECTED  → no-op (idempotent)
    DUPLICATE → skip

Dependencies: json, logging, pathlib
              talos.projects.unauth.decision_filter
              talos.replay.db
              talos.findings.db / model
Data flow:
    filter_cli / control-panel API → apply_unauth_decision_filter → DB writes
Side effects:
    Updates unauth_results and findings when dry_run=False.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from talos.findings import db as findings_db
from talos.findings.model import (
    EVIDENCE_TYPE_UNAUTH_RESULT,
    FINDING_STATUS_CONFIRMED,
    FINDING_STATUS_DUPLICATE,
    FINDING_STATUS_REJECTED,
    FINDING_STATUS_TRIAGING,
    TIMELINE_ACTOR_SYSTEM,
)
from talos.projects.unauth.decision_filter import (
    FILTER_FILENAME,
    VERDICT_BYPASS,
    VERDICT_SECURE,
    ResponseData,
    UnauthDecisionResult,
    evaluate_response,
    load_filter,
)
from talos.replay import db as replay_db

_log = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Summary models                                                       #
# ------------------------------------------------------------------ #

@dataclass
class ApplyRowAction:
    """One per-result decision during apply (for dry-run tables / UI)."""
    replay_flow_id: str
    old_verdict: str
    new_verdict: str
    finding_id: Optional[str]
    finding_status: Optional[str]
    action: str  # unchanged | result_updated | reject | skip_confirmed | skip_status | would_create | incomplete
    reason: str = ""
    matched_section: Optional[str] = None
    matched_group: Optional[str] = None
    matched_rules: list[str] = field(default_factory=list)


@dataclass
class ApplySummary:
    """Aggregate result of apply_unauth_decision_filter."""
    dry_run: bool
    include_confirmed: bool
    results_total: int = 0
    results_unchanged: int = 0
    results_updated: int = 0
    findings_rejected: int = 0
    findings_skipped_confirmed: int = 0
    findings_skipped_other: int = 0
    would_create_finding: int = 0
    incomplete: int = 0
    rows: list[ApplyRowAction] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "dry_run": self.dry_run,
            "include_confirmed": self.include_confirmed,
            "results_total": self.results_total,
            "results_unchanged": self.results_unchanged,
            "results_updated": self.results_updated,
            "findings_rejected": self.findings_rejected,
            "findings_skipped_confirmed": self.findings_skipped_confirmed,
            "findings_skipped_other": self.findings_skipped_other,
            "would_create_finding": self.would_create_finding,
            "incomplete": self.incomplete,
            "error": self.error,
            "rows": [
                {
                    "replay_flow_id": r.replay_flow_id,
                    "old_verdict": r.old_verdict,
                    "new_verdict": r.new_verdict,
                    "finding_id": r.finding_id,
                    "finding_status": r.finding_status,
                    "action": r.action,
                    "reason": r.reason,
                    "matched_section": r.matched_section,
                    "matched_group": r.matched_group,
                    "matched_rules": list(r.matched_rules),
                }
                for r in self.rows
            ],
        }


class FilterApplyError(Exception):
    """Raised when the filter file is missing or cannot be parsed."""


# ------------------------------------------------------------------ #
# Public entry point                                                   #
# ------------------------------------------------------------------ #

def apply_unauth_decision_filter(
    db_path: Path,
    project_data_dir: Path,
    *,
    dry_run: bool = False,
    include_confirmed: bool = False,
) -> ApplySummary:
    """
    Purpose:
        Re-evaluate all stored unauth_results against the current decision
        filter and optionally rewrite verdicts + reject false-positive findings.
    Input:
        db_path            — path to talos.db.
        project_data_dir   — directory containing unauth-decision-filter.yaml.
        dry_run            — when True, compute plan only (no DB writes).
        include_confirmed  — when True, also reject CONFIRMED findings on
                             BYPASS→SECURE (CLI --force maps here).
    Output:
        ApplySummary with counts and per-row actions.
    Side effects:
        When dry_run=False: updates unauth_results and findings + timeline.
    Raises:
        FilterApplyError if the filter file is missing or invalid.
    """
    summary = ApplySummary(dry_run=dry_run, include_confirmed=include_confirmed)

    decision_filter = load_filter(project_data_dir)
    if decision_filter is None:
        filter_path = project_data_dir / FILTER_FILENAME
        raise FilterApplyError(
            f"No valid filter at {filter_path}. "
            "Run 'talos attack unauth filter init' and edit the file, "
            "or fix YAML syntax, then re-run apply."
        )

    results = replay_db.list_unauth_results(db_path)
    summary.results_total = len(results)

    for row in results:
        action = _process_one_result(
            db_path=db_path,
            row=row,
            decision_filter=decision_filter,
            dry_run=dry_run,
            include_confirmed=include_confirmed,
            summary=summary,
        )
        if action is not None:
            summary.rows.append(action)

    return summary


def _process_one_result(
    *,
    db_path: Path,
    row: dict,
    decision_filter,
    dry_run: bool,
    include_confirmed: bool,
    summary: ApplySummary,
) -> Optional[ApplyRowAction]:
    replay_id = row["replay_flow_id"]
    old_verdict = (row.get("verdict") or "").upper() or "UNKNOWN"

    flow = replay_db.get_flow_for_replay(db_path, replay_id)
    if flow is None:
        summary.incomplete += 1
        return ApplyRowAction(
            replay_flow_id=replay_id,
            old_verdict=old_verdict,
            new_verdict=old_verdict,
            finding_id=None,
            finding_status=None,
            action="incomplete",
            reason="replay flow missing",
        )

    resp = _response_data_from_flow(flow)
    new_decision: UnauthDecisionResult = evaluate_response(decision_filter, resp)
    new_verdict = new_decision.verdict
    new_rules = list(new_decision.matched_rules or [])
    new_rules_json = json.dumps(new_rules) if new_rules else None

    old_section = row.get("matched_section")
    old_group = row.get("matched_group")
    old_rules_raw = row.get("matched_rules")
    old_rules = _parse_rules_json(old_rules_raw)

    meta_same = (
        new_verdict == old_verdict
        and (new_decision.matched_section or None) == (old_section or None)
        and (new_decision.matched_group_id or None) == (old_group or None)
        and new_rules == old_rules
    )

    findings = findings_db.find_findings_by_evidence_ref(
        db_path, EVIDENCE_TYPE_UNAUTH_RESULT, replay_id
    )
    # Prefer the first finding (normally one-to-one).
    finding = findings[0] if findings else None
    finding_id = finding["id"] if finding else None
    finding_status = finding["status"] if finding else None

    reason = _format_match_reason(new_decision, replay_id)

    # Reverse: non-BYPASS → BYPASS (v1 report only).
    if old_verdict != VERDICT_BYPASS and new_verdict == VERDICT_BYPASS:
        if not meta_same and not dry_run:
            replay_db.update_unauth_result_verdict(
                db_path,
                replay_id,
                verdict=new_verdict,
                matched_section=new_decision.matched_section,
                matched_group=new_decision.matched_group_id,
                matched_rules=new_rules_json,
            )
            summary.results_updated += 1
        elif meta_same:
            summary.results_unchanged += 1
        else:
            summary.results_updated += 1  # dry-run would update

        if finding is None:
            summary.would_create_finding += 1
            return ApplyRowAction(
                replay_flow_id=replay_id,
                old_verdict=old_verdict,
                new_verdict=new_verdict,
                finding_id=None,
                finding_status=None,
                action="would_create",
                reason=reason,
                matched_section=new_decision.matched_section,
                matched_group=new_decision.matched_group_id,
                matched_rules=new_rules,
            )

        # Finding already exists for a non-BYPASS→BYPASS flip (unusual); treat as result update.
        action_name = "unchanged" if meta_same else "result_updated"
        return ApplyRowAction(
            replay_flow_id=replay_id,
            old_verdict=old_verdict,
            new_verdict=new_verdict,
            finding_id=finding_id,
            finding_status=finding_status,
            action=action_name,
            reason=reason,
            matched_section=new_decision.matched_section,
            matched_group=new_decision.matched_group_id,
            matched_rules=new_rules,
        )

    if meta_same:
        summary.results_unchanged += 1
        return ApplyRowAction(
            replay_flow_id=replay_id,
            old_verdict=old_verdict,
            new_verdict=new_verdict,
            finding_id=finding_id,
            finding_status=finding_status,
            action="unchanged",
            reason="",
            matched_section=new_decision.matched_section,
            matched_group=new_decision.matched_group_id,
            matched_rules=new_rules,
        )

    # Verdict / match metadata changed — update result row.
    if not dry_run:
        replay_db.update_unauth_result_verdict(
            db_path,
            replay_id,
            verdict=new_verdict,
            matched_section=new_decision.matched_section,
            matched_group=new_decision.matched_group_id,
            matched_rules=new_rules_json,
        )
    summary.results_updated += 1

    # Auto-reject findings only on BYPASS → SECURE (pass / false-positive path).
    if old_verdict == VERDICT_BYPASS and new_verdict == VERDICT_SECURE and finding:
        return _maybe_reject_finding(
            db_path=db_path,
            finding=finding,
            dry_run=dry_run,
            include_confirmed=include_confirmed,
            summary=summary,
            replay_id=replay_id,
            old_verdict=old_verdict,
            new_verdict=new_verdict,
            reason=reason,
            decision=new_decision,
        )

    return ApplyRowAction(
        replay_flow_id=replay_id,
        old_verdict=old_verdict,
        new_verdict=new_verdict,
        finding_id=finding_id,
        finding_status=finding_status,
        action="result_updated",
        reason=reason,
        matched_section=new_decision.matched_section,
        matched_group=new_decision.matched_group_id,
        matched_rules=new_rules,
    )


def _maybe_reject_finding(
    *,
    db_path: Path,
    finding: dict,
    dry_run: bool,
    include_confirmed: bool,
    summary: ApplySummary,
    replay_id: str,
    old_verdict: str,
    new_verdict: str,
    reason: str,
    decision: UnauthDecisionResult,
) -> ApplyRowAction:
    status = finding["status"]
    finding_id = finding["id"]

    if status == FINDING_STATUS_REJECTED:
        summary.findings_skipped_other += 1
        return ApplyRowAction(
            replay_flow_id=replay_id,
            old_verdict=old_verdict,
            new_verdict=new_verdict,
            finding_id=finding_id,
            finding_status=status,
            action="result_updated",
            reason=reason + " (finding already REJECTED)",
            matched_section=decision.matched_section,
            matched_group=decision.matched_group_id,
            matched_rules=list(decision.matched_rules or []),
        )

    if status == FINDING_STATUS_DUPLICATE:
        summary.findings_skipped_other += 1
        return ApplyRowAction(
            replay_flow_id=replay_id,
            old_verdict=old_verdict,
            new_verdict=new_verdict,
            finding_id=finding_id,
            finding_status=status,
            action="skip_status",
            reason="DUPLICATE findings are not auto-rejected",
            matched_section=decision.matched_section,
            matched_group=decision.matched_group_id,
            matched_rules=list(decision.matched_rules or []),
        )

    if status == FINDING_STATUS_CONFIRMED and not include_confirmed:
        summary.findings_skipped_confirmed += 1
        return ApplyRowAction(
            replay_flow_id=replay_id,
            old_verdict=old_verdict,
            new_verdict=new_verdict,
            finding_id=finding_id,
            finding_status=status,
            action="skip_confirmed",
            reason="CONFIRMED (use --force to include)",
            matched_section=decision.matched_section,
            matched_group=decision.matched_group_id,
            matched_rules=list(decision.matched_rules or []),
        )

    if status not in (FINDING_STATUS_TRIAGING, FINDING_STATUS_CONFIRMED):
        summary.findings_skipped_other += 1
        return ApplyRowAction(
            replay_flow_id=replay_id,
            old_verdict=old_verdict,
            new_verdict=new_verdict,
            finding_id=finding_id,
            finding_status=status,
            action="skip_status",
            reason=f"status {status} not eligible for auto-reject",
            matched_section=decision.matched_section,
            matched_group=decision.matched_group_id,
            matched_rules=list(decision.matched_rules or []),
        )

    # Eligible: TRIAGING, or CONFIRMED with include_confirmed.
    if not dry_run:
        findings_db.update_finding_status(
            db_path, finding_id, FINDING_STATUS_REJECTED
        )
        findings_db.add_timeline_event(
            db_path,
            finding_id,
            f"Auto-rejected: {reason}",
            actor=TIMELINE_ACTOR_SYSTEM,
        )

    summary.findings_rejected += 1
    return ApplyRowAction(
        replay_flow_id=replay_id,
        old_verdict=old_verdict,
        new_verdict=new_verdict,
        finding_id=finding_id,
        finding_status=status,
        action="reject",
        reason=reason,
        matched_section=decision.matched_section,
        matched_group=decision.matched_group_id,
        matched_rules=list(decision.matched_rules or []),
    )


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

def _response_data_from_flow(flow: dict) -> ResponseData:
    """Build ResponseData from a stored replay flow row."""
    raw_headers = flow.get("response_headers") or "{}"
    if isinstance(raw_headers, dict):
        headers = raw_headers
    else:
        try:
            headers = json.loads(raw_headers)
            if not isinstance(headers, dict):
                headers = {}
        except (TypeError, ValueError, json.JSONDecodeError):
            headers = {}

    body = flow.get("response_body")
    body_bytes: Optional[bytes]
    if body is None:
        body_bytes = None
    elif isinstance(body, bytes):
        body_bytes = body
    elif isinstance(body, str):
        body_bytes = body.encode("utf-8", errors="replace")
    else:
        body_bytes = bytes(body)

    status = flow.get("status_code")
    try:
        status_int = int(status) if status is not None else None
    except (TypeError, ValueError):
        status_int = None

    return ResponseData(
        status=status_int,
        headers=headers,
        body=body_bytes,
        response_length=len(body_bytes) if body_bytes else 0,
    )


def _parse_rules_json(raw) -> list[str]:
    if raw is None or raw == "":
        return []
    if isinstance(raw, list):
        return [str(x) for x in raw]
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return [str(x) for x in parsed]
    except (TypeError, ValueError, json.JSONDecodeError):
        pass
    return []


def _format_match_reason(decision: UnauthDecisionResult, replay_id: str) -> str:
    short = (replay_id or "")[:8]
    section = decision.matched_section or "none"
    group = decision.matched_group_id or "-"
    rules = ",".join(decision.matched_rules) if decision.matched_rules else "-"
    return (
        f"Matched decision filter: {section} / group={group} / rules=[{rules}] "
        f"(reclassified unauth result {short})"
    )
