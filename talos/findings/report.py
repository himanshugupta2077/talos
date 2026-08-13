"""
Module: talos.findings.report

Purpose:
    Generate Markdown vulnerability reports for individual findings or
    finding groups.

    A finding report includes:
        - Attack module / test-case name
        - Metadata (status, verdict, attack type, created/updated timestamps)
        - Timeline (full immutable event log)
        - Evidence references (with type labels and reference IDs)
        - Raw HTTP details fetched from the flows table when available:
            * Original captured request + response
            * Replay request + response
            * Replay diff summary
        - Endpoint intelligence (from endpoints table)
        - Analyst notes stored on the finding
        - Duplicate relationship (if status == DUPLICATE)

    Output is a UTF-8 Markdown string — no file I/O is performed here.

Dependencies: sqlite3, json, pathlib, datetime
              talos.findings.db, talos.findings.model
Data flow:
    talos.findings.cli → generate_finding_report(db_path, finding_id) → str
Side effects:
    Read-only DB access only.
"""

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import talos.findings.db as findings_db
from talos.findings.model import (
    ATTACK_DISPLAY,
    RELATION_TYPE_PRIMARY,
    RELATION_TYPE_LINKED,
    EVIDENCE_TYPE_ORIGINAL_FLOW,
    EVIDENCE_TYPE_REPLAY_FLOW,
    EVIDENCE_TYPE_DIFF,
    EVIDENCE_TYPE_ENDPOINT,
    EVIDENCE_TYPE_BAC_RESULT,
    EVIDENCE_TYPE_AUTH_TEST_RESULT,
    EVIDENCE_TYPE_UNAUTH_RESULT,
    EVIDENCE_TYPE_AUTH_SESSION_RESULT,
    EVIDENCE_TYPE_CORS_RESULT,
    EVIDENCE_TYPE_MODULE,
    EVIDENCE_TYPE_ROLE,
    EVIDENCE_TYPE_ANALYST_NOTE,
    EVIDENCE_TYPE_ATTACKER_ROLE,
    EVIDENCE_TYPE_TARGET_ROLE,
    EVIDENCE_TYPE_DECISION_FILTER_RESULT,
)


# ------------------------------------------------------------------ #
# Public API                                                           #
# ------------------------------------------------------------------ #

def generate_finding_report(db_path: Path, finding_id: str) -> str:
    """
    Purpose:
        Produce a full Markdown vulnerability report for one finding.
    Input:
        db_path    — path to the project's talos.db.
        finding_id — UUID of the finding to report on.
    Output:
        UTF-8 Markdown string.
    Raises:
        ValueError if the finding does not exist.
    """
    finding = findings_db.get_finding(db_path, finding_id)
    if finding is None:
        raise ValueError(f"Finding not found: {finding_id}")

    evidence = findings_db.list_evidence(db_path, finding_id)
    timeline = findings_db.list_timeline(db_path, finding_id)
    duplicates = findings_db.list_duplicates_of(db_path, finding_id)

    sections: list[str] = []

    # --- Header ---
    attack_label = ATTACK_DISPLAY.get(finding["attack_type"], finding["attack_type"].upper())
    relation = finding.get("relation_type") or RELATION_TYPE_PRIMARY
    sections.append(f"# Vulnerability Report — {attack_label}\n")
    sections.append(f"**Finding ID:** `{finding['id']}`  ")
    sections.append(f"**Status:** `{finding['status']}`  ")
    sections.append(f"**Relation:** `{relation}`  ")
    if relation == RELATION_TYPE_LINKED and finding.get("parent_finding_id"):
        sections.append(f"**Primary Finding:** `{finding['parent_finding_id']}`  ")
    if finding.get("cluster_key"):
        sections.append(f"**Cluster:** `{finding['cluster_key']}`  ")
    sections.append(f"**Verdict:** `{finding['verdict']}`  ")
    sections.append(f"**Attack Module:** `{finding['attack_type']}`  ")
    sections.append(f"**Created:** {finding['created_at']}  ")
    sections.append(f"**Updated:** {finding['updated_at']}  ")
    if finding.get("endpoint_id"):
        sections.append(f"**Endpoint ID:** `{finding['endpoint_id']}`  ")
    if relation == RELATION_TYPE_PRIMARY:
        linked = findings_db.list_linked_findings(db_path, finding_id)
        if linked:
            linked_ids = ", ".join(f"`{lf['id']}`" for lf in linked)
            sections.append(
                f"**Linked Findings ({len(linked)}):** {linked_ids}  "
            )
    if finding["status"] == "DUPLICATE" and finding.get("duplicate_of"):
        sections.append(f"**Duplicate of:** `{finding['duplicate_of']}`  ")
    if duplicates:
        dup_ids = ", ".join(f"`{d['id']}`" for d in duplicates)
        sections.append(f"**Duplicates referencing this:** {dup_ids}  ")

    module_ev = _find_evidence(evidence, EVIDENCE_TYPE_MODULE)
    role_ev = _find_evidence(evidence, EVIDENCE_TYPE_ROLE)
    if module_ev:
        module_data = _parse_json(module_ev.get("data", "{}"))
        sections.append(f"**Module:** {module_data.get('name') or module_ev.get('reference_id') or '?'}  ")
    if role_ev:
        role_data = _parse_json(role_ev.get("data", "{}"))
        sections.append(f"**Role:** {role_data.get('name') or role_ev.get('reference_id') or '?'}  ")
    sections.append("")

    # --- Leaked secret (passive_secret) ---
    try:
        from talos.passive.finding_bridge import build_secret_exposure

        exposure = build_secret_exposure(db_path, finding_id, evidence=evidence)
    except Exception:  # noqa: BLE001
        exposure = None
    if exposure and exposure.get("hits"):
        sections.append("## Leaked Secret\n")
        for hit in exposure["hits"]:
            redacted = hit.get("redacted_value") or "(redacted)"
            detector = hit.get("detector_id") or "unknown"
            level = hit.get("confidence_level") or ""
            loc = hit.get("url") or hit.get("path") or "unknown path"
            sections.append(f"- **Value:** `{redacted}`")
            sections.append(f"- **Detector:** `{detector}` ({level})")
            if hit.get("matched_key"):
                sections.append(f"- **Matched key:** `{hit['matched_key']}`")
            sections.append(f"- **Location:** `{loc}`")
            start = hit.get("match_start") or 0
            end = hit.get("match_end") or 0
            sections.append(f"- **Offsets:** `{start}–{end}`")
            before = hit.get("context_before") or ""
            after = hit.get("context_after") or ""
            if before or after:
                sections.append(
                    f"- **Context:** `…{before}>>>{redacted}<<<{after}…`"
                )
            sections.append("")

    # --- Endpoint Intelligence ---
    endpoint_ev = _find_evidence(evidence, EVIDENCE_TYPE_ENDPOINT)
    if endpoint_ev and endpoint_ev.get("reference_id"):
        ep = _fetch_endpoint(db_path, endpoint_ev["reference_id"])
        if ep:
            sections.append("## Endpoint Intelligence\n")
            sections.append(f"- **Method:** `{ep.get('method', '?')}`")
            sections.append(f"- **Host:** `{ep.get('host', '?')}`")
            sections.append(f"- **Path:** `{ep.get('path', '?')}`")
            sections.append(f"- **Normalized Path:** `{ep.get('normalized_path', '?')}`")
            sections.append(f"- **Auth Required:** `{bool(ep.get('auth_required'))}`")
            sections.append(f"- **Roles Seen:** `{ep.get('roles_seen', '[]')}`")
            sections.append("")

    # --- BAC attack metadata ---
    bac_ev = _find_evidence(evidence, EVIDENCE_TYPE_BAC_RESULT)
    attacker_ev = _find_evidence(evidence, EVIDENCE_TYPE_ATTACKER_ROLE)
    target_ev = _find_evidence(evidence, EVIDENCE_TYPE_TARGET_ROLE)
    if bac_ev or attacker_ev or target_ev:
        sections.append("## BAC Attack Details\n")
        if attacker_ev:
            role_name = _fetch_role_name(db_path, attacker_ev.get("reference_id"))
            sections.append(f"- **Attacker Role:** `{role_name or attacker_ev.get('reference_id', '?')}`")
        if target_ev:
            role_name = _fetch_role_name(db_path, target_ev.get("reference_id"))
            sections.append(f"- **Target (Victim) Role:** `{role_name or target_ev.get('reference_id', '?')}`")
        if bac_ev:
            bac_data = _parse_json(bac_ev.get("data", "{}"))
            if bac_data.get("attack_type"):
                sections.append(f"- **Attack Type:** `{bac_data['attack_type']}`")
            if bac_data.get("variant"):
                sections.append(f"- **Variant:** `{bac_data['variant']}`")
        sections.append("")

    # --- CORS attack metadata ---
    cors_ev = _find_evidence(evidence, EVIDENCE_TYPE_CORS_RESULT)
    if cors_ev:
        cors_data = _parse_json(cors_ev.get("data", "{}"))
        sections.append("## CORS Misconfiguration Details\n")
        if cors_data.get("technique"):
            sections.append(f"- **Technique:** `{cors_data['technique']}`")
        if cors_data.get("origin_sent"):
            sections.append(f"- **Origin sent:** `{cors_data['origin_sent']}`")
        if cors_data.get("acao"):
            sections.append(f"- **Access-Control-Allow-Origin:** `{cors_data['acao']}`")
        if cors_data.get("acac"):
            sections.append(f"- **Access-Control-Allow-Credentials:** `{cors_data['acac']}`")
        if cors_data.get("risk_hint"):
            sections.append(f"- **Risk hint:** `{cors_data['risk_hint']}`")
        sections.append("")

    # --- Original Captured Flow ---
    orig_ev = _find_evidence(evidence, EVIDENCE_TYPE_ORIGINAL_FLOW)
    if orig_ev and orig_ev.get("reference_id"):
        flow = _fetch_flow(db_path, orig_ev["reference_id"])
        if flow:
            sections.append("## Original Captured Flow\n")
            sections.append(_format_flow_section(flow))
            sections.append("")

    # --- Replay Flow ---
    replay_ev = _find_evidence(evidence, EVIDENCE_TYPE_REPLAY_FLOW)
    if replay_ev and replay_ev.get("reference_id"):
        flow = _fetch_flow(db_path, replay_ev["reference_id"])
        if flow:
            sections.append("## Attack Replay Flow\n")
            sections.append(_format_flow_section(flow))
            sections.append("")

    # --- Replay Diff ---
    diff_ev = _find_evidence(evidence, EVIDENCE_TYPE_DIFF)
    if diff_ev and diff_ev.get("reference_id"):
        diff = _fetch_diff(db_path, diff_ev["reference_id"])
        diff_data = _parse_json(diff_ev.get("data", "{}"))
        sections.append("## Replay Diff\n")
        if diff_data.get("diff_verdict"):
            sections.append(f"- **Diff Verdict:** `{diff_data['diff_verdict']}`")
        if diff:
            if diff.get("status_diff"):
                sections.append(f"- **Status Change:** `{diff['status_diff']}`")
            sections.append(f"- **Length Delta:** `{diff.get('length_diff', 0)}` bytes")
        sections.append("")

    # --- Auth-test result ---
    auth_ev = _find_evidence(evidence, EVIDENCE_TYPE_AUTH_TEST_RESULT)
    if auth_ev and auth_ev.get("reference_id"):
        sections.append("## Auth-Bypass Test Result\n")
        atr = _fetch_auth_test_result(db_path, auth_ev["reference_id"])
        if atr:
            sections.append(f"- **Verdict:** `{atr.get('verdict', '?')}`")
        sections.append("")

    # --- Unauth attack result ---
    unauth_ev = _find_evidence(evidence, EVIDENCE_TYPE_UNAUTH_RESULT)
    if unauth_ev and unauth_ev.get("reference_id"):
        sections.append("## Unauthenticated Execution Result\n")
        ur = _fetch_unauth_result(db_path, unauth_ev["reference_id"])
        if ur:
            sections.append(f"- **Verdict:** `{ur.get('verdict', '?')}`")
            sections.append(f"- **Auth Mutation:** `{ur.get('auth_mutation', '?')}`")
            if ur.get("request_mutation"):
                sections.append(f"- **Request Mutation:** `{ur['request_mutation']}`")
        sections.append("")

    # --- Auth-session attack result ---
    as_ev = _find_evidence(evidence, EVIDENCE_TYPE_AUTH_SESSION_RESULT)
    if as_ev and as_ev.get("reference_id"):
        sections.append("## Authentication & Session Testing Result\n")
        ar = _fetch_auth_session_result(db_path, as_ev["reference_id"])
        as_data = _parse_json(as_ev.get("data", "{}"))
        if ar:
            sections.append(f"- **Verdict:** `{ar.get('verdict', '?')}`")
            sections.append(f"- **Test ID:** `{ar.get('test_id', '?')}`")
            if ar.get("auth_type"):
                sections.append(f"- **Auth Type:** `{ar['auth_type']}`")
            if ar.get("test_family"):
                sections.append(f"- **Family:** `{ar['test_family']}`")
            mut = ar.get("mutation_summary") or as_data.get("mutation_summary")
            if mut:
                sections.append(f"- **Mutation:** `{mut}`")
            if ar.get("diff_verdict"):
                sections.append(f"- **Diff:** `{ar['diff_verdict']}`")
            if ar.get("matched_section"):
                sections.append(
                    f"- **Filter Match:** `{ar['matched_section']}`"
                    + (f" / `{ar.get('matched_group')}`" if ar.get("matched_group") else "")
                )
        else:
            if as_data.get("test_id") or as_data.get("variant"):
                sections.append(
                    f"- **Test ID:** `{as_data.get('test_id') or as_data.get('variant')}`"
                )
        # risk_hint lives in evidence JSON only (no severity column).
        if as_data.get("risk_hint"):
            sections.append(f"- **Risk hint:** `{as_data['risk_hint']}`")
        sections.append("")

    # --- All Evidence References ---
    sections.append("## Evidence References\n")
    sections.append("| # | Type | Label | Reference ID |")
    sections.append("|---|------|-------|--------------|")
    for idx, ev in enumerate(evidence, 1):
        sections.append(
            f"| {idx} | `{ev['evidence_type']}` | {ev['label']} "
            f"| `{ev.get('reference_id') or '—'}` |"
        )
    sections.append("")

    # --- Analyst Notes ---
    if finding.get("notes", "").strip():
        sections.append("## Internal Notes\n")
        sections.append(finding["notes"])
        sections.append("")

    # --- Analyst note evidence items ---
    note_items = [e for e in evidence if e["evidence_type"] == EVIDENCE_TYPE_ANALYST_NOTE]
    if note_items:
        sections.append("## Analyst Notes\n")
        for ni in note_items:
            ts = ni.get("created_at", "")
            sections.append(f"**[{ts}]** {ni['label']}\n")
            note_data = _parse_json(ni.get("data", "{}"))
            if note_data.get("text"):
                sections.append(note_data["text"])
            sections.append("")

    # --- Timeline ---
    sections.append("## Timeline\n")
    for ev in timeline:
        sections.append(f"- `{ev['created_at']}` [{ev['actor']}] {ev['event']}")
    sections.append("")

    return "\n".join(sections)


def generate_group_report(db_path: Path, group_id: str) -> str:
    """
    Purpose:
        Produce a combined Markdown report for all findings in a group.
        Each finding's full report is included sequentially.
    Input:
        db_path  — path to the project's talos.db.
        group_id — UUID of the finding group.
    Output:
        UTF-8 Markdown string.
    Raises:
        ValueError if the group does not exist.
    """
    group = findings_db.get_group(db_path, group_id)
    if group is None:
        raise ValueError(f"Finding group not found: {group_id}")

    members = findings_db.list_group_findings(db_path, group_id)
    lines: list[str] = []
    lines.append(f"# Group Report — {group['name']}\n")
    lines.append(f"**Group ID:** `{group_id}`  ")
    lines.append(f"**Total Findings:** {len(members)}  ")
    lines.append(f"**Created:** {group['created_at']}  ")
    lines.append("")

    # --- Index (only meaningful once there is more than one finding) --- #
    if len(members) > 1:
        lines.append("## Index\n")
        lines.append("| # | Title | Attack | Verdict | Finding ID |")
        lines.append("|---|-------|--------|---------|------------|")
        for idx, finding in enumerate(members, 1):
            attack_label = ATTACK_DISPLAY.get(
                finding["attack_type"], finding["attack_type"].upper()
            )
            title = finding.get("title") or "(untitled)"
            lines.append(
                f"| {idx} | {title} | {attack_label} | `{finding['verdict']}` "
                f"| `{finding['id']}` |"
            )
        lines.append("")

    lines.append("---\n")

    for idx, finding in enumerate(members, 1):
        try:
            report = generate_finding_report(db_path, finding["id"])
            if len(members) > 1:
                lines.append(f"### Finding #{idx}\n")
            lines.append(report)
        except Exception as exc:  # noqa: BLE001
            lines.append(f"*Error generating report for finding `{finding['id']}`: {exc}*\n")
        lines.append("\n---\n")

    return "\n".join(lines)


# ------------------------------------------------------------------ #
# Internal DB fetch helpers                                            #
# ------------------------------------------------------------------ #

def _fetch_flow(db_path: Path, flow_id: str) -> Optional[dict]:
    """Fetch a flow row from the flows table."""
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,)).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:  # noqa: BLE001
        return None


def _fetch_diff(db_path: Path, replay_flow_id: str) -> Optional[dict]:
    """Fetch a replay_diffs row."""
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM replay_diffs WHERE replay_flow_id = ?", (replay_flow_id,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:  # noqa: BLE001
        return None


def _fetch_endpoint(db_path: Path, endpoint_id: str) -> Optional[dict]:
    """Fetch an endpoints row."""
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM endpoints WHERE id = ?", (endpoint_id,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:  # noqa: BLE001
        return None


def _fetch_auth_test_result(db_path: Path, replay_flow_id: str) -> Optional[dict]:
    """Fetch an auth_test_results row."""
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM auth_test_results WHERE replay_flow_id = ?", (replay_flow_id,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:  # noqa: BLE001
        return None


def _fetch_unauth_result(db_path: Path, replay_flow_id: str) -> Optional[dict]:
    """Fetch an unauth_results row."""
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM unauth_results WHERE replay_flow_id = ?", (replay_flow_id,)
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:  # noqa: BLE001
        return None


def _fetch_auth_session_result(db_path: Path, replay_flow_id: str) -> Optional[dict]:
    """Fetch an auth_session_results row."""
    try:
        conn = sqlite3.connect(str(db_path))
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM auth_session_results WHERE replay_flow_id = ?",
            (replay_flow_id,),
        ).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:  # noqa: BLE001
        return None


def _fetch_role_name(db_path: Path, role_id: Optional[str]) -> Optional[str]:
    """Fetch a role name from the roles table."""
    if not role_id:
        return None
    try:
        conn = sqlite3.connect(str(db_path))
        row = conn.execute(
            "SELECT name FROM roles WHERE id = ?", (role_id,)
        ).fetchone()
        conn.close()
        return row[0] if row else None
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------------ #
# Formatting helpers                                                   #
# ------------------------------------------------------------------ #

def _find_evidence(evidence: list[dict], ev_type: str) -> Optional[dict]:
    """Return the first evidence item of the given type, or None."""
    for ev in evidence:
        if ev["evidence_type"] == ev_type:
            return ev
    return None


def _parse_json(raw: str) -> dict:
    """Parse a JSON string; return empty dict on failure."""
    try:
        return json.loads(raw) if raw else {}
    except (ValueError, TypeError):
        return {}


def _format_flow_section(flow: dict) -> str:
    """
    Purpose:
        Format a flow dict as a Markdown HTTP transaction block.
        Includes method, URL, headers, and body for both request and response.
    """
    lines: list[str] = []

    # Request
    method = flow.get("method", "?")
    url = flow.get("url", "?")
    req_headers = _parse_json(flow.get("request_headers", "{}"))
    req_body_raw = flow.get("request_body")

    lines.append("### Request\n")
    lines.append(f"```\n{method} {url}\n")
    for k, v in req_headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if req_body_raw:
        try:
            body_str = (
                req_body_raw.decode("utf-8", errors="replace")
                if isinstance(req_body_raw, bytes)
                else str(req_body_raw)
            )
            lines.append(body_str[:4096])
            if len(body_str) > 4096:
                lines.append(f"\n… (truncated, {len(body_str)} bytes total)")
        except Exception:  # noqa: BLE001
            lines.append("<binary body>")
    lines.append("```\n")

    # Response
    status = flow.get("status_code", "?")
    resp_headers = _parse_json(flow.get("response_headers", "{}"))
    resp_body_raw = flow.get("response_body")

    lines.append("### Response\n")
    lines.append(f"```\nHTTP {status}\n")
    for k, v in resp_headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    if resp_body_raw:
        try:
            body_str = (
                resp_body_raw.decode("utf-8", errors="replace")
                if isinstance(resp_body_raw, bytes)
                else str(resp_body_raw)
            )
            lines.append(body_str[:4096])
            if len(body_str) > 4096:
                lines.append(f"\n… (truncated, {len(body_str)} bytes total)")
        except Exception:  # noqa: BLE001
            lines.append("<binary body>")
    lines.append("```")

    return "\n".join(lines)
