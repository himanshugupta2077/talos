"""
Tests for offline unauth decision-filter apply / reclassify.

Covers:
  - BYPASS→SECURE updates unauth_results + rejects TRIAGING finding
  - CONFIRMED skipped without include_confirmed; rejected with it
  - Already REJECTED: no duplicate timeline spam
  - Dry-run writes nothing
  - Missing filter file raises FilterApplyError
  - Missing replay flow counted incomplete
  - Reverse SECURE→BYPASS: would_create_finding only
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest

from talos.projects.db import init_project_db
import talos.findings.db as findings_db
from talos.findings.model import (
    EVIDENCE_TYPE_UNAUTH_RESULT,
    FINDING_STATUS_CONFIRMED,
    FINDING_STATUS_REJECTED,
    FINDING_STATUS_TRIAGING,
    TIMELINE_ACTOR_SYSTEM,
)
from talos.projects.unauth.decision_filter import FILTER_FILENAME, write_default_filter
from talos.projects.unauth.reclassify import (
    FilterApplyError,
    apply_unauth_decision_filter,
)
from talos.replay import db as replay_db


@pytest.fixture
def project(tmp_path: Path):
    db_path = tmp_path / "talos.db"
    init_project_db(db_path)
    return tmp_path, db_path


def _role_module_ids(db_path: Path) -> tuple[str, str]:
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles WHERE name='global'").fetchone()
        mod = conn.execute("SELECT id FROM modules WHERE name='global'").fetchone()
    assert role and mod
    return role[0], mod[0]


def _insert_flow(
    db_path: Path,
    *,
    flow_id: str | None = None,
    status_code: int = 200,
    body: str = "Welcome",
    headers: dict | None = None,
) -> str:
    fid = flow_id or str(uuid.uuid4())
    hdrs = json.dumps(headers or {"Content-Type": "text/html"})
    role_id, module_id = _role_module_ids(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO flows (
                id, project_id, captured_at, method, url, host, path, query,
                request_headers, request_cookies, request_body,
                request_body_truncated, status_code, response_headers,
                response_body, response_body_truncated, content_type,
                role_id, module_id, source
            ) VALUES (
                ?, 'proj', '2020-01-01T00:00:00+00:00',
                'GET', 'https://ex.test/app', 'ex.test', '/app', '',
                '{}', '{}', NULL, 0, ?, ?, ?, 0, 'text/html',
                ?, ?, 'auto_replay'
            )
            """,
            (fid, status_code, hdrs, body.encode("utf-8"), role_id, module_id),
        )
        conn.commit()
    return fid


def _insert_unauth_result(
    db_path: Path,
    replay_id: str,
    *,
    verdict: str = "BYPASS",
    matched_section: str | None = "failed_detection",
    matched_group: str | None = "status_2xx",
    matched_rules: str | None = '["status_2xx"]',
) -> None:
    replay_db.insert_unauth_result(
        db_path,
        {
            "replay_flow_id": replay_id,
            "original_flow_id": str(uuid.uuid4()),
            "endpoint_id": "ep-1",
            "auth_mutation_family": "remove-auth",
            "auth_mutation": "remove_all_auth",
            "request_mutation_family": None,
            "request_mutation": None,
            "verdict": verdict,
            "matched_section": matched_section,
            "matched_group": matched_group,
            "matched_rules": matched_rules,
        },
    )


def _create_finding_with_evidence(
    db_path: Path,
    replay_id: str,
    *,
    status: str = FINDING_STATUS_TRIAGING,
) -> str:
    fid = findings_db.create_finding(
        db_path=db_path,
        project_id="proj",
        attack_type="unauth",
        verdict="BYPASS",
        endpoint_id="ep-1",
        title="Unauth BYPASS",
        cluster_key="UNAUTH:ep-1",
    )
    findings_db.add_evidence(
        db_path,
        fid,
        EVIDENCE_TYPE_UNAUTH_RESULT,
        replay_id,
        "Unauthenticated-execution attack result",
    )
    if status != FINDING_STATUS_TRIAGING:
        findings_db.update_finding_status(db_path, fid, status)
    return fid


def _write_pass_filter(data_dir: Path, *, body_contains: str = "Welcome") -> None:
    """
    Filter with only passed_detection (body keyword → SECURE).

    Omits failed_detection so a 200 + matching body reclassifies BYPASS→SECURE
    (failed_detection is evaluated first and would otherwise keep 2xx as BYPASS).
    """
    yaml_text = f"""\
version: 1

passed_detection:
  group_operator: OR
  groups:
    - group_id: body_noise
      operator: OR
      rules:
        - location: body
          operator: contains
          value: {body_contains}
"""
    (data_dir / FILTER_FILENAME).write_text(yaml_text, encoding="utf-8")


def _write_fail_filter(data_dir: Path) -> None:
    """Filter that classifies any 2xx as BYPASS (failed_detection only)."""
    yaml_text = """\
version: 1

failed_detection:
  group_operator: OR
  groups:
    - group_id: status_2xx
      operator: AND
      rules:
        - location: status
          operator: equals
          value: 200
"""
    (data_dir / FILTER_FILENAME).write_text(yaml_text, encoding="utf-8")


# ------------------------------------------------------------------ #
# Core paths                                                           #
# ------------------------------------------------------------------ #

def test_bypass_to_secure_rejects_triaging(project):
    data_dir, db_path = project
    replay_id = _insert_flow(db_path, status_code=200, body="Welcome guest")
    _insert_unauth_result(db_path, replay_id, verdict="BYPASS")
    fid = _create_finding_with_evidence(db_path, replay_id)

    _write_pass_filter(data_dir, body_contains="Welcome")

    summary = apply_unauth_decision_filter(
        db_path, data_dir, dry_run=False, include_confirmed=False
    )

    assert summary.results_updated == 1
    assert summary.findings_rejected == 1
    assert summary.rows[0].action == "reject"

    # Result rewritten
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT verdict, matched_section, matched_group FROM unauth_results "
            "WHERE replay_flow_id = ?",
            (replay_id,),
        ).fetchone()
    assert row[0] == "SECURE"
    assert row[1] == "passed_detection"
    assert row[2] == "body_noise"

    finding = findings_db.get_finding(db_path, fid)
    assert finding["status"] == FINDING_STATUS_REJECTED

    timeline = findings_db.list_timeline(db_path, fid)
    auto = [
        e for e in timeline
        if "Auto-rejected" in e["event"] and "Matched decision filter" in e["event"]
    ]
    assert len(auto) == 1
    assert auto[0]["actor"] == TIMELINE_ACTOR_SYSTEM


def test_confirmed_skipped_without_force(project):
    data_dir, db_path = project
    replay_id = _insert_flow(db_path, status_code=200, body="Welcome")
    _insert_unauth_result(db_path, replay_id, verdict="BYPASS")
    fid = _create_finding_with_evidence(
        db_path, replay_id, status=FINDING_STATUS_CONFIRMED
    )
    _write_pass_filter(data_dir)

    summary = apply_unauth_decision_filter(
        db_path, data_dir, dry_run=False, include_confirmed=False
    )
    assert summary.findings_rejected == 0
    assert summary.findings_skipped_confirmed == 1
    assert findings_db.get_finding(db_path, fid)["status"] == FINDING_STATUS_CONFIRMED
    # Result still updated
    with sqlite3.connect(str(db_path)) as conn:
        v = conn.execute(
            "SELECT verdict FROM unauth_results WHERE replay_flow_id = ?",
            (replay_id,),
        ).fetchone()[0]
    assert v == "SECURE"


def test_confirmed_rejected_with_include_confirmed(project):
    data_dir, db_path = project
    replay_id = _insert_flow(db_path, status_code=200, body="Welcome")
    _insert_unauth_result(db_path, replay_id, verdict="BYPASS")
    fid = _create_finding_with_evidence(
        db_path, replay_id, status=FINDING_STATUS_CONFIRMED
    )
    _write_pass_filter(data_dir)

    summary = apply_unauth_decision_filter(
        db_path, data_dir, dry_run=False, include_confirmed=True
    )
    assert summary.findings_rejected == 1
    assert findings_db.get_finding(db_path, fid)["status"] == FINDING_STATUS_REJECTED


def test_already_rejected_no_duplicate_timeline(project):
    data_dir, db_path = project
    replay_id = _insert_flow(db_path, status_code=200, body="Welcome")
    _insert_unauth_result(db_path, replay_id, verdict="BYPASS")
    fid = _create_finding_with_evidence(
        db_path, replay_id, status=FINDING_STATUS_REJECTED
    )
    _write_pass_filter(data_dir)

    # First apply (finding already REJECTED)
    apply_unauth_decision_filter(db_path, data_dir, dry_run=False)
    tl1 = findings_db.list_timeline(db_path, fid)
    auto1 = [e for e in tl1 if "Auto-rejected" in e["event"]]
    assert len(auto1) == 0  # already REJECTED → no auto-reject event

    # Second apply: result already SECURE → unchanged, still no spam
    apply_unauth_decision_filter(db_path, data_dir, dry_run=False)
    tl2 = findings_db.list_timeline(db_path, fid)
    auto2 = [e for e in tl2 if "Auto-rejected" in e["event"]]
    assert len(auto2) == 0


def test_dry_run_writes_nothing(project):
    data_dir, db_path = project
    replay_id = _insert_flow(db_path, status_code=200, body="Welcome")
    _insert_unauth_result(db_path, replay_id, verdict="BYPASS")
    fid = _create_finding_with_evidence(db_path, replay_id)
    _write_pass_filter(data_dir)

    summary = apply_unauth_decision_filter(
        db_path, data_dir, dry_run=True, include_confirmed=False
    )
    assert summary.dry_run is True
    assert summary.results_updated == 1
    assert summary.findings_rejected == 1

    with sqlite3.connect(str(db_path)) as conn:
        v = conn.execute(
            "SELECT verdict FROM unauth_results WHERE replay_flow_id = ?",
            (replay_id,),
        ).fetchone()[0]
    assert v == "BYPASS"
    assert findings_db.get_finding(db_path, fid)["status"] == FINDING_STATUS_TRIAGING


def test_missing_filter_raises(project):
    data_dir, db_path = project
    with pytest.raises(FilterApplyError):
        apply_unauth_decision_filter(db_path, data_dir, dry_run=True)


def test_incomplete_missing_flow(project):
    data_dir, db_path = project
    # Result points at non-existent flow
    missing = str(uuid.uuid4())
    _insert_unauth_result(db_path, missing, verdict="BYPASS")
    _write_pass_filter(data_dir)

    summary = apply_unauth_decision_filter(db_path, data_dir, dry_run=True)
    assert summary.incomplete == 1
    assert summary.rows[0].action == "incomplete"


def test_reverse_would_create_finding(project):
    data_dir, db_path = project
    # Stored as SECURE; filter will reclassify to BYPASS
    replay_id = _insert_flow(db_path, status_code=200, body="ok")
    _insert_unauth_result(
        db_path,
        replay_id,
        verdict="SECURE",
        matched_section="passed_detection",
        matched_group="status_401",
        matched_rules=None,
    )
    _write_fail_filter(data_dir)

    summary = apply_unauth_decision_filter(
        db_path, data_dir, dry_run=False, include_confirmed=False
    )
    assert summary.would_create_finding == 1
    assert summary.findings_rejected == 0
    # Result updated to BYPASS
    with sqlite3.connect(str(db_path)) as conn:
        v = conn.execute(
            "SELECT verdict FROM unauth_results WHERE replay_flow_id = ?",
            (replay_id,),
        ).fetchone()[0]
    assert v == "BYPASS"
    # No finding created
    findings = findings_db.list_findings(db_path, "proj")
    assert findings == []


def test_unchanged_when_filter_agrees(project):
    data_dir, db_path = project
    # 401 body Secure — already SECURE with default-like pass filter
    replay_id = _insert_flow(db_path, status_code=401, body="Unauthorized")
    _insert_unauth_result(
        db_path,
        replay_id,
        verdict="SECURE",
        matched_section="passed_detection",
        matched_group="status_401",
        matched_rules=None,
    )
    write_default_filter(data_dir)

    summary = apply_unauth_decision_filter(db_path, data_dir, dry_run=False)
    # Default filter may rematch with different group/rules → could update meta.
    # At minimum no rejects.
    assert summary.findings_rejected == 0
    assert summary.would_create_finding == 0
