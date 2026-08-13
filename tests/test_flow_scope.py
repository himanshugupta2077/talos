"""Ranked test-flow selection for endpoint / flow attack launchers."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from talos.projects.db import init_project_db
from talos.projects.flow_scope import (
    lookup_flows,
    normalize_flow_ids,
    select_test_flows_for_endpoints,
    unique_endpoint_ids,
)

PROJECT_ID = "proj-scope"
EP_A = "ep-a"
EP_B = "ep-b"
EP_BLOCKED = "ep-blocked"
NOW = "2026-01-01T00:00:00+00:00"


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    with sqlite3.connect(str(path)) as conn:
        role = conn.execute("SELECT id FROM roles WHERE name='global'").fetchone()[0]
        module = conn.execute("SELECT id FROM modules WHERE name='global'").fetchone()[0]
        for eid, host, path_s, blocked in (
            (EP_A, "https://app.example.com", "/a", False),
            (EP_B, "https://app.example.com", "/b", False),
            (EP_BLOCKED, "https://app.example.com", "/out", True),
        ):
            conn.execute(
                """
                INSERT INTO endpoints
                    (id, project_id, method, host, path, normalized_path,
                     content_type, auth_required, roles_seen, first_seen, last_seen)
                VALUES (?, ?, 'GET', ?, ?, ?, 'application/json', 0, '[]', ?, ?)
                """,
                (eid, PROJECT_ID, host, path_s, path_s, NOW, NOW),
            )
            conn.execute(
                """
                INSERT INTO endpoint_policy
                    (endpoint_id, auto_priority, auto_score, excluded,
                     dangerous, logout, qualified, qualification_reason,
                     baseline_flow_id, baseline_status, updated_at)
                VALUES (?, 'HIGH', 50, ?, 0, 0, 1, 'flow_2xx', ?, 200, ?)
                """,
                (
                    eid,
                    1 if blocked else 0,
                    "flow-a-get" if eid == EP_A else None,
                    NOW,
                ),
            )
        # EP_A: GET baseline, newer POST, older PUT, a 404, a replay
        flows = [
            ("flow-a-get", EP_A, "GET", 200, "proxy_capture", "2026-01-01T00:00:00+00:00"),
            ("flow-a-post", EP_A, "POST", 200, "proxy_capture", "2026-01-03T00:00:00+00:00"),
            ("flow-a-put", EP_A, "PUT", 200, "proxy_capture", "2026-01-02T00:00:00+00:00"),
            ("flow-a-old", EP_A, "GET", 200, "proxy_capture", "2025-12-01T00:00:00+00:00"),
            ("flow-a-404", EP_A, "GET", 404, "proxy_capture", "2026-01-04T00:00:00+00:00"),
            ("flow-a-replay", EP_A, "POST", 200, "auto_replay", "2026-01-05T00:00:00+00:00"),
            ("flow-b-get", EP_B, "GET", 201, "proxy_capture", "2026-01-01T00:00:00+00:00"),
            ("flow-blocked", EP_BLOCKED, "GET", 200, "proxy_capture", "2026-01-01T00:00:00+00:00"),
        ]
        for fid, eid, method, status, source, captured in flows:
            conn.execute(
                """
                INSERT INTO flows
                    (id, project_id, captured_at, method, url, host, path,
                     query, request_headers, status_code, endpoint_id,
                     role_id, module_id, tags, source)
                VALUES (?, ?, ?, ?, ?, 'app.example.com', '/x', '', '{}', ?, ?,
                        ?, ?, '[]', ?)
                """,
                (
                    fid,
                    PROJECT_ID,
                    captured,
                    method,
                    f"https://app.example.com/x",
                    status,
                    eid,
                    role,
                    module,
                    source,
                ),
            )
        conn.commit()
    return path


def test_normalize_flow_ids_dedupes_and_splits() -> None:
    assert normalize_flow_ids(["a", "a,b", " c "]) == ["a", "b", "c"]
    assert normalize_flow_ids(None) == []


def test_select_top_five_prefers_baseline_then_method(db_path: Path) -> None:
    refs, skipped = select_test_flows_for_endpoints(db_path, [EP_A], limit_per_endpoint=5)
    assert skipped == []
    ids = [r.flow_id for r in refs]
    assert ids[0] == "flow-a-get"  # baseline
    assert ids[1] == "flow-a-post"  # POST over PUT
    assert ids[2] == "flow-a-put"
    assert "flow-a-404" not in ids
    assert "flow-a-replay" not in ids
    assert len(ids) == 4  # only four usable 2xx proxy captures


def test_select_caps_per_endpoint_and_skips_blocked(db_path: Path) -> None:
    refs, skipped = select_test_flows_for_endpoints(
        db_path, [EP_A, EP_B, EP_BLOCKED], limit_per_endpoint=2
    )
    ids = [r.flow_id for r in refs]
    assert ids == ["flow-a-get", "flow-a-post", "flow-b-get"]
    assert skipped == [EP_BLOCKED]


def test_lookup_preserves_operator_order(db_path: Path) -> None:
    refs, missing = lookup_flows(db_path, ["flow-b-get", "nope", "flow-a-post"])
    assert [r.flow_id for r in refs] == ["flow-b-get", "flow-a-post"]
    assert missing == ["nope"]
    assert unique_endpoint_ids(refs) == [EP_B, EP_A]
