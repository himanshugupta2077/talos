"""Unauth `run --flow` scopes jobs to operator-selected captures."""

from __future__ import annotations

import io
import json
import sqlite3
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from talos.projects.db import init_project_db
from talos.projects.unauth.cli import cmd_unauth_run
from talos.projects.unauth.recipes import UNAUTH_RECIPES
from talos.scheduler.job import UNAUTH_ATTACK

PROJECT_ID = "proj-unauth-flow"
EP = "ep-u"
FLOW = "flow-u"
FLOW_BLOCKED = "flow-blocked"
NOW = "2026-01-01T00:00:00+00:00"


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    with sqlite3.connect(str(path)) as conn:
        role = conn.execute("SELECT id FROM roles WHERE name='global'").fetchone()[0]
        module = conn.execute("SELECT id FROM modules WHERE name='global'").fetchone()[0]
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, 'GET', 'https://app.example.com', '/ok', '/ok',
                    'application/json', 0, '[]', ?, ?)
            """,
            (EP, PROJECT_ID, NOW, NOW),
        )
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, auto_priority, auto_score, excluded,
                 dangerous, logout, qualified, qualification_reason,
                 baseline_flow_id, baseline_status, updated_at)
            VALUES (?, 'HIGH', 50, 0, 0, 0, 1, 'flow_2xx', ?, 200, ?)
            """,
            (EP, FLOW, NOW),
        )
        for fid, excluded in ((FLOW, 0), (FLOW_BLOCKED, 1)):
            if fid == FLOW_BLOCKED:
                conn.execute(
                    """
                    INSERT INTO endpoints
                        (id, project_id, method, host, path, normalized_path,
                         content_type, auth_required, roles_seen, first_seen, last_seen)
                    VALUES ('ep-blocked', ?, 'GET', 'https://app.example.com', '/x', '/x',
                            'application/json', 0, '[]', ?, ?)
                    """,
                    (PROJECT_ID, NOW, NOW),
                )
                conn.execute(
                    """
                    INSERT INTO endpoint_policy
                        (endpoint_id, auto_priority, auto_score, excluded,
                         dangerous, logout, qualified, qualification_reason,
                         baseline_flow_id, baseline_status, updated_at)
                    VALUES ('ep-blocked', 'HIGH', 50, ?, 0, 0, 1, 'flow_2xx', ?, 200, ?)
                    """,
                    (excluded, FLOW_BLOCKED, NOW),
                )
            conn.execute(
                """
                INSERT INTO flows
                    (id, project_id, captured_at, method, url, host, path,
                     query, request_headers, status_code, endpoint_id,
                     role_id, module_id, tags, source)
                VALUES (?, ?, ?, 'GET', 'https://app.example.com/ok',
                        'app.example.com', '/ok', '', '{}', 200, ?,
                        ?, ?, '[]', 'proxy_capture')
                """,
                (
                    fid,
                    PROJECT_ID,
                    NOW,
                    EP if fid == FLOW else "ep-blocked",
                    role,
                    module,
                ),
            )
        conn.commit()
    return path


def _manager(db_path: Path) -> MagicMock:
    project = SimpleNamespace(db_path=db_path, id=PROJECT_ID)
    manager = MagicMock()
    manager.active.return_value = project
    return manager


def test_unauth_run_flow_enqueues_recipes(db_path: Path) -> None:
    args = SimpleNamespace(technique="baseline", flows=[FLOW])
    out = io.StringIO()
    with redirect_stdout(out):
        cmd_unauth_run(_manager(db_path), args)
    text = out.getvalue()
    assert "Jobs enqueued" in text
    with sqlite3.connect(str(db_path)) as conn:
        rows = conn.execute(
            "SELECT flow_id, job_type, meta FROM scheduler_jobs WHERE job_type = ?",
            (UNAUTH_ATTACK,),
        ).fetchall()
    assert rows
    assert all(r[0] == FLOW for r in rows)
    techniques = {json.loads(r[2])["technique"] for r in rows}
    assert techniques == {"baseline"}
    expected = sum(1 for rec in UNAUTH_RECIPES if rec["technique"] == "baseline")
    assert len(rows) == expected


def test_unauth_run_flow_skips_excluded(db_path: Path) -> None:
    args = SimpleNamespace(technique=None, flows=[FLOW_BLOCKED])
    with pytest.raises(SystemExit):
        cmd_unauth_run(_manager(db_path), args)
