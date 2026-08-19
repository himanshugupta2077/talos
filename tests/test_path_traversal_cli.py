"""CLI tests for talos attack path-traversal (enqueue unique jobs, no HTTP)."""

from __future__ import annotations

import argparse
import io
import json
import sqlite3
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from talos.path_traversal.cli import (
    build_path_traversal_parser,
    cmd_run,
    cmd_techniques,
)
from talos.projects.db import init_project_db
from talos.scheduler.db import get_next_pending
from talos.scheduler.job import PATH_TRAVERSAL_ATTACK, PRIORITY_HIGH, PRIORITY_MANUAL

PROJECT_ID = "proj-lfi-cli"
EP = "ep-lfi-cli"
FLOW = "flow-lfi-cli"
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
            VALUES (?, ?, 'GET', 'https://app.example.com', '/view', '/view',
                    'text/html', 0, '[]', ?, ?)
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
        conn.execute(
            """
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path,
                 query, request_headers, request_body, status_code,
                 endpoint_id, role_id, module_id, tags, source)
            VALUES (?, ?, ?, 'GET',
                    'https://app.example.com/view?file=home.html',
                    'app.example.com', '/view', 'file=home.html', ?, ?, 200, ?,
                    ?, ?, '[]', 'proxy_capture')
            """,
            (
                FLOW,
                PROJECT_ID,
                NOW,
                json.dumps({"Accept": "text/html"}),
                b"",
                EP,
                role,
                module,
            ),
        )
        conn.commit()
    return path


def _manager(db_path: Path) -> MagicMock:
    project = SimpleNamespace(
        db_path=db_path,
        id=PROJECT_ID,
        scope=["https://app.example.com"],
    )
    manager = MagicMock()
    manager.active.return_value = project
    return manager


def test_run_parser_accepts_param() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")
    build_path_traversal_parser(sub)
    args = parser.parse_args(
        [
            "path-traversal",
            "run",
            "--flow",
            FLOW,
            "--param",
            "file",
            "--parameter",
            "query:file",
        ]
    )
    assert args.params == ["file", "query:file"]


def test_techniques_json() -> None:
    manager = MagicMock()
    args = SimpleNamespace(output_format="json", family=None)
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_techniques(manager, args)
    data = json.loads(buf.getvalue())
    names = {row["name"] for row in data}
    assert "unix_passwd" in names
    assert "php_filter_passwd" in names


def test_run_enqueues_high_priority_jobs(db_path: Path) -> None:
    manager = _manager(db_path)
    args = SimpleNamespace(
        flows=[FLOW],
        params=["file"],
        technique="unix_passwd",
        family=None,
        right_now=False,
        high_priority=True,
        output_format="json",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_run(manager, args)
    data = json.loads(buf.getvalue())
    assert data["jobs_enqueued"] == 1
    assert data["priority"] == PRIORITY_HIGH
    nxt = get_next_pending(db_path, PROJECT_ID)
    assert nxt is not None
    assert nxt.job_type == PATH_TRAVERSAL_ATTACK
    assert nxt.priority == PRIORITY_HIGH


def test_run_no_high_priority(db_path: Path) -> None:
    manager = _manager(db_path)
    args = SimpleNamespace(
        flows=[FLOW],
        params=["file"],
        technique="unix_passwd",
        family=None,
        right_now=False,
        high_priority=False,
        output_format="json",
    )
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_run(manager, args)
    data = json.loads(buf.getvalue())
    assert data["priority"] == PRIORITY_MANUAL
