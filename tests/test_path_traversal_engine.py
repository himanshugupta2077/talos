"""Path-traversal engine: unique replay flows + file-content verdicts (httpx mocked)."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from talos.findings import db as findings_db
from talos.path_traversal.db import list_path_traversal_results
from talos.path_traversal.engine import execute_path_traversal_job
from talos.path_traversal.findings_bridge import maybe_create_path_traversal_finding
from talos.path_traversal.models import VERDICT_PATH_TRAVERSAL, VERDICT_SECURE
from talos.projects.db import init_project_db

PROJECT_ID = "proj-lfi"
EP = "ep-lfi"
FLOW = "flow-lfi"
NOW = "2026-01-01T00:00:00+00:00"

BASELINE_BODY = b"<html>download ok</html>"
PASSWD_BODY = b"root:x:0:0:root:/root:/bin/bash\n"


def _context_ids(db_path: Path) -> tuple[str, str]:
    with sqlite3.connect(str(db_path)) as conn:
        role = conn.execute("SELECT id FROM roles WHERE name='global'").fetchone()[0]
        module = conn.execute("SELECT id FROM modules WHERE name='global'").fetchone()[0]
    return role, module


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    role_id, module_id = _context_ids(path)
    with sqlite3.connect(str(path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, 'GET', 'https://app.example.com', '/view',
                    '/view', 'text/html', 1, '[]', ?, ?)
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
                 query, request_headers, request_cookies, request_body,
                 status_code, response_headers, response_body, content_type,
                 endpoint_id, role_id, module_id, tags, source)
            VALUES (?, ?, ?, 'GET', 'https://app.example.com/view?file=home.html',
                    'app.example.com', '/view', 'file=home.html', ?, '{}', ?, 200,
                    ?, ?, 'text/html', ?, ?, ?, '[]', 'proxy_capture')
            """,
            (
                FLOW,
                PROJECT_ID,
                NOW,
                json.dumps({"Accept": "text/html"}),
                b"",
                json.dumps({"Content-Type": "text/html"}),
                BASELINE_BODY,
                EP,
                role_id,
                module_id,
            ),
        )
        conn.commit()
    return path


def _mock_response(body: bytes, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.headers = {"content-type": "text/plain"}
    resp.content = body
    return resp


def _meta() -> dict:
    return {
        "technique": "unix_passwd",
        "technique_family": "unix",
        "location": "query",
        "param_name": "file",
        "surface_kind": "query",
        "payload_sent": "/etc/passwd",
        "original_value": "home.html",
    }


def test_new_passwd_creates_finding(db_path: Path) -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.request.return_value = _mock_response(PASSWD_BODY)

    with patch("talos.path_traversal.engine.create_async_client", return_value=client):
        with patch("talos.burp.snapshot.record_send_response"):
            outcome = asyncio.run(
                execute_path_traversal_job(FLOW, _meta(), db_path, PROJECT_ID)
            )

    assert outcome.verdict == VERDICT_PATH_TRAVERSAL
    assert outcome.os_hint == "unix"
    assert outcome.replayed_flow_id
    finding_id = maybe_create_path_traversal_finding(
        db_path=db_path,
        project_id=PROJECT_ID,
        outcome=outcome,
    )
    assert finding_id
    rows = list_path_traversal_results(db_path)
    assert len(rows) == 1
    assert rows[0]["param_name"] == "file"
    assert rows[0]["verdict"] == VERDICT_PATH_TRAVERSAL
    finding = findings_db.get_finding(db_path, finding_id)
    assert finding["attack_type"] == "path_traversal"
    assert finding["verdict"] == VERDICT_PATH_TRAVERSAL


def test_same_baseline_html_is_secure(db_path: Path) -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.request.return_value = _mock_response(BASELINE_BODY)

    with patch("talos.path_traversal.engine.create_async_client", return_value=client):
        with patch("talos.burp.snapshot.record_send_response"):
            outcome = asyncio.run(
                execute_path_traversal_job(FLOW, _meta(), db_path, PROJECT_ID)
            )

    assert outcome.verdict == VERDICT_SECURE
    assert maybe_create_path_traversal_finding(
        db_path=db_path, project_id=PROJECT_ID, outcome=outcome
    ) is None
