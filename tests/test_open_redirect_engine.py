"""Open-redirect engine: unique replay flows + Location verdicts (httpx mocked)."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from talos.findings import db as findings_db
from talos.open_redirect.db import list_open_redirect_results
from talos.open_redirect.engine import execute_open_redirect_job
from talos.open_redirect.findings_bridge import maybe_create_open_redirect_finding
from talos.open_redirect.models import CANARY_HOST, VERDICT_OPEN_REDIRECT, VERDICT_SECURE
from talos.projects.db import init_project_db

PROJECT_ID = "proj-or"
EP = "ep-or"
FLOW = "flow-or"
NOW = "2026-01-01T00:00:00+00:00"

BASELINE_BODY = b"<html>ok</html>"


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
            VALUES (?, ?, 'GET', 'https://app.example.com', '/out',
                    '/out', 'text/html', 1, '[]', ?, ?)
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
            VALUES (?, ?, ?, 'GET', 'https://app.example.com/out?next=/home',
                    'app.example.com', '/out', 'next=/home', ?, '{}', ?, 302,
                    ?, ?, 'text/html', ?, ?, ?, '[]', 'proxy_capture')
            """,
            (
                FLOW,
                PROJECT_ID,
                NOW,
                json.dumps({"Accept": "text/html"}),
                b"",
                json.dumps({"Location": "https://app.example.com/home"}),
                BASELINE_BODY,
                EP,
                role_id,
                module_id,
            ),
        )
        conn.commit()
    return path


def _mock_response(location: str, status: int = 302) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.headers = {"location": location, "content-type": "text/html"}
    resp.content = b""
    return resp


def _meta() -> dict:
    return {
        "technique": "abs_https",
        "technique_family": "absolute",
        "location": "query",
        "param_name": "next",
        "surface_kind": "query",
        "payload_sent": f"https://{CANARY_HOST}/",
        "original_value": "/home",
        "canary_host": CANARY_HOST,
    }


def test_new_location_creates_finding(db_path: Path) -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.request.return_value = _mock_response(f"https://{CANARY_HOST}/")

    with patch("talos.open_redirect.engine.create_async_client", return_value=client):
        with patch("talos.burp.snapshot.record_send_response"):
            outcome = asyncio.run(
                execute_open_redirect_job(FLOW, _meta(), db_path, PROJECT_ID)
            )

    assert outcome.verdict == VERDICT_OPEN_REDIRECT
    assert CANARY_HOST in outcome.redirect_url
    finding_id = maybe_create_open_redirect_finding(
        db_path=db_path,
        project_id=PROJECT_ID,
        outcome=outcome,
    )
    assert finding_id
    rows = list_open_redirect_results(db_path)
    assert len(rows) == 1
    assert rows[0]["param_name"] == "next"
    finding = findings_db.get_finding(db_path, finding_id)
    assert finding["attack_type"] == "open_redirect"
    assert finding["verdict"] == VERDICT_OPEN_REDIRECT


def test_internal_redirect_is_secure(db_path: Path) -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.request.return_value = _mock_response("https://app.example.com/home")

    with patch("talos.open_redirect.engine.create_async_client", return_value=client):
        with patch("talos.burp.snapshot.record_send_response"):
            outcome = asyncio.run(
                execute_open_redirect_job(FLOW, _meta(), db_path, PROJECT_ID)
            )

    assert outcome.verdict == VERDICT_SECURE
