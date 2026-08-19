"""XSS engine: unique replay flows + canary verdicts (httpx mocked)."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from talos.findings import db as findings_db
from talos.xss.db import list_xss_results
from talos.xss.engine import execute_xss_job
from talos.xss.findings_bridge import maybe_create_xss_finding
from talos.xss.models import CANARY, VERDICT_HTMLI, VERDICT_SECURE, VERDICT_XSS
from talos.projects.db import init_project_db

PROJECT_ID = "proj-xss"
EP = "ep-xss"
FLOW = "flow-xss"
NOW = "2026-01-01T00:00:00+00:00"

BASELINE_BODY = b"<html>search ok</html>"
XSS_BODY = f"<html>hello<script>alert('{CANARY}')</script></html>".encode()
HTMLI_BODY = f"<html><h1>{CANARY}</h1></html>".encode()


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
            VALUES (?, ?, 'GET', 'https://app.example.com', '/search',
                    '/search', 'text/html', 1, '[]', ?, ?)
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
            VALUES (?, ?, ?, 'GET', 'https://app.example.com/search?q=hello',
                    'app.example.com', '/search', 'q=hello', ?, '{}', ?, 200,
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
    resp.headers = {"content-type": "text/html"}
    resp.content = body
    return resp


def _meta(*, technique="script_alert", family="html_tag", payload=None, risk="xss") -> dict:
    return {
        "technique": technique,
        "technique_family": family,
        "location": "query",
        "param_name": "q",
        "surface_kind": "query",
        "payload_sent": payload or f"<script>alert('{CANARY}')</script>",
        "original_value": "hello",
        "risk_class": risk,
    }


def test_raw_script_creates_finding(db_path: Path) -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.request.return_value = _mock_response(XSS_BODY)

    with patch("talos.xss.engine.create_async_client", return_value=client):
        with patch("talos.burp.snapshot.record_send_response"):
            outcome = asyncio.run(
                execute_xss_job(FLOW, _meta(), db_path, PROJECT_ID)
            )

    assert outcome.verdict == VERDICT_XSS
    assert outcome.replayed_flow_id
    finding_id = maybe_create_xss_finding(
        db_path=db_path,
        project_id=PROJECT_ID,
        outcome=outcome,
    )
    assert finding_id
    rows = list_xss_results(db_path)
    assert len(rows) == 1
    assert rows[0]["param_name"] == "q"
    assert rows[0]["verdict"] == VERDICT_XSS
    finding = findings_db.get_finding(db_path, finding_id)
    assert finding["attack_type"] == "xss"
    assert finding["verdict"] == VERDICT_XSS


def test_h1_creates_htmli_finding(db_path: Path) -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.request.return_value = _mock_response(HTMLI_BODY)

    with patch("talos.xss.engine.create_async_client", return_value=client):
        with patch("talos.burp.snapshot.record_send_response"):
            outcome = asyncio.run(
                execute_xss_job(
                    FLOW,
                    _meta(
                        technique="h1_tag",
                        family="htmli",
                        payload=f"<h1>{CANARY}</h1>",
                        risk="htmli",
                    ),
                    db_path,
                    PROJECT_ID,
                )
            )

    assert outcome.verdict == VERDICT_HTMLI
    finding_id = maybe_create_xss_finding(
        db_path=db_path, project_id=PROJECT_ID, outcome=outcome
    )
    assert finding_id


def test_same_baseline_html_is_secure(db_path: Path) -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.request.return_value = _mock_response(BASELINE_BODY)

    with patch("talos.xss.engine.create_async_client", return_value=client):
        with patch("talos.burp.snapshot.record_send_response"):
            outcome = asyncio.run(
                execute_xss_job(FLOW, _meta(), db_path, PROJECT_ID)
            )

    assert outcome.verdict == VERDICT_SECURE
    assert maybe_create_xss_finding(
        db_path=db_path, project_id=PROJECT_ID, outcome=outcome
    ) is None
