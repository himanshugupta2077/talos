"""SQLi engine: unique replay flows + error-based verdicts (httpx mocked)."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from talos.findings import db as findings_db
from talos.projects.db import init_project_db
from talos.sqli.db import list_sqli_results
from talos.sqli.engine import execute_sqli_job
from talos.sqli.findings_bridge import maybe_create_sqli_finding
from talos.sqli.models import VERDICT_SECURE, VERDICT_SQLI

PROJECT_ID = "proj-sqli"
EP = "ep-sqli"
FLOW = "flow-sqli"
NOW = "2026-01-01T00:00:00+00:00"

BASELINE_BODY = (
    b'{"error":"(\'22007\', \'[22007] [Microsoft][ODBC Driver 17 for SQL Server]'
    b"[SQL Server]Conversion failed when converting date and/or time from "
    b"character string. (241) (SQLExecDirectW)')\",\"ok\":false}"
)
SYNTAX_BODY = (
    b'{"error":"[Microsoft][ODBC Driver 17 for SQL Server][SQL Server]'
    b"Unclosed quotation mark after the character string.\"}"
)


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
            VALUES (?, ?, 'POST', 'https://app.example.com', '/api/n',
                    '/api/n', 'application/json', 1, '[]', ?, ?)
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
            VALUES (?, ?, ?, 'POST', 'https://app.example.com/api/n',
                    'app.example.com', '/api/n', '', ?, '{}', ?, 200,
                    ?, ?, 'application/json', ?, ?, ?, '[]', 'proxy_capture')
            """,
            (
                FLOW,
                PROJECT_ID,
                NOW,
                json.dumps({"Content-Type": "application/json"}),
                b'["test","test","info","111111-11-11T11:11"]',
                json.dumps({"Content-Type": "application/json"}),
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
    resp.headers = {"content-type": "application/json"}
    resp.content = body
    return resp


def _meta() -> dict:
    return {
        "technique": "quote_single",
        "technique_family": "error",
        "location": "body",
        "param_name": "[3]",
        "surface_kind": "json_body",
        "payload_sent": "'",
        "original_value": "111111-11-11T11:11",
        "delay_s": 0,
    }


def test_new_sql_error_creates_finding(db_path: Path) -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.request.return_value = _mock_response(SYNTAX_BODY)

    with patch("talos.sqli.engine.create_async_client", return_value=client):
        with patch("talos.burp.snapshot.record_send_response"):
            outcome = asyncio.run(
                execute_sqli_job(FLOW, _meta(), db_path, PROJECT_ID)
            )

    assert outcome.verdict == VERDICT_SQLI
    assert outcome.dbms == "sqlserver"
    assert outcome.replayed_flow_id
    finding_id = maybe_create_sqli_finding(
        db_path=db_path,
        project_id=PROJECT_ID,
        outcome=outcome,
    )
    assert finding_id
    rows = list_sqli_results(db_path)
    assert len(rows) == 1
    assert rows[0]["param_name"] == "[3]"
    assert rows[0]["verdict"] == VERDICT_SQLI
    finding = findings_db.get_finding(db_path, finding_id)
    assert finding["attack_type"] == "sqli"
    assert finding["verdict"] == VERDICT_SQLI


def test_same_baseline_error_is_secure(db_path: Path) -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.request.return_value = _mock_response(BASELINE_BODY)

    with patch("talos.sqli.engine.create_async_client", return_value=client):
        with patch("talos.burp.snapshot.record_send_response"):
            outcome = asyncio.run(
                execute_sqli_job(FLOW, _meta(), db_path, PROJECT_ID)
            )

    assert outcome.verdict == VERDICT_SECURE
    assert maybe_create_sqli_finding(
        db_path=db_path, project_id=PROJECT_ID, outcome=outcome
    ) is None
