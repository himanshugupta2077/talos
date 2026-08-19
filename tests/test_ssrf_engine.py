"""SSRF engine: unique replay flows + in-band verdicts (httpx mocked)."""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from talos.findings import db as findings_db
from talos.projects.db import init_project_db
from talos.ssrf.db import list_ssrf_results
from talos.ssrf.engine import execute_ssrf_job
from talos.ssrf.findings_bridge import maybe_create_ssrf_finding
from talos.ssrf.models import VERDICT_SECURE, VERDICT_SSRF

PROJECT_ID = "proj-ssrf"
EP = "ep-ssrf"
FLOW = "flow-ssrf"
NOW = "2026-01-01T00:00:00+00:00"

BASELINE_BODY = b"<html>webhook ok</html>"
AWS_BODY = b"ami-id\nami-0abcdef1234567890\ninstance-id\ni-0123456789abcdef0\n"


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
            VALUES (?, ?, 'POST', 'https://app.example.com', '/hook',
                    '/hook', 'application/json', 1, '[]', ?, ?)
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
            VALUES (?, ?, ?, 'POST', 'https://app.example.com/hook?url=https://cdn.example/x',
                    'app.example.com', '/hook', 'url=https://cdn.example/x', ?, '{}', ?, 200,
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
        "technique": "cloud_aws_meta",
        "technique_family": "cloud",
        "location": "query",
        "param_name": "url",
        "surface_kind": "query",
        "payload_sent": "http://169.254.169.254/latest/meta-data/",
        "original_value": "https://cdn.example/x",
    }


def test_new_metadata_creates_finding(db_path: Path) -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.request.return_value = _mock_response(AWS_BODY)

    with patch("talos.ssrf.engine.create_async_client", return_value=client):
        with patch("talos.burp.snapshot.record_send_response"):
            outcome = asyncio.run(
                execute_ssrf_job(FLOW, _meta(), db_path, PROJECT_ID)
            )

    assert outcome.verdict == VERDICT_SSRF
    assert outcome.sink_hint == "cloud"
    assert outcome.replayed_flow_id
    finding_id = maybe_create_ssrf_finding(
        db_path=db_path,
        project_id=PROJECT_ID,
        outcome=outcome,
    )
    assert finding_id
    rows = list_ssrf_results(db_path)
    assert len(rows) == 1
    assert rows[0]["param_name"] == "url"
    assert rows[0]["verdict"] == VERDICT_SSRF
    finding = findings_db.get_finding(db_path, finding_id)
    assert finding["attack_type"] == "ssrf"
    assert finding["verdict"] == VERDICT_SSRF


def test_same_baseline_html_is_secure(db_path: Path) -> None:
    client = AsyncMock()
    client.__aenter__.return_value = client
    client.request.return_value = _mock_response(BASELINE_BODY)

    with patch("talos.ssrf.engine.create_async_client", return_value=client):
        with patch("talos.burp.snapshot.record_send_response"):
            outcome = asyncio.run(
                execute_ssrf_job(FLOW, _meta(), db_path, PROJECT_ID)
            )

    assert outcome.verdict == VERDICT_SECURE
