"""Smuggle engine: unique replay flows + mocked raw socket."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import patch

import pytest

from talos.findings import db as findings_db
from talos.projects.db import init_project_db
from talos.smuggle.db import list_smuggle_results
from talos.smuggle.engine import execute_smuggle_job
from talos.smuggle.findings_bridge import maybe_create_smuggle_finding
from talos.smuggle.models import VERDICT_SECURE, VERDICT_SMUGGLE
from talos.smuggle.transport import RawResponse

PROJECT_ID = "proj-smuggle"
EP = "ep-smuggle"
FLOW = "flow-smuggle"
NOW = "2026-01-01T00:00:00+00:00"


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
            VALUES (?, ?, 'POST', 'https://app.example.com', '/login',
                    '/login', 'application/json', 1, '[]', ?, ?)
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
            VALUES (?, ?, ?, 'POST', 'https://app.example.com/login',
                    'app.example.com', '/login', '', ?, '{}', ?, 200,
                    ?, ?, 'application/json', ?, ?, ?, '[]', 'proxy_capture')
            """,
            (
                FLOW,
                PROJECT_ID,
                NOW,
                json.dumps({"Cookie": "sid=abc"}),
                b"user=a",
                json.dumps({"Content-Type": "text/html"}),
                b"ok",
                EP,
                role_id,
                module_id,
            ),
        )
        conn.commit()
    return path


class _ScriptedConn:
    def __init__(self, replies: list[RawResponse]) -> None:
        self.replies = list(replies)
        self.sent: list[bytes] = []
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)

    def read_response(self, timeout=None) -> RawResponse:  # noqa: ANN001
        del timeout
        if not self.replies:
            raise OSError("no more scripted replies")
        return self.replies.pop(0)

    def close(self) -> None:
        self.closed = True


def _resp(status: int, body: bytes = b"ok") -> RawResponse:
    return RawResponse(status=status, reason="OK", body=body, headers=[("Content-Type", "text/html")])


def _meta() -> dict:
    return {"technique": "cl_te", "technique_family": "cl_te", "nonce": "aabbccdd"}


def test_poisoned_followup_creates_finding(db_path: Path) -> None:
    conn = _ScriptedConn(
        [
            _resp(200),  # baseline
            _resp(200),  # probe
            _resp(404, b"Not Found"),  # follow-up
        ]
    )

    def _connect(url: str, timeout: float = 8.0) -> _ScriptedConn:
        del url, timeout
        return conn

    with patch("talos.smuggle.engine.match_ntlm_profile", return_value=None):
        with patch("talos.burp.snapshot.record_request"):
            with patch("talos.burp.snapshot.record_http_response"):
                outcome = execute_smuggle_job(
                    FLOW, _meta(), db_path, PROJECT_ID, connect_fn=_connect
                )

    assert outcome.verdict == VERDICT_SMUGGLE
    assert outcome.replayed_flow_id
    assert outcome.baseline_status == 200
    assert outcome.followup_status == 404
    assert conn.closed
    assert any(b"Transfer-Encoding" in chunk or b"transfer-encoding" in chunk.lower() for chunk in conn.sent)

    finding_id = maybe_create_smuggle_finding(
        db_path=db_path, project_id=PROJECT_ID, outcome=outcome
    )
    assert finding_id
    rows = list_smuggle_results(db_path)
    assert len(rows) == 1
    assert rows[0]["technique"] == "cl_te"
    finding = findings_db.get_finding(db_path, finding_id)
    assert finding["attack_type"] == "smuggle"
    assert finding["verdict"] == VERDICT_SMUGGLE
    assert finding["cluster_key"] == "SMUGGLE:https://app.example.com"


def test_matching_followup_is_secure(db_path: Path) -> None:
    conn = _ScriptedConn([_resp(200), _resp(400), _resp(200)])

    def _connect(url: str, timeout: float = 8.0) -> _ScriptedConn:
        del url, timeout
        return conn

    with patch("talos.smuggle.engine.match_ntlm_profile", return_value=None):
        with patch("talos.burp.snapshot.record_request"):
            with patch("talos.burp.snapshot.record_http_response"):
                outcome = execute_smuggle_job(
                    FLOW, _meta(), db_path, PROJECT_ID, connect_fn=_connect
                )

    assert outcome.verdict == VERDICT_SECURE
    assert maybe_create_smuggle_finding(
        db_path=db_path, project_id=PROJECT_ID, outcome=outcome
    ) is None


def test_unknown_flow() -> None:
    from pathlib import Path as P
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        path = P(tmp) / "talos.db"
        init_project_db(path)
        outcome = execute_smuggle_job("missing", _meta(), path, PROJECT_ID)
    assert outcome.failure_reason == "flow_not_found"
    assert outcome.replayed_flow_id is None
