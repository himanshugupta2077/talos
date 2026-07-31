"""
Tests: auth-session Phase 3 engine (mutate → one HTTP → result).

httpx is mocked; no real network. Uses asyncio.run (no pytest-asyncio).
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from talos.auth_session import db as as_db
from talos.auth_session.engine import execute_auth_session_job
from talos.auth_session.jwt_codec import encode_jwt
from talos.auth_session.models import (
    STATUS_APPROVED,
    VERDICT_SECURE,
    VERDICT_UNKNOWN,
    VERDICT_WEAK_VALIDATION,
)
from talos.projects.auth import set_auth_fields
from talos.projects.db import init_project_db

PROJECT_ID = "proj-eng"
EP = "ep-eng"
FLOW = "flow-eng"
NOW = "2026-01-01T00:00:00+00:00"
BODY = b'{"user":"u1","role":"user"}'


def _jwt() -> str:
    return encode_jwt(
        {"alg": "RS256", "typ": "JWT"},
        {"sub": "u1", "role": "user", "exp": 9999999999},
        "sig-original",
    )


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    bearer = f"Bearer {_jwt()}"
    with sqlite3.connect(str(path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, 'GET', 'api.example.com', '/api/me', '/api/me',
                    'application/json', 1, '[]', ?, ?)
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
                 query, request_headers, request_cookies, status_code,
                 response_headers, response_body, content_type,
                 endpoint_id, role_id, module_id, tags, source)
            VALUES (?, ?, ?, 'GET', 'https://api.example.com/api/me',
                    'api.example.com', '/api/me', '', ?, '{}', 200,
                    ?, ?, 'application/json', ?, '', '', '[]', 'proxy_capture')
            """,
            (
                FLOW,
                PROJECT_ID,
                NOW,
                json.dumps({"Authorization": bearer, "Host": "api.example.com"}),
                json.dumps({"content-type": "application/json"}),
                BODY,
                EP,
            ),
        )
        conn.commit()
    set_auth_fields(path, cookies=[], headers=["Authorization"])
    return path


def _seed_candidate(db_path: Path, test_id: str = "jwt.alg_none") -> tuple[str, str]:
    binding = as_db.insert_binding(
        db_path, location="header", name="Authorization", auth_type="jwt"
    )
    cand = as_db.insert_candidate(
        db_path,
        binding_id=binding.id,
        baseline_flow_id=FLOW,
        auth_type="jwt",
        test_id=test_id,
        test_family="algorithm",
        title="test",
        mutation_summary="test mutation",
        endpoint_id=EP,
        status=STATUS_APPROVED,
    )
    return binding.id, cand.id


def _meta(binding_id: str, candidate_id: str, test_id: str = "jwt.alg_none") -> dict:
    return {
        "candidate_id": candidate_id,
        "binding_id": binding_id,
        "auth_type": "jwt",
        "test_id": test_id,
        "test_family": "algorithm",
        "baseline_flow_id": FLOW,
        "endpoint_id": EP,
    }


def _mock_httpx(status: int = 200, body: bytes = BODY, headers: dict | None = None):
    resp = MagicMock()
    resp.status_code = status
    resp.content = body
    resp.headers = headers or {"content-type": "application/json"}

    client = MagicMock()
    client.request = AsyncMock(return_value=resp)
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    return patch("talos.auth_session.engine.httpx.AsyncClient", return_value=client)


def test_weak_validation_2xx_same_body(db_path: Path) -> None:
    binding_id, cand_id = _seed_candidate(db_path)
    with _mock_httpx(200, BODY):
        outcome = asyncio.run(
            execute_auth_session_job(
                FLOW, _meta(binding_id, cand_id), db_path, PROJECT_ID
            )
        )
    assert outcome.failure_reason is None
    assert outcome.auth_session_verdict == VERDICT_WEAK_VALIDATION
    assert outcome.diff_verdict == "SAME"
    assert outcome.replayed_flow_id is not None
    assert outcome.replay_status == 200

    result = as_db.get_result(db_path, outcome.replayed_flow_id)
    assert result is not None
    assert result.verdict == VERDICT_WEAK_VALIDATION
    assert result.test_id == "jwt.alg_none"
    assert result.endpoint_id == EP
    assert result.candidate_id == cand_id


def test_secure_on_401(db_path: Path) -> None:
    binding_id, cand_id = _seed_candidate(db_path)
    with _mock_httpx(401, b"Unauthorized"):
        outcome = asyncio.run(
            execute_auth_session_job(
                FLOW, _meta(binding_id, cand_id), db_path, PROJECT_ID
            )
        )
    assert outcome.failure_reason is None
    assert outcome.auth_session_verdict == VERDICT_SECURE
    assert outcome.replay_status == 401


def test_unknown_2xx_different_body(db_path: Path) -> None:
    binding_id, cand_id = _seed_candidate(db_path)
    big = b"x" * 5000
    with _mock_httpx(200, big):
        outcome = asyncio.run(
            execute_auth_session_job(
                FLOW, _meta(binding_id, cand_id), db_path, PROJECT_ID
            )
        )
    assert outcome.auth_session_verdict == VERDICT_UNKNOWN
    assert outcome.diff_verdict == "DIFFERENT"


def test_decision_filter_soft_fail_body_secure(db_path: Path) -> None:
    """Default filter body keywords force SECURE even on 2xx soft-fail."""
    from talos.auth_session.decision_filter import write_default_filter

    write_default_filter(db_path.parent)
    binding_id, cand_id = _seed_candidate(db_path)
    # Body similar length to baseline but contains soft-fail keyword.
    soft = b'{"error":"Invalid token"}'  # ~24 bytes; baseline BODY is small too
    with _mock_httpx(200, soft):
        outcome = asyncio.run(
            execute_auth_session_job(
                FLOW, _meta(binding_id, cand_id), db_path, PROJECT_ID
            )
        )
    assert outcome.failure_reason is None
    assert outcome.auth_session_verdict == VERDICT_SECURE
    assert outcome.matched_section == "passed_detection"
    assert outcome.replayed_flow_id is not None
    result = as_db.get_result(db_path, outcome.replayed_flow_id)
    assert result is not None
    assert result.matched_section == "passed_detection"


def test_one_outbound_request_per_job(db_path: Path) -> None:
    binding_id, cand_id = _seed_candidate(db_path, "jwt.invalid_signature")
    with _mock_httpx(200, BODY) as mock_cls:
        asyncio.run(
            execute_auth_session_job(
                FLOW,
                _meta(binding_id, cand_id, "jwt.invalid_signature"),
                db_path,
                PROJECT_ID,
            )
        )
        client = mock_cls.return_value
        assert client.request.await_count == 1
        call_kwargs = client.request.await_args.kwargs
        headers = dict(call_kwargs["headers"])
        auth = headers.get("Authorization") or next(
            (v for k, v in headers.items() if str(k).lower() == "authorization"),
            None,
        )
        assert auth is not None
        assert "sig-original" not in auth


def test_incomplete_meta_fails(db_path: Path) -> None:
    outcome = asyncio.run(
        execute_auth_session_job(FLOW, {}, db_path, PROJECT_ID)
    )
    assert outcome.failure_reason == "auth_session_meta_incomplete"
    assert outcome.replayed_flow_id is None


def test_meta_only_candidate_id_loads_from_db(db_path: Path) -> None:
    """candidate_id alone is enough — binding/test_id come from the row."""
    _binding_id, cand_id = _seed_candidate(db_path)
    with _mock_httpx(200, BODY):
        outcome = asyncio.run(
            execute_auth_session_job(
                FLOW,
                {"candidate_id": cand_id},
                db_path,
                PROJECT_ID,
            )
        )
    assert outcome.failure_reason is None
    assert outcome.auth_session_verdict == VERDICT_WEAK_VALIDATION
    assert outcome.test_id == "jwt.alg_none"
    assert outcome.candidate_id == cand_id


def test_cookie_header_only_preserves_sibling_cookies(tmp_path: Path) -> None:
    """
    When access_token lives only on the Cookie header (empty request_cookies),
    mutating it must not drop sibling cookies (e.g. other=keepme).
    """
    path = tmp_path / "cookie-hdr.db"
    init_project_db(path)
    token = _jwt()
    with sqlite3.connect(str(path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, 'GET', 'api.example.com', '/api/me', '/api/me',
                    'application/json', 1, '[]', ?, ?)
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
                 query, request_headers, request_cookies, status_code,
                 response_headers, response_body, content_type,
                 endpoint_id, role_id, module_id, tags, source)
            VALUES (?, ?, ?, 'GET', 'https://api.example.com/api/me',
                    'api.example.com', '/api/me', '', ?, '{}', 200,
                    ?, ?, 'application/json', ?, '', '', '[]', 'proxy_capture')
            """,
            (
                FLOW,
                PROJECT_ID,
                NOW,
                json.dumps({
                    "Cookie": f"access_token={token}; other=keepme",
                    "Host": "api.example.com",
                }),
                json.dumps({"content-type": "application/json"}),
                BODY,
                EP,
            ),
        )
        conn.commit()
    set_auth_fields(path, cookies=["access_token"], headers=[])

    binding = as_db.insert_binding(
        path, location="cookie", name="access_token", auth_type="jwt"
    )
    cand = as_db.insert_candidate(
        path,
        binding_id=binding.id,
        baseline_flow_id=FLOW,
        auth_type="jwt",
        test_id="jwt.alg_none",
        test_family="algorithm",
        title="t",
        mutation_summary="m",
        endpoint_id=EP,
        status=STATUS_APPROVED,
    )
    with _mock_httpx(200, BODY) as mock_cls:
        outcome = asyncio.run(
            execute_auth_session_job(
                FLOW,
                {
                    "candidate_id": cand.id,
                    "binding_id": binding.id,
                    "test_id": "jwt.alg_none",
                    "auth_type": "jwt",
                },
                path,
                PROJECT_ID,
            )
        )
        call_headers = dict(mock_cls.return_value.request.await_args.kwargs["headers"])
    assert outcome.failure_reason is None
    cookie_hdr = next(
        (v for k, v in call_headers.items() if str(k).lower() == "cookie"),
        None,
    )
    assert cookie_hdr is not None
    assert "other=keepme" in str(cookie_hdr)
    assert "access_token=" in str(cookie_hdr)
    # Mutated JWT must not contain the original signature segment.
    assert "sig-original" not in str(cookie_hdr)


def test_candidate_not_found(db_path: Path) -> None:
    outcome = asyncio.run(
        execute_auth_session_job(
            FLOW,
            {
                "candidate_id": "no-such",
                "binding_id": "b",
                "test_id": "jwt.alg_none",
                "auth_type": "jwt",
            },
            db_path,
            PROJECT_ID,
        )
    )
    assert outcome.failure_reason == "candidate_not_found"


def test_endpoint_not_qualified_skip(db_path: Path) -> None:
    binding_id, cand_id = _seed_candidate(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "UPDATE endpoint_policy SET qualified = 0 WHERE endpoint_id = ?",
            (EP,),
        )
        conn.commit()
    with _mock_httpx() as mock_cls:
        outcome = asyncio.run(
            execute_auth_session_job(
                FLOW, _meta(binding_id, cand_id), db_path, PROJECT_ID
            )
        )
        assert mock_cls.return_value.request.await_count == 0
    assert outcome.failure_reason == "endpoint_not_qualified"


def test_connection_error_unknown(db_path: Path) -> None:
    binding_id, cand_id = _seed_candidate(db_path)
    client = MagicMock()
    client.request = AsyncMock(side_effect=httpx.ConnectError("refused"))
    client.__aenter__ = AsyncMock(return_value=client)
    client.__aexit__ = AsyncMock(return_value=None)
    with patch("talos.auth_session.engine.httpx.AsyncClient", return_value=client):
        outcome = asyncio.run(
            execute_auth_session_job(
                FLOW, _meta(binding_id, cand_id), db_path, PROJECT_ID
            )
        )
    assert outcome.auth_session_verdict == VERDICT_UNKNOWN
    assert outcome.failure_reason is not None
    assert "connection_error" in outcome.failure_reason
    assert outcome.replayed_flow_id is not None
