"""
Tests: auth-session Phase 2 extract + candidate generation.

Covers:
  - extract JWT from Authorization header (Bearer) and cookie
  - generate insert-if-absent; second generate skips
  - force-refresh reopens rejected
  - safe-method default skips POST without --include-unsafe-methods
  - no token → skip
  - explicit --flow baseline
  - claim elevation included when role claim present
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from talos.auth_session import db as as_db
from talos.auth_session.candidates import (
    generate_candidates,
    generate_for_binding_baseline,
    select_baselines_for_binding,
    BaselineSelection,
    GenerateStats,
)
from talos.auth_session.extract import (
    extract_token_context,
    get_auth_field_value,
)
from talos.auth_session.jwt_codec import encode_jwt
from talos.auth_session.models import STATUS_PENDING, STATUS_REJECTED
from talos.projects.auth import set_auth_fields
from talos.projects.db import init_project_db

PROJECT_ID = "proj-as"
EP_GET = "ep-get"
EP_POST = "ep-post"
FLOW_GET = "flow-get"
FLOW_POST = "flow-post"
FLOW_NO_JWT = "flow-no-jwt"
NOW = "2026-01-01T00:00:00+00:00"


def _make_jwt(alg: str = "RS256", **claims) -> str:
    payload = {"sub": "u1", "exp": 9999999999}
    payload.update(claims)
    return encode_jwt({"alg": alg, "typ": "JWT"}, payload, "sigbytes")


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    jwt = _make_jwt(role="user")
    bearer = f"Bearer {jwt}"
    with sqlite3.connect(str(path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, 'GET', 'api.example.com', '/api/me', '/api/me',
                    'application/json', 1, '[]', ?, ?)
            """,
            (EP_GET, PROJECT_ID, NOW, NOW),
        )
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, 'POST', 'api.example.com', '/api/orders', '/api/orders',
                    'application/json', 1, '[]', ?, ?)
            """,
            (EP_POST, PROJECT_ID, NOW, NOW),
        )
        for ep_id, flow_id, method, headers, cookies in [
            (
                EP_GET,
                FLOW_GET,
                "GET",
                json.dumps({"Authorization": bearer, "Host": "api.example.com"}),
                "{}",
            ),
            (
                EP_POST,
                FLOW_POST,
                "POST",
                json.dumps({"Authorization": bearer}),
                "{}",
            ),
            (
                EP_GET,
                FLOW_NO_JWT,
                "GET",
                json.dumps({"Authorization": "not-a-jwt"}),
                "{}",
            ),
        ]:
            conn.execute(
                """
                INSERT INTO flows
                    (id, project_id, captured_at, method, url, host, path,
                     query, request_headers, request_cookies, status_code,
                     response_headers, content_type, endpoint_id, role_id,
                     module_id, tags, source)
                VALUES (?, ?, ?, ?, ?, 'api.example.com', '/api/x', '',
                        ?, ?, 200, '{}', 'application/json', ?, '',
                        '', '[]', 'proxy_capture')
                """,
                (
                    flow_id,
                    PROJECT_ID,
                    NOW,
                    method,
                    f"https://api.example.com/api/x",
                    headers,
                    cookies,
                    ep_id,
                ),
            )
        # Only GET endpoint qualified + baseline (POST also for unsafe tests)
        for ep_id, flow_id in [(EP_GET, FLOW_GET), (EP_POST, FLOW_POST)]:
            conn.execute(
                """
                INSERT INTO endpoint_policy
                    (endpoint_id, auto_priority, auto_score, excluded,
                     dangerous, logout, qualified, qualification_reason,
                     baseline_flow_id, baseline_status, updated_at)
                VALUES (?, 'HIGH', 50, 0, 0, 0, 1, 'flow_2xx', ?, 200, ?)
                """,
                (ep_id, flow_id, NOW),
            )
        conn.commit()

    set_auth_fields(path, cookies=[], headers=["Authorization"])
    return path


def _bind(db_path: Path):
    return as_db.insert_binding(
        db_path,
        location="header",
        name="Authorization",
        auth_type="jwt",
    )


def test_extract_bearer_header(db_path: Path) -> None:
    flow = {
        "request_headers": json.dumps({
            "Authorization": f"Bearer {_make_jwt()}",
        }),
        "request_cookies": "{}",
    }
    raw = get_auth_field_value(flow, "header", "Authorization")
    assert raw and raw.startswith("Bearer ")
    binding = _bind(db_path)
    # re-get after bind
    binding = as_db.list_bindings(db_path)[0]
    ctx, reason = extract_token_context(flow, binding)
    assert reason is None
    assert ctx is not None
    assert ctx.scheme == "Bearer"
    assert ctx.header.get("alg") == "RS256"


def test_extract_cookie_jwt(db_path: Path) -> None:
    tok = _make_jwt()
    flow = {
        "request_headers": "{}",
        "request_cookies": json.dumps({"access_token": tok}),
    }
    set_auth_fields(db_path, cookies=["access_token"], headers=[])
    binding = as_db.insert_binding(
        db_path, location="cookie", name="access_token", auth_type="jwt"
    )
    ctx, reason = extract_token_context(flow, binding)
    assert reason is None
    assert ctx is not None
    assert ctx.scheme is None
    assert ctx.raw_token == tok


def test_generate_creates_pending_insert_if_absent(db_path: Path) -> None:
    _bind(db_path)
    stats = generate_candidates(
        db_path, PROJECT_ID, endpoint_id=EP_GET
    )
    assert stats.created > 0
    assert stats.bindings_processed == 1
    rows = as_db.list_candidates(db_path, status=STATUS_PENDING)
    assert len(rows) == stats.created
    # alg_none from core + degrade rs256_to_hs*
    test_ids = {r.test_id for r in rows}
    assert "jwt.alg_none" in test_ids
    assert "jwt.alg_degrade.rs256_to_hs256" in test_ids
    assert not any(t.endswith("_to_none") for t in test_ids)
    # elevate_role present (role claim in JWT)
    assert "jwt.elevate_role" in test_ids

    # Second generate: all skip existing
    stats2 = generate_candidates(
        db_path, PROJECT_ID, endpoint_id=EP_GET
    )
    assert stats2.created == 0
    assert stats2.skipped_existing >= stats.created


def test_generate_force_refresh_rejected(db_path: Path) -> None:
    _bind(db_path)
    generate_candidates(db_path, PROJECT_ID, endpoint_id=EP_GET)
    rows = as_db.list_candidates(db_path, status=STATUS_PENDING)
    cid = rows[0].id
    as_db.reject_candidates(db_path, [cid], reason="nope")
    assert as_db.get_candidate(db_path, cid).status == STATUS_REJECTED

    stats = generate_candidates(
        db_path, PROJECT_ID, endpoint_id=EP_GET, force_refresh=True
    )
    assert stats.refreshed >= 1
    assert as_db.get_candidate(db_path, cid).status == STATUS_PENDING


def test_generate_skips_post_without_unsafe_flag(db_path: Path) -> None:
    _bind(db_path)
    stats = generate_candidates(
        db_path, PROJECT_ID, endpoint_id=EP_POST
    )
    assert stats.created == 0
    assert stats.skipped_unsafe_method >= 1

    stats2 = generate_candidates(
        db_path,
        PROJECT_ID,
        endpoint_id=EP_POST,
        include_unsafe_methods=True,
    )
    assert stats2.created > 0


def test_generate_explicit_flow(db_path: Path) -> None:
    _bind(db_path)
    stats = generate_candidates(
        db_path, PROJECT_ID, flow_id=FLOW_GET
    )
    assert stats.created > 0
    rows = as_db.list_candidates(db_path)
    assert all(r.baseline_flow_id == FLOW_GET for r in rows)


def test_generate_skips_when_token_not_detectable(db_path: Path) -> None:
    _bind(db_path)
    stats = generate_candidates(
        db_path, PROJECT_ID, flow_id=FLOW_NO_JWT
    )
    assert stats.created == 0
    assert stats.skipped_no_token >= 1


def test_generate_test_id_filter(db_path: Path) -> None:
    _bind(db_path)
    stats = generate_candidates(
        db_path,
        PROJECT_ID,
        endpoint_id=EP_GET,
        test_ids=["jwt.alg_none", "jwt.invalid_signature"],
    )
    assert stats.created == 2
    ids = {r.test_id for r in as_db.list_candidates(db_path)}
    assert ids == {"jwt.alg_none", "jwt.invalid_signature"}


def test_select_baselines_explicit_flow(db_path: Path) -> None:
    binding = _bind(db_path)
    stats = GenerateStats()
    sels = select_baselines_for_binding(
        db_path,
        PROJECT_ID,
        binding,
        flow_id=FLOW_GET,
        stats=stats,
    )
    assert len(sels) == 1
    assert sels[0].source == "explicit_flow"
    assert sels[0].flow_id == FLOW_GET
