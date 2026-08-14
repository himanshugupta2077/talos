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


def test_prefer_role_over_baseline_when_role_has_jwt(db_path: Path) -> None:
    """CLI/binding --role must prefer that role's JWT flow over baseline."""
    from talos.auth_session.candidates import _prefer_jwt_bearing_flow
    from talos.replay import db as replay_db

    ROLE_A = "role-pref-a"
    ROLE_B = "role-pref-b"
    FLOW_ROLE_A = "flow-role-a-jwt"
    jwt_a = _make_jwt(role="admin")
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO roles (id, name) VALUES (?, ?)",
            (ROLE_A, "pref-admin"),
        )
        conn.execute(
            "INSERT INTO roles (id, name) VALUES (?, ?)",
            (ROLE_B, "pref-user"),
        )
        # Extra flow for preferred role on EP_GET (baseline is FLOW_GET).
        conn.execute(
            """
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path,
                 query, request_headers, request_cookies, status_code,
                 response_headers, content_type, endpoint_id, role_id,
                 module_id, tags, source)
            VALUES (?, ?, ?, 'GET', 'https://api.example.com/api/x',
                    'api.example.com', '/api/x', '', ?, '{}', 200, '{}',
                    'application/json', ?, ?, '', '[]', 'proxy_capture')
            """,
            (
                FLOW_ROLE_A,
                PROJECT_ID,
                NOW,
                json.dumps({"Authorization": f"Bearer {jwt_a}"}),
                EP_GET,
                ROLE_A,
            ),
        )
        # Stamp baseline as ROLE_B so roles differ.
        conn.execute(
            "UPDATE flows SET role_id = ? WHERE id = ?",
            (ROLE_B, FLOW_GET),
        )
        conn.commit()

    binding = _bind(db_path)
    primary = replay_db.get_flow_for_replay(db_path, FLOW_GET)
    assert primary is not None
    primary = dict(primary)
    primary["_baseline_source"] = "baseline_policy"

    chosen, source = _prefer_jwt_bearing_flow(
        db_path, PROJECT_ID, EP_GET, binding, ROLE_A, primary
    )
    assert chosen is not None
    assert chosen["id"] == FLOW_ROLE_A
    assert source == "role_preferred"


def test_prefer_does_not_return_non_jwt_primary(db_path: Path) -> None:
    """If no JWT-bearing flow exists, return None (not a garbage baseline)."""
    from talos.auth_session.candidates import _prefer_jwt_bearing_flow
    from talos.replay import db as replay_db

    binding = _bind(db_path)
    primary = replay_db.get_flow_for_replay(db_path, FLOW_NO_JWT)
    assert primary is not None
    # Only FLOW_NO_JWT on a dedicated endpoint would be ideal; here primary
    # is non-JWT but EP_GET still has FLOW_GET with JWT → falls to that.
    # Use preferred role with only non-JWT, and no other JWT on endpoint
    # by scanning a fake endpoint id that only has FLOW_NO_JWT.
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "UPDATE flows SET endpoint_id = ? WHERE id = ?",
            ("ep-orphan", FLOW_NO_JWT),
        )
        conn.commit()

    primary = dict(primary)
    primary["endpoint_id"] = "ep-orphan"
    chosen, source = _prefer_jwt_bearing_flow(
        db_path, PROJECT_ID, "ep-orphan", binding, None, primary
    )
    assert chosen is None
    assert source == "none"


def _add_method_endpoint(
    db_path: Path,
    *,
    ep_id: str,
    flow_id: str,
    method: str,
    path: str,
    captured_at: str = NOW,
) -> None:
    jwt = _make_jwt(role="user")
    bearer = f"Bearer {jwt}"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, ?, 'api.example.com', ?, ?,
                    'application/json', 1, '[]', ?, ?)
            """,
            (ep_id, PROJECT_ID, method, path, path, captured_at, captured_at),
        )
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, auto_priority, auto_score, excluded,
                 dangerous, logout, qualified, qualification_reason,
                 baseline_flow_id, baseline_status, updated_at)
            VALUES (?, 'HIGH', 50, 0, 0, 0, 1, 'flow_2xx', ?, 200, ?)
            """,
            (ep_id, flow_id, captured_at),
        )
        conn.execute(
            """
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path,
                 query, request_headers, request_cookies, status_code,
                 response_headers, content_type, endpoint_id, role_id,
                 module_id, tags, source)
            VALUES (?, ?, ?, ?, ?,
                    'api.example.com', ?, '', ?, '{}', 200,
                    '{}', 'application/json', ?, '', '', '[]', 'proxy_capture')
            """,
            (
                flow_id,
                PROJECT_ID,
                captured_at,
                method,
                f"https://api.example.com{path}",
                path,
                json.dumps({"Authorization": bearer}),
                ep_id,
            ),
        )
        conn.commit()


def test_select_top_jwt_targets_method_diversity(db_path: Path) -> None:
    from talos.auth_session.candidates import select_top_jwt_targets

    _add_method_endpoint(
        db_path, ep_id="ep-patch", flow_id="flow-patch",
        method="PATCH", path="/api/item",
    )
    _add_method_endpoint(
        db_path, ep_id="ep-put", flow_id="flow-put",
        method="PUT", path="/api/item2",
    )
    _add_method_endpoint(
        db_path, ep_id="ep-get2", flow_id="flow-get2",
        method="GET", path="/api/other",
    )
    binding = _bind(db_path)
    picks = select_top_jwt_targets(db_path, PROJECT_ID, binding, limit=5)
    methods = [p.method.upper() for p in picks]
    assert "GET" in methods
    assert "POST" in methods
    assert "PATCH" in methods
    assert methods.count("PUT") == 0 or "PATCH" in methods
    assert len(picks) <= 5
    assert len({p.flow_id for p in picks}) == len(picks)


def test_add_and_remove_target_flow(db_path: Path) -> None:
    from talos.auth_session.candidates import (
        add_target_flow,
        list_target_flows,
        remove_target_flow,
    )

    binding = _bind(db_path)
    stats = add_target_flow(db_path, PROJECT_ID, binding, FLOW_POST)
    assert stats.created > 0
    targets = list_target_flows(db_path, binding_id=binding.id)
    ids = {t["flow_id"] for t in targets}
    assert FLOW_POST in ids

    result = remove_target_flow(
        db_path, binding_id=binding.id, flow_id=FLOW_POST
    )
    assert result["ok"] is True
    assert result["deleted"] > 0
    leftover = {
        t["flow_id"]
        for t in list_target_flows(db_path, binding_id=binding.id)
    }
    assert FLOW_POST not in leftover
