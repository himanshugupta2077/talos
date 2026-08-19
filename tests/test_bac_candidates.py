"""
Tests for BAC candidate generation.

Covers:
  - Endpoint exclusions remove flows from BAC candidates
  - Path-rule exclusions remove matching endpoints
  - Unqualified endpoints never produce candidates
  - 2xx success statuses (201/202/204/206) produce candidates (not only 200)
  - --endpoint scope restricts candidates to one endpoint
  - --module scope restricts candidates to one module
  - endpoint_id and module_id are mutually exclusive
  - Project scope (default) still returns multi-endpoint candidates
  - Scoped get_testable_endpoints avoids full project when endpoint_id set
  - Engine pre-check enforces excluded / logout / dangerous / not qualified
"""

from __future__ import annotations

import asyncio
import sqlite3
from pathlib import Path

import pytest

from talos.projects.db import init_project_db
from talos.projects.policy import (
    get_testable_endpoints,
    is_endpoint_testable,
    set_dangerous,
    set_excluded,
    set_logout,
    set_path_rule,
)
from talos.projects.bac.candidates import (
    exclude_endpoints_from_candidates,
    restrict_candidates_to_flows,
    scan_candidates,
)
from talos.projects.bac.engine import execute_bac_job, _endpoint_policy_pre_check


PROJECT_ID = "proj-bac-test"
ROLE_ADMIN = "role-admin"
ROLE_USER = "role-user"
MODULE_ORDERS = "mod-orders"
MODULE_ADMIN = "mod-admin"
EP_ORDERS = "ep-orders"
EP_ADMIN = "ep-admin"
EP_EXCLUDED = "ep-excluded"
FLOW_ORDERS = "flow-orders"
FLOW_ADMIN = "flow-admin"
FLOW_EXCLUDED = "flow-excluded"


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    _seed(path)
    return path


def _seed(db_path: Path) -> None:
    """Insert roles, modules, access map, endpoints, policies, and flows."""
    now = "2026-01-01T00:00:00+00:00"
    with sqlite3.connect(str(db_path)) as conn:
        conn.executemany(
            "INSERT INTO roles (id, name) VALUES (?, ?)",
            [
                (ROLE_ADMIN, "admin"),
                (ROLE_USER, "user"),
            ],
        )
        conn.executemany(
            "INSERT INTO modules (id, name) VALUES (?, ?)",
            [
                (MODULE_ORDERS, "orders"),
                (MODULE_ADMIN, "admin-panel"),
            ],
        )
        # admin ALLOW both modules; user DENY both → BAC candidates
        conn.executemany(
            """
            INSERT INTO access_map
                (role_id, module_id, client_allowed, server_expected)
            VALUES (?, ?, ?, ?)
            """,
            [
                (ROLE_ADMIN, MODULE_ORDERS, "ALLOW", "ALLOW"),
                (ROLE_ADMIN, MODULE_ADMIN, "ALLOW", "ALLOW"),
                (ROLE_USER, MODULE_ORDERS, "DENY", "DENY"),
                (ROLE_USER, MODULE_ADMIN, "DENY", "DENY"),
            ],
        )
        conn.executemany(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (EP_ORDERS, PROJECT_ID, "GET", "api.example.com",
                 "/api/orders", "/api/orders", "application/json", 1,
                 '["admin"]', now, now),
                (EP_ADMIN, PROJECT_ID, "GET", "api.example.com",
                 "/api/admin/users", "/api/admin/users", "application/json", 1,
                 '["admin"]', now, now),
                (EP_EXCLUDED, PROJECT_ID, "GET", "api.example.com",
                 "/api/admin/secrets", "/api/admin/secrets", "application/json", 1,
                 '["admin"]', now, now),
            ],
        )
        # endpoint_policy rows — all start qualified with baselines
        for ep_id, flow_id in [
            (EP_ORDERS, FLOW_ORDERS),
            (EP_ADMIN, FLOW_ADMIN),
            (EP_EXCLUDED, FLOW_EXCLUDED),
        ]:
            conn.execute(
                """
                INSERT INTO endpoint_policy
                    (endpoint_id, auto_priority, auto_score, excluded,
                     dangerous, logout, qualified, qualification_reason,
                     baseline_flow_id, baseline_status, updated_at)
                VALUES (?, 'HIGH', 50, 0, 0, 0, 1, 'flow_2xx', ?, 200, ?)
                """,
                (ep_id, flow_id, now),
            )
        # Successful 2xx proxy_capture flows for admin on both modules
        for flow_id, ep_id, mod_id, path in [
            (FLOW_ORDERS, EP_ORDERS, MODULE_ORDERS, "/api/orders"),
            (FLOW_ADMIN, EP_ADMIN, MODULE_ADMIN, "/api/admin/users"),
            (FLOW_EXCLUDED, EP_EXCLUDED, MODULE_ADMIN, "/api/admin/secrets"),
        ]:
            conn.execute(
                """
                INSERT INTO flows
                    (id, project_id, captured_at, method, url, host, path,
                     query, request_headers, request_cookies, status_code,
                     response_headers, content_type, endpoint_id, role_id,
                     module_id, tags, source)
                VALUES (?, ?, ?, 'GET', ?, 'api.example.com', ?, '',
                        '{}', '{}', 200, '{}', 'application/json',
                        ?, ?, ?, '[]', 'proxy_capture')
                """,
                (
                    flow_id, PROJECT_ID, now,
                    f"https://api.example.com{path}", path,
                    ep_id, ROLE_ADMIN, mod_id,
                ),
            )
        conn.commit()


def _add_2xx_endpoint(
    db_path: Path,
    *,
    ep_id: str,
    flow_id: str,
    status_code: int,
    path: str,
    module_id: str = MODULE_ORDERS,
    method: str = "POST",
) -> None:
    """Insert a qualified endpoint whose only flow returns a non-200 2xx status."""
    now = "2026-01-02T00:00:00+00:00"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, ?, 'api.example.com', ?, ?,
                    'application/json', 1, '["admin"]', ?, ?)
            """,
            (ep_id, PROJECT_ID, method, path, path, now, now),
        )
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, auto_priority, auto_score, excluded,
                 dangerous, logout, qualified, qualification_reason,
                 baseline_flow_id, baseline_status, updated_at)
            VALUES (?, 'HIGH', 50, 0, 0, 0, 1, 'flow_2xx', ?, ?, ?)
            """,
            (ep_id, flow_id, status_code, now),
        )
        conn.execute(
            """
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path,
                 query, request_headers, request_cookies, status_code,
                 response_headers, content_type, endpoint_id, role_id,
                 module_id, tags, source)
            VALUES (?, ?, ?, ?, ?, 'api.example.com', ?, '',
                    '{}', '{}', ?, '{}', 'application/json',
                    ?, ?, ?, '[]', 'proxy_capture')
            """,
            (
                flow_id, PROJECT_ID, now, method,
                f"https://api.example.com{path}", path,
                status_code, ep_id, ROLE_ADMIN, module_id,
            ),
        )
        conn.commit()


# ------------------------------------------------------------------ #
# Exclusion respect                                                    #
# ------------------------------------------------------------------ #

def test_excluded_endpoint_produces_no_candidates(db_path: Path):
    """Excluding an endpoint removes its flows from BAC candidates."""
    before = scan_candidates(db_path, PROJECT_ID)
    all_flow_ids = {fid for c in before for fid in c.flow_ids}
    assert FLOW_EXCLUDED in all_flow_ids

    set_excluded(db_path, EP_EXCLUDED, excluded=True)

    after = scan_candidates(db_path, PROJECT_ID)
    after_flow_ids = {fid for c in after for fid in c.flow_ids}
    assert FLOW_EXCLUDED not in after_flow_ids
    # Other endpoints still present
    assert FLOW_ORDERS in after_flow_ids
    assert FLOW_ADMIN in after_flow_ids


def test_path_rule_exclusion_removes_matching_endpoints(db_path: Path):
    """A path rule with excluded=1 removes matching endpoints from candidates."""
    set_path_rule(
        db_path, PROJECT_ID, pattern="/api/admin/*", excluded=True
    )

    candidates = scan_candidates(db_path, PROJECT_ID)
    flow_ids = {fid for c in candidates for fid in c.flow_ids}
    assert FLOW_ADMIN not in flow_ids
    assert FLOW_EXCLUDED not in flow_ids
    assert FLOW_ORDERS in flow_ids


def test_unqualified_endpoint_excluded_from_candidates(db_path: Path):
    """Setting qualified=0 removes the endpoint from candidates."""
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            UPDATE endpoint_policy
            SET qualified = 0, qualification_reason = 'no_2xx_response'
            WHERE endpoint_id = ?
            """,
            (EP_ORDERS,),
        )
        conn.commit()

    candidates = scan_candidates(db_path, PROJECT_ID)
    flow_ids = {fid for c in candidates for fid in c.flow_ids}
    assert FLOW_ORDERS not in flow_ids
    assert FLOW_ADMIN in flow_ids


# ------------------------------------------------------------------ #
# 2xx qualification parity                                             #
# ------------------------------------------------------------------ #

@pytest.mark.parametrize("status_code", [201, 202, 204, 206])
def test_non_200_2xx_flows_produce_candidates(db_path: Path, status_code: int):
    """
    Endpoint Qualification uses BETWEEN 200 AND 299. BAC candidate generation
    must accept the same success statuses (not only 200 OK).
    """
    ep_id = f"ep-status-{status_code}"
    flow_id = f"flow-status-{status_code}"
    _add_2xx_endpoint(
        db_path,
        ep_id=ep_id,
        flow_id=flow_id,
        status_code=status_code,
        path=f"/api/resource-{status_code}",
    )

    candidates = scan_candidates(db_path, PROJECT_ID, endpoint_id=ep_id)
    flow_ids = {fid for c in candidates for fid in c.flow_ids}
    assert flow_id in flow_ids, (
        f"status {status_code} should produce BAC candidates"
    )


def test_4xx_flow_does_not_produce_candidates_for_unqualified(db_path: Path):
    """A 404-only endpoint that is not qualified yields no candidates."""
    ep_id = "ep-404"
    flow_id = "flow-404"
    now = "2026-01-03T00:00:00+00:00"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, method, host, path, normalized_path,
                 content_type, auth_required, roles_seen, first_seen, last_seen)
            VALUES (?, ?, 'GET', 'api.example.com', '/api/missing',
                    '/api/missing', 'application/json', 1, '[]', ?, ?)
            """,
            (ep_id, PROJECT_ID, now, now),
        )
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, auto_priority, auto_score, excluded,
                 dangerous, logout, qualified, qualification_reason,
                 baseline_flow_id, baseline_status, updated_at)
            VALUES (?, 'LOW', 0, 0, 0, 0, 0, 'no_2xx_response', NULL, NULL, ?)
            """,
            (ep_id, now),
        )
        conn.execute(
            """
            INSERT INTO flows
                (id, project_id, captured_at, method, url, host, path,
                 query, request_headers, request_cookies, status_code,
                 response_headers, content_type, endpoint_id, role_id,
                 module_id, tags, source)
            VALUES (?, ?, ?, 'GET', 'https://api.example.com/api/missing',
                    'api.example.com', '/api/missing', '',
                    '{}', '{}', 404, '{}', 'application/json',
                    ?, ?, ?, '[]', 'proxy_capture')
            """,
            (flow_id, PROJECT_ID, now, ep_id, ROLE_ADMIN, MODULE_ORDERS),
        )
        conn.commit()

    candidates = scan_candidates(db_path, PROJECT_ID, endpoint_id=ep_id)
    assert candidates == []


# ------------------------------------------------------------------ #
# Scoped testing                                                       #
# ------------------------------------------------------------------ #

def test_endpoint_scope_returns_only_that_endpoint(db_path: Path):
    candidates = scan_candidates(
        db_path, PROJECT_ID, endpoint_id=EP_ORDERS
    )
    assert candidates
    flow_ids = {fid for c in candidates for fid in c.flow_ids}
    assert flow_ids == {FLOW_ORDERS}
    assert all(c.module_id == MODULE_ORDERS for c in candidates)


def test_endpoint_scope_on_excluded_returns_empty(db_path: Path):
    set_excluded(db_path, EP_ORDERS, excluded=True)
    candidates = scan_candidates(
        db_path, PROJECT_ID, endpoint_id=EP_ORDERS
    )
    assert candidates == []


def test_module_scope_returns_only_that_module(db_path: Path):
    candidates = scan_candidates(
        db_path, PROJECT_ID, module_id=MODULE_ADMIN
    )
    assert candidates
    assert all(c.module_id == MODULE_ADMIN for c in candidates)
    flow_ids = {fid for c in candidates for fid in c.flow_ids}
    assert FLOW_ORDERS not in flow_ids
    assert FLOW_ADMIN in flow_ids
    assert FLOW_EXCLUDED in flow_ids


def test_attacker_role_filter_still_works(db_path: Path):
    only_user = scan_candidates(
        db_path, PROJECT_ID, attacker_role_id=ROLE_USER
    )
    assert only_user
    assert all(c.attacker_role_id == ROLE_USER for c in only_user)

    only_admin = scan_candidates(
        db_path, PROJECT_ID, attacker_role_id=ROLE_ADMIN
    )
    # admin is ALLOW on all modules — never an attacker
    assert only_admin == []


def test_endpoint_and_module_scopes_are_mutually_exclusive(db_path: Path):
    with pytest.raises(ValueError, match="mutually exclusive"):
        scan_candidates(
            db_path, PROJECT_ID,
            endpoint_id=EP_ORDERS, module_id=MODULE_ORDERS,
        )


def test_project_scope_returns_all_testable(db_path: Path):
    candidates = scan_candidates(db_path, PROJECT_ID)
    flow_ids = {fid for c in candidates for fid in c.flow_ids}
    assert FLOW_ORDERS in flow_ids
    assert FLOW_ADMIN in flow_ids
    assert FLOW_EXCLUDED in flow_ids


# ------------------------------------------------------------------ #
# Scoped Policy API                                                    #
# ------------------------------------------------------------------ #

def test_get_testable_endpoints_endpoint_scope(db_path: Path):
    rows = get_testable_endpoints(
        db_path, PROJECT_ID, endpoint_id=EP_ORDERS
    )
    assert len(rows) == 1
    assert rows[0]["id"] == EP_ORDERS


def test_get_testable_endpoints_module_scope(db_path: Path):
    rows = get_testable_endpoints(
        db_path, PROJECT_ID, module_id=MODULE_ADMIN
    )
    ids = {r["id"] for r in rows}
    assert EP_ADMIN in ids
    assert EP_EXCLUDED in ids
    assert EP_ORDERS not in ids


def test_get_testable_endpoints_scopes_mutually_exclusive(db_path: Path):
    with pytest.raises(ValueError, match="mutually exclusive"):
        get_testable_endpoints(
            db_path, PROJECT_ID,
            endpoint_id=EP_ORDERS, module_id=MODULE_ORDERS,
        )


def test_restrict_candidates_to_selected_flows(db_path: Path):
    all_cands = scan_candidates(db_path, PROJECT_ID)
    all_ids = {fid for c in all_cands for fid in c.flow_ids}
    assert FLOW_ORDERS in all_ids
    assert FLOW_ADMIN in all_ids
    filtered = restrict_candidates_to_flows(all_cands, [FLOW_ORDERS])
    kept = {fid for c in filtered for fid in c.flow_ids}
    assert kept == {FLOW_ORDERS}
    empty = restrict_candidates_to_flows(all_cands, ["no-such-flow"])
    assert empty == []


def test_exclude_endpoints_from_candidates(db_path: Path):
    all_cands = scan_candidates(db_path, PROJECT_ID)
    all_ids = {fid for c in all_cands for fid in c.flow_ids}
    assert FLOW_ORDERS in all_ids
    assert FLOW_ADMIN in all_ids
    filtered = exclude_endpoints_from_candidates(all_cands, [EP_ORDERS], db_path)
    kept = {fid for c in filtered for fid in c.flow_ids}
    assert FLOW_ORDERS not in kept
    assert FLOW_ADMIN in kept
    none_left = exclude_endpoints_from_candidates(
        all_cands, [EP_ORDERS, EP_ADMIN, EP_EXCLUDED], db_path
    )
    assert none_left == []
    unchanged = exclude_endpoints_from_candidates(all_cands, [], db_path)
    assert {fid for c in unchanged for fid in c.flow_ids} == all_ids


def test_is_endpoint_testable(db_path: Path):
    assert is_endpoint_testable(db_path, PROJECT_ID, EP_ORDERS) is True
    set_excluded(db_path, EP_ORDERS, excluded=True)
    assert is_endpoint_testable(db_path, PROJECT_ID, EP_ORDERS) is False


# ------------------------------------------------------------------ #
# Runtime defence-in-depth                                             #
# ------------------------------------------------------------------ #

def test_engine_pre_check_detects_exclusion(db_path: Path):
    assert _endpoint_policy_pre_check(db_path, PROJECT_ID, EP_ORDERS) is None

    set_excluded(db_path, EP_ORDERS, excluded=True)
    assert (
        _endpoint_policy_pre_check(db_path, PROJECT_ID, EP_ORDERS)
        == "endpoint_excluded"
    )


def test_engine_pre_check_detects_logout(db_path: Path):
    set_logout(db_path, EP_ORDERS, logout=True)
    assert (
        _endpoint_policy_pre_check(db_path, PROJECT_ID, EP_ORDERS)
        == "endpoint_annotated_logout"
    )


def test_engine_pre_check_detects_dangerous(db_path: Path):
    set_dangerous(db_path, EP_ORDERS, dangerous=True)
    assert (
        _endpoint_policy_pre_check(db_path, PROJECT_ID, EP_ORDERS)
        == "endpoint_annotated_dangerous"
    )


def test_engine_pre_check_detects_not_qualified(db_path: Path):
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            UPDATE endpoint_policy
            SET qualified = 0, qualification_reason = 'no_2xx_response'
            WHERE endpoint_id = ?
            """,
            (EP_ORDERS,),
        )
        conn.commit()
    assert (
        _endpoint_policy_pre_check(db_path, PROJECT_ID, EP_ORDERS)
        == "endpoint_not_qualified"
    )


def test_execute_bac_job_skips_excluded_endpoint(db_path: Path):
    set_excluded(db_path, EP_ORDERS, excluded=True)

    outcome = asyncio.run(
        execute_bac_job(
            flow_id=FLOW_ORDERS,
            meta={
                "attacker_role_id": ROLE_USER,
                "target_role_id": ROLE_ADMIN,
                "module_id": MODULE_ORDERS,
                "variant": "session_swap",
            },
            attack_type="bac_session_swap",
            db_path=db_path,
            project_id=PROJECT_ID,
        )
    )
    assert outcome.failure_reason == "endpoint_excluded"
    assert outcome.bac_verdict == "UNKNOWN"
    assert outcome.replayed_flow_id is None


def test_execute_bac_job_skips_dangerous_endpoint(db_path: Path):
    set_dangerous(db_path, EP_ORDERS, dangerous=True)

    outcome = asyncio.run(
        execute_bac_job(
            flow_id=FLOW_ORDERS,
            meta={
                "attacker_role_id": ROLE_USER,
                "target_role_id": ROLE_ADMIN,
                "module_id": MODULE_ORDERS,
                "variant": "session_swap",
            },
            attack_type="bac_session_swap",
            db_path=db_path,
            project_id=PROJECT_ID,
        )
    )
    assert outcome.failure_reason == "endpoint_annotated_dangerous"
    assert outcome.replayed_flow_id is None
