"""
Privilege ranks and automatic privilege-diff BAC candidates.

Covers:
  - roles.privilege schema (v58) + migration
  - create / set privilege (0 = highest)
  - same privilege = peer accounts (no automatic pair)
  - higher-vs-lower endpoint coverage becomes BAC candidates
  - built-in global is excluded from automatic pairing
  - access-map candidates still work independently
  - collect_bac_candidates merges both sources
"""

from __future__ import annotations

import argparse
import io
import sqlite3
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from talos.projects.access import (
    create_role,
    get_role,
    list_roles,
    set_role_privilege,
)
from talos.projects.bac.candidates import (
    SOURCE_ACCESS_MAP,
    SOURCE_BOTH,
    SOURCE_PRIVILEGE_DIFF,
    collect_bac_candidates,
    list_privilege_gaps,
    scan_candidates,
    scan_privilege_candidates,
)
from talos.projects.db import (
    SCHEMA_VERSION,
    get_schema_version,
    init_project_db,
    migrate_project_db,
)


PROJECT_ID = "proj-priv-bac"
ROLE_ALPHA = "role-alpha"
ROLE_BETA = "role-beta"
ROLE_PEER = "role-peer"
MODULE_APP = "mod-app"
EP_SHARED = "ep-shared"
EP_PRIV = "ep-priv"
EP_PRIV2 = "ep-priv2"
FLOW_SHARED_A = "flow-shared-a"
FLOW_PRIV_A = "flow-priv-a"
FLOW_PRIV2_A = "flow-priv2-a"
FLOW_SHARED_B = "flow-shared-b"


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


def _qualify(conn: sqlite3.Connection, ep_id: str, flow_id: str, now: str) -> None:
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


def _add_endpoint(
    conn: sqlite3.Connection, ep_id: str, path: str, now: str
) -> None:
    conn.execute(
        """
        INSERT INTO endpoints
            (id, project_id, method, host, path, normalized_path,
             content_type, auth_required, roles_seen, first_seen, last_seen)
        VALUES (?, ?, 'GET', 'app.example', ?, ?,
                'application/json', 1, '[]', ?, ?)
        """,
        (ep_id, PROJECT_ID, path, path, now, now),
    )


def _add_flow(
    conn: sqlite3.Connection,
    flow_id: str,
    ep_id: str,
    role_id: str,
    path: str,
    now: str,
) -> None:
    conn.execute(
        """
        INSERT INTO flows
            (id, project_id, captured_at, method, url, host, path,
             query, request_headers, request_cookies, status_code,
             response_headers, content_type, endpoint_id, role_id,
             module_id, tags, source)
        VALUES (?, ?, ?, 'GET', ?, 'app.example', ?, '',
                '{}', '{}', 200, '{}', 'application/json',
                ?, ?, ?, '[]', 'proxy_capture')
        """,
        (
            flow_id,
            PROJECT_ID,
            now,
            f"https://app.example{path}",
            path,
            ep_id,
            role_id,
            MODULE_APP,
        ),
    )


def _seed_roles_and_traffic(db_path: Path) -> None:
    now = "2026-08-18T00:00:00+00:00"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO roles (id, name, is_active, privilege) VALUES (?, ?, 0, ?)",
            (ROLE_ALPHA, "alpha", 0),
        )
        conn.execute(
            "INSERT INTO roles (id, name, is_active, privilege) VALUES (?, ?, 0, ?)",
            (ROLE_BETA, "beta", 1),
        )
        conn.execute(
            "INSERT INTO roles (id, name, is_active, privilege) VALUES (?, ?, 0, ?)",
            (ROLE_PEER, "peer", 0),
        )
        conn.execute(
            "INSERT INTO modules (id, name) VALUES (?, ?)",
            (MODULE_APP, "app"),
        )
        for ep_id, path in (
            (EP_SHARED, "/api/home"),
            (EP_PRIV, "/api/admin/users"),
            (EP_PRIV2, "/api/admin/settings"),
        ):
            _add_endpoint(conn, ep_id, path, now)
        _qualify(conn, EP_SHARED, FLOW_SHARED_A, now)
        _qualify(conn, EP_PRIV, FLOW_PRIV_A, now)
        _qualify(conn, EP_PRIV2, FLOW_PRIV2_A, now)
        _add_flow(conn, FLOW_SHARED_A, EP_SHARED, ROLE_ALPHA, "/api/home", now)
        _add_flow(conn, FLOW_PRIV_A, EP_PRIV, ROLE_ALPHA, "/api/admin/users", now)
        _add_flow(
            conn, FLOW_PRIV2_A, EP_PRIV2, ROLE_ALPHA, "/api/admin/settings", now
        )
        _add_flow(conn, FLOW_SHARED_B, EP_SHARED, ROLE_BETA, "/api/home", now)
        conn.commit()


def test_schema_version_has_privilege(db_path: Path) -> None:
    assert SCHEMA_VERSION >= 58
    assert get_schema_version(db_path) == SCHEMA_VERSION
    with sqlite3.connect(str(db_path)) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(roles)")}
    assert "privilege" in cols


def test_migrate_adds_privilege_column(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    with sqlite3.connect(str(path)) as conn:
        conn.executescript(
            """
            CREATE TABLE schema_version (version INTEGER NOT NULL);
            INSERT INTO schema_version (version) VALUES (57);
            CREATE TABLE roles (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                is_active INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO roles (id, name, is_active)
            VALUES ('r1', 'global', 1);
            """
        )
        conn.commit()
    migrate_project_db(path)
    assert get_schema_version(path) == SCHEMA_VERSION
    with sqlite3.connect(str(path)) as conn:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(roles)")}
        row = conn.execute("SELECT privilege FROM roles WHERE name='global'").fetchone()
    assert "privilege" in cols
    assert row[0] == 0


def test_create_and_set_privilege(db_path: Path) -> None:
    role_id = create_role(db_path, "alpha", privilege=0)
    create_role(db_path, "beta", privilege=1)
    alpha = get_role(db_path, "alpha")
    beta = get_role(db_path, "beta")
    assert alpha is not None and alpha["privilege"] == 0
    assert beta is not None and beta["privilege"] == 1
    updated = set_role_privilege(db_path, role_id, 2)
    assert updated["privilege"] == 2
    names = [r["name"] for r in list_roles(db_path) if r["name"] != "global"]
    # Ordered by privilege then name: alpha(2), beta(1) wait — 1 then 2
    assert names[0] == "beta"
    assert names[1] == "alpha"


def test_invalid_privilege_rejected(db_path: Path) -> None:
    with pytest.raises(ValueError):
        create_role(db_path, "bad", privilege=-1)
    create_role(db_path, "ok", privilege=0)
    with pytest.raises(ValueError):
        set_role_privilege(db_path, "ok", -3)


def test_same_privilege_is_not_a_candidate_pair(db_path: Path) -> None:
    _seed_roles_and_traffic(db_path)
    # peer shares privilege 0 with alpha — no automatic pair
    gaps = list_privilege_gaps(db_path, PROJECT_ID)
    pairs = {(g.target_role_name, g.attacker_role_name) for g in gaps}
    assert ("alpha", "peer") not in pairs
    assert ("peer", "alpha") not in pairs
    assert ("alpha", "beta") in pairs


def test_privilege_diff_finds_missing_endpoints(db_path: Path) -> None:
    _seed_roles_and_traffic(db_path)
    gaps = list_privilege_gaps(db_path, PROJECT_ID, attacker_role_id=ROLE_BETA)
    assert len(gaps) == 1
    gap = gaps[0]
    assert gap.target_role_name == "alpha"
    assert gap.attacker_role_name == "beta"
    assert gap.target_privilege == 0
    assert gap.attacker_privilege == 1
    paths = {ep.path for ep in gap.endpoints}
    assert paths == {"/api/admin/users", "/api/admin/settings"}
    assert "/api/home" not in paths


def test_privilege_candidates_use_attacker_identity(db_path: Path) -> None:
    _seed_roles_and_traffic(db_path)
    cands = scan_privilege_candidates(db_path, PROJECT_ID)
    assert cands
    assert all(c.source == SOURCE_PRIVILEGE_DIFF for c in cands)
    assert all(c.attacker_role_name == "beta" for c in cands)
    assert all(c.target_role_name == "alpha" for c in cands)
    flow_ids = {fid for c in cands for fid in c.flow_ids}
    assert FLOW_PRIV_A in flow_ids
    assert FLOW_PRIV2_A in flow_ids
    assert FLOW_SHARED_A not in flow_ids


def test_global_role_excluded_from_privilege_pairs(db_path: Path) -> None:
    _seed_roles_and_traffic(db_path)
    now = "2026-08-18T01:00:00+00:00"
    with sqlite3.connect(str(db_path)) as conn:
        global_id = conn.execute(
            "SELECT id FROM roles WHERE name='global'"
        ).fetchone()[0]
        _add_flow(conn, "flow-global", EP_PRIV, global_id, "/api/admin/users", now)
        conn.commit()
    gaps = list_privilege_gaps(db_path, PROJECT_ID)
    names = {g.target_role_name for g in gaps} | {g.attacker_role_name for g in gaps}
    assert "global" not in names


def test_access_map_still_independent(db_path: Path) -> None:
    _seed_roles_and_traffic(db_path)
    with sqlite3.connect(str(db_path)) as conn:
        conn.executemany(
            """
            INSERT INTO access_map
                (role_id, module_id, client_allowed, server_expected)
            VALUES (?, ?, ?, ?)
            """,
            [
                (ROLE_ALPHA, MODULE_APP, "ALLOW", "ALLOW"),
                (ROLE_BETA, MODULE_APP, "DENY", "DENY"),
            ],
        )
        conn.commit()
    map_cands = scan_candidates(db_path, PROJECT_ID)
    assert map_cands
    assert all(c.source == SOURCE_ACCESS_MAP for c in map_cands)
    merged = collect_bac_candidates(db_path, PROJECT_ID)
    assert merged
    # Same triple from both sources should collapse to one candidate.
    keys = {
        (c.target_role_id, c.attacker_role_id, c.module_id) for c in merged
    }
    assert len(keys) == 1
    assert merged[0].source in (
        SOURCE_PRIVILEGE_DIFF,
        SOURCE_ACCESS_MAP,
        SOURCE_BOTH,
    )
    only_map = collect_bac_candidates(
        db_path, PROJECT_ID, source=SOURCE_ACCESS_MAP
    )
    only_priv = collect_bac_candidates(
        db_path, PROJECT_ID, source=SOURCE_PRIVILEGE_DIFF
    )
    assert only_map
    assert only_priv


def test_collect_without_access_map_still_finds_privilege_gaps(
    db_path: Path,
) -> None:
    _seed_roles_and_traffic(db_path)
    assert scan_candidates(db_path, PROJECT_ID) == []
    collected = collect_bac_candidates(db_path, PROJECT_ID)
    assert collected
    assert all(c.source == SOURCE_PRIVILEGE_DIFF for c in collected)


def _manager(db_path: Path) -> MagicMock:
    project = SimpleNamespace(db_path=db_path, id=PROJECT_ID)
    manager = MagicMock()
    manager.active.return_value = project
    return manager


def test_role_list_and_privilege_cli(db_path: Path) -> None:
    from talos.projects.access_cli import cmd_role_create, cmd_role_list, cmd_role_privilege

    manager = _manager(db_path)
    cmd_role_create(
        manager, argparse.Namespace(name="alpha", privilege=0)
    )
    cmd_role_create(
        manager, argparse.Namespace(name="beta", privilege=2)
    )
    cmd_role_privilege(
        manager, argparse.Namespace(name_or_id="beta", privilege=1)
    )
    assert get_role(db_path, "beta")["privilege"] == 1

    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_role_list(manager, argparse.Namespace())
    out = buf.getvalue()
    assert "Privilege" in out
    assert "alpha" in out
    assert "beta" in out


def test_access_privilege_diff_cli(db_path: Path) -> None:
    from talos.projects.access_cli import cmd_access_privilege_diff

    _seed_roles_and_traffic(db_path)
    manager = _manager(db_path)
    buf = io.StringIO()
    with redirect_stdout(buf):
        cmd_access_privilege_diff(
            manager, argparse.Namespace(attacker="beta")
        )
    out = buf.getvalue()
    assert "alpha" in out
    assert "beta" in out
    assert "/api/admin/users" in out
    assert "/api/home" not in out
