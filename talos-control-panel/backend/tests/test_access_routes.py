"""
Access Model routes: matrix enrichment, structured coverage/signals,
mutations via CLI, delete --force, bulk apply.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


@pytest.fixture()
def home(tmp_path, monkeypatch):
    talos_home = tmp_path / "talos-home"
    talos_home.mkdir()
    projects = talos_home / "projects"
    projects.mkdir()
    registry = projects / "registry.json"
    monkeypatch.setenv("TALOS_HOME", str(talos_home))
    import talos_ui.config as cfg

    monkeypatch.setattr(cfg, "TALOS_HOME", talos_home)
    monkeypatch.setattr(cfg, "PROJECTS_ROOT", projects)
    monkeypatch.setattr(cfg, "REGISTRY_PATH", registry)
    return talos_home, projects, registry


@pytest.fixture()
def client(home):
    from talos_ui.main import app

    return TestClient(app)


def _ok_result(cmd=None):
    r = MagicMock()
    r.ok = True
    r.to_dict.return_value = {
        "cmd": cmd or [],
        "stdout": "ok",
        "stderr": "",
        "exit_code": 0,
        "ok": True,
    }
    return r


def _write_registry(registry: Path, projects: dict):
    registry.write_text(json.dumps(projects), encoding="utf-8")


def _seed_access_db(projects_root: Path, project_id: str = "demo") -> Path:
    data_dir = projects_root / project_id
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "talos.db"
    conn = sqlite3.connect(str(db_path))
    conn.executescript(
        """
        CREATE TABLE roles (
          id TEXT PRIMARY KEY,
          name TEXT UNIQUE NOT NULL,
          is_active INTEGER DEFAULT 0
        );
        CREATE TABLE modules (
          id TEXT PRIMARY KEY,
          name TEXT UNIQUE NOT NULL,
          description TEXT DEFAULT '',
          is_active INTEGER DEFAULT 0
        );
        CREATE TABLE access_map (
          role_id TEXT NOT NULL,
          module_id TEXT NOT NULL,
          client_allowed TEXT,
          server_expected TEXT,
          PRIMARY KEY (role_id, module_id)
        );
        CREATE TABLE flows (
          id TEXT PRIMARY KEY,
          role_id TEXT,
          module_id TEXT,
          endpoint_id TEXT
        );
        CREATE TABLE endpoints (
          id TEXT PRIMARY KEY,
          method TEXT,
          host TEXT,
          normalized_path TEXT
        );
        CREATE TABLE endpoint_roles (
          endpoint_id TEXT NOT NULL,
          role_id TEXT NOT NULL,
          PRIMARY KEY (endpoint_id, role_id)
        );

        INSERT INTO roles VALUES ('r-global', 'global', 1);
        INSERT INTO roles VALUES ('r-admin', 'admin', 0);
        INSERT INTO roles VALUES ('r-user', 'user', 0);
        INSERT INTO modules VALUES ('m-global', 'global', '', 1);
        INSERT INTO modules VALUES ('m-orders', 'orders', 'Orders', 0);

        INSERT INTO access_map VALUES ('r-admin', 'm-orders', 'ALLOW', 'ALLOW');
        INSERT INTO access_map VALUES ('r-user', 'm-orders', 'DENY', 'DENY');

        INSERT INTO endpoints VALUES ('e1', 'GET', 'api.example.com', '/orders');
        INSERT INTO flows VALUES ('f1', 'r-admin', 'm-orders', 'e1');
        INSERT INTO flows VALUES ('f2', 'r-user', 'm-orders', 'e1');
        INSERT INTO endpoint_roles VALUES ('e1', 'r-admin');
        INSERT INTO endpoint_roles VALUES ('e1', 'r-user');
        """
    )
    conn.commit()
    conn.close()
    return db_path


def test_matrix_enriched_with_counts(client, home):
    _, projects, registry = home
    _seed_access_db(projects)
    _write_registry(
        registry,
        {
            "demo": {
                "id": "demo",
                "name": "demo",
                "status": "inactive",
                "data_dir": str(projects / "demo"),
            }
        },
    )
    res = client.get("/api/access/matrix", params={"project_id": "demo"})
    assert res.status_code == 200
    cells = res.json()["cells"]
    assert len(cells) == 3 * 2  # 3 roles × 2 modules
    admin_orders = next(
        c
        for c in cells
        if c["role_name"] == "admin" and c["module_name"] == "orders"
    )
    assert admin_orders["client_allowed"] == "ALLOW"
    assert admin_orders["server_expected"] == "ALLOW"
    assert admin_orders["flow_count"] == 1
    assert admin_orders["endpoint_count"] == 1


def test_coverage_structured(client, home):
    _, projects, registry = home
    _seed_access_db(projects)
    _write_registry(
        registry,
        {
            "demo": {
                "id": "demo",
                "name": "demo",
                "status": "inactive",
                "data_dir": str(projects / "demo"),
            }
        },
    )
    res = client.get("/api/access/coverage", params={"project_id": "demo"})
    assert res.status_code == 200
    rows = res.json()["rows"]
    assert len(rows) == 2
    names = {(r["role_name"], r["module_name"]) for r in rows}
    assert ("admin", "orders") in names
    assert ("user", "orders") in names


def test_signals_structured(client, home):
    _, projects, registry = home
    _seed_access_db(projects)
    _write_registry(
        registry,
        {
            "demo": {
                "id": "demo",
                "name": "demo",
                "status": "inactive",
                "data_dir": str(projects / "demo"),
            }
        },
    )
    res = client.get("/api/access/signals", params={"project_id": "demo"})
    assert res.status_code == 200
    data = res.json()
    assert "multi_role" in data
    assert "server_deny_endpoints" in data
    assert "deny_with_flows" in data
    assert "allow_without_flows" in data
    # user DENY on orders but has flows
    deny = data["deny_with_flows"]
    assert any(r["role_name"] == "user" and r["module_name"] == "orders" for r in deny)
    # multi-role endpoint e1
    assert any(r["endpoint_id"] == "e1" for r in data["multi_role"])


def test_delete_uses_force(client):
    with patch("talos_ui.routers.access.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result(["access", "delete", "user", "orders", "--force"])]
        res = client.post(
            "/api/access/delete",
            params={"project_id": "demo"},
            json={"role": "user", "module": "orders"},
        )
        assert res.status_code == 200
        args = run_scoped.call_args[0]
        assert args[0] == "demo"
        assert args[1] == ["access", "delete", "user", "orders", "--force"]


def test_client_set_uses_cli(client):
    with patch("talos_ui.routers.access.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/access/client",
            params={"project_id": "demo"},
            json={"role": "admin", "module": "orders", "value": "ALLOW"},
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "access",
            "client",
            "set",
            "admin",
            "orders",
            "allow",
        ]


def test_bulk_apply_multiple_ops(client):
    with patch("talos_ui.routers.access.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/access/bulk",
            params={"project_id": "demo"},
            json={
                "operations": [
                    {
                        "op": "client_set",
                        "role": "admin",
                        "module": "orders",
                        "value": "allow",
                    },
                    {
                        "op": "server_set",
                        "role": "admin",
                        "module": "orders",
                        "value": "ALLOW",
                    },
                    {"op": "client_unset", "role": "user", "module": "orders"},
                    {"op": "delete", "role": "user", "module": "global"},
                ]
            },
        )
        assert res.status_code == 200
        body = res.json()
        assert body["applied"] == 4
        assert body["failed"] == 0
        assert run_scoped.call_count == 4
        calls = [c[0][1] for c in run_scoped.call_args_list]
        assert calls[0] == ["access", "client", "set", "admin", "orders", "allow"]
        assert calls[1] == ["access", "server", "set", "admin", "orders", "allow"]
        assert calls[2] == ["access", "client", "unset", "user", "orders"]
        assert calls[3] == ["access", "delete", "user", "global", "--force"]


def test_bulk_empty_rejected(client):
    res = client.post(
        "/api/access/bulk",
        params={"project_id": "demo"},
        json={"operations": []},
    )
    assert res.status_code == 400


def test_bulk_too_many_rejected(client):
    ops = [
        {"op": "client_unset", "role": "a", "module": "b"}
        for _ in range(201)
    ]
    res = client.post(
        "/api/access/bulk",
        params={"project_id": "demo"},
        json={"operations": ops},
    )
    assert res.status_code == 400
