"""
Control Panel URL Sink Discovery API tests (PR3).

Covers inventory filters (K13), status aggregates without IV join (K14),
param_uuid parity (K10), and per-project config load (K20).
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parents[1]
MONOREPO = Path(__file__).resolve().parents[3]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))
if str(MONOREPO) not in sys.path:
    sys.path.insert(0, str(MONOREPO))


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
    monkeypatch.setattr(cfg, "TALOS_ROOT", MONOREPO)
    return talos_home, projects, registry


def _write_registry(registry: Path, projects: dict):
    registry.write_text(json.dumps(projects), encoding="utf-8")


def _seed_url_sink_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    host = "https://api.example.com"
    rows = [
        # High-score NRS redirect
        (
            "p1",
            "ep1",
            "callback",
            "query",
            json.dumps(
                {
                    "score": 95,
                    "possible_network_resource": True,
                    "name_category": "redirect",
                    "name_categories": ["redirect"],
                    "looks_like": ["url"],
                    "evidence": ["value_scheme:https"],
                }
            ),
            '["https://cdn.example/x"]',
        ),
        # Webhook body
        (
            "p2",
            "ep2",
            "hook_url",
            "body",
            json.dumps(
                {
                    "score": 88,
                    "possible_network_resource": True,
                    "name_category": "webhook",
                    "name_categories": ["webhook"],
                    "looks_like": ["url", "hostname"],
                }
            ),
            '["https://hooks.example/a"]',
        ),
        # Low score non-NRS (name-only)
        (
            "p3",
            "ep1",
            "next",
            "query",
            json.dumps(
                {
                    "score": 25,
                    "possible_network_resource": False,
                    "name_category": "redirect",
                    "name_categories": ["redirect"],
                    "looks_like": [],
                }
            ),
            '["/home"]',
        ),
        # JWT inventory-only
        (
            "p4",
            "ep1",
            "jwt.jku",
            "header",
            json.dumps(
                {
                    "score": 90,
                    "possible_network_resource": True,
                    "name_category": None,
                    "looks_like": ["url"],
                }
            ),
            '["https://keys.example/jwks"]',
        ),
        # Score 50 NRS no category
        (
            "p5",
            "ep3",
            "abc",
            "query",
            json.dumps(
                {
                    "score": 50,
                    "possible_network_resource": True,
                    "name_category": None,
                    "looks_like": ["hostname"],
                }
            ),
            '["cdn.internal"]',
        ),
    ]
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE endpoints (
              id TEXT PRIMARY KEY, host TEXT, method TEXT, path TEXT,
              normalized_path TEXT
            );
            CREATE TABLE parameters (
              id TEXT PRIMARY KEY, endpoint_id TEXT, name TEXT, location TEXT,
              param_type TEXT, semantic_type TEXT, example_values TEXT,
              seen_count INTEGER DEFAULT 1, url_features TEXT
            );
            CREATE TABLE iv_param_profiles (
              param_uuid TEXT PRIMARY KEY,
              host TEXT, location TEXT, param_name TEXT,
              profile TEXT, updated_at TEXT
            );
            INSERT INTO endpoints (id, host, method, path, normalized_path) VALUES
              ('ep1', 'https://api.example.com', 'GET', '/avatar', '/avatar'),
              ('ep2', 'https://api.example.com', 'POST', '/hook', '/hook'),
              ('ep3', 'https://other.example.com', 'GET', '/x', '/x');
            """
        )
        for pid, eid, name, loc, uf, ex in rows:
            conn.execute(
                """
                INSERT INTO parameters
                  (id, endpoint_id, name, location, param_type, semantic_type,
                   example_values, seen_count, url_features)
                VALUES (?, ?, ?, ?, 'string', 'url', ?, 1, ?)
                """,
                (pid, eid, name, loc, ex, uf),
            )
        # IV profile for callback only (include_iv path)
        from talos.input_validation.db import make_param_uuid

        uuid_cb = make_param_uuid(host, "query", "callback")
        prof = {
            "param_uuid": uuid_cb,
            "name": "callback",
            "location": "query",
            "host": host,
            "capabilities": ["network_resource_sink", "redirect_sink"],
            "candidates": [
                {"attack": "ssrf", "score": 72, "confidence": 60},
                {"attack": "xss", "score": 90, "confidence": 80},
            ],
            "observed": {
                "url_sink": {
                    "confidence": 92,
                    "accepts_url": True,
                    "fetch_behavior": False,
                    "redirect_behavior": True,
                },
                "url_features": {
                    "score": 95,
                    "possible_network_resource": True,
                },
            },
        }
        conn.execute(
            """
            INSERT INTO iv_param_profiles
              (param_uuid, host, location, param_name, profile, updated_at)
            VALUES (?, ?, 'query', 'callback', ?, '2026-01-01T00:00:00Z')
            """,
            (uuid_cb, host, json.dumps(prof)),
        )
        conn.commit()
    finally:
        conn.close()


@pytest.fixture()
def client(home):
    talos_home, projects, registry = home
    pid = "proj1"
    data_dir = projects / pid
    data_dir.mkdir()
    db_path = data_dir / "talos.db"
    _seed_url_sink_db(db_path)
    _write_registry(
        registry,
        {
            pid: {
                "id": pid,
                "name": "proj1",
                "status": "active",
                "data_dir": str(data_dir),
            }
        },
    )
    from talos_ui.main import app

    return TestClient(app), pid, data_dir


def test_status_parameters_only_no_iv_default(client):
    tc, pid, _ = client
    from talos.url_sink.config import UrlSinkRuntimeConfig

    with patch(
        "talos.url_sink.config.load_url_sink_config_for_project",
        return_value=UrlSinkRuntimeConfig(
            passive_enabled=True,
            html_js_enabled=True,
            iv_probes_enabled=True,
            score_threshold=45,
        ),
    ):
        with patch(
            "talos.url_sink.config.get_process_url_sink_config",
            side_effect=AssertionError("process cache forbidden"),
        ):
            r = tc.get("/api/url-sink/status", params={"project_id": pid})
    assert r.status_code == 200
    body = r.json()
    assert body["enabled_passive"] is True
    assert body["score_threshold"] == 45
    assert body["nrs_count"] >= 3  # p1,p2,p4,p5
    assert body["score_ge_70"] >= 2
    assert body["iv_characterized_count"] is None
    assert "disclaimer" in body
    assert body["total_params"] == 5


def test_status_uses_project_config_not_defaults(client):
    tc, pid, data_dir = client
    from talos.url_sink.config import UrlSinkRuntimeConfig

    with patch(
        "talos.url_sink.config.load_url_sink_config_for_project",
        return_value=UrlSinkRuntimeConfig(
            passive_enabled=False,
            html_js_enabled=False,
            iv_probes_enabled=False,
            score_threshold=70,
        ),
    ) as load_cfg:
        r = tc.get("/api/url-sink/status", params={"project_id": pid})
        assert r.status_code == 200
        body = r.json()
        assert body["enabled_passive"] is False
        assert body["score_threshold"] == 70
        assert body["score_ge_threshold"] == body["score_ge_70"]
        load_cfg.assert_called()
        call_args = load_cfg.call_args
        assert Path(call_args[0][0]) == data_dir


def test_inventory_defaults_nrs_and_min_score(client):
    tc, pid, _ = client
    r = tc.get("/api/url-sink/inventory", params={"project_id": pid})
    assert r.status_code == 200
    body = r.json()
    assert body["filters_applied"]["min_score"] == 45
    assert body["filters_applied"]["nrs_only"] is True
    # Low-score non-NRS "next" excluded
    names = {i["name"] for i in body["items"]}
    assert "next" not in names
    assert "callback" in names
    assert body["total_matched"] >= 3


def test_inventory_filters_category_host_location(client):
    tc, pid, _ = client
    r = tc.get(
        "/api/url-sink/inventory",
        params={
            "project_id": pid,
            "category": "webhook",
            "min_score": 0,
            "nrs_only": "false",
        },
    )
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["name"] == "hook_url"

    r2 = tc.get(
        "/api/url-sink/inventory",
        params={
            "project_id": pid,
            "host": "OTHER.example",  # case-insensitive contains
            "min_score": 0,
            "nrs_only": "true",
        },
    )
    assert r2.status_code == 200
    assert r2.json()["total_matched"] == 1
    assert r2.json()["items"][0]["name"] == "abc"

    r3 = tc.get(
        "/api/url-sink/inventory",
        params={
            "project_id": pid,
            "location": "header",
            "min_score": 0,
            "nrs_only": "false",
        },
    )
    assert r3.json()["items"][0]["inventory_only"] is True
    assert r3.json()["items"][0]["name"] == "jwt.jku"


def test_inventory_include_iv_page_bounded(client):
    tc, pid, _ = client
    from talos.input_validation.db import make_param_uuid

    expected = make_param_uuid("https://api.example.com", "query", "callback")
    r = tc.get(
        "/api/url-sink/inventory",
        params={
            "project_id": pid,
            "search": "callback",
            "min_score": 0,
            "nrs_only": "false",
            "include_iv": "true",
        },
    )
    assert r.status_code == 200
    items = r.json()["items"]
    assert len(items) == 1
    assert items[0]["param_uuid"] == expected
    iv = items[0].get("iv")
    assert iv is not None
    assert iv["has_profile"] is True
    assert "network_resource_sink" in iv["capabilities"]
    assert iv["url_sink_confidence"] == 92
    assert iv["top_url_candidate"]["attack"] == "ssrf"


def test_param_uuid_matches_core_helper(client):
    tc, pid, _ = client
    from talos.input_validation.db import make_param_uuid

    host = "https://api.example.com"
    r = tc.get(
        "/api/url-sink/inventory",
        params={
            "project_id": pid,
            "search": "callback",
            "min_score": 0,
            "nrs_only": "false",
        },
    )
    item = r.json()["items"][0]
    assert item["param_uuid"] == make_param_uuid(host, "query", "callback")


def test_overview_and_by_endpoint(client):
    tc, pid, _ = client
    r = tc.get("/api/url-sink/overview", params={"project_id": pid, "top_n": 5})
    assert r.status_code == 200
    body = r.json()
    assert "status" in body
    assert "top_sinks" in body
    assert body["empty_state"]["no_params"] is False
    assert body["empty_state"]["no_nrs"] is False

    r2 = tc.get(
        "/api/url-sink/by-endpoint/ep1",
        params={"project_id": pid},
    )
    assert r2.status_code == 200
    be = r2.json()
    assert be["count"] >= 2
    assert be["nrs_count"] >= 1
    assert be["max_score"] >= 90


def test_inventory_search_and_sort(client):
    tc, pid, _ = client
    r = tc.get(
        "/api/url-sink/inventory",
        params={
            "project_id": pid,
            "min_score": 0,
            "nrs_only": "false",
            "sort": "score_asc",
            "limit": 10,
        },
    )
    scores = [i["url_score"] for i in r.json()["items"]]
    assert scores == sorted(scores)

    r2 = tc.get(
        "/api/url-sink/inventory",
        params={
            "project_id": pid,
            "search": "hook",
            "min_score": 0,
            "nrs_only": "false",
        },
    )
    assert r2.json()["total_matched"] == 1
    assert r2.json()["items"][0]["name"] == "hook_url"
