"""
Control Panel Passive Secret Detection routes — smoke tests.
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
    monorepo = Path(__file__).resolve().parents[3]
    monkeypatch.setattr(cfg, "TALOS_ROOT", monorepo)
    return talos_home, projects, registry


def _write_registry(registry: Path, projects: dict):
    registry.write_text(json.dumps(projects), encoding="utf-8")


def _init_passive_db(db_path: Path, project_id: str = "proj1"):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    try:
        conn.executescript(
            """
            CREATE TABLE source_documents (
                id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                body_hash TEXT NOT NULL,
                source_kind TEXT NOT NULL,
                body_size INTEGER NOT NULL,
                truncated INTEGER NOT NULL DEFAULT 0,
                scanner_version TEXT,
                scan_status TEXT NOT NULL DEFAULT 'pending',
                first_flow_id TEXT,
                first_seen TEXT,
                last_seen TEXT,
                last_scanned_at TEXT,
                error_message TEXT,
                parent_document_id TEXT,
                logical_source_name TEXT,
                UNIQUE (project_id, body_hash)
            );
            CREATE TABLE source_occurrences (
                id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL,
                flow_id TEXT,
                endpoint_id TEXT,
                url TEXT NOT NULL DEFAULT '',
                host TEXT NOT NULL DEFAULT '',
                path TEXT NOT NULL DEFAULT '',
                logical_source_name TEXT,
                content_type TEXT NOT NULL DEFAULT '',
                observed_at TEXT NOT NULL,
                role_id TEXT NOT NULL DEFAULT '',
                module_id TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE passive_detections (
                id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL,
                occurrence_id TEXT,
                detector_id TEXT NOT NULL,
                detector_family TEXT NOT NULL,
                category TEXT NOT NULL,
                secret_type TEXT NOT NULL DEFAULT '',
                matched_key TEXT,
                redacted_value TEXT NOT NULL DEFAULT '',
                value_fingerprint TEXT NOT NULL,
                confidence_score INTEGER NOT NULL DEFAULT 0,
                confidence_level TEXT NOT NULL,
                entropy REAL,
                encoding_chain TEXT NOT NULL DEFAULT '[]',
                decode_depth INTEGER NOT NULL DEFAULT 0,
                match_start INTEGER NOT NULL DEFAULT 0,
                match_end INTEGER NOT NULL DEFAULT 0,
                context_before TEXT NOT NULL DEFAULT '',
                context_after TEXT NOT NULL DEFAULT '',
                suppressed INTEGER NOT NULL DEFAULT 0,
                suppression_reason TEXT,
                finding_id TEXT,
                raw_value_stored INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE passive_scan_config (
                id TEXT PRIMARY KEY DEFAULT 'default',
                enabled INTEGER NOT NULL DEFAULT 1,
                auto_finding_threshold TEXT NOT NULL DEFAULT 'HIGH',
                max_document_size INTEGER NOT NULL DEFAULT 2000000,
                max_decode_depth INTEGER NOT NULL DEFAULT 3,
                max_decode_bytes INTEGER NOT NULL DEFAULT 256000,
                max_candidates_per_document INTEGER NOT NULL DEFAULT 500,
                scan_html INTEGER NOT NULL DEFAULT 1,
                scan_javascript INTEGER NOT NULL DEFAULT 1,
                scan_json INTEGER NOT NULL DEFAULT 1,
                scan_xml INTEGER NOT NULL DEFAULT 1,
                scan_text INTEGER NOT NULL DEFAULT 1,
                scan_css INTEGER NOT NULL DEFAULT 1,
                scan_sourcemaps INTEGER NOT NULL DEFAULT 1,
                scan_wasm INTEGER NOT NULL DEFAULT 0,
                store_raw_secret_in_evidence INTEGER NOT NULL DEFAULT 1,
                store_suppressed_detections INTEGER NOT NULL DEFAULT 0,
                queue_maxsize INTEGER NOT NULL DEFAULT 500,
                max_scan_time_ms INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO passive_scan_config (id) VALUES ('default');
            """
        )
        conn.execute(
            """
            INSERT INTO source_documents (
                id, project_id, body_hash, source_kind, body_size,
                scanner_version, scan_status, first_flow_id,
                first_seen, last_seen, last_scanned_at
            ) VALUES (
                'doc-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                ?, 'hashabc123', 'javascript', 1200,
                '1.3.0', 'scanned', 'flow-1111',
                '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
                '2026-01-01T00:00:00Z'
            )
            """,
            (project_id,),
        )
        conn.execute(
            """
            INSERT INTO source_occurrences (
                id, document_id, flow_id, url, host, path,
                content_type, observed_at
            ) VALUES (
                'occ-1111',
                'doc-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                'flow-1111',
                'https://app.example.com/static/app.js',
                'app.example.com', '/static/app.js',
                'application/javascript', '2026-01-01T00:00:00Z'
            )
            """
        )
        conn.execute(
            """
            INSERT INTO passive_detections (
                id, document_id, occurrence_id,
                detector_id, detector_family, category, secret_type,
                matched_key, redacted_value, value_fingerprint,
                confidence_score, confidence_level, encoding_chain,
                context_before, context_after, created_at, finding_id
            ) VALUES (
                'det-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                'doc-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                'occ-1111',
                'aws_access_key_id', 'provider', 'secret', 'aws_access_key',
                'AWS_KEY', 'AKIA****************', 'fp-secret-1',
                95, 'CONFIRMED_PATTERN', '[]',
                'const k=', ';', '2026-01-01T00:00:00Z',
                'finding-1111'
            )
            """
        )
        conn.execute(
            """
            INSERT INTO passive_detections (
                id, document_id, occurrence_id,
                detector_id, detector_family, category, secret_type,
                redacted_value, value_fingerprint,
                confidence_score, confidence_level, encoding_chain,
                created_at
            ) VALUES (
                'det-infra-bbbb-cccc-dddd-eeeeeeeeeeee',
                'doc-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
                'occ-1111',
                'internal_ip', 'infrastructure', 'infrastructure_disclosure',
                'internal_ip',
                '10.***.***.***', 'fp-ip-1',
                40, 'OBSERVATION_ONLY', '[]',
                '2026-01-01T00:00:01Z'
            )
            """
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
    _init_passive_db(db_path, pid)
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

    return TestClient(app), pid


def test_passive_status_route(client):
    tc, pid = client
    r = tc.get("/api/passive/status", params={"project_id": pid})
    assert r.status_code == 200
    body = r.json()
    assert body["enabled"] is True
    assert body["documents"] == 1
    assert body["detections"] == 2
    assert body["detections_with_finding"] == 1
    assert "scanner_version" in body


def test_passive_overview_route(client):
    tc, pid = client
    r = tc.get("/api/passive/overview", params={"project_id": pid})
    assert r.status_code == 200
    body = r.json()
    assert "status" in body
    assert "top_detections" in body
    assert body["empty_state"]["no_documents"] is False
    # Redaction: no raw_value keys
    for det in body["top_detections"]:
        assert "raw_value" not in det
        assert det.get("redacted_value")


def test_passive_config_get(client):
    tc, pid = client
    r = tc.get("/api/passive/config", params={"project_id": pid})
    assert r.status_code == 200
    body = r.json()
    assert body["config"]["enabled"] is True
    assert "enabled" in body["keys"]


def test_passive_config_set_argv(client):
    tc, pid = client

    class FakeResult:
        ok = True

        def to_dict(self):
            return {"ok": True, "cmd": ["passive", "config", "set"], "stdout": ""}

    with patch("talos_ui.cli.run_scoped") as mock_run:
        mock_run.return_value = [FakeResult()]
        r = tc.post(
            "/api/passive/config",
            params={"project_id": pid},
            json={"key": "enabled", "value": False},
        )
    assert r.status_code == 200
    mock_run.assert_called()
    args = mock_run.call_args[0][1]
    assert args[:3] == ["passive", "config", "set"]
    assert args[3] == "enabled"
    assert args[4] == "false"


def test_passive_documents_list(client):
    tc, pid = client
    r = tc.get("/api/passive/documents", params={"project_id": pid})
    assert r.status_code == 200
    docs = r.json()["documents"]
    assert len(docs) == 1
    assert docs[0]["source_kind"] == "javascript"


def test_passive_document_show_short_id(client):
    tc, pid = client
    r = tc.get(
        "/api/passive/documents/doc-aaaa",
        params={"project_id": pid},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["document"]["id"].startswith("doc-aaaa")
    assert len(body["occurrences"]) == 1
    assert len(body["detections"]) == 2


def test_passive_detections_list_filters(client):
    tc, pid = client
    r = tc.get(
        "/api/passive/detections",
        params={"project_id": pid, "category": "secret"},
    )
    assert r.status_code == 200
    dets = r.json()["detections"]
    assert len(dets) == 1
    assert dets[0]["category"] == "secret"
    assert "raw_value" not in dets[0]
    assert "AKIA" in dets[0]["redacted_value"] or "*" in dets[0]["redacted_value"]


def test_passive_detection_show(client):
    tc, pid = client
    r = tc.get(
        "/api/passive/detections/det-aaaa",
        params={"project_id": pid},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["detection"]["detector_id"] == "aws_access_key_id"
    assert "raw_value" not in body["detection"]
    assert body["document"] is not None
    assert body["occurrence"] is not None


def test_passive_rescan_argv(client):
    tc, pid = client

    class FakeResult:
        ok = True

        def to_dict(self):
            return {"ok": True, "stdout": "Rescan complete"}

    with patch("talos_ui.cli.run_scoped") as mock_run:
        mock_run.return_value = [FakeResult()]
        r = tc.post(
            "/api/passive/rescan",
            params={"project_id": pid},
            json={"mode": "all", "force": True},
        )
    assert r.status_code == 200
    args = mock_run.call_args[0][1]
    assert args == ["passive", "rescan", "--all", "--force"]
    # Extended timeout
    assert mock_run.call_args[1].get("timeout") == 300 or (
        len(mock_run.call_args) > 1
        and mock_run.call_args.kwargs.get("timeout") == 300
    )


def test_passive_by_flow(client):
    tc, pid = client
    r = tc.get(
        "/api/passive/by-flow/flow-1111",
        params={"project_id": pid},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["document_id"].startswith("doc-")
    assert body["detection_count"] == 2
    assert body["has_finding"] is True


def test_passive_rules_list(client):
    tc, pid = client
    r = tc.get("/api/passive/rules", params={"project_id": pid})
    assert r.status_code == 200
    body = r.json()
    assert "rules" in body
    # Package rules should load from monorepo
    assert isinstance(body["rules"], list)
