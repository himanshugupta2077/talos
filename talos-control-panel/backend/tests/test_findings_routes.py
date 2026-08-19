"""
P0 findings: notes routes (CLI stdin), PRIMARY/LINKED list filters, lifecycle --linked.
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


def _seed_findings_db(projects_root: Path, project_id: str = "demo") -> Path:
    data_dir = projects_root / project_id
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "talos.db"
    conn = sqlite3.connect(str(db_path))
    conn.executescript(
        """
        CREATE TABLE findings (
          id TEXT PRIMARY KEY,
          project_id TEXT NOT NULL,
          attack_type TEXT,
          verdict TEXT,
          endpoint_id TEXT,
          status TEXT,
          duplicate_of TEXT,
          created_at TEXT,
          updated_at TEXT,
          title TEXT,
          notes TEXT,
          relation_type TEXT DEFAULT 'PRIMARY',
          parent_finding_id TEXT,
          cluster_key TEXT
        );
        CREATE TABLE finding_evidence (
          id TEXT PRIMARY KEY,
          finding_id TEXT,
          evidence_type TEXT,
          reference_id TEXT,
          label TEXT,
          data TEXT,
          created_at TEXT
        );
        CREATE TABLE finding_timeline (
          id TEXT PRIMARY KEY,
          finding_id TEXT,
          event TEXT,
          actor TEXT,
          created_at TEXT
        );
        CREATE TABLE finding_groups (
          id TEXT PRIMARY KEY,
          project_id TEXT,
          name TEXT,
          created_at TEXT
        );
        CREATE TABLE finding_group_members (
          group_id TEXT,
          finding_id TEXT
        );
        CREATE TABLE roles (
          id TEXT PRIMARY KEY,
          name TEXT
        );
        CREATE TABLE modules (
          id TEXT PRIMARY KEY,
          name TEXT
        );
        """
    )
    conn.execute(
        """
        INSERT INTO findings
        (id, project_id, attack_type, verdict, endpoint_id, status, duplicate_of,
         created_at, updated_at, title, notes, relation_type, parent_finding_id, cluster_key)
        VALUES
        ('p1', ?, 'unauth', 'BYPASS', NULL, 'TRIAGING', NULL,
         '2026-01-01T00:00:00', '2026-01-01T00:00:00', 'Primary bypass', '',
         'PRIMARY', NULL, 'UNAUTH:ep1'),
        ('l1', ?, 'unauth', 'BYPASS', NULL, 'TRIAGING', NULL,
         '2026-01-01T00:01:00', '2026-01-01T00:01:00', 'Linked empty_auth', '',
         'LINKED', 'p1', 'UNAUTH:ep1'),
        ('l2', ?, 'unauth', 'SECURE', NULL, 'TRIAGING', NULL,
         '2026-01-01T00:02:00', '2026-01-01T00:02:00', 'Linked baseline', '',
         'LINKED', 'p1', 'UNAUTH:ep1'),
        ('solo', ?, 'bac', 'POSSIBLE_BAC', NULL, 'CONFIRMED', NULL,
         '2026-01-02T00:00:00', '2026-01-02T00:00:00', 'Solo BAC', 'note here',
         'PRIMARY', NULL, NULL)
        """,
        (project_id, project_id, project_id, project_id),
    )
    conn.commit()
    conn.close()
    return db_path


def _register_demo(registry: Path, projects_root: Path):
    data_dir = projects_root / "demo"
    _write_registry(
        registry,
        {
            "demo": {
                "id": "demo",
                "name": "demo",
                "data_dir": str(data_dir),
                "status": "active",
            }
        },
    )


def test_bulk_lifecycle_confirm(client, home):
    _, projects_root, registry = home
    _write_registry(
        registry,
        {"demo": {"id": "demo", "name": "demo", "status": "ACTIVE", "path": "demo"}},
    )
    _seed_findings_db(projects_root)

    with patch("talos_ui.routers.findings.cli.run_scoped") as scoped:
        scoped.return_value = [_ok_result(["finding", "confirm", "p1"])]
        res = client.post(
            "/api/findings/bulk",
            params={"project_id": "demo"},
            json={"action": "confirm", "finding_ids": ["p1", "l1"], "linked": False},
        )
    assert res.status_code == 200
    body = res.json()
    assert body["requested"] == 2
    assert body["ok"] == 2
    assert body["action"] == "confirm"
    assert scoped.call_count == 2


def test_bulk_lifecycle_rejects_empty(client, home):
    _, projects_root, registry = home
    _write_registry(
        registry,
        {"demo": {"id": "demo", "name": "demo", "status": "ACTIVE", "path": "demo"}},
    )
    _seed_findings_db(projects_root)
    res = client.post(
        "/api/findings/bulk",
        params={"project_id": "demo"},
        json={"action": "reject", "finding_ids": []},
    )
    assert res.status_code == 400


def test_bulk_group_add(client, home):
    _, projects_root, registry = home
    _write_registry(
        registry,
        {"demo": {"id": "demo", "name": "demo", "status": "ACTIVE", "path": "demo"}},
    )
    _seed_findings_db(projects_root)

    with patch("talos_ui.routers.findings.cli.run_scoped") as scoped:
        scoped.return_value = [_ok_result(["finding", "group", "add", "G", "p1"])]
        res = client.post(
            "/api/findings/bulk/group",
            params={"project_id": "demo"},
            json={"group": "Report", "finding_ids": ["p1", "solo"]},
        )
    assert res.status_code == 200
    assert res.json()["ok"] == 2
    assert scoped.call_count == 2


def test_list_findings_defaults_to_primary(client, home):
    _talos_home, projects_root, registry = home
    _seed_findings_db(projects_root)
    _register_demo(registry, projects_root)

    res = client.get("/api/findings", params={"project_id": "demo"})
    assert res.status_code == 200
    body = res.json()
    assert body["view"] == "primary"
    ids = {f["id"] for f in body["findings"]}
    assert "p1" in ids
    assert "solo" in ids
    assert "l1" not in ids
    assert "l2" not in ids
    primary = next(f for f in body["findings"] if f["id"] == "p1")
    assert primary["linked_count"] == 2


def test_list_findings_hides_rejected_by_default(client, home):
    _talos_home, projects_root, registry = home
    db_path = _seed_findings_db(projects_root)
    _register_demo(registry, projects_root)
    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        INSERT INTO findings
        (id, project_id, attack_type, verdict, endpoint_id, status, duplicate_of,
         created_at, updated_at, title, notes, relation_type, parent_finding_id, cluster_key)
        VALUES
        ('rej', ?, 'bac', 'POSSIBLE_BAC', NULL, 'REJECTED', NULL,
         '2026-01-03T00:00:00', '2026-01-03T00:00:00', 'Rejected BAC', '',
         'PRIMARY', NULL, NULL)
        """,
        ("demo",),
    )
    conn.commit()
    conn.close()

    hidden = client.get("/api/findings", params={"project_id": "demo"}).json()
    assert {f["id"] for f in hidden["findings"]} == {"p1", "solo"}

    only_rej = client.get(
        "/api/findings", params={"project_id": "demo", "status": "REJECTED"}
    ).json()
    assert {f["id"] for f in only_rej["findings"]} == {"rej"}

    all_rows = client.get(
        "/api/findings", params={"project_id": "demo", "status": "all"}
    ).json()
    assert {f["id"] for f in all_rows["findings"]} == {"p1", "solo", "rej"}


def test_project_summary_excludes_rejected_findings(client, home):
    _talos_home, projects_root, registry = home
    db_path = _seed_findings_db(projects_root)
    _register_demo(registry, projects_root)
    conn = sqlite3.connect(str(db_path))
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS flows (id TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS endpoints (id TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS scheduler_jobs (
          job_id TEXT PRIMARY KEY,
          status TEXT
        );
        """
    )
    conn.execute(
        """
        INSERT INTO findings
        (id, project_id, attack_type, verdict, endpoint_id, status, duplicate_of,
         created_at, updated_at, title, notes, relation_type, parent_finding_id, cluster_key)
        VALUES
        ('rej', ?, 'bac', 'POSSIBLE_BAC', NULL, 'REJECTED', NULL,
         '2026-01-03T00:00:00', '2026-01-03T00:00:00', 'Rejected BAC', '',
         'PRIMARY', NULL, NULL)
        """,
        ("demo",),
    )
    conn.commit()
    conn.close()

    res = client.get("/api/projects/demo/summary")
    assert res.status_code == 200
    body = res.json()
    assert body["findings_primary"] == 2
    assert body["findings_total"] == 4
    assert body["findings_triaging"] == 3
    assert body["findings_confirmed"] == 1


def test_project_summary_primary_and_total_findings(client, home):
    _talos_home, projects_root, registry = home
    db_path = _seed_findings_db(projects_root)
    _register_demo(registry, projects_root)
    conn = sqlite3.connect(str(db_path))
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS flows (id TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS endpoints (id TEXT PRIMARY KEY);
        CREATE TABLE IF NOT EXISTS scheduler_jobs (
          job_id TEXT PRIMARY KEY,
          status TEXT
        );
        """
    )
    conn.commit()
    conn.close()

    res = client.get("/api/projects/demo/summary")
    assert res.status_code == 200
    body = res.json()
    assert body["findings_primary"] == 2
    assert body["findings_total"] == 4
    assert body["findings_triaging"] == 3
    assert body["findings_confirmed"] == 1


def test_list_findings_linked_and_all(client, home):
    _talos_home, projects_root, registry = home
    _seed_findings_db(projects_root)
    _register_demo(registry, projects_root)

    linked = client.get("/api/findings", params={"project_id": "demo", "view": "linked"}).json()
    assert {f["id"] for f in linked["findings"]} == {"l1", "l2"}

    all_rows = client.get("/api/findings", params={"project_id": "demo", "view": "all"}).json()
    assert {f["id"] for f in all_rows["findings"]} == {"p1", "l1", "l2", "solo"}


def test_finding_detail_includes_cluster(client, home):
    _talos_home, projects_root, registry = home
    _seed_findings_db(projects_root)
    _register_demo(registry, projects_root)

    res = client.get("/api/findings/p1", params={"project_id": "demo"})
    assert res.status_code == 200
    body = res.json()
    assert body["finding"]["id"] == "p1"
    assert {x["id"] for x in body["linked"]} == {"l1", "l2"}
    assert body["parent"] is None
    # No original/replay evidence → no comparison block
    assert body.get("flow_comparison") is None

    child = client.get("/api/findings/l1", params={"project_id": "demo"}).json()
    assert child["parent"]["id"] == "p1"


def test_finding_detail_flow_comparison(client, home):
    """Original vs attack/testcase flow summary for Control Panel finding page."""
    _talos_home, projects_root, registry = home
    db_path = _seed_findings_db(projects_root)
    _register_demo(registry, projects_root)

    conn = sqlite3.connect(str(db_path))
    conn.executescript(
        """
        CREATE TABLE flows (
          id TEXT PRIMARY KEY,
          method TEXT,
          url TEXT,
          path TEXT,
          status_code INTEGER,
          content_type TEXT,
          response_body BLOB,
          captured_at TEXT,
          original_flow_id TEXT,
          replay_reason TEXT
        );
        CREATE TABLE replay_diffs (
          replay_flow_id TEXT PRIMARY KEY,
          verdict TEXT
        );
        INSERT INTO flows
          (id, method, url, path, status_code, content_type, response_body,
           captured_at, original_flow_id, replay_reason)
        VALUES
          ('flow-orig', 'GET', 'https://app.example/api/me', '/api/me', 200,
           'application/json', X'7b226f6b223a747275657d', '2026-01-01T00:00:00',
           NULL, NULL),
          ('flow-atk', 'GET', 'https://app.example/api/me', '/api/me', 401,
           'application/json', X'7b22657272223a317d', '2026-01-01T00:01:00',
           'flow-orig', 'unauth_strip');
        INSERT INTO replay_diffs (replay_flow_id, verdict) VALUES ('flow-atk', 'DIFFERENT');
        INSERT INTO finding_evidence
          (id, finding_id, evidence_type, reference_id, label, data, created_at)
        VALUES
          ('ev-orig', 'p1', 'original_flow', 'flow-orig', 'Original', '{}',
           '2026-01-01T00:00:00'),
          ('ev-rep', 'p1', 'replay_flow', 'flow-atk', 'Attack replay', '{}',
           '2026-01-01T00:01:00'),
          ('ev-diff', 'p1', 'diff', 'flow-atk', 'Diff',
           '{"diff_verdict":"DIFFERENT"}', '2026-01-01T00:01:00');
        """
    )
    conn.commit()
    conn.close()

    res = client.get("/api/findings/p1", params={"project_id": "demo"})
    assert res.status_code == 200
    body = res.json()
    fc = body.get("flow_comparison")
    assert fc is not None
    assert fc["original"]["id"] == "flow-orig"
    assert fc["original"]["method"] == "GET"
    assert fc["original"]["status_code"] == 200
    assert fc["original"]["body_len"] > 0
    assert "response_body" not in fc["original"]
    assert fc["testcase"]["id"] == "flow-atk"
    assert fc["testcase"]["status_code"] == 401
    assert fc["testcase"]["replay_reason"] == "unauth_strip"
    assert fc["delta"]["status_changed"] is True
    assert fc["delta"]["status_from"] == 200
    assert fc["delta"]["status_to"] == 401
    assert fc["diff_verdict"] == "DIFFERENT"


def test_finding_detail_secret_exposure(client, home):
    """Client-side secret findings expose highlighted leak context."""
    _talos_home, projects_root, registry = home
    db_path = _seed_findings_db(projects_root)
    _register_demo(registry, projects_root)

    conn = sqlite3.connect(str(db_path))
    conn.execute(
        """
        UPDATE findings
        SET attack_type = 'passive_secret', title = 'Exposed AWS Access Key ID'
        WHERE id = 'p1'
        """
    )
    conn.execute(
        """
        INSERT INTO finding_evidence
          (id, finding_id, evidence_type, reference_id, label, data, created_at)
        VALUES
          ('ev-sec', 'p1', 'passive_detection', 'det-1',
           'Passive detection — aws_access_key_id (CONFIRMED_PATTERN)',
           ?, '2026-01-01T00:00:00'),
          ('ev-occ', 'p1', 'source_occurrence', 'occ-1',
           'Source occurrence — /static/app.js',
           ?, '2026-01-01T00:00:00')
        """,
        (
            json.dumps(
                {
                    "detector_id": "aws_access_key_id",
                    "secret_type": "aws_access_key",
                    "matched_key": "accessKeyId",
                    "redacted_value": "AKIA****0001",
                    "raw_value": "AKIAIOSFODNN7EXAMPLE0001",
                    "confidence_level": "CONFIRMED_PATTERN",
                    "confidence_score": 95,
                    "match_start": 20,
                    "match_end": 40,
                    "context_before": 'const accessKeyId = "',
                    "context_after": '";',
                }
            ),
            json.dumps(
                {
                    "url": "https://app.example/static/app.js",
                    "path": "/static/app.js",
                    "host": "https://app.example",
                    "flow_id": "flow-orig",
                }
            ),
        ),
    )
    conn.commit()
    conn.close()

    res = client.get("/api/findings/p1", params={"project_id": "demo"})
    assert res.status_code == 200
    body = res.json()
    exp = body.get("secret_exposure")
    assert exp is not None
    assert exp["count"] >= 1
    hit = exp["hits"][0]
    assert hit["redacted_value"] == "AKIA****0001"
    assert hit["raw_value"] == "AKIAIOSFODNN7EXAMPLE0001"
    assert hit["secret_type"] == "aws_access_key"
    assert hit["context_before"] == 'const accessKeyId = "'
    assert hit["context_after"] == '";'
    assert hit["detector_id"] == "aws_access_key_id"
    assert hit["match_start"] == 20
    assert hit["match_end"] == 40


def test_notes_set_uses_stdin_cli(client):
    with patch("talos_ui.routers.findings.cli.run_scoped_with_stdin") as scoped:
        scoped.return_value = [_ok_result(), _ok_result()]
        res = client.post(
            "/api/findings/p1/notes",
            params={"project_id": "demo"},
            json={"notes": "triage: confirmed on staging"},
        )
        assert res.status_code == 200
        scoped.assert_called_once()
        call = scoped.call_args
        assert call[0][0] == "demo"
        assert call[0][1] == ["finding", "note", "set", "p1"]
        assert call[0][2] == "triage: confirmed on staging"


def test_notes_clear_uses_cli(client):
    with patch("talos_ui.routers.findings.cli.run_scoped") as scoped:
        scoped.return_value = [_ok_result()]
        res = client.delete(
            "/api/findings/p1/notes",
            params={"project_id": "demo"},
        )
        assert res.status_code == 200
        assert scoped.call_args[0][1] == ["finding", "note", "clear", "p1"]


def test_notes_set_rejects_empty(client):
    with patch("talos_ui.routers.findings.cli.run_scoped_with_stdin") as scoped:
        res = client.post(
            "/api/findings/p1/notes",
            params={"project_id": "demo"},
            json={"notes": "   "},
        )
        assert res.status_code == 400
        scoped.assert_not_called()


def test_lifecycle_confirm_passes_linked(client):
    with patch("talos_ui.routers.findings.cli.run_scoped") as scoped:
        scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/findings/p1/confirm",
            params={"project_id": "demo"},
            json={"linked": True, "force": True},
        )
        assert res.status_code == 200
        assert scoped.call_args[0][1] == [
            "finding",
            "confirm",
            "p1",
            "--linked",
            "--force",
        ]


def test_lifecycle_reject_default_no_linked_flag(client):
    with patch("talos_ui.routers.findings.cli.run_scoped") as scoped:
        scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/findings/p1/reject",
            params={"project_id": "demo"},
            json={},
        )
        assert res.status_code == 200
        assert scoped.call_args[0][1] == ["finding", "reject", "p1"]


def test_adjacent_primary_default(client, home):
    _talos_home, projects_root, registry = home
    _seed_findings_db(projects_root)
    _register_demo(registry, projects_root)

    # created_at DESC among PRIMARY: solo (newer), p1 (older)
    solo = client.get(
        "/api/findings/solo/adjacent", params={"project_id": "demo"}
    )
    assert solo.status_code == 200
    assert solo.json() == {"prev_id": None, "next_id": "p1"}

    p1 = client.get("/api/findings/p1/adjacent", params={"project_id": "demo"})
    assert p1.status_code == 200
    assert p1.json() == {"prev_id": "solo", "next_id": None}


def test_adjacent_filter_aware_and_fallback(client, home):
    _talos_home, projects_root, registry = home
    _seed_findings_db(projects_root)
    _register_demo(registry, projects_root)

    # view=all DESC: solo, l2, l1, p1
    l1 = client.get(
        "/api/findings/l1/adjacent",
        params={"project_id": "demo", "view": "all"},
    )
    assert l1.json() == {"prev_id": "l2", "next_id": "p1"}

    # LINKED child is not in PRIMARY window → fall back to all findings
    fallback = client.get(
        "/api/findings/l1/adjacent", params={"project_id": "demo"}
    )
    assert fallback.json() == {"prev_id": "l2", "next_id": "p1"}

    # status+view filter: only TRIAGING PRIMARY is p1
    isolated = client.get(
        "/api/findings/p1/adjacent",
        params={"project_id": "demo", "status": "TRIAGING"},
    )
    assert isolated.json() == {"prev_id": None, "next_id": None}

    # attack_type + all: l2, l1, p1 (solo is bac)
    typed = client.get(
        "/api/findings/l1/adjacent",
        params={"project_id": "demo", "view": "all", "attack_type": "unauth"},
    )
    assert typed.json() == {"prev_id": "l2", "next_id": "p1"}


def test_command_tree_unauth_and_finding_parity():
    from talos_ui.command_tree import build_argv, find_command, stdin_text_for

    unauth = find_command("attack.unauth.run")
    assert unauth is not None
    argv = build_argv(unauth, {"technique": "baseline"})
    assert argv == ["attack", "unauth", "run", "--technique", "baseline"]
    # Dead flags must not exist on the model
    arg_names = {a["name"] for a in unauth["args"]}
    assert "max_priority" not in arg_names
    assert "auth_mutation" not in arg_names
    assert "technique" in arg_names

    note_set = find_command("finding.note.set")
    assert note_set is not None
    assert note_set.get("stdin_from") == "notes"
    argv = build_argv(note_set, {"uuid": "p1", "notes": "hello"})
    assert argv == ["finding", "note", "set", "p1"]
    assert stdin_text_for(note_set, {"uuid": "p1", "notes": "hello"}) == "hello"

    confirm = find_command("finding.confirm")
    argv = build_argv(confirm, {"uuid": "p1", "linked": True, "force": True})
    assert argv == ["finding", "confirm", "p1", "--linked", "--force"]
