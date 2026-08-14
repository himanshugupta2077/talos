"""Talos-owned Burp snapshots: per-project files, identity, no mixing."""

from __future__ import annotations

import json
from pathlib import Path

from talos.burp.headers import maybe_apply_burp_headers
from talos.burp.outbound import prepare_send_headers
from talos.burp.snapshot import (
    MAX_RECORDS,
    list_projects,
    load_records,
    record_request,
    resolve_project_identity,
    snapshot_path,
)
from talos.burp.trace import (
    ENGINE_UNAUTH,
    GROUP_ENDPOINTS,
    BurpTrace,
    attach_burp_trace,
    attach_iv_burp_trace,
    trace_from_flow_meta,
)
from talos.burp.config import BurpRuntimeConfig, set_process_burp_config
from talos.projects.db import init_project_db


def _trace(project_id: str, endpoint: str = "GET /x", **kwargs) -> BurpTrace:
    extras = dict(kwargs.pop("extras", {}))
    return BurpTrace(
        engine=ENGINE_UNAUTH,
        group=GROUP_ENDPOINTS,
        endpoint_label=endpoint,
        host="api.example.com",
        endpoint_id="ep-1",
        extras=extras,
        project_id=project_id,
        project_name=kwargs.get("project_name", project_id),
        record_id=kwargs.get("record_id", "rec-1"),
    )


def test_record_request_writes_per_project_files(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    record_request(
        _trace("acme", "GET /a", record_id="a1"),
        method="GET",
        host="acme.test",
        path="/a",
        url="https://acme.test/a",
        headers={"Accept": "*/*"},
    )
    record_request(
        _trace("beta", "POST /b", record_id="b1", project_name="Beta App"),
        method="POST",
        host="beta.test",
        path="/b",
        url="http://beta.test/b",
        headers={"Content-Type": "text/plain"},
        body="hi",
    )
    acme = load_records("acme")
    beta = load_records("beta")
    assert len(acme) == 1
    assert acme[0]["project_id"] == "acme"
    assert acme[0]["endpoint"] == "GET /a"
    assert "GET /a HTTP/1.1" in acme[0]["request_http"]
    assert "X-Talos-" not in acme[0]["request_http"]
    assert len(beta) == 1
    assert beta[0]["project_id"] == "beta"
    projects = {item.project_id: item for item in list_projects()}
    assert set(projects) == {"acme", "beta"}
    assert projects["beta"].name == "Beta App"


def test_record_request_skips_blank_or_unsafe_id(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    assert record_request(_trace("")) is None
    assert record_request(_trace("../etc")) is None
    assert list(tmp_path.joinpath("burp").glob("*")) == []


def test_resolve_identity_uses_registry(tmp_path: Path) -> None:
    projects = tmp_path / "projects"
    acme = projects / "acme"
    acme.mkdir(parents=True)
    (projects / "registry.json").write_text(
        json.dumps({"acme": {"id": "acme", "name": "Acme Corp"}}),
        encoding="utf-8",
    )
    pid, pname = resolve_project_identity(db_path=acme / "talos.db")
    assert pid == "acme"
    assert pname == "Acme Corp"


def test_resolve_identity_ignores_unregistered_folder(tmp_path: Path) -> None:
    db = tmp_path / "scratch" / "talos.db"
    db.parent.mkdir()
    pid, pname = resolve_project_identity(db_path=db)
    assert pid == ""
    assert pname == ""


def test_attach_stamps_project_and_record_id() -> None:
    meta: dict = {}
    attach_burp_trace(
        meta,
        engine=ENGINE_UNAUTH,
        flow={"method": "GET", "path": "/x", "host": "h", "project_id": "acme"},
        project_name="Acme",
    )
    parsed = trace_from_flow_meta(meta)
    assert parsed is not None
    assert parsed.project_id == "acme"
    assert parsed.project_name == "Acme"
    assert parsed.record_id


def test_maybe_apply_snapshots_without_upstream(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    set_process_burp_config(BurpRuntimeConfig(enabled=True))
    meta: dict = {}
    attach_iv_burp_trace(
        meta,
        flow={"method": "POST", "normalized_path": "/v1/item", "host": "api.example.com"},
        project_id="acme",
        project_name="Acme",
        parameter_name="qty",
        location="body",
        analysis="types",
        payload_type="type:int",
    )
    out = maybe_apply_burp_headers(
        {"Accept": "*/*"},
        meta,
        has_upstream=False,
        method="POST",
        host="api.example.com",
        path="/v1/item",
        url="https://api.example.com/v1/item",
        body="qty=1",
    )
    assert "X-Talos-Engine" not in out
    rows = load_records("acme")
    assert len(rows) == 1
    assert rows[0]["engine"] == "input-validation"
    assert "qty=1" in rows[0]["request_http"]


def test_prepare_send_headers_snapshots_from_flow_project(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    db_path = tmp_path / "talos.db"
    init_project_db(db_path)
    set_process_burp_config(BurpRuntimeConfig(enabled=True))
    headers, meta = prepare_send_headers(
        {"Accept": "*/*"},
        db_path=db_path,
        engine=ENGINE_UNAUTH,
        flow={
            "method": "DELETE",
            "path": "/api/Feedbacks/1",
            "host": "myapp.local:3000",
            "url": "http://myapp.local:3000/api/Feedbacks/1",
            "project_id": "juice",
        },
        extras={"technique": "strip_cookies"},
    )
    assert meta["burp"]["project_id"] == "juice"
    rows = load_records("juice")
    assert len(rows) == 1
    assert rows[0]["endpoint"] == "DELETE /api/Feedbacks/1"


def test_record_from_flow_normalizes_origin_host(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    from talos.burp.snapshot import record_from_flow

    record_from_flow(
        project_id="acme",
        engine=ENGINE_UNAUTH,
        flow={
            "method": "GET",
            "host": "http://myapp.local:3000",
            "path": "/rest/user/whoami",
            "url": "http://myapp.local:3000/rest/user/whoami",
            "request_headers": {
                "Host": "myapp.local:3000",
                "Accept": "application/json",
                "Cookie": "session=abc",
            },
        },
        record_id="whoami-1",
    )
    rows = load_records("acme")
    assert rows[0]["host"] == "myapp.local:3000"
    raw = rows[0]["request_http"]
    assert "Host: myapp.local:3000" in raw
    assert "Host: http://" not in raw
    assert "Accept: application/json" in raw
    assert "Cookie: session=abc" in raw


def test_record_from_flow_writes_response(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    from talos.burp.snapshot import record_from_flow

    record_from_flow(
        project_id="acme",
        engine=ENGINE_UNAUTH,
        flow={
            "method": "GET",
            "host": "acme.test",
            "path": "/a",
            "url": "https://acme.test/a",
            "request_headers": {"Accept": "*/*"},
            "status_code": 201,
            "response_headers": {"Content-Type": "text/plain"},
            "response_body": b"created",
        },
        record_id="flow-1",
        status=201,
    )
    rows = load_records("acme")
    assert len(rows) == 1
    assert rows[0]["status"] == "201"
    assert "HTTP/1.1 201" in rows[0]["response_http"]
    assert "created" in rows[0]["response_http"]


def test_record_http_response_merges_onto_request(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    from talos.burp.snapshot import record_http_response

    record_request(
        _trace("acme", "GET /a", record_id="r-resp"),
        method="GET",
        host="acme.test",
        path="/a",
        url="https://acme.test/a",
        headers={"Accept": "*/*"},
    )
    record_http_response(
        {"burp": {"record_id": "r-resp", "project_id": "acme"}},
        project_id="acme",
        status=200,
        headers={"Content-Type": "application/json"},
        body=b'{"ok":true}',
        reason="OK",
    )
    rows = load_records("acme")
    assert len(rows) == 1
    assert rows[0]["status"] == "200"
    assert "HTTP/1.1 200 OK" in rows[0]["response_http"]
    assert '{"ok":true}' in rows[0]["response_http"]


def test_backfill_responses_from_db(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    from talos.burp.snapshot import backfill_responses_from_db

    db_path = tmp_path / "talos.db"
    init_project_db(db_path)
    record_request(
        _trace("acme", "GET /ok", record_id="ok-1"),
        method="GET",
        host="acme.test",
        path="/ok",
        url="https://acme.test/ok",
    )
    record_request(
        _trace("acme", "GET /fail", record_id="fail-1"),
        method="GET",
        host="acme.test",
        path="/fail",
        url="https://acme.test/fail",
    )
    import sqlite3

    meta_ok = json.dumps({"burp": {"record_id": "ok-1", "project_id": "acme"}})
    meta_fail = json.dumps({"burp": {"record_id": "fail-1", "project_id": "acme"}})
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO flows (
                id, project_id, captured_at, method, url, host, path,
                status_code, response_headers, response_body, flow_meta,
                role_id, module_id, source
            ) VALUES
            ('f1', 'acme', 't', 'GET', 'https://acme.test/ok', 'acme.test', '/ok',
             200, '{"Content-Type":"text/plain"}', 'hello', ?, 'r', 'm', 'auto_replay'),
            ('f2', 'acme', 't', 'GET', 'https://acme.test/fail', 'acme.test', '/fail',
             NULL, '{}', NULL, ?, 'r', 'm', 'auto_replay')
            """,
            (meta_ok, meta_fail),
        )
        conn.execute(
            "UPDATE flows SET replay_error = 'connection_error' WHERE id = 'f2'"
        )
        conn.commit()

    written = backfill_responses_from_db("acme", db_path)
    assert written == 2
    rows = {row["record_id"]: row for row in load_records("acme")}
    assert "HTTP/1.1 200" in rows["ok-1"]["response_http"]
    assert "hello" in rows["ok-1"]["response_http"]
    assert rows["fail-1"]["status"] == "502"
    assert "connection_error" in rows["fail-1"]["response_http"]
    assert backfill_responses_from_db("acme", db_path) == 0


def test_ensure_project_snapshot_creates_dir(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    from talos.burp.snapshot import ensure_project_snapshot

    path = ensure_project_snapshot("new-proj", "New Proj")
    assert path is not None
    assert path.is_file()
    assert load_records("new-proj") == []
    listed = {item.project_id: item for item in list_projects()}
    assert listed["new-proj"].name == "New Proj"


def test_snapshot_module_has_no_fcntl_import() -> None:
    """Windows has no fcntl; CLI startup imports this module unconditionally."""
    import inspect

    from talos import burp as burp_pkg
    from talos.burp import snapshot as snap

    assert "import fcntl" not in inspect.getsource(snap)
    assert "import fcntl" not in inspect.getsource(burp_pkg)


def test_cli_import_chain_survives_missing_fcntl() -> None:
    """
    Regression: `talos project create` on Windows died at
    `from talos.replay.cli import run_replay_cli` because burp.snapshot
    imported fcntl at module load.
    """
    import os
    import subprocess
    import sys

    repo = Path(__file__).resolve().parents[1]
    script = r"""
import builtins
import sys

real_import = builtins.__import__

def no_fcntl(name, globals=None, locals=None, fromlist=(), level=0):
    if name == "fcntl" or (isinstance(name, str) and name.startswith("fcntl.")):
        raise ModuleNotFoundError("No module named 'fcntl'")
    return real_import(name, globals, locals, fromlist, level)

builtins.__import__ = no_fcntl
sys.modules.pop("fcntl", None)

from talos.burp.snapshot import ensure_project_snapshot, resolve_project_identity
from talos.replay.cli import run_replay_cli

assert callable(ensure_project_snapshot)
assert callable(resolve_project_identity)
assert callable(run_replay_cli)
print("ok")
"""
    env = os.environ.copy()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        str(repo) if not existing else os.pathsep.join([str(repo), existing])
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(repo),
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert "ok" in result.stdout


def test_snapshot_compact_keeps_last_n(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    monkeypatch.setattr("talos.burp.snapshot.MAX_RECORDS", 3)
    for i in range(6):
        record_request(
            _trace("acme", f"GET /{i}", record_id=f"r{i}"),
            method="GET",
            path=f"/{i}",
            host="h",
        )
    rows = load_records("acme")
    assert len(rows) == 3
    assert [row["endpoint"] for row in rows] == ["GET /3", "GET /4", "GET /5"]
    # MAX_RECORDS imported at test module load; the compact used the patched name.
    assert MAX_RECORDS >= 3
    path = snapshot_path("acme")
    assert path is not None
    kinds = [
        json.loads(line)["kind"]
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert kinds[0] == "meta"
    assert kinds.count("record") == 3


def test_build_request_http_bodyless_has_two_blank_lines() -> None:
    from talos.burp.snapshot import build_request_http

    raw = build_request_http(
        method="GET",
        url="http://myapp.local:3000/rest/admin/application-configuration",
        path="/rest/admin/application-configuration",
        host="myapp.local:3000",
        headers={
            "Host": "myapp.local:3000",
            "Authorization": "",
        },
        body=None,
    )
    assert raw.endswith("\r\n\r\n\r\n")
    assert not raw.endswith("\r\n\r\n\r\n\r\n")
    assert raw.rstrip("\r\n").endswith("Authorization: ")


def test_build_request_http_with_body_keeps_single_separator() -> None:
    from talos.burp.snapshot import build_request_http

    raw = build_request_http(
        method="POST",
        url="http://h/x",
        path="/x",
        host="h",
        headers={"Host": "h"},
        body="hi",
    )
    assert raw.endswith("hi")
    assert "\r\n\r\n" in raw
    assert not raw.endswith("\r\n\r\n\r\n")


def _insert_flow(db_path: Path, flow_id: str, project_id: str = "acme") -> None:
    import sqlite3

    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO flows (
                id, project_id, captured_at, method, url, host, path,
                status_code, request_headers, request_body,
                response_headers, response_body,
                role_id, module_id, source
            ) VALUES (
                ?, ?, 't', 'GET',
                'http://myapp.local:3000/rest/admin/application-configuration',
                'myapp.local:3000',
                '/rest/admin/application-configuration',
                200,
                '{"Host":"myapp.local:3000","Authorization":""}',
                NULL,
                '{"Content-Type":"application/json"}',
                '{"ok":true}',
                'r', 'm', 'auto_replay'
            )
            """,
            (flow_id, project_id),
        )
        conn.commit()


def test_record_finding_groups_under_findings_engine(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    from talos.burp.snapshot import record_finding
    from talos.findings.model import ATTACK_DISPLAY

    db_path = tmp_path / "talos.db"
    init_project_db(db_path)
    _insert_flow(db_path, "flow-unauth")
    import talos.findings.db as findings_db

    finding_id = findings_db.create_finding(
        db_path,
        project_id="acme",
        attack_type="unauth",
        verdict="BYPASS",
        endpoint_id="ep-1",
        title="Unauthenticated Execution — BYPASS",
        cluster_key="UNAUTH:ep-1",
    )
    findings_db.add_evidence(
        db_path,
        finding_id,
        "replay_flow",
        "flow-unauth",
        "Attack replay flow",
    )
    path = record_finding(
        project_id="acme",
        finding_id=finding_id,
        db_path=db_path,
        attack_type="unauth",
        title="Unauthenticated Execution — BYPASS",
        flow_id="flow-unauth",
    )
    assert path is not None
    rows = load_records("acme")
    assert len(rows) == 1
    assert rows[0]["engine"] == "findings"
    assert rows[0]["endpoint"] == ATTACK_DISPLAY["unauth"]
    assert rows[0]["endpoint_id"] == "unauth"
    assert rows[0]["record_id"] == f"finding:{finding_id}"
    assert "GET /rest/admin/application-configuration HTTP/1.1" in rows[0]["request_http"]
    assert rows[0]["request_http"].endswith("\r\n\r\n\r\n")
    assert "HTTP/1.1 200" in rows[0]["response_http"]


def test_backfill_findings_from_db(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    from talos.burp.snapshot import backfill_findings_from_db
    from talos.findings.model import ATTACK_DISPLAY

    db_path = tmp_path / "talos.db"
    init_project_db(db_path)
    _insert_flow(db_path, "flow-cors")
    import talos.findings.db as findings_db

    finding_id = findings_db.create_finding(
        db_path,
        project_id="acme",
        attack_type="cors",
        verdict="CORS_MISCONFIG",
        endpoint_id="ep-2",
        title="CORS — ACAO *",
        cluster_key="CORS:http://myapp.local:3000",
    )
    findings_db.add_evidence(
        db_path,
        finding_id,
        "replay_flow",
        "flow-cors",
        "Attack replay flow",
    )
    written = backfill_findings_from_db("acme", db_path)
    assert written == 1
    rows = load_records("acme")
    assert rows[0]["engine"] == "findings"
    assert rows[0]["endpoint"] == ATTACK_DISPLAY["cors"]
    assert backfill_findings_from_db("acme", db_path) == 0


def test_create_finding_from_verdict_snapshots_burp(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    from talos.findings.creator import create_finding_from_verdict
    from talos.findings.model import ATTACK_DISPLAY

    db_path = tmp_path / "talos.db"
    init_project_db(db_path)
    _insert_flow(db_path, "flow-replay")
    fid = create_finding_from_verdict(
        db_path=db_path,
        project_id="acme",
        attack_module="unauth",
        verdict="BYPASS",
        endpoint_id="ep-1",
        original_flow_id=None,
        replayed_flow_id="flow-replay",
        variant="remove_all_auth",
    )
    assert fid is not None
    rows = load_records("acme")
    assert len(rows) == 1
    assert rows[0]["engine"] == "findings"
    assert rows[0]["endpoint"] == ATTACK_DISPLAY["unauth"]
    assert rows[0]["detail"].startswith("Unauthenticated Execution")


def test_passive_burp_detail_is_unmasked(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp"))
    from talos.passive.constants import SourceKind
    from talos.passive.db import insert_detection, insert_occurrence, upsert_document
    from talos.passive.models import Detection
    from talos.passive.redaction import fingerprint_secret, redact_secret

    db_path = tmp_path / "talos.db"
    init_project_db(db_path)
    secret = "AKIAIOSFODNN7EXAMPLE"
    doc, _ = upsert_document(
        db_path,
        project_id="acme",
        body_hash="a" * 64,
        source_kind=SourceKind.JAVASCRIPT,
        body_size=40,
        first_flow_id="f1",
    )
    occ = insert_occurrence(
        db_path,
        document_id=doc.id,
        flow_id="f1",
        url="https://acme.test/app.js",
        host="acme.test",
        path="/app.js",
        content_type="application/javascript",
        observed_at="2026-01-01T00:00:00+00:00",
    )
    det = Detection(
        id="",
        document_id=doc.id,
        occurrence_id=occ.id,
        detector_id="aws_access_key",
        detector_family="provider",
        category="secret",
        secret_type="aws_access_key",
        matched_key="AWS_ACCESS_KEY_ID",
        redacted_value=redact_secret(secret),
        value_fingerprint=fingerprint_secret("provider", secret),
        confidence_score=90,
        confidence_level="HIGH",
        match_start=0,
        match_end=len(secret),
        raw_value=secret,
    )
    stored = insert_detection(db_path, det)
    assert stored is not None
    rows = load_records("acme")
    assert rows
    detail = rows[0]["detail"]
    assert secret in detail
    assert "****" not in detail
    assert "aws_access_key" in detail
