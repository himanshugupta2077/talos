"""
Clear-cache / run --ignore-cache must wipe probe evidence and profiles
so the planner starts at baseline again.
"""

from __future__ import annotations

import io
import json
import sqlite3
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from talos.input_validation import db as iv_db
from talos.input_validation.cli import run_input_validation_cli
from talos.input_validation.config import IVAnalysesConfig, IVConfig, save_config
from talos.input_validation.engine import make_param_uuid, schedule_endpoint, schedule_host
from talos.input_validation.profile import empty_param_profile
from talos.projects.db import init_project_db
from talos.scheduler.job import IV_BASELINE


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


def _seed_endpoint(
    db_path: Path,
    *,
    host: str,
    path: str,
    param_name: str,
    location: str = "query",
) -> tuple[str, str]:
    ep_id = str(uuid.uuid4())
    param_uuid = make_param_uuid(host, location, param_name)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO endpoints
                (id, project_id, host, method, path, normalized_path,
                 first_seen, last_seen)
            VALUES (?, 'proj', ?, 'GET', ?, ?, datetime('now'), datetime('now'))
            """,
            (ep_id, host, path, path),
        )
        conn.execute(
            """
            INSERT INTO endpoint_policy
                (endpoint_id, qualified, excluded, updated_at)
            VALUES (?, 1, 0, datetime('now'))
            """,
            (ep_id,),
        )
        conn.execute(
            """
            INSERT INTO parameters (id, endpoint_id, name, location, param_type)
            VALUES (?, ?, ?, ?, 'string')
            """,
            (str(uuid.uuid4()), ep_id, param_name, location),
        )
        conn.commit()
    return ep_id, param_uuid


def _seed_completed_scan(
    db_path: Path,
    *,
    host: str,
    endpoint_id: str,
    param_name: str,
    param_uuid: str,
    location: str = "query",
) -> None:
    iv_db.upsert_probe_result(
        db_path,
        param_uuid,
        endpoint_id,
        host,
        location,
        param_name,
        "baseline",
        None,
        "baseline",
        0,
        "flow-baseline",
        iv_db.STATUS_COMPLETED,
    )
    iv_db.upsert_probe_result(
        db_path,
        param_uuid,
        endpoint_id,
        host,
        location,
        param_name,
        "multiprobe",
        "TLabc",
        "multiprobe",
        0,
        "flow-mp",
        iv_db.STATUS_COMPLETED,
    )
    iv_db.upsert_param_cache(
        db_path,
        host,
        location,
        param_name,
        "transformations",
        iv_db.STATUS_COMPLETED,
        {"ok": True},
    )
    iv_db.upsert_reflection_cache(
        db_path,
        endpoint_id,
        param_name,
        location,
        iv_db.STATUS_COMPLETED,
        {"state": "reflected"},
    )
    profile = empty_param_profile(
        param_uuid=param_uuid,
        host=host,
        location=location,
        name=param_name,
    )
    profile["requests_used"] = 12
    profile["inferred"]["synthesis"] = {"source": "probes"}
    iv_db.upsert_param_profile(
        db_path,
        param_uuid=param_uuid,
        host=host,
        location=location,
        param_name=param_name,
        profile=profile,
    )
    iv_db.upsert_endpoint_profile(db_path, endpoint_id=endpoint_id, host=host)
    iv_db.upsert_app_profile(db_path, host=host)


def _count(db_path: Path, table: str, where: str = "1=1", params: tuple = ()) -> int:
    with sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            f"SELECT COUNT(*) FROM {table} WHERE {where}", params
        ).fetchone()
    return int(row[0])


def _pending_job(
    db_path: Path,
    *,
    endpoint_id: str,
    host: str,
    param_name: str,
    job_type: str = IV_BASELINE,
) -> str:
    job_id = str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT INTO scheduler_jobs
                (job_id, endpoint_id, job_type, priority, status, created_at, meta)
            VALUES (?, ?, ?, 10, 'pending', datetime('now'), ?)
            """,
            (
                job_id,
                endpoint_id,
                job_type,
                json.dumps(
                    {
                        "host": host,
                        "parameter_name": param_name,
                        "endpoint_id": endpoint_id,
                    }
                ),
            ),
        )
        conn.commit()
    return job_id


def _job_types(db_path: Path) -> list[str]:
    with sqlite3.connect(str(db_path)) as conn:
        return [
            row[0]
            for row in conn.execute(
                "SELECT job_type FROM scheduler_jobs WHERE status = 'pending' "
                "ORDER BY created_at"
            )
        ]


class TestResetIvScanState:
    def test_project_reset_wipes_evidence(self, db_path: Path) -> None:
        ep_id, param_uuid = _seed_endpoint(
            db_path, host="api.example.com", path="/a", param_name="q"
        )
        _seed_completed_scan(
            db_path,
            host="api.example.com",
            endpoint_id=ep_id,
            param_name="q",
            param_uuid=param_uuid,
        )
        job_id = _pending_job(
            db_path, endpoint_id=ep_id, host="api.example.com", param_name="q"
        )

        counts = iv_db.reset_iv_scan_state(db_path)
        assert counts["probes"] == 2
        assert counts["param_profiles"] == 1
        assert counts["endpoint_profiles"] == 1
        assert counts["app_profiles"] == 1
        assert counts["param_cache"] == 1
        assert counts["reflection_cache"] == 1
        assert counts["jobs_cancelled"] == 1

        assert _count(db_path, "iv_probe_results") == 0
        assert _count(db_path, "iv_param_profiles") == 0
        assert _count(db_path, "iv_endpoint_profiles") == 0
        assert _count(db_path, "iv_app_profiles") == 0
        assert _count(db_path, "iv_param_cache") == 0
        assert _count(db_path, "iv_reflection_cache") == 0
        with sqlite3.connect(str(db_path)) as conn:
            status = conn.execute(
                "SELECT status, failure_reason FROM scheduler_jobs WHERE job_id = ?",
                (job_id,),
            ).fetchone()
        assert status == ("cancelled", "iv_scan_reset")

    def test_host_scope_leaves_other_host(self, db_path: Path) -> None:
        ep_a, uuid_a = _seed_endpoint(
            db_path, host="a.example.com", path="/a", param_name="q"
        )
        ep_b, uuid_b = _seed_endpoint(
            db_path, host="b.example.com", path="/b", param_name="q"
        )
        _seed_completed_scan(
            db_path,
            host="a.example.com",
            endpoint_id=ep_a,
            param_name="q",
            param_uuid=uuid_a,
        )
        _seed_completed_scan(
            db_path,
            host="b.example.com",
            endpoint_id=ep_b,
            param_name="q",
            param_uuid=uuid_b,
        )

        iv_db.reset_iv_scan_state(db_path, host="a.example.com")
        assert _count(db_path, "iv_probe_results", "host = ?", ("a.example.com",)) == 0
        assert _count(db_path, "iv_probe_results", "host = ?", ("b.example.com",)) == 2
        assert iv_db.get_param_profile(db_path, uuid_a) is None
        assert iv_db.get_param_profile(db_path, uuid_b) is not None
        assert iv_db.get_app_profile(db_path, "a.example.com") is None
        assert iv_db.get_app_profile(db_path, "b.example.com") is not None

    def test_parameter_scope_leaves_other_name(self, db_path: Path) -> None:
        ep_id, uuid_q = _seed_endpoint(
            db_path, host="api.example.com", path="/a", param_name="q"
        )
        _seed_endpoint(
            db_path, host="api.example.com", path="/b", param_name="id"
        )
        uuid_id = make_param_uuid("api.example.com", "query", "id")
        _seed_completed_scan(
            db_path,
            host="api.example.com",
            endpoint_id=ep_id,
            param_name="q",
            param_uuid=uuid_q,
        )
        iv_db.upsert_probe_result(
            db_path,
            uuid_id,
            ep_id,
            "api.example.com",
            "query",
            "id",
            "baseline",
            None,
            "baseline",
            0,
            "flow-id",
            iv_db.STATUS_COMPLETED,
        )
        iv_db.upsert_param_profile(
            db_path,
            param_uuid=uuid_id,
            host="api.example.com",
            location="query",
            param_name="id",
            profile={},
        )

        iv_db.reset_iv_scan_state(db_path, param_name="q")
        assert _count(db_path, "iv_probe_results", "param_name = ?", ("q",)) == 0
        assert _count(db_path, "iv_probe_results", "param_name = ?", ("id",)) == 1
        assert iv_db.get_param_profile(db_path, uuid_q) is None
        assert iv_db.get_param_profile(db_path, uuid_id) is not None


class TestIgnoreCachePlannerRerun:
    def test_ignore_cache_run_starts_at_baseline(self, db_path: Path) -> None:
        save_config(
            db_path,
            IVConfig(enabled=True, probe_strategy="standard", analyses=IVAnalysesConfig()),
        )
        ep_id, param_uuid = _seed_endpoint(
            db_path, host="api.example.com", path="/v1/items", param_name="q"
        )
        _seed_completed_scan(
            db_path,
            host="api.example.com",
            endpoint_id=ep_id,
            param_name="q",
            param_uuid=param_uuid,
        )

        schedule_endpoint(db_path, "proj", ep_id, ignore_cache=False)
        # Completed evidence → planner does not go back to baseline.
        with sqlite3.connect(str(db_path)) as conn:
            resume_types = [
                row[0]
                for row in conn.execute("SELECT job_type FROM scheduler_jobs")
            ]
        assert IV_BASELINE not in resume_types

        n = schedule_endpoint(db_path, "proj", ep_id, ignore_cache=True)
        assert n == 1
        assert _job_types(db_path) == [IV_BASELINE]
        assert _count(db_path, "iv_probe_results") == 0
        assert iv_db.get_param_profile(db_path, param_uuid) is None

    def test_host_ignore_cache_does_not_reset_other_host(self, db_path: Path) -> None:
        save_config(db_path, IVConfig(enabled=True, probe_strategy="standard"))
        ep_a, uuid_a = _seed_endpoint(
            db_path, host="a.example.com", path="/a", param_name="q"
        )
        ep_b, uuid_b = _seed_endpoint(
            db_path, host="b.example.com", path="/b", param_name="q"
        )
        _seed_completed_scan(
            db_path,
            host="a.example.com",
            endpoint_id=ep_a,
            param_name="q",
            param_uuid=uuid_a,
        )
        _seed_completed_scan(
            db_path,
            host="b.example.com",
            endpoint_id=ep_b,
            param_name="q",
            param_uuid=uuid_b,
        )

        n = schedule_host(db_path, "proj", "a.example.com", ignore_cache=True)
        assert n == 1
        assert _count(db_path, "iv_probe_results", "host = ?", ("a.example.com",)) == 0
        assert _count(db_path, "iv_probe_results", "host = ?", ("b.example.com",)) == 2
        assert iv_db.get_param_profile(db_path, uuid_b) is not None

    def test_phase_ignore_cache_does_not_wipe_probes(self, db_path: Path) -> None:
        save_config(db_path, IVConfig(enabled=True, probe_strategy="standard"))
        ep_id, param_uuid = _seed_endpoint(
            db_path, host="api.example.com", path="/a", param_name="q"
        )
        _seed_completed_scan(
            db_path,
            host="api.example.com",
            endpoint_id=ep_id,
            param_name="q",
            param_uuid=param_uuid,
        )
        n = schedule_endpoint(
            db_path, "proj", ep_id, phase_filter=IV_BASELINE, ignore_cache=True
        )
        assert n == 1
        assert _count(db_path, "iv_probe_results") == 2
        assert iv_db.get_param_profile(db_path, param_uuid) is not None


class TestClearCacheCliResetsEvidence:
    def test_clear_cache_then_run_enqueues_baseline(self, db_path: Path) -> None:
        save_config(db_path, IVConfig(enabled=True, probe_strategy="standard"))
        ep_id, param_uuid = _seed_endpoint(
            db_path, host="api.example.com", path="/a", param_name="q"
        )
        _seed_completed_scan(
            db_path,
            host="api.example.com",
            endpoint_id=ep_id,
            param_name="q",
            param_uuid=param_uuid,
        )
        project = SimpleNamespace(db_path=db_path, id="proj")
        manager = MagicMock()
        manager.active.return_value = project

        out = io.StringIO()
        with redirect_stdout(out):
            run_input_validation_cli(manager, ["clear-cache", "--force"])
        text = out.getvalue()
        assert "Reset IV scan state" in text
        assert "2 probe" in text
        assert _count(db_path, "iv_probe_results") == 0
        assert iv_db.get_param_profile(db_path, param_uuid) is None

        n = schedule_endpoint(db_path, "proj", ep_id, ignore_cache=False)
        assert n == 1
        assert _job_types(db_path) == [IV_BASELINE]
