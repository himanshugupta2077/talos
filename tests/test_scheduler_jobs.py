"""
CLI-016 — Scheduler job management.

Covers:
  - DB: list_jobs, get_job, cancel_job, prune_jobs, count_jobs_by_status
  - CLI: jobs list / jobs show / cancel / prune
  - Confirmation policy on prune (CLI-015)
  - --format json on list/show (CLI-014)
"""

from __future__ import annotations

import argparse
import io
import json
import uuid
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from talos.cli_output import EXIT_CANCELLED, EXIT_FAILURE, EXIT_USAGE
from talos.projects.db import init_project_db
from talos.scheduler import db as sched_db
from talos.scheduler.cli import (
    cmd_cancel,
    cmd_jobs_list,
    cmd_jobs_show,
    cmd_prune,
)
from talos.scheduler.job import (
    BAC_SESSION_SWAP,
    REPLAY_ENDPOINT,
    REPLAY_FLOW,
    STATUS_CANCELLED,
    STATUS_DONE,
    STATUS_FAILED,
    STATUS_PAUSED,
    STATUS_PENDING,
    STATUS_RUNNING,
    STATUS_SKIPPED,
    UNAUTH_ATTACK,
)


# ------------------------------------------------------------------ #
# Fixtures                                                             #
# ------------------------------------------------------------------ #


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


@pytest.fixture()
def project(db_path: Path) -> SimpleNamespace:
    return SimpleNamespace(db_path=db_path, id="test-project")


def _enqueue(
    db_path: Path,
    *,
    job_type: str = REPLAY_FLOW,
    status: str | None = None,
    flow_id: str | None = None,
    endpoint_id: str | None = None,
    meta: str | None = None,
    job_id: str | None = None,
) -> str:
    jid = job_id or str(uuid.uuid4())
    sched_db.enqueue_job(
        db_path,
        jid,
        job_type,
        "test-project",
        endpoint_id=endpoint_id,
        flow_id=flow_id or (str(uuid.uuid4()) if job_type == REPLAY_FLOW else None),
        meta=meta,
    )
    if status and status != STATUS_PENDING:
        with sched_db._connect_rw(db_path) as conn:
            conn.execute(
                "UPDATE scheduler_jobs SET status = ? WHERE job_id = ?",
                (status, jid),
            )
            if status in (
                STATUS_DONE,
                STATUS_FAILED,
                STATUS_SKIPPED,
                STATUS_CANCELLED,
            ):
                conn.execute(
                    "UPDATE scheduler_jobs SET finished_at = ? WHERE job_id = ?",
                    (sched_db._now_iso(), jid),
                )
            if status == STATUS_FAILED:
                conn.execute(
                    "UPDATE scheduler_jobs SET failure_reason = ? WHERE job_id = ?",
                    ("network error", jid),
                )
            conn.commit()
    return jid


# ================================================================== #
# DB layer                                                             #
# ================================================================== #


class TestListJobs:
    def test_list_all(self, db_path: Path) -> None:
        _enqueue(db_path)
        _enqueue(db_path, job_type=REPLAY_ENDPOINT, endpoint_id=str(uuid.uuid4()))
        jobs = sched_db.list_jobs(db_path, "test-project")
        assert len(jobs) == 2

    def test_filter_status(self, db_path: Path) -> None:
        _enqueue(db_path)
        failed = _enqueue(db_path, status=STATUS_FAILED)
        jobs = sched_db.list_jobs(db_path, "test-project", status=STATUS_FAILED)
        assert len(jobs) == 1
        assert jobs[0].job_id == failed

    def test_filter_type_exact(self, db_path: Path) -> None:
        _enqueue(db_path, job_type=REPLAY_FLOW)
        _enqueue(db_path, job_type=UNAUTH_ATTACK, endpoint_id=str(uuid.uuid4()))
        jobs = sched_db.list_jobs(
            db_path, "test-project", job_type=UNAUTH_ATTACK
        )
        assert len(jobs) == 1
        assert jobs[0].job_type == UNAUTH_ATTACK

    def test_filter_type_family_prefix(self, db_path: Path) -> None:
        _enqueue(db_path, job_type=REPLAY_FLOW)
        _enqueue(
            db_path, job_type=REPLAY_ENDPOINT, endpoint_id=str(uuid.uuid4())
        )
        _enqueue(db_path, job_type=UNAUTH_ATTACK, endpoint_id=str(uuid.uuid4()))
        jobs = sched_db.list_jobs(db_path, "test-project", job_type="replay")
        assert len(jobs) == 2
        assert {j.job_type for j in jobs} == {REPLAY_FLOW, REPLAY_ENDPOINT}

    def test_filter_type_bac_family(self, db_path: Path) -> None:
        _enqueue(
            db_path,
            job_type=BAC_SESSION_SWAP,
            flow_id=str(uuid.uuid4()),
            meta=json.dumps({"attacker_role_id": "r1", "variant": "v1"}),
        )
        _enqueue(db_path, job_type=REPLAY_FLOW)
        jobs = sched_db.list_jobs(db_path, "test-project", job_type="bac")
        assert len(jobs) == 1
        assert jobs[0].job_type == BAC_SESSION_SWAP

    def test_limit(self, db_path: Path) -> None:
        for _ in range(5):
            _enqueue(db_path)
        jobs = sched_db.list_jobs(db_path, "test-project", limit=2)
        assert len(jobs) == 2

    def test_list_jobs_by_status_delegates(self, db_path: Path) -> None:
        _enqueue(db_path, status=STATUS_DONE)
        jobs = sched_db.list_jobs_by_status(
            db_path, "test-project", STATUS_DONE
        )
        assert len(jobs) == 1


class TestGetJob:
    def test_exact_match(self, db_path: Path) -> None:
        jid = _enqueue(db_path)
        job = sched_db.get_job(db_path, "test-project", jid)
        assert job is not None
        assert job.job_id == jid

    def test_prefix_match(self, db_path: Path) -> None:
        jid = _enqueue(db_path)
        job = sched_db.get_job(db_path, "test-project", jid[:8])
        assert job is not None
        assert job.job_id == jid

    def test_not_found(self, db_path: Path) -> None:
        assert sched_db.get_job(db_path, "test-project", "deadbeef") is None

    def test_ambiguous_prefix(self, db_path: Path) -> None:
        # Force two jobs sharing a long common prefix by crafting UUIDs.
        a = "aaaaaaaa-1111-1111-1111-111111111111"
        b = "aaaaaaaa-2222-2222-2222-222222222222"
        _enqueue(db_path, job_id=a)
        _enqueue(db_path, job_id=b)
        with pytest.raises(ValueError, match="Ambiguous"):
            sched_db.get_job(db_path, "test-project", "aaaaaaaa")


class TestCancelJob:
    def test_cancel_pending(self, db_path: Path) -> None:
        jid = _enqueue(db_path)
        prev = sched_db.cancel_job(db_path, jid)
        assert prev == STATUS_PENDING
        job = sched_db.get_job(db_path, "test-project", jid)
        assert job is not None
        assert job.status == STATUS_CANCELLED
        assert job.failure_reason == "cancelled by user"

    def test_cancel_paused(self, db_path: Path) -> None:
        jid = _enqueue(db_path, status=STATUS_PAUSED)
        prev = sched_db.cancel_job(db_path, jid)
        assert prev == STATUS_PAUSED
        job = sched_db.get_job(db_path, "test-project", jid)
        assert job is not None
        assert job.status == STATUS_CANCELLED

    def test_cancel_running_refused(self, db_path: Path) -> None:
        jid = _enqueue(db_path, status=STATUS_RUNNING)
        assert sched_db.cancel_job(db_path, jid) is None
        job = sched_db.get_job(db_path, "test-project", jid)
        assert job is not None
        assert job.status == STATUS_RUNNING

    def test_cancel_done_refused(self, db_path: Path) -> None:
        jid = _enqueue(db_path, status=STATUS_DONE)
        assert sched_db.cancel_job(db_path, jid) is None

    def test_cancel_missing(self, db_path: Path) -> None:
        assert sched_db.cancel_job(db_path, str(uuid.uuid4())) is None


class TestPruneJobs:
    def test_prune_failed(self, db_path: Path) -> None:
        _enqueue(db_path, status=STATUS_FAILED)
        _enqueue(db_path, status=STATUS_DONE)
        _enqueue(db_path)  # pending
        removed = sched_db.prune_jobs(db_path, STATUS_FAILED)
        assert removed == 1
        remaining = sched_db.list_jobs(db_path, "test-project", limit=100)
        statuses = {j.status for j in remaining}
        assert STATUS_FAILED not in statuses
        assert STATUS_DONE in statuses
        assert STATUS_PENDING in statuses

    def test_prune_done(self, db_path: Path) -> None:
        _enqueue(db_path, status=STATUS_DONE)
        _enqueue(db_path, status=STATUS_DONE)
        assert sched_db.prune_jobs(db_path, STATUS_DONE) == 2
        assert sched_db.count_jobs_by_status(db_path, STATUS_DONE) == 0

    def test_prune_pending_rejected(self, db_path: Path) -> None:
        with pytest.raises(ValueError, match="Cannot prune"):
            sched_db.prune_jobs(db_path, STATUS_PENDING)

    def test_count_by_status(self, db_path: Path) -> None:
        _enqueue(db_path, status=STATUS_FAILED)
        _enqueue(db_path, status=STATUS_FAILED)
        assert sched_db.count_jobs_by_status(db_path, STATUS_FAILED) == 2


# ================================================================== #
# CLI handlers                                                         #
# ================================================================== #


class TestCmdJobsList:
    def test_table_output(self, project: SimpleNamespace, db_path: Path) -> None:
        jid = _enqueue(db_path, status=STATUS_FAILED)
        buf = io.StringIO()
        args = argparse.Namespace(
            status=STATUS_FAILED,
            filter_type=None,
            limit=50,
            output_format="table",
        )
        with redirect_stdout(buf):
            cmd_jobs_list(project, args)
        out = buf.getvalue()
        assert "UUID" in out
        assert jid in out
        assert "failed" in out

    def test_json_output(self, project: SimpleNamespace, db_path: Path) -> None:
        jid = _enqueue(db_path)
        buf = io.StringIO()
        args = argparse.Namespace(
            status=None,
            filter_type=None,
            limit=50,
            output_format="json",
        )
        with redirect_stdout(buf):
            cmd_jobs_list(project, args)
        data = json.loads(buf.getvalue())
        assert isinstance(data, list)
        assert data[0]["job_id"] == jid

    def test_empty_json_is_array(
        self, project: SimpleNamespace, db_path: Path
    ) -> None:
        buf = io.StringIO()
        args = argparse.Namespace(
            status=STATUS_FAILED,
            filter_type=None,
            limit=50,
            output_format="json",
        )
        with redirect_stdout(buf):
            cmd_jobs_list(project, args)
        assert json.loads(buf.getvalue()) == []

    def test_invalid_limit(self, project: SimpleNamespace) -> None:
        args = argparse.Namespace(
            status=None,
            filter_type=None,
            limit=0,
            output_format="table",
        )
        with pytest.raises(SystemExit) as exc:
            cmd_jobs_list(project, args)
        assert exc.value.code == EXIT_USAGE


class TestCmdJobsShow:
    def test_show_detail(self, project: SimpleNamespace, db_path: Path) -> None:
        jid = _enqueue(db_path, status=STATUS_FAILED)
        buf = io.StringIO()
        args = argparse.Namespace(job_id=jid, output_format="table")
        with redirect_stdout(buf):
            cmd_jobs_show(project, args)
        out = buf.getvalue()
        assert jid in out
        assert "Status:" in out
        assert "failed" in out
        assert "network error" in out
        assert "Retry count:" in out

    def test_show_by_prefix(self, project: SimpleNamespace, db_path: Path) -> None:
        jid = _enqueue(db_path)
        buf = io.StringIO()
        args = argparse.Namespace(job_id=jid[:8], output_format="table")
        with redirect_stdout(buf):
            cmd_jobs_show(project, args)
        assert jid in buf.getvalue()

    def test_show_json(self, project: SimpleNamespace, db_path: Path) -> None:
        jid = _enqueue(db_path)
        buf = io.StringIO()
        args = argparse.Namespace(job_id=jid, output_format="json")
        with redirect_stdout(buf):
            cmd_jobs_show(project, args)
        data = json.loads(buf.getvalue())
        assert data["job_id"] == jid
        assert data["status"] == STATUS_PENDING

    def test_show_not_found(self, project: SimpleNamespace) -> None:
        args = argparse.Namespace(job_id="missing-id", output_format="table")
        err = io.StringIO()
        with redirect_stderr(err), pytest.raises(SystemExit) as exc:
            cmd_jobs_show(project, args)
        assert exc.value.code == EXIT_FAILURE
        assert "Error:" in err.getvalue()


class TestCmdCancel:
    def test_cancel_success(self, project: SimpleNamespace, db_path: Path) -> None:
        jid = _enqueue(db_path)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_cancel(project, argparse.Namespace(job_id=jid))
        out = buf.getvalue()
        assert "Cancelled." in out
        assert jid in out
        job = sched_db.get_job(db_path, "test-project", jid)
        assert job is not None
        assert job.status == STATUS_CANCELLED

    def test_cancel_running_errors(
        self, project: SimpleNamespace, db_path: Path
    ) -> None:
        jid = _enqueue(db_path, status=STATUS_RUNNING)
        err = io.StringIO()
        with redirect_stderr(err), pytest.raises(SystemExit) as exc:
            cmd_cancel(project, argparse.Namespace(job_id=jid))
        assert exc.value.code == EXIT_FAILURE
        assert "running" in err.getvalue().lower()


class TestCmdPrune:
    def test_prune_force(self, project: SimpleNamespace, db_path: Path) -> None:
        _enqueue(db_path, status=STATUS_FAILED)
        _enqueue(db_path, status=STATUS_FAILED)
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_prune(
                project,
                argparse.Namespace(status=STATUS_FAILED, force=True),
            )
        assert "Pruned 2" in buf.getvalue()
        assert sched_db.count_jobs_by_status(db_path, STATUS_FAILED) == 0

    def test_prune_empty(self, project: SimpleNamespace, db_path: Path) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_prune(
                project,
                argparse.Namespace(status=STATUS_DONE, force=True),
            )
        assert "No jobs" in buf.getvalue()

    def test_prune_decline_cancels(
        self, project: SimpleNamespace, db_path: Path
    ) -> None:
        _enqueue(db_path, status=STATUS_DONE)
        with (
            patch("talos.cli_output.is_interactive", return_value=True),
            patch("builtins.input", return_value="n"),
            pytest.raises(SystemExit) as exc,
        ):
            cmd_prune(
                project,
                argparse.Namespace(status=STATUS_DONE, force=False),
            )
        assert exc.value.code == EXIT_CANCELLED
        assert sched_db.count_jobs_by_status(db_path, STATUS_DONE) == 1

    def test_prune_noninteractive_requires_force(
        self, project: SimpleNamespace, db_path: Path
    ) -> None:
        _enqueue(db_path, status=STATUS_DONE)
        err = io.StringIO()
        with (
            patch("talos.cli_output.is_interactive", return_value=False),
            patch(
                "builtins.input",
                side_effect=AssertionError("must not prompt non-interactively"),
            ),
            redirect_stderr(err),
            pytest.raises(SystemExit) as exc,
        ):
            cmd_prune(
                project,
                argparse.Namespace(status=STATUS_DONE, force=False),
            )
        assert exc.value.code == EXIT_USAGE
        assert "requires --force" in err.getvalue()


class TestCliDispatch:
    def test_run_scheduler_cli_jobs_list(
        self, project: SimpleNamespace, db_path: Path
    ) -> None:
        from talos.scheduler.cli import run_scheduler_cli

        _enqueue(db_path)
        manager = MagicMock()
        manager.active.return_value = project
        buf = io.StringIO()
        with redirect_stdout(buf):
            run_scheduler_cli(manager, ["jobs", "list", "--limit", "10"])
        assert "UUID" in buf.getvalue() or "No scheduler" in buf.getvalue()

    def test_run_scheduler_cli_cancel(
        self, project: SimpleNamespace, db_path: Path
    ) -> None:
        from talos.scheduler.cli import run_scheduler_cli

        jid = _enqueue(db_path)
        manager = MagicMock()
        manager.active.return_value = project
        buf = io.StringIO()
        with redirect_stdout(buf):
            run_scheduler_cli(manager, ["cancel", jid])
        assert "Cancelled." in buf.getvalue()
