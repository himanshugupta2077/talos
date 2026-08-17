"""IST testing-window gate: parse, evaluate, CLI, scheduler hold."""

from __future__ import annotations

import argparse
import io
import time
import uuid
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import yaml

from talos.cli_output import EXIT_USAGE
from talos.projects.db import init_project_db
from talos.scheduler import db as sched_db
from talos.scheduler.cli import cmd_config, cmd_status
from talos.scheduler.job import REPLAY_FLOW, STATUS_PENDING
from talos.scheduler.scheduler import ReplayScheduler
from talos.scheduler.testing_windows import (
    IST,
    WindowParseError,
    allows_execution,
    evaluate,
    in_any_window,
    normalize_windows,
    parse_window,
    window_contains,
)


def _ist(hour: int, minute: int, day: int = 17) -> datetime:
    """Fixed IST clock on 2026-08-17 (or ``day``)."""
    return datetime(2026, 8, day, hour, minute, tzinfo=IST)


class TestParse:
    def test_parse_and_normalize(self) -> None:
        start, end = parse_window("09:00-18:00")
        assert (start.hour, start.minute) == (9, 0)
        assert (end.hour, end.minute) == (18, 0)
        assert normalize_windows(["09:00 - 18:00", "09:00-18:00"]) == (
            "09:00-18:00",
        )

    def test_reject_equal_and_bad(self) -> None:
        with pytest.raises(WindowParseError):
            parse_window("09:00-09:00")
        with pytest.raises(WindowParseError):
            parse_window("9-18")
        with pytest.raises(WindowParseError):
            parse_window("25:00-18:00")


class TestContains:
    def test_same_day_inclusive_start_exclusive_end(self) -> None:
        start, end = parse_window("09:00-18:00")
        from datetime import time

        assert window_contains(start, end, time(9, 0))
        assert window_contains(start, end, time(17, 59, 59))
        assert not window_contains(start, end, time(18, 0))
        assert not window_contains(start, end, time(8, 59))

    def test_overnight_wrap(self) -> None:
        start, end = parse_window("22:00-06:00")
        from datetime import time

        assert window_contains(start, end, time(22, 0))
        assert window_contains(start, end, time(23, 30))
        assert window_contains(start, end, time(0, 0))
        assert window_contains(start, end, time(5, 59))
        assert not window_contains(start, end, time(6, 0))
        assert not window_contains(start, end, time(12, 0))


class TestEvaluate:
    def test_disabled_always_allows(self) -> None:
        assert allows_execution(False, [], now=_ist(3, 0)) is True
        state = evaluate(False, ["09:00-18:00"], now=_ist(3, 0))
        assert state.allows_execution is True
        assert state.enabled is False
        assert state.timezone == "IST"

    def test_enabled_empty_holds(self) -> None:
        assert allows_execution(True, [], now=_ist(12, 0)) is False
        state = evaluate(True, [], now=_ist(12, 0))
        assert "no windows" in state.detail

    def test_inside_and_outside(self) -> None:
        windows = ["09:00-18:00"]
        assert in_any_window(windows, now=_ist(9, 0)) is True
        assert in_any_window(windows, now=_ist(18, 0)) is False
        assert in_any_window(windows, now=_ist(8, 59)) is False
        inside = evaluate(True, windows, now=_ist(10, 15))
        assert inside.allows_execution is True
        assert inside.now_ist == "10:15"
        outside = evaluate(True, windows, now=_ist(22, 15))
        assert outside.allows_execution is False
        assert "next window 09:00" in outside.detail

    def test_multiple_and_overnight(self) -> None:
        windows = ["10:00-13:00", "22:00-06:00"]
        assert in_any_window(windows, now=_ist(11, 0)) is True
        assert in_any_window(windows, now=_ist(23, 0)) is True
        assert in_any_window(windows, now=_ist(2, 0)) is True
        assert in_any_window(windows, now=_ist(14, 0)) is False


@pytest.fixture()
def db_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    data_dir = tmp_path / "talos-data"
    data_dir.mkdir()
    (data_dir / "projects").mkdir()
    monkeypatch.setenv("TALOS_DATA_DIR", str(data_dir))
    project_dir = data_dir / "projects" / "demo"
    project_dir.mkdir()
    path = project_dir / "talos.db"
    init_project_db(path)
    return path


@pytest.fixture()
def project(db_path: Path) -> SimpleNamespace:
    return SimpleNamespace(db_path=db_path, id="demo")


def _args(**kwargs):
    defaults = dict(
        min_delay=None,
        max_delay=None,
        max_queue_size=None,
        testing_windows=None,
        windows=None,
        clear_windows=False,
    )
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


class TestCliConfig:
    def test_default_off(self, project: SimpleNamespace) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_config(project, _args())
        out = buf.getvalue()
        assert "enabled        : off" in out
        assert "(none)" in out

    def test_set_windows_and_enable(
        self, project: SimpleNamespace, db_path: Path
    ) -> None:
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_config(
                project,
                _args(
                    testing_windows="on",
                    windows=["09:00-18:00", "20:00-22:00"],
                ),
            )
        out = buf.getvalue()
        assert "Scheduler config updated." in out
        assert "enabled        : on" in out
        assert "09:00-18:00" in out
        cfg = sched_db.get_scheduler_config(db_path)
        assert cfg["testing_windows_enabled"] is True
        assert cfg["testing_windows"] == ["09:00-18:00", "20:00-22:00"]
        data = yaml.safe_load((db_path.parent / "project.yaml").read_text())
        assert data["scheduler"]["testing_windows"]["enabled"] is True

    def test_enable_without_windows_errors(
        self, project: SimpleNamespace
    ) -> None:
        err = io.StringIO()
        with redirect_stderr(err), pytest.raises(SystemExit) as exc:
            cmd_config(project, _args(testing_windows="on"))
        assert exc.value.code == EXIT_USAGE
        assert "cannot be on without" in err.getvalue()

    def test_clear_windows_turns_off(
        self, project: SimpleNamespace, db_path: Path
    ) -> None:
        cmd_config(
            project,
            _args(testing_windows="on", windows=["09:00-18:00"]),
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            cmd_config(project, _args(clear_windows=True))
        cfg = sched_db.get_scheduler_config(db_path)
        assert cfg["testing_windows_enabled"] is False
        assert cfg["testing_windows"] == []

    def test_status_json_includes_windows(
        self, project: SimpleNamespace
    ) -> None:
        cmd_config(
            project,
            _args(testing_windows="on", windows=["09:00-18:00"]),
        )
        buf = io.StringIO()
        with (
            patch("talos.scheduler.runtime.SchedulerRuntimeManager") as mgr,
            redirect_stdout(buf),
        ):
            inst = mgr.return_value
            inst.status.return_value.to_dict.return_value = {"state": "stopped"}
            inst.status.return_value.state.value = "stopped"
            inst.status.return_value.pid = None
            inst.status.return_value.project_id = None
            inst.status.return_value.validation_deferred = False
            inst.status.return_value.log_path = None
            cmd_status(project, argparse.Namespace(output_format="json"))
        import json

        payload = json.loads(buf.getvalue())
        assert "testing_windows" in payload
        assert payload["testing_windows"]["timezone"] == "IST"
        assert payload["config"]["testing_windows"] == ["09:00-18:00"]


class TestSchedulerHold:
    def _enqueue(self, db_path: Path) -> str:
        jid = str(uuid.uuid4())
        sched_db.enqueue_job(
            db_path, jid, REPLAY_FLOW, "demo", flow_id=str(uuid.uuid4())
        )
        return jid

    def test_holds_outside_window(self, db_path: Path, project: SimpleNamespace) -> None:
        self._enqueue(db_path)
        sched_db.set_testing_windows_config(
            db_path, enabled=True, windows=["09:00-18:00"]
        )
        sched = ReplayScheduler(project)  # type: ignore[arg-type]
        with (
            patch.object(ReplayScheduler, "_execute_job") as exe,
            patch(
                "talos.scheduler.testing_windows.now_ist",
                return_value=_ist(22, 0),
            ),
        ):
            sched.start()
            time.sleep(0.25)
            sched.stop()
        exe.assert_not_called()
        jobs = sched_db.list_jobs(db_path, "demo")
        assert jobs[0].status == STATUS_PENDING

    def test_runs_inside_window(self, db_path: Path, project: SimpleNamespace) -> None:
        self._enqueue(db_path)
        sched_db.set_testing_windows_config(
            db_path, enabled=True, windows=["00:00-23:59"]
        )
        sched = ReplayScheduler(project)  # type: ignore[arg-type]
        with patch.object(ReplayScheduler, "_execute_job") as exe:
            sched.start()
            deadline = time.monotonic() + 2.0
            while time.monotonic() < deadline and exe.call_count == 0:
                time.sleep(0.05)
            sched.stop()
        exe.assert_called()
