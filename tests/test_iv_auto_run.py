"""
IV auto-run and unified operator scan.

Covers:
    - auto_run default off; persist on/off
    - CLI --auto-run on enables the engine and the unified deep scan
    - unique endpoint + unique parameter identity (duplicate captures / same
      param on two endpoints → one untested target)
    - synthesized or in-flight params are skipped
    - logout / dangerous / excluded endpoints are skipped
    - auto_enqueue_pending_params no-ops when auto_run or enabled is off
    - default run upgrades leftover standard/exhaustive to deep
"""

from __future__ import annotations

import io
import json
import sqlite3
import uuid
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from talos.input_validation import db as iv_db
from talos.input_validation.cli import run_input_validation_cli
from talos.input_validation.config import (
    OPERATOR_SCAN_TIER,
    IVConfig,
    apply_operator_scan,
    get_iv_auto_run,
    load_config,
    save_config,
    set_iv_auto_run,
)
from talos.input_validation.engine import (
    auto_enqueue_pending_params,
    get_untested_iv_params,
    make_param_uuid,
)
from talos.input_validation.profile import empty_param_profile
from talos.projects.db import SCHEMA_VERSION, get_schema_version, init_project_db


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


@pytest.fixture
def manager_enabled(db_path: Path) -> MagicMock:
    save_config(db_path, IVConfig(enabled=True))
    project = SimpleNamespace(db_path=db_path, id="proj")
    manager = MagicMock()
    manager.active.return_value = project
    return manager


def _run_iv(manager: MagicMock, argv: list[str]) -> str:
    out = io.StringIO()
    with redirect_stdout(out):
        run_input_validation_cli(manager, argv)
    return out.getvalue()


def _seed_param(
    db_path: Path,
    *,
    host: str,
    path: str,
    name: str,
    location: str = "query",
    endpoint_id: str | None = None,
    qualified: int = 1,
    excluded: int = 0,
    logout: int = 0,
    dangerous: int = 0,
    project_id: str = "proj",
) -> tuple[str, str]:
    ep_id = endpoint_id or str(uuid.uuid4())
    param_uuid = make_param_uuid(host, location, name)
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO endpoints
                (id, project_id, host, method, path, normalized_path,
                 first_seen, last_seen)
            VALUES (?, ?, ?, 'GET', ?, ?, datetime('now'), datetime('now'))
            """,
            (ep_id, project_id, host, path, path),
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO endpoint_policy
                (endpoint_id, qualified, excluded, logout, dangerous, updated_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            """,
            (ep_id, qualified, excluded, logout, dangerous),
        )
        conn.execute(
            """
            INSERT INTO parameters (id, endpoint_id, name, location, param_type)
            VALUES (?, ?, ?, ?, 'string')
            """,
            (str(uuid.uuid4()), ep_id, name, location),
        )
        conn.commit()
    return ep_id, param_uuid


def _mark_synthesized(
    db_path: Path, *, host: str, location: str, name: str, param_uuid: str
) -> None:
    profile = empty_param_profile(
        param_uuid=param_uuid,
        host=host,
        location=location,
        name=name,
        budget_tier=OPERATOR_SCAN_TIER,
    )
    inferred = profile.setdefault("inferred", {})
    inferred["synthesis"] = {"source": "probes"}
    iv_db.upsert_param_profile(
        db_path,
        param_uuid=param_uuid,
        host=host,
        location=location,
        param_name=name,
        profile=profile,
    )


# ================================================================== #
# Config helpers                                                       #
# ================================================================== #


class TestIvAutoRunConfig:
    def test_schema_includes_auto_run(self, db_path: Path) -> None:
        assert get_schema_version(db_path) == SCHEMA_VERSION
        with sqlite3.connect(str(db_path)) as conn:
            cols = {
                row[1]
                for row in conn.execute(
                    "PRAGMA table_info(input_validation_config)"
                ).fetchall()
            }
        assert "auto_run" in cols

    def test_default_is_off(self, db_path: Path) -> None:
        cfg = load_config(db_path)
        assert cfg.auto_run is False
        assert get_iv_auto_run(db_path) is False

    def test_default_probe_strategy_is_deep(self, db_path: Path) -> None:
        assert load_config(db_path).probe_strategy == OPERATOR_SCAN_TIER

    def test_set_on_enables_engine_and_deep(self, db_path: Path) -> None:
        save_config(db_path, IVConfig(enabled=False, probe_strategy="exhaustive"))
        cfg = set_iv_auto_run(db_path, True)
        assert cfg.auto_run is True
        assert cfg.enabled is True
        assert cfg.probe_strategy == OPERATOR_SCAN_TIER
        assert get_iv_auto_run(db_path) is True

    def test_set_off_leaves_engine(self, db_path: Path) -> None:
        set_iv_auto_run(db_path, True)
        cfg = set_iv_auto_run(db_path, False)
        assert cfg.auto_run is False
        assert cfg.enabled is True

    def test_apply_operator_scan_upgrades_legacy(self) -> None:
        cfg = IVConfig(probe_strategy="exhaustive")
        assert apply_operator_scan(cfg) is True
        assert cfg.probe_strategy == "deep"
        assert apply_operator_scan(cfg) is False


# ================================================================== #
# CLI                                                                  #
# ================================================================== #


class TestIvAutoRunCli:
    def test_enable_auto_run(self, manager_enabled: MagicMock, db_path: Path) -> None:
        text = _run_iv(manager_enabled, ["config", "--auto-run", "on"])
        assert "Auto Run       : Enabled" in text
        assert get_iv_auto_run(db_path) is True
        assert load_config(db_path).enabled is True
        assert load_config(db_path).probe_strategy == OPERATOR_SCAN_TIER

    def test_disable_auto_run(self, manager_enabled: MagicMock, db_path: Path) -> None:
        set_iv_auto_run(db_path, True)
        text = _run_iv(manager_enabled, ["config", "--auto-run", "off"])
        assert "Auto Run       : Disabled" in text
        assert get_iv_auto_run(db_path) is False

    def test_run_without_budget_upgrades_to_deep(
        self, manager_enabled: MagicMock, db_path: Path
    ) -> None:
        save_config(db_path, IVConfig(enabled=True, probe_strategy="exhaustive"))
        with (
            patch(
                "talos.input_validation.engine.verify_auth_for_iv_scan",
                return_value=[],
            ),
            patch(
                "talos.input_validation.engine.schedule_project",
                return_value=1,
            ),
        ):
            text = _run_iv(manager_enabled, ["run"])
        assert load_config(db_path).probe_strategy == "deep"
        assert "deep" in text


# ================================================================== #
# Uniqueness / skip rules                                              #
# ================================================================== #


class TestUntestedParamDiscovery:
    def test_duplicate_captures_of_same_endpoint_once(self, db_path: Path) -> None:
        # Five identical browser captures collapse to one unique endpoint
        # (method + origin + normalized path) and one parameter row
        # (UNIQUE endpoint_id, name, location). Auto-run sees one target.
        ep, uid = _seed_param(db_path, host="app.example.com", path="/login", name="user")
        targets = get_untested_iv_params(db_path, "proj", limit=20)
        assert len(targets) == 1
        assert targets[0]["param_uuid"] == uid
        assert targets[0]["endpoint_id"] == ep
        assert targets[0]["name"] == "user"

    def test_same_param_on_two_endpoints_once(self, db_path: Path) -> None:
        _seed_param(db_path, host="app.example.com", path="/a", name="q")
        _seed_param(db_path, host="app.example.com", path="/b", name="q")
        targets = get_untested_iv_params(db_path, "proj", limit=20)
        assert len(targets) == 1
        assert targets[0]["param_uuid"] == make_param_uuid("app.example.com", "query", "q")

    def test_different_names_are_distinct(self, db_path: Path) -> None:
        ep, _ = _seed_param(db_path, host="app.example.com", path="/a", name="user")
        _seed_param(
            db_path,
            host="app.example.com",
            path="/a",
            name="pass",
            endpoint_id=ep,
        )
        names = {t["name"] for t in get_untested_iv_params(db_path, "proj", limit=20)}
        assert names == {"user", "pass"}

    def test_skips_synthesized(self, db_path: Path) -> None:
        _ep, uid = _seed_param(db_path, host="app.example.com", path="/a", name="q")
        _mark_synthesized(
            db_path, host="app.example.com", location="query", name="q", param_uuid=uid
        )
        assert get_untested_iv_params(db_path, "proj") == []

    def test_skips_pending_job(self, db_path: Path) -> None:
        ep, uid = _seed_param(db_path, host="app.example.com", path="/a", name="q")
        with sqlite3.connect(str(db_path)) as conn:
            conn.execute(
                """
                INSERT INTO scheduler_jobs
                    (job_id, endpoint_id, job_type, status, created_at, meta)
                VALUES (?, ?, 'iv_baseline', 'pending', datetime('now'), ?)
                """,
                (
                    str(uuid.uuid4()),
                    ep,
                    json.dumps({"parameter_uuid": uid, "planner_action": "baseline"}),
                ),
            )
            conn.commit()
        assert get_untested_iv_params(db_path, "proj") == []

    def test_skips_logout_and_dangerous(self, db_path: Path) -> None:
        _seed_param(
            db_path, host="app.example.com", path="/out", name="q", logout=1
        )
        _seed_param(
            db_path, host="app.example.com", path="/boom", name="q2", dangerous=1
        )
        assert get_untested_iv_params(db_path, "proj") == []

    def test_skips_inventory_only(self, db_path: Path) -> None:
        _seed_param(
            db_path,
            host="app.example.com",
            path="/page",
            name="script_src",
            location="response",
        )
        assert get_untested_iv_params(db_path, "proj") == []


# ================================================================== #
# Auto enqueue                                                         #
# ================================================================== #


class TestAutoEnqueue:
    def test_off_is_noop(self, db_path: Path) -> None:
        _seed_param(db_path, host="app.example.com", path="/a", name="q")
        save_config(db_path, IVConfig(enabled=True, auto_run=False))
        assert auto_enqueue_pending_params(db_path, "proj") == 0

    def test_disabled_engine_is_noop(self, db_path: Path) -> None:
        _seed_param(db_path, host="app.example.com", path="/a", name="q")
        save_config(db_path, IVConfig(enabled=False, auto_run=True))
        assert auto_enqueue_pending_params(db_path, "proj") == 0

    def test_enqueues_and_then_is_idempotent(self, db_path: Path) -> None:
        _seed_param(db_path, host="app.example.com", path="/a", name="q")
        save_config(db_path, IVConfig(enabled=True, auto_run=True))
        first = auto_enqueue_pending_params(db_path, "proj")
        assert first > 0
        assert load_config(db_path).probe_strategy == OPERATOR_SCAN_TIER
        second = auto_enqueue_pending_params(db_path, "proj")
        assert second == 0
        assert get_untested_iv_params(db_path, "proj") == []
