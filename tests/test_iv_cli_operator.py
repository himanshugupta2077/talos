"""
Module 12 — Operator CLI surface smoke tests.

Covers:
    - Help lists candidates / synthesize / budget-related commands
    - status includes confidence summary keys
    - candidates command produces table or JSON
    - export parameter --format json includes version fields
    - Talos Helper documents new IV surface
"""

from __future__ import annotations

import io
import json
import sqlite3
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from talos.__main__ import _print_usage
from talos.input_validation import db as iv_db
from talos.input_validation.candidates import (
    enrich_profile_capabilities_and_candidates,
)
from talos.input_validation.cli import run_input_validation_cli
from talos.input_validation.config import IVConfig, save_config
from talos.input_validation.profile import empty_param_profile
from talos.projects.db import init_project_db


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    path = tmp_path / "talos.db"
    init_project_db(path)
    return path


@pytest.fixture
def manager(db_path: Path, tmp_path: Path) -> MagicMock:
    # exports/ lives next to talos.db
    project = SimpleNamespace(
        db_path=db_path,
        id="test-project",
        data_dir=tmp_path,
    )
    m = MagicMock()
    m.active.return_value = project
    return m


def _seed_profile(db_path: Path) -> str:
    uid = "a" * 32
    profile = empty_param_profile(
        param_uuid=uid,
        host="api.example.com",
        location="query",
        name="q",
        budget_tier="standard",
    )
    profile["observed"]["reflection"] = {
        "state": "reflected",
        "confidence": 92,
        "uncertainty": "none",
        "contexts": ["html"],
        "encoding": None,
        "evidence_flow_ids": ["f1"],
    }
    profile["observed"]["acceptance"] = {
        "classes": {
            "markup": {"outcome": "accepted", "confidence": 88},
            "quote": {"outcome": "accepted", "confidence": 80},
        }
    }
    profile["observed"]["types"] = {
        "string": {"outcome": "accepted", "confidence": 90},
    }
    profile["observed"]["length"] = {
        "state": "open",
        "max_accepted": 100,
        "confidence": 70,
    }
    enrich_profile_capabilities_and_candidates(profile)
    iv_db.upsert_param_profile(
        db_path,
        param_uuid=uid,
        host="api.example.com",
        location="query",
        param_name="q",
        profile=profile,
        bump_version=False,
    )
    return uid


def test_iv_help_lists_operator_commands() -> None:
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            run_input_validation_cli(MagicMock(), ["--help"])
        except SystemExit as e:
            assert e.code in (0, None)
    text = out.getvalue() + err.getvalue()
    assert "candidates" in text
    assert "synthesize" in text
    assert "export" in text
    assert "status" in text


def test_candidates_help_documents_filters() -> None:
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            run_input_validation_cli(MagicMock(), ["candidates", "--help"])
        except SystemExit as e:
            assert e.code in (0, None)
    text = out.getvalue() + err.getvalue()
    assert "--attack" in text
    assert "--min-score" in text
    assert "--capability" in text
    assert "--host" in text
    # QA-USD-10 / QA-USD-14: help lists new Phase 4 attacks + NRS capability
    assert "webhook_abuse" in text
    assert "oauth_redirect" in text
    assert "network_resource_sink" in text


def test_export_parameter_help_documents_format() -> None:
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            run_input_validation_cli(
                MagicMock(), ["export", "parameter", "--help"]
            )
        except SystemExit as e:
            assert e.code in (0, None)
    text = out.getvalue() + err.getvalue()
    assert "--format" in text
    assert "json" in text


def test_run_help_documents_budget() -> None:
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            run_input_validation_cli(MagicMock(), ["run", "--help"])
        except SystemExit as e:
            assert e.code in (0, None)
    text = out.getvalue() + err.getvalue()
    assert "--budget" in text
    # QA-USD-15: run help mentions url_sink_probes / canary path
    assert "url_sink" in text.lower()


def test_status_includes_confidence(manager: MagicMock, db_path: Path) -> None:
    _seed_profile(db_path)
    # Minimal cache row so total_params can be non-zero without jobs.
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO iv_param_cache
            (id, host, location, param_name, phase, status, result)
            VALUES ('c1', 'api.example.com', 'query', 'q', 'baseline', 'completed', '{}')
            """
        )
        conn.commit()

    out = io.StringIO()
    with redirect_stdout(out):
        run_input_validation_cli(manager, ["status", "--format", "json"])
    data = json.loads(out.getvalue())
    assert "budget_tier" in data
    assert "requests_used" in data
    assert "confidence" in data
    conf = data["confidence"]
    assert "buckets" in conf
    assert "profiles_with_candidates" in conf
    assert conf["profiles_with_candidates"] >= 1


def test_candidates_list_json(manager: MagicMock, db_path: Path) -> None:
    _seed_profile(db_path)
    out = io.StringIO()
    with redirect_stdout(out):
        run_input_validation_cli(
            manager,
            ["candidates", "--min-score", "1", "--format", "json"],
        )
    data = json.loads(out.getvalue())
    assert "candidates" in data
    assert data["count"] >= 1
    assert "note" in data
    assert "prioritization" in data["note"].lower()
    row = data["candidates"][0]
    assert "attack" in row
    assert "score" in row
    assert "confidence" in row


def test_export_parameter_json_version_fields(
    manager: MagicMock, db_path: Path, tmp_path: Path
) -> None:
    uid = _seed_profile(db_path)
    out_file = tmp_path / "param.json"
    out = io.StringIO()
    with redirect_stdout(out):
        run_input_validation_cli(
            manager,
            [
                "export",
                "parameter",
                uid,
                "--format",
                "json",
                "-o",
                str(out_file),
            ],
        )
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["export_type"] == "parameter"
    assert data["param_uuid"] == uid
    assert "schema_version" in data
    assert data["schema_version"] is not None
    assert "capabilities" in data
    assert "candidates" in data
    assert isinstance(data["candidates"], list)


def test_talos_helper_documents_iv_operator_surface() -> None:
    out = io.StringIO()
    with redirect_stdout(out):
        _print_usage()
    text = out.getvalue()
    assert "input-validation" in text
    assert "candidates" in text
    assert "synthesize" in text
    assert "--budget" in text or "budget" in text
