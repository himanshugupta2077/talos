"""
Tests for Talos AI Layer — Phase E (core CLI only).

Covers:
    - Schema v52 ai_draft_findings
    - Minimal markdown KB (~/.talos/ai/kb/*.md) list/search/show + kb.search tool
    - draft_finding.create/list/show tools + promote CLI path
    - ATTACK_DISPLAY ai_draft + create_finding mapping (never confirm)
    - session export bundle
    - No subprocess under handlers; registry sealed
    - Control Panel intentionally out of scope for this ship
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from pathlib import Path

import pytest

from talos.ai.drafts import store as drafts_store
from talos.ai.kb import store as kb_store
from talos.ai.models import AutonomyMode
from talos.ai.policy import reset_token_store_for_tests
from talos.ai.tools.registry import default_registry, reset_default_registry_for_tests
from talos.ai.workflow.engine import WorkflowEngine, WorkflowEngineError
from talos.findings.db import get_finding, list_evidence
from talos.findings.model import ATTACK_DISPLAY, FINDING_STATUS_TRIAGING
from talos.projects.db import SCHEMA_VERSION, get_schema_version, migrate_project_db
from talos.projects.manager import ProjectManager, TALOS_PROJECT_ENV


@pytest.fixture(autouse=True)
def _clean_ai_singletons() -> None:
    reset_token_store_for_tests()
    reset_default_registry_for_tests()
    yield
    reset_token_store_for_tests()
    reset_default_registry_for_tests()


@pytest.fixture
def projects_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv(TALOS_PROJECT_ENV, raising=False)
    root = tmp_path / "projects"
    root.mkdir()
    return root


@pytest.fixture
def talos_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Point TalosConfig data_dir (and thus ~/.talos/ai/kb) at tmp."""
    home = tmp_path / "talos-home"
    home.mkdir()
    monkeypatch.setenv("TALOS_DATA_DIR", str(home))
    return home


@pytest.fixture
def manager(projects_root: Path) -> ProjectManager:
    return ProjectManager(projects_root)


@pytest.fixture
def project(manager: ProjectManager):
    p = manager.create(name="AI Phase E App", scope=["example.com"])
    manager.open(p.id)
    return manager.get(p.id)


@pytest.fixture
def engine(manager: ProjectManager, project) -> WorkflowEngine:
    return WorkflowEngine(manager)


def _insert_endpoint(db_path: Path, project_id: str, endpoint_id: str | None = None) -> str:
    eid = endpoint_id or str(uuid.uuid4())
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO endpoints (
                id, project_id, method, host, path, normalized_path,
                first_seen, last_seen
            ) VALUES (?, ?, 'GET', 'https://example.com', '/api/item',
                      '/api/item', '2020-01-01T00:00:00+00:00',
                      '2020-01-01T00:00:00+00:00')
            """,
            (eid, project_id),
        )
        conn.commit()
    return eid


# ================================================================== #
# Schema                                                               #
# ================================================================== #


class TestSchemaPhaseE:
    def test_schema_version_is_52(self) -> None:
        assert SCHEMA_VERSION == 52

    def test_fresh_db_has_draft_table(self, project) -> None:
        assert get_schema_version(project.db_path) == 52
        with sqlite3.connect(str(project.db_path)) as conn:
            tables = {
                r[0]
                for r in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
        assert "ai_draft_findings" in tables
        # KB is filesystem-only — no project KB table required
        assert "ai_project_kb_cards" not in tables

    def test_migrate_51_to_52(self, tmp_path: Path) -> None:
        from talos.projects.db import init_project_db

        db = tmp_path / "old.db"
        init_project_db(db)
        with sqlite3.connect(str(db)) as conn:
            # Simulate pre-v52: drop draft table and set version 51
            conn.execute("DROP TABLE IF EXISTS ai_draft_findings")
            conn.execute("UPDATE schema_version SET version = 51")
            conn.commit()
        migrate_project_db(db)
        assert get_schema_version(db) == 52
        with sqlite3.connect(str(db)) as conn:
            row = conn.execute(
                "SELECT name FROM sqlite_master WHERE name='ai_draft_findings'"
            ).fetchone()
        assert row is not None


# ================================================================== #
# Markdown KB                                                          #
# ================================================================== #


class TestMarkdownKb:
    def test_empty_kb_list(self, talos_home: Path, engine: WorkflowEngine) -> None:
        payload = engine.kb_list()
        assert payload["count"] == 0
        assert Path(payload["kb_dir"]).exists()
        assert str(talos_home) in payload["kb_dir"] or payload["kb_dir"].endswith(
            "ai/kb"
        )

    def test_search_and_show(
        self, talos_home: Path, engine: WorkflowEngine
    ) -> None:
        kb = kb_store.ensure_kb_dir()
        (kb / "idor-checklist.md").write_text(
            "# IDOR checklist\n\nSwap object ids between roles.\n",
            encoding="utf-8",
        )
        (kb / "nested").mkdir()
        (kb / "nested" / "xss.md").write_text(
            "# XSS notes\n\nReflected canary probes.\n",
            encoding="utf-8",
        )

        listed = engine.kb_list()
        assert listed["count"] == 2
        ids = {d["doc_id"] for d in listed["docs"]}
        assert "idor-checklist" in ids
        assert "nested/xss" in ids

        hits = engine.kb_search("idor object")
        assert hits["count"] >= 1
        assert any(h["doc_id"] == "idor-checklist" for h in hits["hits"])

        shown = engine.kb_show("idor-checklist")
        assert "Swap object ids" in (shown["doc"]["body"] or "")

        shown2 = engine.kb_show("nested/xss")
        assert shown2["doc"]["title"].lower().startswith("xss")

    def test_kb_search_tool(
        self, talos_home: Path, engine: WorkflowEngine, project
    ) -> None:
        kb = kb_store.ensure_kb_dir()
        (kb / "bac.md").write_text(
            "# BAC\nBroken access control session swap.\n", encoding="utf-8"
        )
        session = engine.start("kb", mode=AutonomyMode.STEP)
        plan, obs = engine.validate_and_execute(
            "kb.search",
            {"query": "access control", "limit": 5},
            session_id=session.session_id,
            force=True,
        )
        assert plan is not None
        assert obs.success
        assert obs.data.get("count", 0) >= 1


# ================================================================== #
# Draft findings                                                       #
# ================================================================== #


class TestDraftFindings:
    def test_attack_display_has_ai_draft(self) -> None:
        assert ATTACK_DISPLAY.get("ai_draft") == "AI Draft (promoted)"

    def test_create_list_show_promote(
        self, engine: WorkflowEngine, project
    ) -> None:
        eid = _insert_endpoint(project.db_path, project.id)
        session = engine.start("drafts", mode=AutonomyMode.STEP)
        plan, obs = engine.validate_and_execute(
            "draft_finding.create",
            {
                "title": "Possible IDOR on /api/item",
                "description": "Role A can read Role B object id=2.",
                "endpoint_id": eid,
                "attack_type": "ai_draft",
                "vulnerability_class": "idor",
                "confidence": 0.8,
                "evidence_refs": {"endpoint_ids": [eid], "flow_ids": []},
            },
            session_id=session.session_id,
            force=True,
        )
        assert obs.success, obs.error
        draft_id = obs.data["draft"]["id"]

        listed = engine.draft_list(status="draft")
        assert listed["count"] >= 1
        shown = engine.draft_show(draft_id)
        assert shown["draft"]["title"].startswith("Possible IDOR")

        result = engine.draft_promote(draft_id)
        finding_id = result["finding_id"]
        finding = get_finding(project.db_path, finding_id)
        assert finding is not None
        assert finding["status"] == FINDING_STATUS_TRIAGING
        assert finding["attack_type"] == "ai_draft"
        assert finding["verdict"] == "AI_DRAFT_PROMOTED"
        assert finding["title"].startswith("Possible IDOR")
        assert "Role A can read" in (finding.get("notes") or "")

        evidence = list_evidence(project.db_path, finding_id)
        types = {e["evidence_type"] for e in evidence}
        assert "endpoint" in types
        assert "analyst_note" in types

        # Re-promote rejected
        with pytest.raises(WorkflowEngineError):
            engine.draft_promote(draft_id)

    def test_create_rejects_unknown_attack_type(
        self, engine: WorkflowEngine, project
    ) -> None:
        eid = _insert_endpoint(project.db_path, project.id)
        session = engine.start("bad", mode=AutonomyMode.STEP)
        # Schema enum rejects at validate time
        with pytest.raises(WorkflowEngineError):
            engine.validate_and_execute(
                "draft_finding.create",
                {
                    "title": "x",
                    "description": "y" * 5,
                    "endpoint_id": eid,
                    "attack_type": "not_a_real_type",
                },
                session_id=session.session_id,
                force=True,
            )

    def test_create_requires_existing_endpoint(
        self, engine: WorkflowEngine, project
    ) -> None:
        session = engine.start("ep", mode=AutonomyMode.STEP)
        _, obs = engine.validate_and_execute(
            "draft_finding.create",
            {
                "title": "Missing endpoint",
                "description": "Should fail because endpoint does not exist.",
                "endpoint_id": str(uuid.uuid4()),
            },
            session_id=session.session_id,
            force=True,
        )
        assert not obs.success

    def test_reject_draft(self, engine: WorkflowEngine, project) -> None:
        eid = _insert_endpoint(project.db_path, project.id)
        draft = drafts_store.create_draft(
            project.db_path,
            project.id,
            title="Temp",
            description="Will reject",
            endpoint_id=eid,
        )
        out = engine.draft_reject(draft.id)
        assert out["draft"]["status"] == "rejected"


# ================================================================== #
# Session export                                                       #
# ================================================================== #


class TestSessionExport:
    def test_export_bundle(self, engine: WorkflowEngine, project) -> None:
        session = engine.start("export me", mode=AutonomyMode.STEP)
        engine.validate_and_execute(
            "endpoint.list",
            {"limit": 5},
            session_id=session.session_id,
            force=True,
        )
        bundle = engine.export_session(session.session_id)
        assert bundle["export_version"] == 1
        assert bundle["session"]["session_id"] == session.session_id
        assert bundle["session"]["goal"] == "export me"
        assert "suggestions" in bundle
        assert "plans" in bundle
        assert "observations" in bundle
        assert "audit" in bundle
        assert "notes" in bundle
        # capability tokens must not appear
        blob = json.dumps(bundle)
        assert "capability_token" not in blob


# ================================================================== #
# Registry / tools                                                     #
# ================================================================== #


class TestRegistryPhaseE:
    def test_phase_e_tools_registered(self, engine: WorkflowEngine) -> None:
        names = {t["name"] for t in engine.list_tools()}
        for n in (
            "kb.search",
            "draft_finding.list",
            "draft_finding.show",
            "draft_finding.create",
        ):
            assert n in names
        # Minimal KB: no AI write/promote tools
        assert "kb.project.upsert" not in names
        assert "kb.global.propose" not in names
        reg = default_registry()
        assert not hasattr(reg, "call")
        assert not hasattr(reg, "execute")

    def test_no_subprocess_import_in_handlers(self) -> None:
        import pathlib
        import re

        root = (
            pathlib.Path(__file__).resolve().parents[1]
            / "talos"
            / "ai"
            / "tools"
            / "handlers"
        )
        # Word-boundary import/call of subprocess, not doc comments.
        pat = re.compile(r"^\s*(import subprocess|from subprocess\b)", re.M)
        for path in root.glob("*.py"):
            text = path.read_text(encoding="utf-8")
            assert not pat.search(text), path
