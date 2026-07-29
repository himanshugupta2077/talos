"""
CLI-020: Help output and command hierarchy must match the live parsers.

Guards against documentation / Talos Helper drift where operators copy a
command from ``talos --help`` or docs and the argparse tree rejects it.

Primary regression from CLI-020:
  Help/docs said ``talos endpoint rules list``
  Parser accepts ``talos endpoint rules`` only
"""

from __future__ import annotations

import io
import re
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from talos.__main__ import _print_usage
from talos.projects.endpoint_cli import run_endpoint_cli
from talos.projects.manager import ProjectManager


# ------------------------------------------------------------------ #
# Talos Helper (root --help)                                           #
# ------------------------------------------------------------------ #


def _root_help_text() -> str:
    """Capture root help text from the Talos Helper."""
    out = io.StringIO()
    with redirect_stdout(out):
        _print_usage()
    return out.getvalue()


def test_talos_helper_endpoint_rules_is_leaf_not_rules_list() -> None:
    """
    Root help must document ``rules`` as path-rule inventory (alias) and the
    first-class ``rule`` resource — not the obsolete two-token form
    ``rules list``.
    """
    text = _root_help_text()
    assert "endpoint" in text
    # Canonical rule resource.
    assert re.search(r"^\s+rule add\|update\|delete\|list\|show\|preview", text, re.M)
    # Compat alias for list.
    assert re.search(r"^\s+rules\s+", text, re.M)
    # Must not advertise nested ``rules list`` (parser has no list under rules).
    assert not re.search(r"^\s+rules list\b", text, re.M)
    # Policy explanation command.
    assert re.search(r"^\s+policy <id>\s+", text, re.M)


def test_talos_helper_scheduler_documents_job_management() -> None:
    """Scheduler section must stay aligned with CLI-016 job commands."""
    text = _root_help_text()
    assert "jobs list" in text
    assert "jobs show" in text
    assert "cancel" in text
    assert "prune" in text


def test_talos_helper_auth_config_documents_session_recovery() -> None:
    """auth-config section must list CLI-021 recovery commands."""
    text = _root_help_text()
    assert re.search(r"^\s+clear-session\s+", text, re.M)
    assert re.search(r"^\s+reset-health\s+", text, re.M)


def test_talos_helper_documents_layered_config() -> None:
    """Root help must advertise CLI-022 talos config commands."""
    text = _root_help_text()
    assert re.search(r"^\s+config\s+", text, re.M)
    assert "effective" in text
    assert "Layered configuration" in text or "layered configuration" in text.lower()
    assert "proxy|capture|scheduler|attack|http" in text
    assert "HTTP Manipulation Engine" in text or "http" in text


def test_talos_helper_documents_send_repeater() -> None:
    """Root help must advertise Repeater Phase 2 (talos send) verbs."""
    text = _root_help_text()
    assert re.search(r"^\s+send\s+", text, re.M)
    assert "from <flow_id>" in text or "from" in text
    assert "once" in text
    assert "history" in text
    assert "diff" in text
    # Phase 2 surface
    assert "redo" in text
    assert "dup" in text
    assert "export" in text
    assert "note" in text
    assert "edit" in text
    assert "tree" in text
    # Persistent tab archive
    assert "tab open" in text or "tab" in text


def test_talos_helper_documents_intruder() -> None:
    """Root help must advertise Intruder Phase 1–4 (talos intruder) verbs."""
    text = _root_help_text()
    assert re.search(r"^\s+intruder\s+", text, re.M)
    assert "session create" in text
    assert "payload set" in text or "payload" in text
    assert "sniper" in text
    assert "results" in text
    # Phase 4
    assert "suggest" in text
    assert "adaptive" in text or "token_bucket" in text
    assert "bruteforce" in text or "dates" in text or "pattern" in text
    # Distinct from exact replay.
    assert "replay" in text
    assert "Repeater" in text or "mutable" in text.lower()


# ------------------------------------------------------------------ #
# Live endpoint rules parser                                           #
# ------------------------------------------------------------------ #


def _project_manager(tmp_path: Path) -> tuple[ProjectManager, MagicMock]:
    """
    Build a ProjectManager mock with an active project so rules can run.
    """
    project = MagicMock()
    project.id = "proj-hierarchy"
    project.db_path = tmp_path / "talos.db"
    # Empty DB is enough for rules list (returns "No path rules defined.")
    from talos.projects.db import init_project_db

    init_project_db(project.db_path)

    manager = MagicMock(spec=ProjectManager)
    manager.active.return_value = project
    return manager, project


def test_endpoint_rules_accepted_without_list(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``talos endpoint rules`` is the canonical inventory command."""
    manager, _ = _project_manager(tmp_path)
    run_endpoint_cli(manager, ["rules"])
    out = capsys.readouterr().out
    assert "path rule" in out.lower() or "No path rules" in out


def test_endpoint_rules_list_rejected_by_parser(tmp_path: Path) -> None:
    """
    Obsolete form ``endpoint rules list`` must fail at parse time so help
    cannot silently diverge again without a failing test.
    """
    manager, _ = _project_manager(tmp_path)
    with pytest.raises(SystemExit) as exc:
        run_endpoint_cli(manager, ["rules", "list"])
    assert exc.value.code == 2


def test_endpoint_rules_help_documents_format_not_list_subcommand(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Subcommand help for ``rules`` has no nested ``list`` choice."""
    manager, _ = _project_manager(tmp_path)
    with pytest.raises(SystemExit) as exc:
        run_endpoint_cli(manager, ["rules", "--help"])
    assert exc.value.code == 0
    combined = capsys.readouterr().out + capsys.readouterr().err
    assert "talos endpoint rules" in combined
    assert "--format" in combined
    # Usage line is the leaf form; no ``rules list`` path in usage.
    assert "rules list" not in combined
