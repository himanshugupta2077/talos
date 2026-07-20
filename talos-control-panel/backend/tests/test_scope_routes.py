"""
Control Panel scope/outscope route tests.

Mutations must go through Talos CLI helpers (run_scoped / run_scoped_with_temp_file).
Upload endpoints accept file bytes only — never client-supplied backend paths.
"""

from __future__ import annotations

import io
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# Ensure package import when tests run from repo root or backend dir.
import sys

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("TALOS_HOME", str(tmp_path / "talos-home"))
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


def test_scope_add_uses_cli(client):
    with patch("talos_ui.routers.projects.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result(["project", "scope", "add", "example.com"])]
        res = client.post(
            "/api/projects/demo/scope/add",
            json={"prefix": "example.com"},
        )
        assert res.status_code == 200
        run_scoped.assert_called_once()
        args = run_scoped.call_args[0]
        assert args[0] == "demo"
        assert args[1] == ["project", "scope", "add", "example.com"]


def test_scope_bulk_uses_temp_file_import(client):
    with patch("talos_ui.routers.projects.cli.run_scoped_with_temp_file") as bulk:
        bulk.return_value = [_ok_result(), _ok_result()]
        text = "example.com\napi.example.com\n"
        res = client.post(
            "/api/projects/demo/scope/bulk",
            json={"text": text, "replace": False},
        )
        assert res.status_code == 200
        bulk.assert_called_once()
        call_args = bulk.call_args
        assert call_args[0][0] == "demo"
        assert call_args[0][1] == ["project", "scope", "import"]
        assert call_args[0][2] == text
        assert call_args[1].get("suffix") == ".txt" or (
            len(call_args[0]) > 3 and call_args[0][3] == ".txt"
        ) or call_args.kwargs.get("suffix") == ".txt"


def test_scope_import_upload_no_client_path(client):
    with patch("talos_ui.routers.projects.cli.run_scoped_with_temp_file") as imp:
        imp.return_value = [_ok_result(), _ok_result()]
        content = b"# comment\nexample.com\n"
        res = client.post(
            "/api/projects/demo/scope/import",
            files={"file": ("hosts.txt", io.BytesIO(content), "text/plain")},
        )
        assert res.status_code == 200
        imp.assert_called_once()
        # Content passed as string body for temp file — not a client path.
        assert imp.call_args[0][2] == content.decode("utf-8")
        assert "/etc/" not in str(imp.call_args)


def test_outscope_add_uses_cli_prefix_not_domain_token(client):
    with patch("talos_ui.routers.projects.cli.run_scoped") as run_scoped:
        run_scoped.return_value = [_ok_result()]
        res = client.post(
            "/api/projects/demo/outscope",
            json={"prefix": "analytics.example.com"},
        )
        assert res.status_code == 200
        assert run_scoped.call_args[0][1] == [
            "project",
            "outscope",
            "add",
            "analytics.example.com",
        ]
        # Must not still require the legacy "domain" token.
        assert "domain" not in run_scoped.call_args[0][1]


def test_outscope_import_upload(client):
    with patch("talos_ui.routers.projects.cli.run_scoped_with_temp_file") as imp:
        imp.return_value = [_ok_result(), _ok_result()]
        res = client.post(
            "/api/projects/demo/outscope/import",
            files={"file": ("oos.txt", io.BytesIO(b"cdn.example.com\n"), "text/plain")},
        )
        assert res.status_code == 200
        assert imp.call_args[0][1] == ["project", "outscope", "import"]


def test_scope_upload_size_limit(client):
    big = b"a" * (256 * 1024 + 10)
    res = client.post(
        "/api/projects/demo/scope/import",
        files={"file": ("big.txt", io.BytesIO(big), "text/plain")},
    )
    assert res.status_code == 413


def test_commas_preserved_in_bulk_payload(client):
    """Frontend must not split commas; backend forwards raw text to core import."""
    with patch("talos_ui.routers.projects.cli.run_scoped_with_temp_file") as bulk:
        bulk.return_value = [_ok_result(), _ok_result()]
        raw = "example.com, still one line if core rejects\n"
        client.post(
            "/api/projects/demo/scope/bulk",
            json={"text": raw},
        )
        assert bulk.call_args[0][2] == raw
