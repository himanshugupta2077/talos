"""
Tests for Windows-safe atomic_write_text used by proxy/scheduler state.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from talos.proxy.runtime.atomic_io import atomic_write_text
from talos.proxy.runtime.state import (
    ProxyRuntimeState,
    ProxyState,
    load_state,
    save_state,
)


def test_atomic_write_text_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "state.json"
    atomic_write_text(path, '{"ok": true}\n', prefix=".state.", suffix=".tmp")
    assert path.read_text(encoding="utf-8") == '{"ok": true}\n'
    # No leftover temps.
    leftovers = list(path.parent.glob(".state.*"))
    assert leftovers == []


def test_atomic_write_retries_permission_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "proxy.json"
    path.write_text("old\n", encoding="utf-8")
    calls = {"n": 0}
    real_replace = __import__("os").replace

    def flaky_replace(src: str, dst: str | Path) -> None:  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if calls["n"] < 3:
            raise PermissionError(13, "Access is denied")
        real_replace(src, dst)

    monkeypatch.setattr("talos.proxy.runtime.atomic_io._REPLACE_BASE_DELAY_S", 0.0)
    with patch("talos.proxy.runtime.atomic_io.os.replace", side_effect=flaky_replace):
        atomic_write_text(path, "new\n", prefix=".proxy.json.", suffix=".tmp")

    assert path.read_text(encoding="utf-8") == "new\n"
    assert calls["n"] == 3


def test_atomic_write_fallback_in_place_when_replace_always_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "proxy.json"
    path.write_text("old\n", encoding="utf-8")

    def always_fail(src: str, dst: str | Path) -> None:  # type: ignore[no-untyped-def]
        raise PermissionError(13, "Access is denied")

    monkeypatch.setattr("talos.proxy.runtime.atomic_io.os.replace", always_fail)
    monkeypatch.setattr("talos.proxy.runtime.atomic_io.sys.platform", "win32")
    monkeypatch.setattr("talos.proxy.runtime.atomic_io._REPLACE_ATTEMPTS", 2)
    monkeypatch.setattr("talos.proxy.runtime.atomic_io._REPLACE_BASE_DELAY_S", 0.0)

    atomic_write_text(path, "recovered\n", prefix=".proxy.json.", suffix=".tmp")
    assert path.read_text(encoding="utf-8") == "recovered\n"


def test_save_and_load_state(tmp_path: Path) -> None:
    state = ProxyRuntimeState(
        state=ProxyState.RUNNING,
        pid=12345,
        create_time=1.0,
        project_id="proj-1",
        listen_host="127.0.0.1",
        listen_port=8080,
    )
    save_state(tmp_path, state)
    loaded = load_state(tmp_path)
    assert loaded.state == ProxyState.RUNNING
    assert loaded.pid == 12345
    assert loaded.project_id == "proj-1"
    raw = json.loads((tmp_path / "runtime" / "proxy.json").read_text(encoding="utf-8"))
    assert raw["listen_port"] == 8080
