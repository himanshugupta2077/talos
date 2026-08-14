"""Isolate Burp snapshot writes away from the operator's ~/.talos/burp."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _isolate_burp_snapshots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TALOS_BURP_DIR", str(tmp_path / "burp-snapshots"))
