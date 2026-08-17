"""
Import hygiene for talos.send.

Control Panel Send-to-Repeater only needs talos.send.db. That import must
not pull talos.send.engine (httpx). Regression for issue #4.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def _run(script: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_send_db_importable_without_httpx():
    script = r"""
import builtins
import sys

real_import = builtins.__import__

def _blocked(name, *args, **kwargs):
    if name == "httpx" or name.startswith("httpx."):
        raise ModuleNotFoundError("No module named 'httpx'")
    return real_import(name, *args, **kwargs)

builtins.__import__ = _blocked
from talos.send import db as send_db
assert "talos.send.engine" not in sys.modules
assert hasattr(send_db, "list_repeater_tabs")
assert hasattr(send_db, "open_repeater_tab")
"""
    result = _run(script)
    assert result.returncode == 0, result.stdout + result.stderr


def test_send_package_lazy_engine_still_exports():
    script = r"""
from talos.send import send_once, MAX_PROFILE_N, SendOutcome
assert callable(send_once)
assert MAX_PROFILE_N == 50
assert SendOutcome.__name__ == "SendOutcome"
"""
    result = _run(script)
    assert result.returncode == 0, result.stdout + result.stderr
