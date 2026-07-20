"""
Talos Control Panel — backend configuration.

Paths default to the integrated monorepo layout (control panel lives inside
the Talos repository). Everything remains overridable via environment
variables for unusual installs.

  TALOS_HOME     — root of Talos's local state. Default: ~/.talos
  TALOS_ROOT     — Talos repo root (pyproject.toml + talos package).
                   Default: three levels above this file (monorepo root).
  TALOS_PYTHON   — Python used to run `python -m talos`. Default:
                   <TALOS_ROOT>/.venv/bin/python (Unix) or
                   <TALOS_ROOT>/.venv/Scripts/python.exe (Windows).
  CP_HOST/PORT   — where this control panel's API listens.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# talos_ui/config.py → backend → talos-control-panel → <repo root>
_MONOREPO_ROOT: Path = Path(__file__).resolve().parents[3]


def _default_talos_python(talos_root: Path) -> str:
    if sys.platform == "win32":
        return str(talos_root / ".venv" / "Scripts" / "python.exe")
    return str(talos_root / ".venv" / "bin" / "python")


TALOS_HOME: Path = Path(os.environ.get("TALOS_HOME", str(Path.home() / ".talos"))).expanduser()
PROJECTS_ROOT: Path = TALOS_HOME / "projects"
REGISTRY_PATH: Path = PROJECTS_ROOT / "registry.json"

TALOS_ROOT: Path = Path(
    os.environ.get("TALOS_ROOT", str(_MONOREPO_ROOT))
).expanduser().resolve()

TALOS_PYTHON: str = os.environ.get(
    "TALOS_PYTHON",
    _default_talos_python(TALOS_ROOT),
)

# Display / health only — mutations always go through TALOS_PYTHON -m talos.
TALOS_BIN: str = os.environ.get("TALOS_BIN", TALOS_PYTHON)

# Command timeout for normal (non-long-running) CLI calls, in seconds.
CLI_TIMEOUT: int = int(os.environ.get("TALOS_CP_CLI_TIMEOUT", "60"))

CP_HOST: str = os.environ.get("CP_HOST", "127.0.0.1")
CP_PORT: int = int(os.environ.get("CP_PORT", "8420"))

# Allowed origins for the Vite dev server / built frontend.
CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
]


def project_data_dir(project_id: str, record: dict | None = None) -> Path:
    """
    Resolve the on-disk data directory for a project.
    Prefers an explicit 'data_dir' key in the registry record; falls back to
    the conventional <PROJECTS_ROOT>/<project_id>/ layout used throughout the
    Talos docs (see BAC-decision-filter.md path examples).
    """
    if record and record.get("data_dir"):
        return Path(record["data_dir"]).expanduser()
    return PROJECTS_ROOT / project_id


def project_db_path(project_id: str, record: dict | None = None) -> Path:
    return project_data_dir(project_id, record) / "talos.db"


def project_archive_dir(project_id: str, record: dict | None = None) -> Path:
    return project_data_dir(project_id, record) / "archive"
