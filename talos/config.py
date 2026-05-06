"""
Module: talos.config

Purpose:
    Central configuration for runtime paths and settings.
    Single source of truth for where Talos stores its data.

Dependencies: pathlib, os
Data flow:
    All modules import TalosConfig to resolve storage paths.
Side effects:
    - Reads environment variable TALOS_DATA_DIR (override for test isolation).
    - Falls back to ~/.talos if not set.
"""

import os
from pathlib import Path


class TalosConfig:
    """
    Purpose:
        Holds all runtime-configurable paths for Talos.
        Constructed once at startup; passed to subsystems that need paths.

    Fields:
        data_dir      — Root storage directory for all Talos data.
        projects_dir  — Subdirectory containing all project workspaces.
    """

    def __init__(self, data_dir: Path) -> None:
        # Why store as Path: consumers need path operations, not strings.
        self.data_dir: Path = data_dir
        self.projects_dir: Path = data_dir / "projects"

    @classmethod
    def from_env(cls) -> "TalosConfig":
        """
        Purpose:
            Build config from environment, falling back to ~/.talos.
            TALOS_DATA_DIR env var overrides the default (useful for tests).
        Output:  TalosConfig instance.
        Side effects: None.
        """
        raw = os.environ.get("TALOS_DATA_DIR", "")
        if raw:
            data_dir = Path(raw).expanduser().resolve()
        else:
            data_dir = Path.home() / ".talos"
        return cls(data_dir=data_dir)
