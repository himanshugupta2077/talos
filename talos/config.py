"""
Module: talos.config

Purpose:
    Runtime path configuration for Talos data storage.
    Resolves where Talos stores global state and projects.

    Application settings (proxy, capture, scheduler, attack, mutation)
    are NOT here — they live in the layered configuration system:

        talos.configuration  (CLI-022)
            defaults → ~/.talos/config.yaml → project.yaml → CLI

    Use ConfigurationManager / load_effective_config for those values.
    This module only answers: "where is the Talos data directory?"

Dependencies: pathlib, os
Data flow:
    All modules import TalosConfig to resolve storage paths.
Side effects:
    - Reads environment variable TALOS_DATA_DIR (override for test isolation).
    - Falls back to ~/.talos if not set.

Related environment variables (resolved elsewhere):
    TALOS_PROJECT — process-scoped project id (CLI-013); read by ProjectManager.
                    Equivalent to root flag: talos --project <id> …
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
        Note:
            Project selection (TALOS_PROJECT) is handled by ProjectManager,
            not this class.
        """
        raw = os.environ.get("TALOS_DATA_DIR", "")
        if raw:
            data_dir = Path(raw).expanduser().resolve()
        else:
            data_dir = Path.home() / ".talos"
        return cls(data_dir=data_dir)
