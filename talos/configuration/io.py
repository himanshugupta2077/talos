"""
Module: talos.configuration.io

Purpose:
    Load and save YAML configuration files and legacy text filters
    (headers_drop.txt). Isolates filesystem I/O for the configuration package.

Dependencies: pathlib, yaml
Data flow:
    ConfigurationManager → load_yaml_file / save_yaml_file / load_headers_drop_file
Side effects:
    - save_yaml_file writes (and creates parent dirs).
    - loaders return empty dict / empty list when files are absent.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

import yaml

logger = logging.getLogger(__name__)

# Global config filename under data_dir (typically ~/.talos/config.yaml).
GLOBAL_CONFIG_NAME = "config.yaml"

# Per-project config filename under project data_dir.
PROJECT_CONFIG_NAME = "project.yaml"


class ConfigIOError(ValueError):
    """
    Purpose:
        Raised when a configuration file cannot be parsed or is not a mapping.
        CLI maps this to EXIT_FAILURE or EXIT_USAGE as appropriate.
    """


def global_config_path(data_dir: Path) -> Path:
    """
    Purpose: Resolve the global config.yaml path under the Talos data directory.
    Side effects: None.
    """
    return Path(data_dir) / GLOBAL_CONFIG_NAME


def project_config_path(project_data_dir: Path) -> Path:
    """
    Purpose: Resolve project.yaml under a project data directory.
    Side effects: None.
    """
    return Path(project_data_dir) / PROJECT_CONFIG_NAME


def load_yaml_file(path: Path) -> dict:
    """
    Purpose:
        Load a YAML mapping from disk.
    Input:
        path — absolute path to a .yaml file.
    Output:
        Dict (empty when file is missing or empty).
    Side effects: Reads the file when it exists.
    Raises:
        ConfigIOError when the file exists but is not a YAML mapping.
    """
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigIOError(f"Cannot read config file {path}: {exc}") from exc
    if not text.strip():
        return {}
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigIOError(f"Invalid YAML in {path}: {exc}") from exc
    if data is None:
        return {}
    if not isinstance(data, dict):
        raise ConfigIOError(
            f"Config file {path} must be a YAML mapping at the top level."
        )
    return data


def save_yaml_file(path: Path, data: dict) -> None:
    """
    Purpose:
        Persist a configuration mapping as YAML.
    Input:
        path — destination path.
        data — mapping to write (empty dict writes an empty document).
    Side effects:
        Creates parent directories; overwrites path.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    # sort_keys=False preserves human section order when we write known shapes.
    dumped = yaml.safe_dump(
        data,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
    )
    path.write_text(dumped if dumped.strip() else "", encoding="utf-8")


def load_headers_drop_file(path: Path) -> Optional[list[str]]:
    """
    Purpose:
        Parse a headers_drop.txt-style file into a list of header names.
    Input:
        path — path to the filter file.
    Output:
        List of non-comment header names, or None if the file is missing.
    Side effects: Reads the file when present.
    """
    if not path.exists():
        return None
    names: list[str] = []
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            names.append(stripped)
    except OSError as exc:
        logger.warning("Failed to read headers_drop at %s: %s", path, exc)
        return None
    return names


def ensure_empty_project_config(project_data_dir: Path) -> Path:
    """
    Purpose:
        Create an empty project.yaml on project creation so operators have a
        stable edit target. Does not overwrite existing files.
    Input:
        project_data_dir — project storage directory.
    Output:
        Path to project.yaml.
    Side effects:
        May create project.yaml with a short comment header.
    """
    path = project_config_path(project_data_dir)
    if path.exists():
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "# Talos project configuration overrides.\n"
        "# Only store values that differ from global / defaults.\n"
        "# Manage with: talos config set|unset|edit\n"
        "# View effective: talos config effective\n",
        encoding="utf-8",
    )
    return path
