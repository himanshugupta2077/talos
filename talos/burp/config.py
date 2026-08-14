"""
Module: talos.burp.config

Purpose:
    Runtime Burp metadata-header knobs with a process-level cache so
    replay never calls ConfigurationManager on every probe.

    Defaults match BUILTIN_DEFAULTS['burp'] (enabled, prefix X-Talos).

Dependencies: dataclasses, pathlib, threading; optional ConfigurationManager
Data flow: first replay / tests → load_burp_config_for_project → process cache
Side effects: Process-level globals for cache only.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_HEADER_PREFIX = "X-Talos"


@dataclass(frozen=True)
class BurpRuntimeConfig:
    """
    Frozen knobs for Burp metadata headers.
    Defaults match BUILTIN_DEFAULTS['burp'].
    """

    enabled: bool = True
    header_prefix: str = DEFAULT_HEADER_PREFIX


_process_cfg: BurpRuntimeConfig | None = None
_process_cfg_lock = threading.Lock()
_process_cfg_loaded: bool = False


def set_process_burp_config(cfg: BurpRuntimeConfig) -> None:
    """
    Purpose:
        Install pre-resolved config for this process (scheduler init / tests).
    Input:
        cfg — frozen runtime knobs.
    Side effects: Replaces the process cache.
    """
    global _process_cfg, _process_cfg_loaded
    with _process_cfg_lock:
        _process_cfg = cfg
        _process_cfg_loaded = True


def get_process_burp_config() -> BurpRuntimeConfig:
    """
    Purpose:
        Return process-cached config or defaults (no YAML I/O).
    Output:
        BurpRuntimeConfig.
    Side effects: None.
    """
    cfg = _process_cfg
    if cfg is not None:
        return cfg
    return BurpRuntimeConfig()


def ensure_process_burp_config(
    project_data_dir: Path | None = None,
    *,
    project: Any = None,
) -> BurpRuntimeConfig:
    """
    Purpose:
        Return process-cached config; load once from layered config if never set.
    Input:
        project_data_dir — project data directory (parent of talos.db).
        project          — optional Project-like with .data_dir / .db_path.
    Output:
        BurpRuntimeConfig.
    Side effects: May read YAML on first call.
    """
    global _process_cfg, _process_cfg_loaded
    if _process_cfg_loaded and _process_cfg is not None:
        return _process_cfg
    with _process_cfg_lock:
        if _process_cfg_loaded and _process_cfg is not None:
            return _process_cfg
        cfg = load_burp_config_for_project(project_data_dir, project=project)
        _process_cfg = cfg
        _process_cfg_loaded = True
        return cfg


def reset_process_burp_config() -> None:
    """
    Purpose:
        Clear process cache (tests only).
    Side effects: Next ensure/load will re-read layered config.
    """
    global _process_cfg, _process_cfg_loaded
    with _process_cfg_lock:
        _process_cfg = None
        _process_cfg_loaded = False


def burp_config_from_effective(effective: Any) -> BurpRuntimeConfig:
    """
    Purpose:
        Map EffectiveConfig.burp → BurpRuntimeConfig.
    Input:
        effective — EffectiveConfig or duck-typed object with .burp / .get.
    Output:
        BurpRuntimeConfig (defaults on failure).
    Side effects: None.
    """
    try:
        section = effective.burp
        prefix = str(getattr(section, "header_prefix", DEFAULT_HEADER_PREFIX) or "")
        return BurpRuntimeConfig(
            enabled=bool(section.enabled),
            header_prefix=prefix.strip() or DEFAULT_HEADER_PREFIX,
        )
    except Exception:
        pass
    try:
        get = getattr(effective, "get", None)
        if callable(get):
            prefix = str(get("burp.header_prefix", DEFAULT_HEADER_PREFIX) or "")
            return BurpRuntimeConfig(
                enabled=bool(get("burp.enabled", True)),
                header_prefix=prefix.strip() or DEFAULT_HEADER_PREFIX,
            )
    except Exception:
        pass
    return BurpRuntimeConfig()


def load_burp_config_for_project(
    project_data_dir: Path | None = None,
    *,
    project: Any = None,
) -> BurpRuntimeConfig:
    """
    Purpose:
        Load burp knobs from layered configuration for a project.
    Input:
        project_data_dir — project data directory (parent of talos.db).
        project          — optional Project-like with .data_dir / .db_path.
    Output:
        BurpRuntimeConfig (defaults on failure).
    Side effects: May read YAML via ConfigurationManager.
    """
    data_dir: Path | None = None
    if project is not None:
        data_dir = getattr(project, "data_dir", None)
        if data_dir is None:
            db_path = getattr(project, "db_path", None)
            if db_path is not None:
                data_dir = Path(db_path).parent
    if data_dir is None and project_data_dir is not None:
        data_dir = Path(project_data_dir)
    try:
        from talos.configuration.manager import ConfigurationManager

        mgr = ConfigurationManager.from_env()
        effective = mgr.load(project_data_dir=data_dir)
        return burp_config_from_effective(effective)
    except Exception as exc:
        logger.debug("burp config load failed — using defaults: %s", exc)
        return BurpRuntimeConfig()
