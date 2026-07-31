"""
Module: talos.url_sink.config

Purpose:
    Runtime URL Sink Discovery knobs with process-level caching so the
    FlowWorker and IV planner never call ConfigurationManager per flow.

    Defaults match BUILTIN_DEFAULTS['url_sink'] (all features on; score 45).

Dependencies: dataclasses, pathlib, threading; optional ConfigurationManager
Data flow: worker/IV init → load_url_sink_config_for_project → process cache
Side effects: Process-level globals for cache only.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class UrlSinkRuntimeConfig:
    """
    Frozen knobs for passive inventory + IV canaries.
    Defaults match BUILTIN_DEFAULTS['url_sink'].
    """

    passive_enabled: bool = True
    html_js_enabled: bool = True
    iv_probes_enabled: bool = True
    score_threshold: int = 45


_process_cfg: UrlSinkRuntimeConfig | None = None
_process_cfg_lock = threading.Lock()
_process_cfg_loaded: bool = False


def set_process_url_sink_config(cfg: UrlSinkRuntimeConfig) -> None:
    """Install pre-resolved config for this process (worker init / tests)."""
    global _process_cfg, _process_cfg_loaded
    with _process_cfg_lock:
        _process_cfg = cfg
        _process_cfg_loaded = True


def get_process_url_sink_config() -> UrlSinkRuntimeConfig:
    """Return process-cached config or defaults (no YAML I/O)."""
    cfg = _process_cfg
    if cfg is not None:
        return cfg
    return UrlSinkRuntimeConfig()


def ensure_process_url_sink_config(
    project_data_dir: Path | None = None,
    *,
    project: Any = None,
) -> UrlSinkRuntimeConfig:
    """
    Return process-cached config; load once from layered config if never set.
    """
    global _process_cfg, _process_cfg_loaded
    if _process_cfg_loaded and _process_cfg is not None:
        return _process_cfg
    with _process_cfg_lock:
        if _process_cfg_loaded and _process_cfg is not None:
            return _process_cfg
        cfg = load_url_sink_config_for_project(project_data_dir, project=project)
        _process_cfg = cfg
        _process_cfg_loaded = True
        return cfg


def reset_process_url_sink_config() -> None:
    """Clear process cache (tests only)."""
    global _process_cfg, _process_cfg_loaded
    with _process_cfg_lock:
        _process_cfg = None
        _process_cfg_loaded = False


def url_sink_config_from_effective(effective: Any) -> UrlSinkRuntimeConfig:
    """Map EffectiveConfig.url_sink → UrlSinkRuntimeConfig."""
    try:
        us = effective.url_sink
        return UrlSinkRuntimeConfig(
            passive_enabled=bool(us.passive_enabled),
            html_js_enabled=bool(us.html_js_enabled),
            iv_probes_enabled=bool(us.iv_probes_enabled),
            score_threshold=int(us.score_threshold),
        )
    except Exception:
        pass
    # Fallback via dotted get on raw tree.
    try:
        get = getattr(effective, "get", None)
        if callable(get):
            return UrlSinkRuntimeConfig(
                passive_enabled=bool(get("url_sink.passive.enabled", True)),
                html_js_enabled=bool(get("url_sink.html_js.enabled", True)),
                iv_probes_enabled=bool(get("url_sink.iv_probes.enabled", True)),
                score_threshold=int(get("url_sink.score_threshold", 45) or 45),
            )
    except Exception:
        pass
    return UrlSinkRuntimeConfig()


def load_url_sink_config_for_project(
    project_data_dir: Path | None = None,
    *,
    project: Any = None,
) -> UrlSinkRuntimeConfig:
    """
    Purpose:
        Load url_sink knobs from layered configuration for a project.
    Input:
        project_data_dir — project data directory (parent of talos.db).
        project          — optional Project-like with .data_dir / .db_path.
    Output:
        UrlSinkRuntimeConfig (defaults on failure).
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
        return url_sink_config_from_effective(effective)
    except Exception as exc:
        logger.debug("url_sink config load failed — using defaults: %s", exc)
        return UrlSinkRuntimeConfig()
