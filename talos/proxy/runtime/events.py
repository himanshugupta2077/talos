"""
Module: talos.proxy.runtime.events

Purpose:
    Central notify path for proxy-relevant configuration commits.
    Domain modules call notify_proxy_config_changed after successful writes;
    they never spawn or signal mitmdump.

    Behaviour:
        1. Bump per-project desired generation (unless inside transaction).
        2. Unless TALOS_PROXY_AUTO_RESTART=0, call ProxyRuntimeManager.reconcile.

Dependencies: os, logging, pathlib, talos.config, generation, manager
Data flow:
    domain write → notify → bump → reconcile (optional)
Side effects:
    Generation file write; may restart/stop proxy under lifecycle lock.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Optional

from talos.config import TalosConfig
from talos.projects.manager import ProjectManager
from talos.proxy.runtime.generation import bump_generation, get_generation
from talos.proxy.runtime.manager import ProxyRuntimeManager

logger = logging.getLogger(__name__)

_AUTO_RESTART_ENV = "TALOS_PROXY_AUTO_RESTART"


def _auto_restart_enabled() -> bool:
    raw = os.environ.get(_AUTO_RESTART_ENV, "1").strip().lower()
    return raw not in ("0", "false", "no", "off")


def notify_proxy_config_changed(
    project_id: str,
    reason: str,
    *,
    projects_root: Optional[Path] = None,
    data_dir: Optional[Path] = None,
    reconcile: bool = True,
) -> int:
    """
    Purpose:
        Record a proxy-relevant config commit and optionally reconcile runtime.
    Input:
        project_id    — project whose generation advances.
        reason        — short log/audit reason.
        projects_root — override projects dir (tests).
        data_dir      — override Talos data dir (tests).
        reconcile     — if False, only bump generation.
    Output:
        New desired generation for project_id.
    Side effects:
        Bumps generation; may stop/restart managed proxy.
    """
    config = TalosConfig.from_env()
    root = Path(projects_root) if projects_root is not None else config.projects_dir
    ddir = Path(data_dir) if data_dir is not None else config.data_dir

    new_gen = bump_generation(root, project_id, reason=reason)

    if not reconcile or not _auto_restart_enabled():
        logger.info(
            "Proxy config changed project=%s gen=%s reason=%s (no auto-restart)",
            project_id,
            new_gen,
            reason,
        )
        return new_gen

    # project_override="" disables TALOS_PROJECT env so tests and CLI
    # notifies use registry ACTIVE under projects_root only.
    manager_pm = ProjectManager(projects_root=root, project_override="")
    try:
        active = manager_pm.active()
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Proxy notify: could not resolve active project (%s); "
            "generation bumped to %s but reconcile skipped",
            exc,
            new_gen,
        )
        return new_gen
    runtime = ProxyRuntimeManager(data_dir=ddir)

    spawn_gen = 0
    if active is not None:
        spawn_gen = get_generation(root, active.id)

    logger.info(
        "Proxy config changed project=%s gen=%s reason=%s — reconciling",
        project_id,
        new_gen,
        reason,
    )
    runtime.reconcile(
        active_project=active,
        spawn_generation=spawn_gen,
        generation_reader=lambda pid: get_generation(root, pid),
    )
    return new_gen
