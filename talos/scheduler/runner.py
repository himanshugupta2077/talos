"""
Module: talos.scheduler.runner

Purpose:
    Standalone process entry for the ReplayScheduler daemon.
    Invoked by SchedulerRuntimeManager as a managed child:

        python -m talos.scheduler.runner --project <id>

    Keeps the process alive until SIGTERM / SIGINT / CTRL_BREAK, then
    stops the scheduler cleanly.

Dependencies: argparse, logging, os, signal, sys, time, talos.config,
              talos.projects.manager, talos.scheduler.scheduler
Data flow:
    ProcessOps.spawn → runner main → ReplayScheduler.start → wait → stop
Side effects:
    Runs attack/replay jobs against the bound project DB until signaled.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import time

from talos.config import TalosConfig
from talos.projects.manager import ProjectManager, ProjectNotFound, TALOS_PROJECT_ENV
from talos.scheduler.scheduler import ReplayScheduler

logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(levelname)s [%(name)s] %(message)s",
)
_log = logging.getLogger("talos.scheduler.runner")


def main(argv: list[str] | None = None) -> int:
    """
    Purpose:
        Parse args, bind project, run scheduler until graceful signal.
    Output:
        Process exit code (0 on clean stop).
    """
    parser = argparse.ArgumentParser(prog="talos.scheduler.runner")
    parser.add_argument(
        "--project",
        required=True,
        help="Project id to bind the scheduler to.",
    )
    args = parser.parse_args(argv)

    project_id = args.project.strip()
    os.environ[TALOS_PROJECT_ENV] = project_id

    config = TalosConfig.from_env()
    manager = ProjectManager(
        projects_root=config.projects_dir,
        project_override=project_id,
    )
    try:
        project = manager.get(project_id)
    except ProjectNotFound as exc:
        _log.error("%s", exc)
        return 1

    scheduler = ReplayScheduler(project=project)
    stop = {"flag": False}

    def _on_stop(signum: int, frame: object) -> None:  # noqa: ARG001
        _log.info("Scheduler runner received signal %s — stopping", signum)
        stop["flag"] = True

    signal.signal(signal.SIGTERM, _on_stop)
    signal.signal(signal.SIGINT, _on_stop)
    if sys.platform == "win32":
        signal.signal(signal.SIGBREAK, _on_stop)  # type: ignore[attr-defined]

    scheduler.start()
    _log.info("Scheduler runner active for project=%s", project.id)

    try:
        while not stop["flag"]:
            time.sleep(0.3)
    finally:
        scheduler.stop()
        _log.info("Scheduler runner exited for project=%s", project.id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
