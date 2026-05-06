"""
Module: talos.proxy.cli

Purpose:
    Command-line interface for proxy lifecycle management.
    Entry point for: talos proxy start

Dependencies: argparse, subprocess, sys, pathlib, talos.projects.manager, talos.config
Data flow:
    CLI args → cmd_start → project verification → mitmdump subprocess
Side effects:
    - Verifies active project before launching proxy; exits 1 if none.
    - Launches mitmdump as a subprocess with the TalosAddon script.
    - On POSIX, replaces the current process image via os.execvp.
    - On Windows, delegates to subprocess.run (process is not replaced).
"""

import argparse
import logging
import os
import subprocess
import sys
from pathlib import Path

from talos.projects.manager import ProjectManager


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_start(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Verify an active project exists, then launch mitmdump with the
        Talos capture addon.
    Input:
        manager — ProjectManager for active-project verification.
        args    — parsed CLI args: port (int), listen_host (str).
    Side effects:
        - Exits 1 if no active project is set.
        - Prints startup summary to stdout.
        - Replaces current process with mitmdump (POSIX) or blocks until
          mitmdump exits (Windows).
    """
    # Enable INFO-level logging for the talos logger unless --quiet is set.
    # CAPTURE/SKIP logs are at DEBUG level and not visible by default.
    # Worker shutdown log shows processed count for capture verification.
    if not args.quiet:
        logging.getLogger("talos").setLevel(logging.INFO)

    project = manager.active()
    if project is None:
        print(
            "Error: No active project. Run 'talos project open <id>' before starting the proxy.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not project.scope:
        print(
            "Warning: Project has no scope entries. No traffic will be captured.",
            file=sys.stderr,
        )

    addon_path = Path(__file__).parent / "addon.py"

    print(f"Starting proxy for project '{project.id}'")
    print(f"  Scope entries : {len(project.scope)}")
    print(f"  Store bodies  : {project.constraints.store_bodies}")
    print(f"  Max body size : {project.constraints.max_body_size:,} bytes")
    print(f"  Listen        : {args.listen_host}:{args.port}")
    print(f"  Addon         : {addon_path}")

    mitmdump_cmd = [
        "mitmdump",
        "--listen-host", args.listen_host,
        "--listen-port", str(args.port),
        # Skip upstream TLS verification — required for pentest interception.
        # mitmproxy's certifi bundle cannot verify all certificate chains
        # (common with Cloudflare and some CDNs on Windows). This is intentional
        # for a MITM tool; we are the intended man-in-the-middle.
        "--ssl-insecure",
        "-s", str(addon_path),
    ]

    if sys.platform == "win32":
        # os.execvp is not available on Windows; subprocess.run blocks instead.
        # Ctrl+C sends SIGINT to the whole console process group — mitmdump receives
        # it and shuts down, but subprocess.run() re-raises KeyboardInterrupt from
        # wait(). Catch it and let the process finish its cleanup naturally.
        try:
            subprocess.run(mitmdump_cmd, check=False)
        except KeyboardInterrupt:
            pass
    else:
        # Replace current process — mitmdump becomes the running process.
        # Signals and exit codes flow cleanly to the caller.
        os.execvp("mitmdump", mitmdump_cmd)


# ------------------------------------------------------------------ #
# Parser construction                                                  #
# ------------------------------------------------------------------ #

def build_parser() -> argparse.ArgumentParser:
    """
    Purpose:  Construct the argument parser for 'talos proxy' subcommands.
    Output:   Configured ArgumentParser.
    Side effects: None.
    """
    parser = argparse.ArgumentParser(
        prog="talos proxy",
        description="Control the Talos capture proxy.",
    )
    sub = parser.add_subparsers(dest="command", metavar="command", required=True)

    # start
    p_start = sub.add_parser(
        "start",
        help="Launch the capture proxy for the active project.",
    )
    p_start.add_argument(
        "--port", "-p",
        type=int,
        default=8080,
        help="Proxy listen port (default: 8080).",
    )
    p_start.add_argument(
        "--listen-host",
        default="127.0.0.1",
        help="Interface to bind (default: 127.0.0.1).",
    )
    p_start.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress addon startup and worker shutdown logs.",
    )

    return parser


_COMMAND_MAP = {
    "start": cmd_start,
}


def run_proxy_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse argv and dispatch to the appropriate proxy command handler.
    Input:
        manager — ProjectManager instance.
        argv    — list of CLI arguments after 'talos proxy'.
    Side effects:
        Delegates to command handlers; may exit with sys.exit().
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    handler = _COMMAND_MAP.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    handler(manager, args)
