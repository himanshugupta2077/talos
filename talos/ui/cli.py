"""
Module: talos.ui.cli

Purpose:
    CLI handler for the 'talos ui' subcommand.
    Starts a uvicorn server serving the Talos web UI.

Dependencies: uvicorn, talos.ui.app, talos.projects.manager
Data flow:
    talos ui → parse args → build app → uvicorn.run()
Side effects:
    - Binds to a local TCP port (default 8000).
    - Blocks until SIGINT/SIGTERM.
"""

import argparse
import sys
from pathlib import Path

from talos.ui.app import create_app
from talos.projects.manager import ProjectManager


def run_inspect_cli(projects_root: Path, argv: list[str]) -> None:
    """
    Purpose:
        Parse inspect subcommand args and start the uvicorn HTTP server.
    Input:
        projects_root — resolved projects directory path.
        argv          — remaining CLI arguments after 'inspect'.
    Side effects:
        - Starts a blocking HTTP server.
        - Prints the listening address to stdout.
    """
    parser = argparse.ArgumentParser(
        prog="talos ui",
        description="Start the Talos web UI.",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Bind port (default: 8000)",
    )
    args = parser.parse_args(argv)

    try:
        import uvicorn
    except ImportError:
        print(
            "ERROR: uvicorn is required. Install with: pip install uvicorn",
            file=sys.stderr,
        )
        sys.exit(1)

    app = create_app(projects_root=projects_root)

    print(f"Talos UI  ->  http://{args.host}:{args.port}/")
    print("Press Ctrl+C to stop.")

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
