#!/usr/bin/env python3
"""
Fixture child process for ProcessOps lifecycle tests.

Behaviour:
    - Writes READY file when started.
    - Installs graceful-shutdown handler (SIGTERM / Windows CTRL_BREAK).
    - On graceful signal: writes GRACEFUL file and exits 0.
    - Optional --ignore-graceful: ignore first N graceful signals (for force-kill tests).
    - Optional --hold-seconds: exit on its own after N seconds if not signaled.

Usage:
    python graceful_child.py --ready /tmp/ready --graceful /tmp/graceful
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ready", required=True, help="Path to READY marker file")
    parser.add_argument("--graceful", required=True, help="Path to GRACEFUL marker file")
    parser.add_argument(
        "--ignore-graceful",
        type=int,
        default=0,
        help="Number of graceful signals to ignore before exiting",
    )
    parser.add_argument(
        "--hold-seconds",
        type=float,
        default=60.0,
        help="Max lifetime if never signaled",
    )
    parser.add_argument(
        "--listen-port",
        type=int,
        default=0,
        help="If >0, bind 127.0.0.1:port so proxy readiness checks pass.",
    )
    args = parser.parse_args()

    ready_path = Path(args.ready)
    graceful_path = Path(args.graceful)
    ignores_left = {"n": args.ignore_graceful}
    stop = {"flag": False}
    listen_sock = None

    def _on_graceful(signum: int, frame: object) -> None:  # noqa: ARG001
        if ignores_left["n"] > 0:
            ignores_left["n"] -= 1
            return
        graceful_path.write_text("ok\n", encoding="utf-8")
        stop["flag"] = True

    if sys.platform == "win32":
        # CTRL_BREAK_EVENT is delivered as SIGBREAK on Windows Python.
        signal.signal(signal.SIGBREAK, _on_graceful)  # type: ignore[attr-defined]
        signal.signal(signal.SIGTERM, _on_graceful)
    else:
        signal.signal(signal.SIGTERM, _on_graceful)
        signal.signal(signal.SIGINT, _on_graceful)

    if args.listen_port > 0:
        import socket

        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind(("127.0.0.1", args.listen_port))
        listen_sock.listen(5)
        listen_sock.settimeout(0.2)

    ready_path.write_text(f"pid={os.getpid()}\n", encoding="utf-8")

    deadline = time.monotonic() + args.hold_seconds
    while time.monotonic() < deadline and not stop["flag"]:
        if listen_sock is not None:
            try:
                conn, _addr = listen_sock.accept()
                conn.close()
            except (OSError, TimeoutError):
                pass
        else:
            time.sleep(0.1)
    if listen_sock is not None:
        try:
            listen_sock.close()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
