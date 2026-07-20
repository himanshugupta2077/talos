"""
Module: talos_ui.platform_open

Purpose:
    Open a local directory in the operating system's default file explorer.
    Used only for Control Panel OS UI integration (not Talos state mutations).

Inputs / outputs:
    open_directory(path) — path must already exist and be a directory.
    Raises OpenDirectoryError with an actionable message on failure.
    Returns None on successful launch of the opener.

Side effects:
    Spawns a short-lived process (or uses the OS startfile API on Windows)
    that opens the system file manager. Does not wait for the file manager
    window to close. Does not write files or touch SQLite.

Security:
    Callers must resolve paths server-side from project identity. This module
    never interprets browser-supplied path strings as open targets.

Supported platforms: Linux (xdg-open), Windows (os.startfile).
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


class OpenDirectoryError(Exception):
    """
    Purpose:
        Actionable failure opening a directory in the system file explorer.
    Attributes:
        message — operator-facing explanation (also str(exc)).
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


def open_directory(path: Path) -> None:
    """
    Purpose:
        Launch the platform default file explorer for an existing directory.
    Input:
        path — absolute or relative Path that must exist and be a directory.
    Output:
        None on successful opener launch.
    Side effects:
        Starts a non-blocking process (Linux) or os.startfile (Windows).
        Does not block on the explorer remaining open.
    Raises:
        OpenDirectoryError — missing/not-a-dir path, unsupported OS,
        missing opener executable, or process launch failure.
    """
    directory = Path(path).expanduser()
    try:
        directory = directory.resolve(strict=False)
    except OSError as exc:
        raise OpenDirectoryError(
            f"Cannot resolve directory path: {exc}"
        ) from exc

    if not directory.exists():
        raise OpenDirectoryError(
            f"Project data directory does not exist: {directory}"
        )
    if not directory.is_dir():
        raise OpenDirectoryError(
            f"Path is not a directory: {directory}"
        )

    platform = sys.platform
    if platform.startswith("linux"):
        _open_linux(directory)
    elif platform == "win32":
        _open_windows(directory)
    else:
        raise OpenDirectoryError(
            f"Unsupported operating system for Open directory "
            f"(supported: Linux, Windows); platform={platform!r}"
        )


def _open_linux(directory: Path) -> None:
    """
    Purpose:
        Open directory via the FreeDesktop default handler (xdg-open).
    Input:
        directory — existing directory path.
    Output:
        None.
    Side effects:
        Popen(["xdg-open", <dir>]) with shell=False; does not wait.
    """
    argv = ["xdg-open", str(directory)]
    try:
        # start_new_session detaches so uvicorn is not blocked / reaped with child.
        subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise OpenDirectoryError(
            "Default directory opener unavailable: xdg-open was not found on PATH. "
            "Install xdg-utils or open the path manually."
        ) from exc
    except OSError as exc:
        raise OpenDirectoryError(
            f"Failed to launch directory opener: {exc}"
        ) from exc
    logger.info("open_directory linux argv=%s", argv)


def _open_windows(directory: Path) -> None:
    """
    Purpose:
        Open directory in File Explorer via the Windows startfile API.
    Input:
        directory — existing directory path.
    Output:
        None.
    Side effects:
        os.startfile(directory) — platform-native open; no shell string.
    """
    try:
        # os.startfile is the Windows-native association launcher (Explorer for dirs).
        # It does not use the shell and does not accept concatenated command strings.
        os.startfile(str(directory))  # type: ignore[attr-defined]
    except AttributeError as exc:
        # Non-Windows Python incorrectly reporting win32, or stripped build.
        raise OpenDirectoryError(
            "Unsupported operating system for Open directory: "
            "os.startfile is unavailable"
        ) from exc
    except OSError as exc:
        raise OpenDirectoryError(
            f"Failed to launch directory opener: {exc}"
        ) from exc
    logger.info("open_directory windows startfile path=%s", directory)
