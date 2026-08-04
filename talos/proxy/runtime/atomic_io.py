"""
Module: talos.proxy.runtime.atomic_io

Purpose:
    Cross-platform atomic text writes for small runtime state files
    (proxy.json, scheduler.json, generation markers).

    Linux/macOS: temp file + os.replace is reliable.
    Windows: os.replace fails with WinError 5 (Access denied) or
    WinError 32 (Sharing violation) when another process has the
    destination open without FILE_SHARE_DELETE — common with Control
    Panel status polls, AV scanners, and search indexers. Retry with
    backoff, then fall back to best-effort replace / in-place write.

Dependencies: logging, os, sys, tempfile, time, pathlib
Data flow:
    save_state / save_scheduler_state / generation → atomic_write_text → disk
Side effects:
    Creates parent dirs; writes/replaces the target file; may leave no
    temp files behind on success.
"""

from __future__ import annotations

import logging
import os
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Transient Windows contention: AV / status readers holding proxy.json.
_REPLACE_ATTEMPTS: int = 12
_REPLACE_BASE_DELAY_S: float = 0.05


def atomic_write_text(
    path: Path,
    text: str,
    *,
    prefix: str = ".atomic.",
    suffix: str = ".tmp",
) -> None:
    """
    Purpose:
        Write ``text`` to ``path`` as atomically as the platform allows.
    Input:
        path   — destination file.
        text   — full file contents (UTF-8).
        prefix / suffix — temp-file naming under path.parent.
    Side effects:
        Creates parent directory; replaces path on success.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=prefix,
        suffix=suffix,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        _replace_with_retry(tmp_name, path, payload=text)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _is_transient_replace_error(exc: BaseException) -> bool:
    """True for errors that often resolve after a brief wait on Windows."""
    if isinstance(exc, PermissionError):
        return True
    if not isinstance(exc, OSError):
        return False
    # WinError 5 ACCESS_DENIED, 32 SHARING_VIOLATION, 33 LOCK_VIOLATION
    winerror = getattr(exc, "winerror", None)
    if winerror in (5, 32, 33):
        return True
    # POSIX errno EACCES / EBUSY (rare for replace but harmless to retry).
    if exc.errno in (getattr(os, "EACCES", 13), getattr(os, "EBUSY", 16)):
        return True
    return False


def _clear_readonly(path: Path) -> None:
    try:
        mode = path.stat().st_mode
        if not (mode & stat.S_IWRITE):
            path.chmod(mode | stat.S_IWRITE)
    except OSError:
        pass


def _replace_with_retry(tmp_name: str, path: Path, *, payload: str) -> None:
    last_exc: Optional[BaseException] = None
    for attempt in range(_REPLACE_ATTEMPTS):
        try:
            os.replace(tmp_name, path)
            if attempt > 0:
                logger.info(
                    "Atomic replace succeeded after %s attempt(s) for %s",
                    attempt + 1,
                    path,
                )
            return
        except OSError as exc:
            last_exc = exc
            if not _is_transient_replace_error(exc):
                raise
            delay = _REPLACE_BASE_DELAY_S * (attempt + 1)
            logger.debug(
                "Atomic replace attempt %s/%s failed for %s (%s); retry in %.2fs",
                attempt + 1,
                _REPLACE_ATTEMPTS,
                path,
                exc,
                delay,
            )
            time.sleep(delay)

    # Windows fallback chain when destination stays locked or read-only.
    if sys.platform == "win32":
        if _windows_fallback_replace(tmp_name, path, payload=payload):
            logger.warning(
                "Atomic replace fell back after %s attempts for %s (last=%s)",
                _REPLACE_ATTEMPTS,
                path,
                last_exc,
            )
            return

    assert last_exc is not None
    raise last_exc


def _windows_fallback_replace(tmp_name: str, path: Path, *, payload: str) -> bool:
    """
    Best-effort Windows recovery when os.replace keeps failing.

    1. Clear read-only on destination, unlink, rename temp.
    2. If that fails, write payload in-place (non-atomic) so lifecycle
       can still progress; readers may briefly see partial content.
    """
    # Step 1: unlink destination then rename.
    try:
        if path.exists():
            _clear_readonly(path)
            try:
                os.unlink(path)
            except OSError:
                pass
        os.replace(tmp_name, path)
        return True
    except OSError as exc:
        logger.debug("Windows unlink+replace fallback failed for %s: %s", path, exc)

    # Step 2: in-place overwrite from known payload; drop temp.
    try:
        if path.exists():
            _clear_readonly(path)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        return True
    except OSError as exc:
        logger.debug("Windows in-place write fallback failed for %s: %s", path, exc)
        return False
