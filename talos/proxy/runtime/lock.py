"""
Module: talos.proxy.runtime.lock

Purpose:
    Cross-platform exclusive file lock for proxy/scheduler lifecycle
    mutations. Supports blocking acquire and short try-lock for status.

    Linux/macOS: fcntl.flock
    Windows: msvcrt.locking on a dedicated lock byte range

Dependencies: os, sys, time, pathlib
Data flow:
    ProxyRuntimeManager → RuntimeLock → OS file lock
Side effects:
    Creates lock file; holds OS exclusive lock until released.
"""

from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path
from types import TracebackType
from typing import Optional, Type

logger = logging.getLogger(__name__)


class RuntimeLock:
    """
    Purpose:
        Exclusive lock around a lifecycle resource (proxy or scheduler).

    Usage:
        with RuntimeLock(path).acquire():
            ...
        # or
        lock = RuntimeLock(path)
        if lock.try_acquire(timeout_s=0.2):
            try:
                ...
            finally:
                lock.release()
    """

    def __init__(self, lock_path: Path) -> None:
        self._path = lock_path
        self._fd: Optional[int] = None

    def acquire(self, timeout_s: Optional[float] = None) -> "RuntimeLock":
        """
        Purpose:
            Block until the exclusive lock is held (or timeout).
        Input:
            timeout_s — max wait; None waits indefinitely.
        Output:
            self (for context-manager use).
        Side effects:
            Opens lock file; acquires exclusive lock.
        Raises:
            TimeoutError if timeout_s elapses without acquiring.
        """
        self._path.parent.mkdir(parents=True, exist_ok=True)
        deadline = None if timeout_s is None else time.monotonic() + timeout_s
        while True:
            if self._try_lock_once():
                return self
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError(f"Could not acquire lock: {self._path}")
            time.sleep(0.05)

    def try_acquire(self, timeout_s: float = 0.0) -> bool:
        """
        Purpose:
            Attempt to acquire the lock without long blocking.
        Input:
            timeout_s — how long to keep trying (0 = single attempt).
        Output:
            True if lock held by this instance.
        Side effects:
            May open lock file and acquire lock.
        """
        try:
            self.acquire(timeout_s=timeout_s if timeout_s > 0 else 0.0)
            return True
        except TimeoutError:
            return False

    def release(self) -> None:
        """Release the lock and close the file descriptor."""
        if self._fd is None:
            return
        try:
            if sys.platform == "win32":
                self._windows_unlock(self._fd)
            else:
                import fcntl

                fcntl.flock(self._fd, fcntl.LOCK_UN)
        except OSError as exc:
            logger.warning("Error releasing lock %s: %s", self._path, exc)
        try:
            os.close(self._fd)
        except OSError:
            pass
        self._fd = None

    def __enter__(self) -> "RuntimeLock":
        if self._fd is None:
            self.acquire()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc: Optional[BaseException],
        tb: Optional[TracebackType],
    ) -> None:
        self.release()

    # ------------------------------------------------------------------ #
    # Internals                                                            #
    # ------------------------------------------------------------------ #

    def _try_lock_once(self) -> bool:
        if self._fd is not None:
            return True
        flags = os.O_RDWR | os.O_CREAT
        fd = os.open(str(self._path), flags, 0o644)
        try:
            if sys.platform == "win32":
                self._ensure_lock_byte(fd)
                locked = self._windows_try_lock(fd)
            else:
                import fcntl

                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked = True
                except BlockingIOError:
                    locked = False
            if not locked:
                os.close(fd)
                return False
            self._fd = fd
            return True
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise

    def _ensure_lock_byte(self, fd: int) -> None:
        """msvcrt.locking needs a byte range; seed one on a new lock file."""
        if os.fstat(fd).st_size == 0:
            os.write(fd, b"\0")
        os.lseek(fd, 0, os.SEEK_SET)

    def _windows_try_lock(self, fd: int) -> bool:
        import msvcrt

        try:
            # Lock one byte from the start of the file.
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            return True
        except OSError:
            return False

    def _windows_unlock(self, fd: int) -> None:
        import msvcrt

        os.lseek(fd, 0, os.SEEK_SET)
        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
