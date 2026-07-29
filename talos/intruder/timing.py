"""
Module: talos.intruder.timing

Purpose:
    Micro rate control inside an Intruder segment (fixed RPS + concurrency).
    Phase 2: optional per-host concurrency cap.

    Scheduler owns inter-job coarse delay; this owns per-attempt pacing.

Dependencies: asyncio, random, time
Data flow:
    engine loop → TimingController.acquire([host]) → grant → HTTP
Side effects:
    asyncio sleep only.
"""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any, Optional

from talos.intruder.models import (
    AttemptResult,
    DEFAULT_JITTER_MS,
    DEFAULT_MAX_CONCURRENCY,
    DEFAULT_RPS,
)


class TimingController:
    """
    mode=fixed — sleep to maintain target RPS before each launch.
    Semaphore limits global in-flight concurrency.
    Optional per-host semaphores when max_concurrency_per_host is set.
    """

    def __init__(
        self,
        *,
        mode: str = "fixed",
        rps: float = DEFAULT_RPS,
        max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
        max_concurrency_per_host: Optional[int] = None,
        jitter_ms: float = DEFAULT_JITTER_MS,
    ) -> None:
        self.mode = mode or "fixed"
        self.rps = max(0.0, float(rps))
        self.max_concurrency = max(1, int(max_concurrency))
        self.max_concurrency_per_host: Optional[int]
        if max_concurrency_per_host is None:
            self.max_concurrency_per_host = None
        else:
            self.max_concurrency_per_host = max(1, int(max_concurrency_per_host))
        self.jitter_ms = max(0.0, float(jitter_ms))
        self._sem = asyncio.Semaphore(self.max_concurrency)
        self._host_sems: dict[str, asyncio.Semaphore] = {}
        self._host_held: dict[int, str] = {}  # task id → host when per-host held
        self._last_grant = 0.0
        self._lock = asyncio.Lock()
        self._ema_rps: Optional[float] = None
        self._last_response_mono: Optional[float] = None

    def update(self, config: dict[str, Any]) -> None:
        if "mode" in config:
            self.mode = str(config["mode"] or "fixed")
        if "rps" in config:
            self.rps = max(0.0, float(config["rps"]))
        if "max_concurrency" in config:
            new_c = max(1, int(config["max_concurrency"]))
            if new_c != self.max_concurrency:
                self.max_concurrency = new_c
                self._sem = asyncio.Semaphore(self.max_concurrency)
        if "max_concurrency_per_host" in config:
            raw = config["max_concurrency_per_host"]
            if raw is None:
                self.max_concurrency_per_host = None
                self._host_sems.clear()
            else:
                new_h = max(1, int(raw))
                if new_h != self.max_concurrency_per_host:
                    self.max_concurrency_per_host = new_h
                    self._host_sems.clear()
        if "jitter_ms" in config:
            self.jitter_ms = max(0.0, float(config["jitter_ms"]))

    def _host_sem(self, host: str) -> asyncio.Semaphore:
        assert self.max_concurrency_per_host is not None
        key = host or ""
        if key not in self._host_sems:
            self._host_sems[key] = asyncio.Semaphore(self.max_concurrency_per_host)
        return self._host_sems[key]

    async def acquire(self, host: Optional[str] = None) -> None:
        """
        Wait for concurrency slot (+ optional host slot) + rate limit
        before launching attempt.
        """
        await self._sem.acquire()
        held_host: Optional[str] = None
        if self.max_concurrency_per_host is not None and host is not None:
            held_host = host or ""
            await self._host_sem(held_host).acquire()
            # Track for release (works with concurrency 1+ sequential or concurrent tasks)
            try:
                task = asyncio.current_task()
                if task is not None:
                    self._host_held[id(task)] = held_host
            except Exception:  # noqa: BLE001
                pass
        if self.mode == "unlimited" or self.rps <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            min_interval = 1.0 / self.rps if self.rps > 0 else 0.0
            elapsed = now - self._last_grant if self._last_grant else min_interval
            wait = min_interval - elapsed
            if self.jitter_ms > 0:
                wait += random.uniform(-self.jitter_ms, self.jitter_ms) / 1000.0
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_grant = time.monotonic()

    def release(self, host: Optional[str] = None) -> None:
        """Release concurrency slot (and host slot) after attempt finishes."""
        held: Optional[str] = host
        try:
            task = asyncio.current_task()
            if task is not None:
                held = self._host_held.pop(id(task), held)
        except Exception:  # noqa: BLE001
            pass
        if held is not None and self.max_concurrency_per_host is not None:
            sem = self._host_sems.get(held or "")
            if sem is not None:
                sem.release()
        self._sem.release()

    def note_response(self, result: AttemptResult) -> None:
        """Update EMA RPS estimate from response timings."""
        now = time.monotonic()
        if self._last_response_mono is not None:
            dt = now - self._last_response_mono
            if dt > 0:
                inst = 1.0 / dt
                if self._ema_rps is None:
                    self._ema_rps = inst
                else:
                    self._ema_rps = 0.3 * inst + 0.7 * self._ema_rps
        self._last_response_mono = now

    @property
    def rps_ema(self) -> Optional[float]:
        return self._ema_rps
