"""
Module: talos.intruder.timing

Purpose:
    Micro rate control inside an Intruder segment (fixed RPS + concurrency).
    Scheduler owns inter-job coarse delay; this owns per-attempt pacing.

Dependencies: asyncio, random, time
Data flow:
    engine loop → TimingController.acquire() → grant → HTTP
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
    Phase 1: mode=fixed — sleep to maintain target RPS before each launch.
    Semaphore limits in-flight concurrency.
    """

    def __init__(
        self,
        *,
        mode: str = "fixed",
        rps: float = DEFAULT_RPS,
        max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
        jitter_ms: float = DEFAULT_JITTER_MS,
    ) -> None:
        self.mode = mode or "fixed"
        self.rps = max(0.0, float(rps))
        self.max_concurrency = max(1, int(max_concurrency))
        self.jitter_ms = max(0.0, float(jitter_ms))
        self._sem = asyncio.Semaphore(self.max_concurrency)
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
        if "jitter_ms" in config:
            self.jitter_ms = max(0.0, float(config["jitter_ms"]))

    async def acquire(self) -> None:
        """Wait for concurrency slot + rate limit before launching attempt."""
        await self._sem.acquire()
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

    def release(self) -> None:
        """Release concurrency slot after attempt finishes (success or fail)."""
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
