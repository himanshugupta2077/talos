"""
Module: talos.intruder.timing

Purpose:
    Micro rate control inside an Intruder segment.

    Modes (Phase 1–4):
      - fixed        — constant target RPS with optional jitter
      - unlimited    — no rate sleep (concurrency still applies)
      - token_bucket — bursty allowance up to burst_size at target RPS refill
      - adaptive     — raise/lower effective RPS from response health (Phase 4)

    Scheduler owns inter-job coarse delay; this owns per-attempt pacing.

Dependencies: asyncio, random, time, collections
Data flow:
    engine loop → TimingController.acquire([host]) → grant → HTTP
    engine → note_response(result) → adjust adaptive / refill accounting
Side effects:
    asyncio sleep only.
"""

from __future__ import annotations

import asyncio
import random
import time
from collections import deque
from typing import Any, Deque, Optional

from talos.intruder.models import (
    AttemptResult,
    DEFAULT_ADAPTIVE_DOWN_FACTOR,
    DEFAULT_ADAPTIVE_ERROR_STATUSES,
    DEFAULT_ADAPTIVE_SLOW_MS,
    DEFAULT_ADAPTIVE_UP_FACTOR,
    DEFAULT_ADAPTIVE_WINDOW,
    DEFAULT_BURST_SIZE,
    DEFAULT_JITTER_MS,
    DEFAULT_MAX_CONCURRENCY,
    DEFAULT_MAX_RPS,
    DEFAULT_MIN_RPS,
    DEFAULT_RPS,
    TIMING_ADAPTIVE,
    TIMING_FIXED,
    TIMING_TOKEN_BUCKET,
    TIMING_UNLIMITED,
)


class TimingController:
    """
    Rate + concurrency controller for Intruder attempts.

    Semaphore limits global in-flight concurrency.
    Optional per-host semaphores when max_concurrency_per_host is set.
    """

    def __init__(
        self,
        *,
        mode: str = TIMING_FIXED,
        rps: float = DEFAULT_RPS,
        max_concurrency: int = DEFAULT_MAX_CONCURRENCY,
        max_concurrency_per_host: Optional[int] = None,
        jitter_ms: float = DEFAULT_JITTER_MS,
        burst_size: int = DEFAULT_BURST_SIZE,
        min_rps: float = DEFAULT_MIN_RPS,
        max_rps: Optional[float] = None,
        slow_ms: float = DEFAULT_ADAPTIVE_SLOW_MS,
        adaptive_window: int = DEFAULT_ADAPTIVE_WINDOW,
        up_factor: float = DEFAULT_ADAPTIVE_UP_FACTOR,
        down_factor: float = DEFAULT_ADAPTIVE_DOWN_FACTOR,
        error_statuses: Optional[list[int] | tuple[int, ...]] = None,
    ) -> None:
        self.mode = (mode or TIMING_FIXED).strip().lower()
        self.rps = max(0.0, float(rps))
        self.max_concurrency = max(1, int(max_concurrency))
        self.max_concurrency_per_host: Optional[int]
        if max_concurrency_per_host is None:
            self.max_concurrency_per_host = None
        else:
            self.max_concurrency_per_host = max(1, int(max_concurrency_per_host))
        self.jitter_ms = max(0.0, float(jitter_ms))

        # token_bucket / adaptive shared knobs
        self.burst_size = max(1, int(burst_size))
        self.min_rps = max(0.01, float(min_rps))
        # max_rps defaults to max(rps, DEFAULT_MAX_RPS) when unset so adaptive can climb
        if max_rps is None:
            self.max_rps = max(self.rps if self.rps > 0 else DEFAULT_MAX_RPS, DEFAULT_MAX_RPS)
        else:
            self.max_rps = max(self.min_rps, float(max_rps))
        self.slow_ms = max(0.0, float(slow_ms))
        self.adaptive_window = max(1, int(adaptive_window))
        self.up_factor = max(1.0, float(up_factor))
        self.down_factor = min(1.0, max(0.01, float(down_factor)))
        if error_statuses is None:
            self.error_statuses: set[int] = set(DEFAULT_ADAPTIVE_ERROR_STATUSES)
        else:
            self.error_statuses = {int(s) for s in error_statuses}

        # Adaptive effective RPS starts at configured target (or min if target 0)
        self._effective_rps = self.rps if self.rps > 0 else self.min_rps
        self._effective_rps = min(max(self._effective_rps, self.min_rps), self.max_rps)

        self._sem = asyncio.Semaphore(self.max_concurrency)
        self._host_sems: dict[str, asyncio.Semaphore] = {}
        self._host_held: dict[int, str] = {}  # task id → host when per-host held
        self._last_grant = 0.0
        self._lock = asyncio.Lock()
        self._ema_rps: Optional[float] = None
        self._last_response_mono: Optional[float] = None

        # Token bucket state (tokens refill at target rps up to burst_size)
        self._tokens = float(self.burst_size)
        self._last_refill = time.monotonic()

        # Adaptive health window: True = healthy, False = pressure
        self._health: Deque[bool] = deque(maxlen=self.adaptive_window)

    def update(self, config: dict[str, Any]) -> None:
        if "mode" in config:
            self.mode = str(config["mode"] or TIMING_FIXED).strip().lower()
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
        if "burst_size" in config:
            self.burst_size = max(1, int(config["burst_size"]))
            self._tokens = min(self._tokens, float(self.burst_size))
        if "min_rps" in config:
            self.min_rps = max(0.01, float(config["min_rps"]))
        if "max_rps" in config and config["max_rps"] is not None:
            self.max_rps = max(self.min_rps, float(config["max_rps"]))
        if "slow_ms" in config:
            self.slow_ms = max(0.0, float(config["slow_ms"]))
        if "adaptive_window" in config:
            self.adaptive_window = max(1, int(config["adaptive_window"]))
            self._health = deque(self._health, maxlen=self.adaptive_window)
        if "up_factor" in config:
            self.up_factor = max(1.0, float(config["up_factor"]))
        if "down_factor" in config:
            self.down_factor = min(1.0, max(0.01, float(config["down_factor"])))
        if "error_statuses" in config and config["error_statuses"] is not None:
            self.error_statuses = {int(s) for s in config["error_statuses"]}

        # Keep effective RPS in bounds after config change
        if self.mode == TIMING_ADAPTIVE:
            target = self.rps if self.rps > 0 else self.min_rps
            self._effective_rps = min(max(target, self.min_rps), self.max_rps)

    def _host_sem(self, host: str) -> asyncio.Semaphore:
        assert self.max_concurrency_per_host is not None
        key = host or ""
        if key not in self._host_sems:
            self._host_sems[key] = asyncio.Semaphore(self.max_concurrency_per_host)
        return self._host_sems[key]

    def _refill_tokens(self, now: float) -> None:
        """Refill token bucket based on target RPS."""
        rate = self.rps if self.rps > 0 else 0.0
        if rate <= 0:
            self._tokens = float(self.burst_size)
            self._last_refill = now
            return
        elapsed = now - self._last_refill
        if elapsed <= 0:
            return
        self._tokens = min(float(self.burst_size), self._tokens + elapsed * rate)
        self._last_refill = now

    def _target_rps_for_pace(self) -> float:
        """RPS used for inter-request spacing."""
        if self.mode == TIMING_ADAPTIVE:
            return max(self.min_rps, self._effective_rps)
        return self.rps

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
            try:
                task = asyncio.current_task()
                if task is not None:
                    self._host_held[id(task)] = held_host
            except Exception:  # noqa: BLE001
                pass

        if self.mode == TIMING_UNLIMITED:
            return

        if self.mode == TIMING_TOKEN_BUCKET:
            async with self._lock:
                while True:
                    now = time.monotonic()
                    self._refill_tokens(now)
                    if self._tokens >= 1.0:
                        self._tokens -= 1.0
                        self._last_grant = now
                        return
                    # Wait for next token
                    rate = self.rps if self.rps > 0 else 0.0
                    if rate <= 0:
                        # Unlimited refill when rps disabled
                        self._tokens = float(self.burst_size)
                        self._tokens -= 1.0
                        self._last_grant = now
                        return
                    need = 1.0 - self._tokens
                    wait = need / rate
                    if self.jitter_ms > 0:
                        wait += random.uniform(-self.jitter_ms, self.jitter_ms) / 1000.0
                    if wait > 0:
                        await asyncio.sleep(wait)
                    else:
                        # Spin once more after tiny yield
                        await asyncio.sleep(0)
            return

        # fixed + adaptive: classic min-interval spacing on effective/target RPS
        target = self._target_rps_for_pace()
        if target <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            min_interval = 1.0 / target
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
        """Update EMA RPS estimate and (in adaptive mode) effective rate."""
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

        if self.mode != TIMING_ADAPTIVE:
            return

        healthy = True
        if not result.success:
            healthy = False
        elif result.status_code is not None and int(result.status_code) in self.error_statuses:
            healthy = False
        elif (
            result.duration_ms is not None
            and self.slow_ms > 0
            and float(result.duration_ms) >= self.slow_ms
        ):
            healthy = False

        self._health.append(healthy)

        # Need a full window before adjusting (stable control)
        if len(self._health) < self.adaptive_window:
            return

        bad = sum(1 for h in self._health if not h)
        good = len(self._health) - bad
        # Majority unhealthy → slow down; all healthy → speed up slightly
        if bad >= max(1, self.adaptive_window // 2):
            self._effective_rps = max(
                self.min_rps,
                self._effective_rps * self.down_factor,
            )
            self._health.clear()
        elif good == len(self._health):
            # Climb toward max_rps (rps is the initial / preferred target)
            self._effective_rps = min(
                self.max_rps,
                self._effective_rps * self.up_factor,
            )
            self._health.clear()

    @property
    def rps_ema(self) -> Optional[float]:
        return self._ema_rps

    @property
    def effective_rps(self) -> float:
        """Current pacing RPS (adaptive adjusts; fixed/token_bucket report target)."""
        if self.mode == TIMING_ADAPTIVE:
            return self._effective_rps
        return self.rps

    def snapshot(self) -> dict[str, Any]:
        """Small status dict for progress_json / debugging."""
        return {
            "mode": self.mode,
            "rps": self.rps,
            "effective_rps": self.effective_rps,
            "rps_ema": self._ema_rps,
            "burst_size": self.burst_size,
            "tokens": round(self._tokens, 3) if self.mode == TIMING_TOKEN_BUCKET else None,
            "min_rps": self.min_rps,
            "max_rps": self.max_rps,
        }
