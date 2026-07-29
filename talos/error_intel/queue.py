"""
Module: talos.error_intel.queue

Purpose:
    Bounded, thread-safe queue for ErrorIntelJob payloads.

    Decouples FlowWorker (capture path) from ErrorIntelWorker so heavy
    detect / normalize / classify work never blocks proxy capture.

Design decisions (mirror talos.passive.queue.PassiveScanQueue):
    - Bounded maxsize (default from DEFAULT_QUEUE_MAXSIZE / config).
    - Non-blocking put: queue full → drop job, WARNING log, counter++.
    - Capture / FlowWorker thread MUST NOT block waiting for consumers.

Dependencies: queue (stdlib), logging; talos.error_intel.constants, models
Data flow:
    FlowWorker → ErrorIntelQueue.put(ErrorIntelJob) → ErrorIntelWorker.get()
Side effects:
    - Logs dropped jobs at WARNING with running dropped count.
"""

from __future__ import annotations

import logging
import queue
from typing import Optional

from talos.error_intel.constants import DEFAULT_QUEUE_MAXSIZE
from talos.error_intel.models import ErrorIntelJob

logger = logging.getLogger(__name__)


class ErrorIntelQueue:
    """
    Purpose:
        Thread-safe bounded queue for ErrorIntelJob instances.

    Fields:
        _q                    — underlying stdlib Queue.
        dropped_job_count     — public counter of jobs discarded on overflow.
        enqueued_count        — public counter of successful puts (lifetime).

    Invariant:
        put() never raises on Full — jobs are dropped with WARNING.
        Producer threads (FlowWorker) are never blocked by this class.
    """

    def __init__(self, maxsize: int = DEFAULT_QUEUE_MAXSIZE) -> None:
        # Why bounded: unbounded growth would exhaust memory if the error
        # worker stalls under heavy capture of error-like responses.
        size = max(1, int(maxsize))
        self._q: queue.Queue[ErrorIntelJob] = queue.Queue(maxsize=size)
        self.dropped_job_count: int = 0
        self.enqueued_count: int = 0

    def put(self, job: ErrorIntelJob) -> bool:
        """
        Purpose:
            Enqueue an error-intel job. Drops without raising if the queue
            is full.
        Input:
            job — ErrorIntelJob (flow_id is the body source of truth).
        Output:
            True if enqueued, False if dropped (queue full).
        Side effects:
            - Increments enqueued_count or dropped_job_count.
            - Logs WARNING on overflow.
        """
        try:
            self._q.put_nowait(job)
            self.enqueued_count += 1
            return True
        except queue.Full:
            self.dropped_job_count += 1
            logger.warning(
                "Error intel queue full — dropped job flow_id=%s path=%s "
                "(dropped_job_count=%d)",
                job.flow_id,
                job.path or "?",
                self.dropped_job_count,
            )
            return False

    def get(self, timeout: Optional[float] = None) -> Optional[ErrorIntelJob]:
        """
        Purpose:
            Dequeue the next job for ErrorIntelWorker.
        Input:
            timeout — seconds to wait; None blocks indefinitely; 0 is non-blocking.
        Output:
            ErrorIntelJob, or None if empty / timeout.
        Side effects: None.
        """
        try:
            if timeout is None:
                return self._q.get()
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    def size(self) -> int:
        """Current approximate number of pending jobs. Side effects: None."""
        return self._q.qsize()

    def maxsize(self) -> int:
        """Configured capacity. Side effects: None."""
        return self._q.maxsize
