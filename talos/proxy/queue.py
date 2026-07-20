"""
Module: talos.proxy.queue

Purpose:
    In-memory, bounded, thread-safe queue that decouples the proxy capture
    thread from downstream workers.

    Stage 1: Python stdlib queue.Queue.
    Stage 2 (future): Replace backing store with Redis without changing the
                      public interface.

Design decisions:
    - Bounded (maxsize configurable) — prevents unbounded memory growth under load.
    - Non-blocking put: queue full → flow is dropped and logged at WARNING.
    - Proxy thread MUST NOT block waiting for consumers. Ever.

Dependencies: queue (stdlib), logging
Data flow:
    proxy addon → FlowQueue.put(flow_dict) → future worker → FlowQueue.get()
Side effects:
    - Logs dropped flows at WARNING level (host + running dropped count).
"""

import logging
import queue
from typing import Optional

logger = logging.getLogger(__name__)

# 2 000 flows is enough headroom for sustained browsing bursts before workers
# consume them. Raise if worker lag becomes a problem.
_DEFAULT_MAXSIZE = 2000


class FlowQueue:
    """
    Purpose:
        Thread-safe bounded queue for raw captured flow dicts.

    Fields:
        _q                 — underlying stdlib Queue instance.
        dropped_flow_count — public counter of flows discarded due to queue overflow.
                             Read directly by monitoring/stats callers.

    Invariant:
        put() never raises — dropped flows are silently discarded at WARNING.
        Proxy thread is never blocked by this class.
    """

    def __init__(self, maxsize: int = _DEFAULT_MAXSIZE) -> None:
        # Why maxsize: unbounded growth would eventually exhaust memory during
        # heavy browsing sessions if workers stall.
        self._q: queue.Queue[dict] = queue.Queue(maxsize=maxsize)
        # Public counter — read directly; no accessor wrapper needed.
        self.dropped_flow_count: int = 0

    def put(self, flow: dict) -> None:
        """
        Purpose:
            Enqueue a captured flow dict.
            Drops the flow without raising if the queue is at capacity.
        Input:
            flow — extracted flow dict produced by the proxy addon.
        Side effects:
            - Increments _dropped and logs at WARNING on overflow.
        """
        try:
            self._q.put_nowait(flow)
        except queue.Full:
            self.dropped_flow_count += 1
            logger.warning(
                "Flow queue full — dropped flow for %s (dropped_flow_count: %d)",
                flow.get("host", "unknown"),
                self.dropped_flow_count,
            )

    def get(self, timeout: Optional[float] = None) -> Optional[dict]:
        """
        Purpose:
            Dequeue the next available flow for processing.
        Input:
            timeout — seconds to wait; None blocks indefinitely.
        Output:
            Flow dict, or None if timeout expires before an item is available.
        Side effects: None.
        """
        try:
            return self._q.get(timeout=timeout)
        except queue.Empty:
            return None

    def size(self) -> int:
        """Current number of items in the queue (approximate — not synchronized)."""
        return self._q.qsize()


# Module-level singleton shared between the addon and future workers running in
# the same process. Why singleton: mitmproxy addon and workers share one runtime;
# a module-level instance avoids passing the queue through layers that don't own it.
flow_queue = FlowQueue()
