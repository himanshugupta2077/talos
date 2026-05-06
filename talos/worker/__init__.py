"""
Package: talos.worker

Purpose:
    Worker layer — consumes captured flows from the queue and persists
    them to the project database and raw archive.

    Runs independently of the proxy thread. The proxy only enqueues;
    this package owns all downstream processing.

Exports:
    FlowWorker — the primary worker class.
"""

from talos.worker.worker import FlowWorker

__all__ = ["FlowWorker"]
