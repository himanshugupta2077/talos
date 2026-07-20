"""
Module: talos.proxy.runtime

Purpose:
    Proxy process lifecycle management — the only subsystem allowed to
    spawn, signal, or inspect the managed mitmdump child.

    Public surface:
        ProxyRuntimeManager  — start / stop / restart / status / reconcile
        ProxyRuntimeInfo     — immutable status snapshot
        ProxyState           — lifecycle state enum
        ProcessOps           — OS process control abstraction
        ProcessIdentity      — PID + create_time identity

Dependencies: talos.proxy.runtime.manager, process_ops
Data flow:
    CLI / notify → ProxyRuntimeManager → ProcessOps → mitmdump child
Side effects:
    Persists ~/.talos/runtime/proxy.json and holds proxy.lock during mutations.
"""

from talos.proxy.runtime.manager import (
    ProxyAlreadyRunning,
    ProxyRuntimeInfo,
    ProxyRuntimeManager,
    ProxyStartError,
)
from talos.proxy.runtime.process_ops import ProcessIdentity, ProcessOps
from talos.proxy.runtime.state import ProxyState

__all__ = [
    "ProcessIdentity",
    "ProcessOps",
    "ProxyAlreadyRunning",
    "ProxyRuntimeInfo",
    "ProxyRuntimeManager",
    "ProxyStartError",
    "ProxyState",
]
