"""
Module: talos.proxy.runtime.port_ops

Purpose:
    Cross-platform helpers to detect whether a TCP listen address is free
    and which process IDs currently own it. Used by ProxyRuntimeManager for
    pre-start checks and `talos proxy kill` port reclamation.

Dependencies: socket, subprocess, sys, re, logging
Data flow:
    manager / CLI → is_port_free / find_listening_pids → OS
Side effects:
    May spawn ss/netstat/fuser briefly; does not kill processes itself.
"""

from __future__ import annotations

import logging
import re
import socket
import subprocess
import sys
from typing import Optional

logger = logging.getLogger(__name__)


def is_port_free(host: str, port: int) -> bool:
    """
    Purpose:
        Return True if host:port can be bound for TCP listen right now.
    Input:
        host — bind address (e.g. 127.0.0.1 or 0.0.0.0).
        port — TCP port.
    Output:
        bool.
    Side effects: Brief bind attempt (socket closed immediately).
    """
    family = socket.AF_INET6 if ":" in host and not host.startswith(":") else socket.AF_INET
    # Map wildcard names.
    bind_host = host
    if host in ("0.0.0.0", "::"):
        bind_host = host
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_host, port))
            return True
    except OSError:
        return False


def is_port_listening(host: str, port: int, *, timeout_s: float = 0.3) -> bool:
    """
    Purpose:
        Return True if something accepts TCP connections on host:port.
        Used as post-start readiness (mitmdump is actually listening).
    """
    # Connecting to 0.0.0.0 is invalid — use loopback.
    connect_host = "127.0.0.1" if host in ("0.0.0.0", "") else host
    if host == "::":
        connect_host = "::1"
    try:
        with socket.create_connection((connect_host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def find_listening_pids(host: str, port: int) -> list[int]:
    """
    Purpose:
        Best-effort list of PIDs listening on host:port.
    Output:
        Deduplicated list of positive PIDs (may be empty if tools unavailable).
    """
    if sys.platform == "win32":
        return _windows_listening_pids(port)
    return _posix_listening_pids(host, port)


def describe_listeners(host: str, port: int) -> str:
    """
    Purpose:
        Human-readable summary of who holds host:port for error messages.
    """
    pids = find_listening_pids(host, port)
    if not pids:
        return f"{host}:{port} is in use (owner pid unknown)"
    parts: list[str] = []
    for pid in pids:
        cmd = _cmdline_for_pid(pid) or "(unknown command)"
        parts.append(f"pid={pid} cmd={cmd}")
    return f"{host}:{port} held by: " + "; ".join(parts)


def _cmdline_for_pid(pid: int) -> Optional[str]:
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(
                ["wmic", "process", "where", f"ProcessId={pid}", "get", "CommandLine", "/value"],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=3,
            )
            for line in out.splitlines():
                if line.startswith("CommandLine="):
                    return line.split("=", 1)[1].strip()[:200] or None
        except (OSError, subprocess.SubprocessError):
            return None
        return None
    try:
        raw = open(f"/proc/{pid}/cmdline", "rb").read()  # noqa: SIM115
        if not raw:
            return None
        return raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()[:200]
    except OSError:
        return None


def _posix_listening_pids(host: str, port: int) -> list[int]:
    pids: set[int] = set()
    # ss is widely available; parse users:(("name",pid=123,fd=N))
    try:
        out = subprocess.check_output(
            ["ss", "-ltnp"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
        port_token = f":{port}"
        pid_re = re.compile(r"pid=(\d+)")
        for line in out.splitlines():
            if port_token not in line:
                continue
            # Prefer lines that mention our host or wildcard.
            if host not in ("0.0.0.0", "127.0.0.1", "::", "*") and host not in line:
                # Still accept if local address ends with :port (common format).
                if not re.search(rf"[\s\*:]{port}\s", line) and not re.search(
                    rf":{port}\s", line
                ):
                    continue
            for match in pid_re.finditer(line):
                pids.add(int(match.group(1)))
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("ss lookup failed: %s", exc)

    if pids:
        return sorted(pids)

    # Fallback: fuser
    try:
        out = subprocess.check_output(
            ["fuser", f"{port}/tcp"],
            text=True,
            stderr=subprocess.STDOUT,
            timeout=5,
        )
        for token in out.replace("\n", " ").split():
            if token.isdigit():
                pids.add(int(token))
    except (OSError, subprocess.SubprocessError):
        pass
    return sorted(pids)


def _windows_listening_pids(port: int) -> list[int]:
    pids: set[int] = set()
    try:
        out = subprocess.check_output(
            ["netstat", "-ano", "-p", "tcp"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug("netstat lookup failed: %s", exc)
        return []

    # Proto  Local Address  Foreign Address  State  PID
    for line in out.splitlines():
        line = line.strip()
        if "LISTENING" not in line.upper() and "LISTEN" not in line.upper():
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        local = parts[1] if parts[0].upper().startswith("TCP") else parts[0]
        if not local.endswith(f":{port}"):
            continue
        try:
            pid = int(parts[-1])
        except ValueError:
            continue
        if pid > 0:
            pids.add(pid)
    return sorted(pids)


def looks_like_mitmdump(pid: int) -> bool:
    """True if cmdline suggests mitmdump / talos proxy child."""
    cmd = (_cmdline_for_pid(pid) or "").lower()
    return "mitmdump" in cmd or "mitmproxy" in cmd
