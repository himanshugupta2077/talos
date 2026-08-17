"""
Module: talos.proxy.launcher

Purpose:
    Single shared function that builds the mitmdump command line used by
    `talos proxy start`. This is the only place that knows the exact
    mitmdump flags Talos launches with, so any future proxy-related
    option only needs to be implemented once.

    Talos supports two proxy startup modes:
        Direct mode          — mitmdump connects straight to the target server.
        Upstream Proxy mode  — mitmdump forwards all traffic to another proxy
                                (Burp Suite, OWASP ZAP, a corporate proxy, or
                                any other HTTP proxy) via `--mode upstream:<url>`.
    The mode is selected solely by whether an upstream_url is supplied —
    callers resolve it via talos.projects.proxy_config.resolve_upstream_url
    (project config + optional CLI overrides) and pass the result through.
    No host, port, URL, or credentials are hardcoded here.

    Origin protocol flags (HTTP/2, keep-alive) also live here so CLI and
    the runtime manager cannot drift. HTTP/2 off is required for IIS
    Windows Integrated Auth through a MITM.

Dependencies: pathlib, typing
Data flow:
    talos.proxy.cli.cmd_start → resolve_upstream_url → build_mitmdump_command(...)
Side effects: None — pure function, builds an argv list only.
"""

from pathlib import Path
from typing import Optional


def build_mitmdump_command(
    *,
    listen_host: str,
    port: int,
    addon_path: Path,
    upstream_url: Optional[str] = None,
    http2: bool = True,
    keep_alive: bool = True,
) -> list[str]:
    """
    Purpose:
        Build the exact mitmdump argv list Talos launches with, for either
        Direct mode or Upstream Proxy mode.
    Input:
        listen_host  — interface Talos's proxy binds to (e.g. '127.0.0.1').
        port         — port Talos's proxy listens on (e.g. 8080).
        addon_path   — absolute Path to talos/proxy/addon.py.
        upstream_url — when set (e.g. 'http://127.0.0.1:8081'), mitmdump is
                       started in Upstream Proxy mode, forwarding all traffic
                       to this address. When None/empty, Direct mode is used
                       (mitmdump connects straight to the target server).
                       Callers must supply the already-resolved value from
                       proxy_config — never invent a default host/port here.
        http2        — when False, pass --set http2=false (force HTTP/1.1).
        keep_alive   — when True, eager origin connections; when False the
                       addon also sends Connection: close.
    Output:
        List of argv strings suitable for subprocess.run / os.execvp /
        asyncio.create_subprocess_exec.
    Side effects: None.
    """
    cmd = [
        "mitmdump",
        "--listen-host", listen_host,
        "--listen-port", str(port),
    ]

    # Upstream mode is entirely dynamic: only add --mode when a URL was
    # resolved from project config or a CLI override. Empty/None → Direct.
    if upstream_url:
        cmd += [
            "--mode",
            f"upstream:{upstream_url}",
        ]

    cmd += [
        "--set",
        f"http2={'true' if http2 else 'false'}",
        "--set",
        f"connection_strategy={'eager' if keep_alive else 'lazy'}",
        # Skip upstream TLS verification — required for pentest interception.
        # mitmproxy's certifi bundle cannot verify all certificate chains
        # (common with Cloudflare and some CDNs on Windows). This is intentional
        # for a MITM tool; we are the intended man-in-the-middle.
        "--ssl-insecure",
        "-s", str(addon_path),
    ]

    return cmd
