"""
Module: talos.proxy.cli

Purpose:
    Command-line interface for proxy lifecycle management.
    Entry points:
        talos proxy start                          — managed mitmdump start.
        talos proxy start --foreground             — block until proxy exits.
        talos proxy start --upstream <url>         — one-shot Upstream mode.
        talos proxy start --no-upstream            — one-shot Direct mode.
        talos proxy stop                           — graceful stop.
        talos proxy restart                        — graceful restart.
        talos proxy status                         — runtime status.
        talos proxy config                          — show/update Direct vs Upstream,
                                                      HTTP/1.1, keep-alive.
        talos proxy auth                            — platform authentication (NTLM).

    All process spawn/stop goes through ProxyRuntimeManager — this module
    never calls os.execvp or subprocess for mitmdump directly.

Dependencies: argparse, logging, sys, pathlib, talos.projects.manager,
              talos.projects.proxy_config, talos.proxy.runtime,
              talos.config, talos.cli_output
Data flow:
    CLI args → handlers → ProxyRuntimeManager / proxy_config
Side effects:
    - Verifies bound project before start/restart; may exit 3 if none.
    - Starts/stops managed mitmdump via ProxyRuntimeManager.
    - config: writes to the proxy_config table.
"""

from talos.cli_output import (
    add_format_argument,
    cli_error,
    cli_json,
    cli_precondition_error,
    cli_usage_error,
    cli_warning,
    wants_json,
)

import argparse
import logging
import sys

from talos.config import TalosConfig
from talos.projects.manager import ProjectManager
from talos.configuration.manager import parse_platform_auth_entry
from talos.projects.proxy_config import (
    InvalidUpstreamUrl,
    add_platform_auth_entry,
    clear_upstream_url,
    get_platform_auth_entry,
    get_upstream_url,
    load_proxy_transport,
    remove_platform_auth_entry,
    resolve_upstream_url,
    set_http2,
    set_keep_alive,
    set_platform_auth_enabled,
    set_platform_auth_entry_enabled,
    set_upstream_url,
    update_platform_auth_entry,
    use_platform_auth_entry,
)
from talos.proxy.runtime import (
    ProxyAlreadyRunning,
    ProxyRuntimeManager,
    ProxyStartError,
    ProxyState,
)


def _runtime_manager() -> ProxyRuntimeManager:
    config = TalosConfig.from_env()
    return ProxyRuntimeManager(data_dir=config.data_dir)


def _require_project(manager: ProjectManager):
    project = manager.active()
    if project is None:
        cli_precondition_error(
            "No active project. Run 'talos project open <id>', "
            "or pass --project <id> / set TALOS_PROJECT."
        )
    return project


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_start(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Verify a bound project exists, then start the managed capture proxy.
    Side effects:
        Spawns mitmdump via ProxyRuntimeManager (background by default).
    """
    if not args.quiet:
        logging.getLogger("talos").setLevel(logging.INFO)

    project = _require_project(manager)

    if args.upstream and args.no_upstream:
        cli_usage_error("--upstream and --no-upstream are mutually exclusive.")

    if not project.scope:
        cli_warning("Project has no scope entries. No traffic will be captured.")

    try:
        upstream_url = resolve_upstream_url(
            project.db_path,
            cli_upstream=args.upstream,
            cli_no_upstream=args.no_upstream,
        )
    except InvalidUpstreamUrl as exc:
        cli_usage_error(str(exc))

    print(f"Starting proxy for project '{project.id}'")
    print(f"  Scope entries : {len(project.scope)}")
    print(f"  Store bodies  : {project.constraints.store_bodies}")
    print(f"  Max body size : {project.constraints.max_body_size:,} bytes")
    print(f"  Listen        : {args.listen_host}:{args.port}")
    print(
        f"  Mode          : "
        f"{'Upstream Proxy -> ' + upstream_url if upstream_url else 'Direct'}"
    )
    transport = load_proxy_transport(project.db_path)
    print(f"  HTTP          : {'HTTP/2' if transport.http2 else 'HTTP/1.1'}")
    print(f"  Keep-alive    : {'on' if transport.keep_alive else 'off'}")
    auth_on = [
        row
        for row in transport.platform_auth_entries
        if row.enabled
    ]
    print(
        f"  Platform auth : "
        + (
            f"on ({len(auth_on)}/{len(transport.platform_auth_entries)} profile(s))"
            if transport.platform_auth_enabled and transport.platform_auth_entries
            else "off"
        )
    )
    print(f"  Foreground    : {bool(args.foreground)}")

    runtime = _runtime_manager()
    try:
        info = runtime.start(
            project=project,
            listen_host=args.listen_host,
            port=args.port,
            upstream_url=upstream_url,
            quiet=bool(args.quiet),
            foreground=bool(args.foreground),
        )
    except ProxyAlreadyRunning as exc:
        cli_error(str(exc))
    except ProxyStartError as exc:
        cli_error(str(exc))

    if args.foreground:
        # Session already ended inside start().
        return

    print(f"Proxy started (pid={info.pid})")
    print(f"  State         : {info.state.value}")
    print(f"  Log           : {info.log_path}")
    print("Use 'talos proxy status' / 'talos proxy stop' to manage the process.")


def cmd_stop(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Gracefully stop the managed proxy if running.
    """
    del manager, args  # stop is global to the data_dir runtime, not project-scoped.
    runtime = _runtime_manager()
    info = runtime.stop()
    if info.state == ProxyState.STOPPED and info.pid is None:
        print("Proxy is stopped.")
        print(
            "If port 8080 is still busy (orphan mitmdump), run: "
            "talos proxy kill --port 8080"
        )
        return
    print(f"Proxy stop complete (state={info.state.value}).")


def cmd_kill(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Force-recover proxy: stop managed process and free the listen port
        (orphan mitmdump from old launches is the common case).
    """
    del manager
    runtime = _runtime_manager()
    summary = runtime.kill(
        listen_host=args.listen_host,
        port=args.port,
        force_any_owner=bool(args.force),
    )
    if wants_json(args):
        cli_json(summary)
        return

    print("Proxy kill complete")
    print(f"  Target        : {summary['listen_host']}:{summary['listen_port']}")
    print(f"  Managed stop  : {'yes' if summary['managed_stopped'] else 'no'}")
    killed = summary["killed_pids"]
    print(f"  Killed pids   : {killed if killed else '(none)'}")
    skipped = summary["skipped_pids"]
    if skipped:
        print(
            f"  Skipped pids  : {skipped} "
            "(not mitmdump; re-run with --force to kill)"
        )
    print(f"  Port free     : {'yes' if summary['port_free'] else 'NO'}")
    if not summary["port_free"]:
        print(
            "Port still in use. Identify the owner and stop it, or "
            "talos proxy kill --force --port "
            f"{summary['listen_port']}"
        )


def cmd_restart(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Gracefully restart the proxy for the bound project.
    """
    project = _require_project(manager)

    if args.upstream and args.no_upstream:
        cli_usage_error("--upstream and --no-upstream are mutually exclusive.")

    try:
        # Resolve upstream: explicit flags, else re-read project config on restart.
        if args.upstream or args.no_upstream:
            upstream_url = resolve_upstream_url(
                project.db_path,
                cli_upstream=args.upstream,
                cli_no_upstream=args.no_upstream,
            )
        else:
            upstream_url = get_upstream_url(project.db_path)
    except InvalidUpstreamUrl as exc:
        cli_usage_error(str(exc))

    runtime = _runtime_manager()
    try:
        info = runtime.restart(
            project=project,
            listen_host=args.listen_host,
            port=args.port,
            upstream_url=upstream_url,
            quiet=bool(args.quiet) if getattr(args, "quiet", False) else None,
        )
    except ProxyStartError as exc:
        cli_error(str(exc))

    print(f"Proxy restarted (pid={info.pid})")
    print(f"  Project       : {info.project_id}")
    print(f"  Listen        : {info.listen_host}:{info.listen_port}")
    print(
        f"  Mode          : "
        f"{'Upstream Proxy -> ' + info.upstream_url if info.upstream_url else 'Direct'}"
    )


def cmd_status(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Show managed proxy runtime status (non-blocking).
    """
    del manager
    runtime = _runtime_manager()
    info = runtime.status()
    payload = info.to_dict()

    if wants_json(args):
        cli_json(payload)
        return

    print(f"Proxy state     : {info.state.value}")
    if info.transitional:
        print("  Transitional  : yes")
    if info.validation_deferred:
        print("  Validation    : deferred (lifecycle lock busy)")
    print(f"  PID           : {info.pid if info.pid is not None else '-'}")
    print(f"  Project       : {info.project_id or '-'}")
    print(f"  Role          : {info.role_id or '-'}")
    print(f"  Module        : {info.module_id or '-'}")
    listen = (
        f"{info.listen_host}:{info.listen_port}"
        if info.listen_host is not None and info.listen_port is not None
        else "-"
    )
    print(f"  Listen        : {listen}")
    print(
        f"  Mode          : "
        f"{'Upstream -> ' + info.upstream_url if info.upstream_url else 'Direct'}"
    )
    print(f"  Started       : {info.startup_time or '-'}")
    print(
        f"  Applied gen   : "
        f"{info.applied_generation if info.applied_generation is not None else '-'}"
        f" ({info.applied_project_id or '-'})"
    )
    if info.restart_pending:
        print("  Restart pending: yes")
    if info.last_error:
        print(f"  Last error    : {info.last_error}")
    if info.log_path:
        print(f"  Log           : {info.log_path}")


def cmd_config(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Show or update the bound project's proxy transport (upstream, HTTP/1.1,
        keep-alive). Config commits notify ProxyRuntimeManager.
    """
    project = _require_project(manager)

    if args.upstream and args.no_upstream:
        cli_usage_error("--upstream and --no-upstream are mutually exclusive.")
    if getattr(args, "http1", False) and getattr(args, "force_http2", False):
        cli_usage_error("--http1 and --http2 are mutually exclusive.")
    if getattr(args, "keep_alive", False) and getattr(args, "no_keep_alive", False):
        cli_usage_error("--keep-alive and --no-keep-alive are mutually exclusive.")

    changed: list[str] = []

    if args.upstream:
        try:
            stored = set_upstream_url(project.db_path, args.upstream)
        except InvalidUpstreamUrl as exc:
            cli_usage_error(str(exc))
        print("Proxy mode updated: Upstream Proxy")
        print(f"  Upstream : {stored}")
        changed.append(f"upstream {stored}")

    if args.no_upstream:
        clear_upstream_url(project.db_path)
        print("Proxy mode updated: Direct")
        changed.append("no-upstream")

    if getattr(args, "http1", False):
        set_http2(project.db_path, False)
        print("Origin protocol updated: HTTP/1.1 (HTTP/2 disabled)")
        changed.append("http1")
    elif getattr(args, "force_http2", False):
        set_http2(project.db_path, True)
        print("Origin protocol updated: HTTP/2 allowed")
        changed.append("http2")

    if getattr(args, "keep_alive", False):
        set_keep_alive(project.db_path, True)
        print("Keep-alive updated: on")
        changed.append("keep-alive")
    elif getattr(args, "no_keep_alive", False):
        set_keep_alive(project.db_path, False)
        print("Keep-alive updated: off")
        changed.append("no-keep-alive")

    if changed:
        from talos.proxy.runtime.events import notify_proxy_config_changed

        notify_proxy_config_changed(
            project.id, "proxy config " + ", ".join(changed)
        )
        return

    _print_proxy_config(project, args)


def _print_proxy_config(project, args: argparse.Namespace) -> None:
    """Show effective proxy transport (human or JSON)."""
    transport = load_proxy_transport(project.db_path)
    upstream_url = transport.upstream_url
    payload = {
        "project_id": project.id,
        "mode": "upstream" if upstream_url else "direct",
        "upstream_url": upstream_url,
        "http2": transport.http2,
        "keep_alive": transport.keep_alive,
        "platform_auth": {
            "enabled": transport.platform_auth_enabled,
            "entries": [row.to_public_dict() for row in transport.platform_auth_entries],
        },
    }
    if wants_json(args):
        cli_json(payload)
        return

    if upstream_url:
        print("Proxy mode : Upstream Proxy")
        print(f"  Upstream : {upstream_url}")
    else:
        print("Proxy mode : Direct")
    print(f"  HTTP     : {'HTTP/2' if transport.http2 else 'HTTP/1.1'}")
    print(f"  Keep-alive: {'on' if transport.keep_alive else 'off'}")
    enabled_n = sum(1 for row in transport.platform_auth_entries if row.enabled)
    print(
        "  Platform auth: "
        + (
            f"on ({enabled_n}/{len(transport.platform_auth_entries)} profile(s))"
            if transport.platform_auth_enabled and transport.platform_auth_entries
            else "off"
        )
    )
    if transport.platform_auth_entries:
        print("  Use 'talos proxy auth list' for profiles.")


def cmd_auth(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        List / add / edit / use / enable / disable / remove platform-auth
        profiles.
    Side effects: Writes project.yaml; may auto-restart the proxy.
    """
    project = _require_project(manager)
    action = args.auth_command or "list"
    if action == "list":
        _auth_list(project, args)
        return
    if action == "add":
        _auth_add(project, args)
        return
    if action == "edit":
        _auth_edit(project, args)
        return
    if action == "use":
        _auth_use(project, args)
        return
    if action == "remove":
        _auth_remove(project, args)
        return
    if action == "enable":
        _auth_set_enabled(project, args, True)
        return
    if action == "disable":
        _auth_set_enabled(project, args, False)
        return
    cli_usage_error(
        "Use talos proxy auth list|add|edit|use|remove|enable|disable."
    )


def _auth_list(project, args: argparse.Namespace) -> None:
    transport = load_proxy_transport(project.db_path)
    rows = [row.to_public_dict() for row in transport.platform_auth_entries]
    if wants_json(args):
        cli_json(
            {
                "enabled": transport.platform_auth_enabled,
                "entries": rows,
            }
        )
        return
    print(
        "Platform authentication: "
        + ("enabled" if transport.platform_auth_enabled else "disabled")
        + " (master)"
    )
    if not rows:
        print("No profiles. Add one:")
        print(
            "  talos proxy auth add --name 'Charter UAT' --host example.com "
            "--type ntlmv2 --username USER --password PASS "
            "--domain-hostname example.com"
        )
        return
    print()
    for row in rows:
        state = "on" if row["enabled"] else "off"
        print(f"{row['name']}  [{state}]")
        print(f"  id              : {row['id']}")
        print(f"  host            : {row['host']}")
        print(f"  type            : {row['auth_type']}")
        print(f"  username        : {row['username'] or '(none)'}")
        print(f"  password        : {'set' if row['password_set'] else '(empty)'}")
        print(f"  domain          : {row['domain'] or '(empty)'}")
        print(f"  domain hostname : {row['domain_hostname'] or '(empty)'}")
        print(f"  SPNEGO encoding : {'on' if row['spnego'] else 'off'}")
        print(f"  Negotiate scheme: {'on' if row['negotiate'] else 'off'}")


def _auth_add(project, args: argparse.Namespace) -> None:
    try:
        entry = parse_platform_auth_entry(
            {
                "id": getattr(args, "profile_id", None) or "",
                "name": args.name or "",
                "host": args.host,
                "auth_type": args.type,
                "username": args.username or "",
                "password": args.password or "",
                "domain": args.domain or "",
                "domain_hostname": args.domain_hostname or "",
                "spnego": bool(args.spnego),
                "negotiate": bool(args.negotiate),
                "enabled": not bool(getattr(args, "disabled", False)),
            }
        )
    except ValueError as exc:
        cli_usage_error(str(exc))
        return
    if not entry.username and not entry.password:
        cli_warning(
            "No credentials stored — Talos will only strip Negotiate on this host."
        )
    stored = add_platform_auth_entry(project.db_path, entry)
    _notify_auth(project.id, f"platform auth add {stored.id}")
    print(f"Platform auth profile saved: {stored.display_name()}")
    print(f"  id              : {stored.id}")
    print(f"  host            : {stored.host}")
    print(f"  enabled         : {'on' if stored.enabled else 'off'}")
    print(f"  type            : {stored.auth_type}")
    print(f"  username        : {stored.username or '(none)'}")
    print(f"  domain hostname : {stored.domain_hostname or '(empty)'}")
    print(f"  SPNEGO encoding : {'on' if stored.spnego else 'off'}")
    print(f"  Negotiate scheme: {'on' if stored.negotiate else 'off'}")


def _auth_key(args: argparse.Namespace) -> str:
    key = (getattr(args, "profile_id", None) or getattr(args, "host", None) or "").strip()
    if not key:
        cli_usage_error("Provide --id (or --host when the host is unique).")
    return key


def _auth_edit(project, args: argparse.Namespace) -> None:
    key = _auth_key(args)
    existing = get_platform_auth_entry(project.db_path, key)
    if existing is None:
        extra = ""
        host = (getattr(args, "host", None) or "").strip()
        if host and get_platform_auth_entry(project.db_path, host) is None:
            hits = [
                row
                for row in load_proxy_transport(project.db_path).platform_auth_entries
                if row.host.lower() == host.lower()
            ]
            if len(hits) > 1:
                extra = " Multiple profiles share that host — use --id."
        cli_error(f"No platform-auth profile for {key!r}.{extra}")
        return
    try:
        stored = update_platform_auth_entry(
            project.db_path,
            existing.id,
            name=args.name,
            host=args.host if args.host and args.host != existing.host else None,
            auth_type=args.type,
            username=args.username,
            password=args.password,
            domain=args.domain,
            domain_hostname=args.domain_hostname,
            spnego=True if args.spnego else (False if args.no_spnego else None),
            negotiate=(
                True if args.negotiate else (False if args.no_negotiate else None)
            ),
        )
    except ValueError as exc:
        cli_usage_error(str(exc))
        return
    if stored is None:
        cli_error(f"No platform-auth profile for {key!r}.")
        return
    _notify_auth(project.id, f"platform auth edit {stored.id}")
    print(f"Updated platform auth profile: {stored.display_name()}")
    print(f"  id              : {stored.id}")
    print(f"  host            : {stored.host}")
    print(f"  enabled         : {'on' if stored.enabled else 'off'}")
    print(f"  username        : {stored.username or '(none)'}")
    print(f"  password        : {'set' if stored.password else '(empty)'}")


def _auth_use(project, args: argparse.Namespace) -> None:
    key = _auth_key(args)
    stored = use_platform_auth_entry(project.db_path, key)
    if stored is None:
        cli_error(f"No platform-auth profile for {key!r}.")
        return
    _notify_auth(project.id, f"platform auth use {stored.id}")
    print(f"Using platform auth profile: {stored.display_name()} ({stored.id})")
    print(f"  host            : {stored.host}")
    print("  Other profiles for this host are disabled.")


def _auth_set_enabled(project, args: argparse.Namespace, enabled: bool) -> None:
    key = (getattr(args, "profile_id", None) or getattr(args, "host", None) or "").strip()
    verb = "enable" if enabled else "disable"
    if not key:
        set_platform_auth_enabled(project.db_path, enabled)
        _notify_auth(project.id, f"platform auth {verb}")
        print(
            "Platform authentication "
            + ("enabled" if enabled else "disabled")
            + " (master)."
        )
        return
    stored = set_platform_auth_entry_enabled(project.db_path, key, enabled)
    if stored is None:
        cli_error(f"No platform-auth profile for {key!r}.")
        return
    _notify_auth(project.id, f"platform auth {verb} {stored.id}")
    print(
        f"Profile {stored.display_name()} ({stored.id}) "
        + ("enabled." if enabled else "disabled.")
    )


def _auth_remove(project, args: argparse.Namespace) -> None:
    key = _auth_key(args)
    existing = get_platform_auth_entry(project.db_path, key)
    if existing is None:
        host = (getattr(args, "host", None) or "").strip()
        if host:
            hits = [
                row
                for row in load_proxy_transport(project.db_path).platform_auth_entries
                if row.host.lower() == host.lower()
            ]
            if len(hits) > 1:
                ids = ", ".join(row.id for row in hits)
                cli_error(
                    f"Multiple profiles for host {host!r} ({ids}). "
                    "Use --id to choose one."
                )
                return
        cli_error(f"No platform-auth profile for {key!r}.")
        return
    if not remove_platform_auth_entry(project.db_path, existing.id):
        cli_error(f"No platform-auth profile for {key!r}.")
        return
    _notify_auth(project.id, f"platform auth remove {existing.id}")
    print(f"Removed platform auth profile {existing.display_name()} ({existing.id})")


def _notify_auth(project_id: str, reason: str) -> None:
    from talos.proxy.runtime.events import notify_proxy_config_changed

    notify_proxy_config_changed(project_id, reason)


# ------------------------------------------------------------------ #
# Parser construction                                                  #
# ------------------------------------------------------------------ #

_UPSTREAM_HELP = (
    "Upstream proxy URL (http:// or https:// host[:port]), e.g. "
    "http://127.0.0.1:8081 for Burp/ZAP/a corporate proxy."
)


def build_parser() -> argparse.ArgumentParser:
    """
    Purpose:  Construct the argument parser for 'talos proxy' subcommands.
    Output:   Configured ArgumentParser.
    Side effects: None.
    """
    parser = argparse.ArgumentParser(
        prog="talos proxy",
        description="Control the Talos capture proxy.",
    )
    sub = parser.add_subparsers(dest="command", metavar="command", required=True)

    # start
    p_start = sub.add_parser(
        "start",
        help="Start the managed capture proxy for the bound project.",
    )
    p_start.add_argument(
        "--port", "-p",
        type=int,
        default=8080,
        help="Proxy listen port (default: 8080).",
    )
    p_start.add_argument(
        "--listen-host",
        default="127.0.0.1",
        help="Interface to bind (default: 127.0.0.1).",
    )
    p_start.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress addon startup and worker shutdown logs.",
    )
    p_start.add_argument(
        "--upstream",
        metavar="URL",
        default=None,
        help=(
            "One-shot Upstream Proxy mode for this start only "
            f"(does not persist). {_UPSTREAM_HELP}"
        ),
    )
    p_start.add_argument(
        "--no-upstream",
        action="store_true",
        help=(
            "One-shot Direct mode for this start only, ignoring any "
            "project-configured upstream (does not persist)."
        ),
    )
    p_start.add_argument(
        "--foreground",
        action="store_true",
        help=(
            "Run in the foreground (block until the proxy exits). "
            "Default is managed background so stop/status work from "
            "another terminal."
        ),
    )

    # stop
    sub.add_parser(
        "stop",
        help="Gracefully stop the managed capture proxy.",
    )

    # kill — managed stop + free listen port (orphans)
    p_kill = sub.add_parser(
        "kill",
        help=(
            "Stop managed proxy and free the listen port "
            "(kills orphan mitmdump holding the port)."
        ),
    )
    p_kill.add_argument(
        "--port", "-p",
        type=int,
        default=None,
        help="Listen port to free (default: last runtime port or 8080).",
    )
    p_kill.add_argument(
        "--listen-host",
        default=None,
        help="Listen host (default: last runtime host or 127.0.0.1).",
    )
    p_kill.add_argument(
        "--force",
        action="store_true",
        help="Kill any process on the port, not only mitmdump.",
    )
    add_format_argument(p_kill)

    # restart
    p_restart = sub.add_parser(
        "restart",
        help="Gracefully restart the managed capture proxy.",
    )
    p_restart.add_argument(
        "--port", "-p",
        type=int,
        default=None,
        help="Override listen port on restart.",
    )
    p_restart.add_argument(
        "--listen-host",
        default=None,
        help="Override listen host on restart.",
    )
    p_restart.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Quiet logging for the new process.",
    )
    p_restart.add_argument(
        "--upstream",
        metavar="URL",
        default=None,
        help=f"One-shot Upstream mode for this restart. {_UPSTREAM_HELP}",
    )
    p_restart.add_argument(
        "--no-upstream",
        action="store_true",
        help="One-shot Direct mode for this restart.",
    )

    # status
    p_status = sub.add_parser(
        "status",
        help="Show managed proxy runtime status.",
    )
    add_format_argument(p_status)

    # config
    p_config = sub.add_parser(
        "config",
        help="Show or update proxy transport (upstream, HTTP/1.1, keep-alive).",
    )
    add_format_argument(p_config)
    p_config.add_argument(
        "--upstream",
        metavar="URL",
        default=None,
        help=(
            "Persist Upstream Proxy mode for the bound project. "
            f"{_UPSTREAM_HELP}"
        ),
    )
    p_config.add_argument(
        "--no-upstream",
        action="store_true",
        help=(
            "Persist Direct mode (no upstream proxy; mitmdump connects "
            "straight to the target)."
        ),
    )
    p_config.add_argument(
        "--http1",
        action="store_true",
        help="Force HTTP/1.1 toward the origin (disable HTTP/2). Restart required.",
    )
    p_config.add_argument(
        "--http2",
        dest="force_http2",
        action="store_true",
        help="Allow HTTP/2 toward the origin (default).",
    )
    p_config.add_argument(
        "--keep-alive",
        dest="keep_alive",
        action="store_true",
        help="Reuse origin connections (needed for IIS Persistent-Auth / NTLM).",
    )
    p_config.add_argument(
        "--no-keep-alive",
        dest="no_keep_alive",
        action="store_true",
        help="Close the origin connection after each request.",
    )

    # auth — Burp-style platform authentication
    p_auth = sub.add_parser(
        "auth",
        help="Platform authentication profiles (NTLM) toward origin hosts.",
    )
    auth_sub = p_auth.add_subparsers(dest="auth_command", metavar="command")
    p_auth_list = auth_sub.add_parser("list", help="List platform-auth profiles.")
    add_format_argument(p_auth_list)
    p_auth_add = auth_sub.add_parser(
        "add",
        help="Add a named profile (same host as another profile is allowed).",
    )
    p_auth_add.add_argument(
        "--id",
        dest="profile_id",
        default=None,
        help="Optional stable id (default: slug of --name or --host).",
    )
    p_auth_add.add_argument(
        "--name",
        default="",
        help="Operator label (default: destination host).",
    )
    p_auth_add.add_argument("--host", required=True, help="Destination host (exact or *.suffix).")
    p_auth_add.add_argument(
        "--type",
        dest="type",
        default="ntlmv2",
        choices=["ntlmv2", "ntlm", "negotiate"],
        help="Authentication type (default: ntlmv2).",
    )
    p_auth_add.add_argument("--username", default="", help="Account username.")
    p_auth_add.add_argument("--password", default="", help="Account password.")
    p_auth_add.add_argument(
        "--domain",
        default="",
        help="Windows domain (empty is valid for local / IIS NTLM).",
    )
    p_auth_add.add_argument(
        "--domain-hostname",
        default="",
        dest="domain_hostname",
        help="NTLM workstation / target hostname (Burp Domain Hostname).",
    )
    p_auth_add.add_argument(
        "--spnego",
        action="store_true",
        help="Enable SPNEGO encoding (off by default, matching Burp unchecked).",
    )
    p_auth_add.add_argument(
        "--negotiate",
        action="store_true",
        help="Use the Negotiate auth scheme (off by default).",
    )
    p_auth_add.add_argument(
        "--disabled",
        action="store_true",
        help="Save the profile but leave it disabled.",
    )
    p_auth_edit = auth_sub.add_parser(
        "edit",
        help="Update an existing profile by --id (or unique --host).",
    )
    p_auth_edit.add_argument(
        "--id",
        dest="profile_id",
        default=None,
        help="Profile id to update.",
    )
    p_auth_edit.add_argument("--name", default=None, help="New operator label.")
    p_auth_edit.add_argument(
        "--host",
        default=None,
        help="Lookup key when --id is omitted, or new host when --id is set.",
    )
    p_auth_edit.add_argument(
        "--type",
        dest="type",
        default=None,
        choices=["ntlmv2", "ntlm", "negotiate"],
        help="Authentication type.",
    )
    p_auth_edit.add_argument("--username", default=None, help="Account username.")
    p_auth_edit.add_argument(
        "--password",
        default=None,
        help="Account password (omit to keep the stored secret).",
    )
    p_auth_edit.add_argument("--domain", default=None, help="Windows domain.")
    p_auth_edit.add_argument(
        "--domain-hostname",
        default=None,
        dest="domain_hostname",
        help="NTLM workstation / target hostname.",
    )
    p_auth_edit.add_argument(
        "--spnego",
        action="store_true",
        help="Enable SPNEGO encoding.",
    )
    p_auth_edit.add_argument(
        "--no-spnego",
        dest="no_spnego",
        action="store_true",
        help="Disable SPNEGO encoding.",
    )
    p_auth_edit.add_argument(
        "--negotiate",
        action="store_true",
        help="Use the Negotiate auth scheme.",
    )
    p_auth_edit.add_argument(
        "--no-negotiate",
        dest="no_negotiate",
        action="store_true",
        help="Disable the Negotiate auth scheme.",
    )
    p_auth_use = auth_sub.add_parser(
        "use",
        help="Enable a profile and disable others for the same host.",
    )
    p_auth_use.add_argument("--id", dest="profile_id", default=None, help="Profile id.")
    p_auth_use.add_argument(
        "--host",
        default=None,
        help="Unique destination host (error if several profiles share it).",
    )
    p_auth_rm = auth_sub.add_parser("remove", help="Remove a profile by --id or unique --host.")
    p_auth_rm.add_argument("--id", dest="profile_id", default=None, help="Profile id.")
    p_auth_rm.add_argument("--host", default=None, help="Destination host (must be unique).")
    p_auth_on = auth_sub.add_parser(
        "enable",
        help="Enable a profile (--id) or the master switch (no --id).",
    )
    p_auth_on.add_argument("--id", dest="profile_id", default=None, help="Profile id.")
    p_auth_on.add_argument("--host", default=None, help="Unique destination host.")
    p_auth_off = auth_sub.add_parser(
        "disable",
        help="Disable a profile (--id) or the master switch (no --id).",
    )
    p_auth_off.add_argument("--id", dest="profile_id", default=None, help="Profile id.")
    p_auth_off.add_argument("--host", default=None, help="Unique destination host.")

    return parser


_COMMAND_MAP = {
    "start": cmd_start,
    "stop": cmd_stop,
    "kill": cmd_kill,
    "restart": cmd_restart,
    "status": cmd_status,
    "config": cmd_config,
    "auth": cmd_auth,
}


def run_proxy_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse argv and dispatch to the appropriate proxy command handler.
    Input:
        manager — ProjectManager instance.
        argv    — list of CLI arguments after 'talos proxy'.
    Side effects:
        Delegates to command handlers; may exit with sys.exit().
    """
    parser = build_parser()
    args = parser.parse_args(argv)

    handler = _COMMAND_MAP.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(1)

    handler(manager, args)
