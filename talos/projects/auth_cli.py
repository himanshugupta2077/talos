"""
Module: talos.projects.auth_cli

Purpose:
    Command-line interface for auth configuration, auth-bypass testing, and
    role-based session management.

    Auth config commands:
        talos auth set   --cookie <name> ... --header <name> ...
        talos auth show
        talos auth clear
        talos auth test  <endpoint_id>

    Role-based session commands:
        talos auth mark-login      <role_id> <flow_id>
        talos auth mark-checkpoint <role_id> <flow_id>
        talos auth generate        <role_id>
        talos auth inject-session-token <role_id> <session_token_id>
        talos auth validate        <role_id>

    'set', 'show', 'clear' manage the per-project auth config stored in
    auth_config table (cookie and header names that constitute authentication).

    'test' runs a Type 2 replay on the best qualifying flow for an endpoint:
    strips configured auth fields, replays, diffs, and outputs the verdict
    (SECURE | BYPASS | UNKNOWN).

    Role-based commands support automated login flow replay, JWT extraction,
    token storage, and checkpoint-based token validation so replay/BAC/IDOR
    testing can obtain valid sessions without manual login.

Dependencies: argparse, asyncio, re, sys,
              talos.projects.manager, talos.projects.auth,
              talos.replay.auth_strip, talos.replay.db, talos.replay.engine
Data flow:
    CLI args → active project DB → auth functions / auth_strip / replay engine → stdout
Side effects:
    - 'set' and 'clear' write to auth_config table.
    - 'test' sends outbound HTTP, writes replay flow + diff + auth_test_result.
    - 'mark-login' / 'mark-checkpoint' write to role_auth table.
    - 'generate' sends outbound HTTP, writes replay flow, writes role_session_tokens.
    - 'inject-session-token' updates active flag in role_session_tokens.
    - 'validate' sends outbound HTTP; may trigger 'generate' on token expiry.
    - All write commands require an active project.
    - Exits 1 on hard errors (no active project, missing config, flow not found).
"""

import argparse
import asyncio
import re
import sys
import uuid

from talos.projects.manager import ProjectManager
from talos.projects.auth import (
    get_auth_config,
    set_auth_fields,
    clear_auth_config,
    get_role_auth,
    set_login_flow,
    set_checkpoint_flow,
    store_session_token,
    activate_session_token,
    get_active_session_token,
    list_session_tokens,
)
from talos.replay import db as replay_db
from talos.replay.auth_strip import AuthTestOutcome, run_auth_bypass_test
from talos.replay.engine import replay_flow
from talos.scheduler import db as sched_db
from talos.scheduler.job import AUTH_TEST, PRIORITY_MANUAL

# JWT regex: covers the vast majority of compact-serialisation JWTs.
_JWT_RE = re.compile(
    r'eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+'
)

# HTTP status codes that signal a dead/expired session at the checkpoint.
_DEAD_SESSION_STATUSES = {401, 403}


# ------------------------------------------------------------------ #
# CLI entry point                                                      #
# ------------------------------------------------------------------ #

def run_auth_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse auth subcommand arguments and dispatch to the appropriate handler.
    Input:
        manager — ProjectManager instance.
        argv    — argument list after 'auth' (e.g. ['set', '--cookie', 'sessionid']).
    Side effects:
        Dispatches to cmd_auth_set/show/clear/test.
        Prints usage and exits 1 for unrecognised subcommands.
    """
    parser = argparse.ArgumentParser(
        prog="talos auth",
        description="Manage auth config, run auth-bypass tests, and manage role sessions.",
    )
    sub = parser.add_subparsers(dest="auth_cmd", metavar="<command>")
    sub.required = True

    # talos auth set --cookie <name> ... --header <name> ...
    p_set = sub.add_parser(
        "set",
        help="Add cookie/header names to the auth config (additive).",
    )
    p_set.add_argument(
        "--cookie",
        dest="cookies",
        action="append",
        default=[],
        metavar="NAME",
        help="Cookie name that carries auth (repeatable).",
    )
    p_set.add_argument(
        "--header",
        dest="headers",
        action="append",
        default=[],
        metavar="NAME",
        help="Header name that carries auth (repeatable).",
    )

    # talos auth show
    sub.add_parser("show", help="Display the current auth config.")

    # talos auth clear
    sub.add_parser("clear", help="Remove all auth config entries.")

    # talos auth test <endpoint_id>
    p_test = sub.add_parser(
        "test",
        help="Run an auth-bypass test on the best flow for an endpoint.",
    )
    p_test.add_argument("endpoint_id", help="UUID of the endpoint to test.")
    p_test.add_argument(
        "--right-now",
        action="store_true",
        help="Run the auth test immediately instead of enqueuing it (debug/manual override).",
    )

    # talos auth mark-login <role_id> <flow_id>
    p_mark_login = sub.add_parser(
        "mark-login",
        help="Assign a login flow to a role (replayed to generate a session token).",
    )
    p_mark_login.add_argument("role_id", help="UUID of the target role.")
    p_mark_login.add_argument("flow_id", help="UUID of the login flow.")

    # talos auth mark-checkpoint <role_id> <flow_id>
    p_mark_cp = sub.add_parser(
        "mark-checkpoint",
        help="Assign a checkpoint flow to a role (replayed to validate a session token).",
    )
    p_mark_cp.add_argument("role_id", help="UUID of the target role.")
    p_mark_cp.add_argument("flow_id", help="UUID of the checkpoint flow.")

    # talos auth generate <role_id>
    p_generate = sub.add_parser(
        "generate",
        help="Replay the login flow for a role and extract + store a session token.",
    )
    p_generate.add_argument("role_id", help="UUID of the target role.")

    # talos auth inject-session-token <role_id> <session_token_id>
    p_inject = sub.add_parser(
        "inject-session-token",
        help="Set a specific stored token as the active token for a role.",
    )
    p_inject.add_argument("role_id", help="UUID of the target role.")
    p_inject.add_argument("session_token_id", help="UUID of the token to activate.")

    # talos auth validate <role_id>
    p_validate = sub.add_parser(
        "validate",
        help=(
            "Validate the active session token for a role via its checkpoint flow. "
            "Generates a new token automatically if none exists or validation fails."
        ),
    )
    p_validate.add_argument("role_id", help="UUID of the target role.")

    args = parser.parse_args(argv)

    project = manager.active()
    if project is None:
        print(
            "Error: No active project. Run 'talos project open <id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    if args.auth_cmd == "set":
        cmd_auth_set(project, args)
    elif args.auth_cmd == "show":
        cmd_auth_show(project)
    elif args.auth_cmd == "clear":
        cmd_auth_clear(project)
    elif args.auth_cmd == "test":
        cmd_auth_test(project, args)
    elif args.auth_cmd == "mark-login":
        cmd_mark_login(project, args)
    elif args.auth_cmd == "mark-checkpoint":
        cmd_mark_checkpoint(project, args)
    elif args.auth_cmd == "generate":
        cmd_generate(project, args)
    elif args.auth_cmd == "inject-session-token":
        cmd_inject_session_token(project, args)
    elif args.auth_cmd == "validate":
        cmd_validate(project, args)


# ------------------------------------------------------------------ #
# Command handlers                                                     #
# ------------------------------------------------------------------ #

def cmd_auth_set(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Add cookie and/or header names to the project's auth config.
        This is additive — existing entries are preserved.
    Input:
        project — active Project instance.
        args    — parsed args with: cookies (list[str]), headers (list[str]).
    Side effects:
        Writes to auth_config table; prints confirmation to stdout.
        Exits 1 if no names were provided.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    cookies: list[str] = args.cookies
    headers: list[str] = args.headers

    if not cookies and not headers:
        print(
            "Error: Provide at least one --cookie or --header name.",
            file=sys.stderr,
        )
        sys.exit(1)

    set_auth_fields(db_path, cookies, headers)

    print("Auth config updated.")
    if cookies:
        print(f"  cookies : {', '.join(cookies)}")
    if headers:
        print(f"  headers : {', '.join(headers)}")
    print("Run 'talos auth show' to see the full config.")


def cmd_auth_show(project: object) -> None:
    """
    Purpose:
        Display the current auth config for the active project.
    Input:
        project — active Project instance.
    Side effects:
        Prints auth config to stdout.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    config = get_auth_config(db_path)

    if not config["cookies"] and not config["headers"]:
        print("Auth config: (empty)")
        print("Use 'talos auth set --cookie <name> --header <name>' to configure.")
        return

    print("Auth config:")
    if config["cookies"]:
        print(f"  cookies : {', '.join(config['cookies'])}")
    else:
        print("  cookies : (none)")
    if config["headers"]:
        print(f"  headers : {', '.join(config['headers'])}")
    else:
        print("  headers : (none)")


def cmd_auth_clear(project: object) -> None:
    """
    Purpose:
        Remove all auth config entries for the active project.
    Input:
        project — active Project instance.
    Side effects:
        Deletes all rows from auth_config; prints confirmation.
    """
    db_path = project.db_path  # type: ignore[attr-defined]
    clear_auth_config(db_path)
    print("Auth config cleared.")


def cmd_auth_test(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Run an auth-bypass test on the best qualifying flow for an endpoint.
        By default enqueues the job for the scheduler.  With --right-now the
        test is executed immediately in-process.
    Input:
        project — active Project instance.
        args    — parsed args with: endpoint_id (str), right_now (bool).
    Side effects:
        --right-now: Sends HTTP request; writes replay flow, diff, auth_test_result.
        default: Inserts one scheduler job; prints job ID to stdout.
        Exits 1 if endpoint not found.
    """
    db_path = project.db_path   # type: ignore[attr-defined]
    project_id = project.id     # type: ignore[attr-defined]
    endpoint_id = args.endpoint_id

    # Validate endpoint exists before doing anything.
    endpoint = replay_db.get_endpoint_by_id(db_path, endpoint_id)
    if endpoint is None:
        print(f"Error: Endpoint '{endpoint_id}' not found.", file=sys.stderr)
        sys.exit(1)

    if not args.right_now:
        job_id = str(uuid.uuid4())
        sched_db.enqueue_job(
            db_path=db_path,
            job_id=job_id,
            job_type=AUTH_TEST,
            project_id=project_id,
            endpoint_id=endpoint_id,
            priority=PRIORITY_MANUAL,
        )
        print(f"Job enqueued: {job_id}")
        return

    ep_label = (
        f"{endpoint['method']} {endpoint['host']}{endpoint['normalized_path']}"
    )
    print(f"Auth bypass test: {ep_label}")

    outcome: AuthTestOutcome = asyncio.run(
        run_auth_bypass_test(endpoint_id, db_path, project_id)
    )

    if outcome.failure_reason == "no_qualifying_flow":
        print(
            f"Error: Endpoint '{endpoint_id}' has no 200 OK proxy_capture flow.",
            file=sys.stderr,
        )
        sys.exit(1)

    if outcome.failure_reason == "auth_config_empty":
        print(
            "Error: Auth config is empty. "
            "Run 'talos auth set --cookie <name> --header <name>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    if outcome.failure_reason == "endpoint_annotated_logout":
        print(
            f"Error: Endpoint '{endpoint_id}' is tagged logout — auth test blocked.",
            file=sys.stderr,
        )
        sys.exit(1)

    if outcome.failure_reason == "endpoint_annotated_dangerous":
        print(
            f"Error: Endpoint '{endpoint_id}' is tagged dangerous — auth test blocked.",
            file=sys.stderr,
        )
        sys.exit(1)

    _print_auth_outcome(outcome)


# ------------------------------------------------------------------ #
# Output formatting                                                    #
# ------------------------------------------------------------------ #

def _print_auth_outcome(outcome: AuthTestOutcome) -> None:
    """
    Purpose:
        Print a human-readable auth-bypass test result to stdout.
    Input:   outcome — AuthTestOutcome instance.
    Side effects: Writes to stdout.
    """
    print(
        f"  original flow : {outcome.original_flow_id}\n"
        f"  replay flow   : {outcome.replayed_flow_id or '—'}\n"
        f"  original status : {outcome.original_status or '—'}\n"
        f"  replay status   : {outcome.replay_status or '—'}\n"
        f"  diff verdict  : {outcome.diff_verdict or '—'}\n"
        f"  auth verdict  : {outcome.auth_verdict}"
    )
    if outcome.failure_reason:
        print(f"  note          : {outcome.failure_reason}")


# ------------------------------------------------------------------ #
# Role-based session management commands                               #
# ------------------------------------------------------------------ #

def cmd_mark_login(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Assign a login flow to a role.  The flow is replayed by 'generate' to
        obtain a fresh session token.
    Input:
        project — active Project instance.
        args    — parsed args with: role_id (str), flow_id (str).
    Side effects:
        Validates role and flow exist; upserts role_auth row; prints confirmation.
        Exits 1 if role or flow not found.
    """
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    if not _role_exists(db_path, args.role_id):
        print(f"Error: Role '{args.role_id}' not found.", file=sys.stderr)
        sys.exit(1)

    if replay_db.get_flow_for_replay(db_path, args.flow_id) is None:
        print(f"Error: Flow '{args.flow_id}' not found.", file=sys.stderr)
        sys.exit(1)

    set_login_flow(db_path, args.role_id, args.flow_id)
    print(f"Login flow set for role {args.role_id}.")
    print(f"  flow : {args.flow_id}")


def cmd_mark_checkpoint(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Assign a checkpoint flow to a role.  The flow is replayed by 'validate'
        to test whether the active session token is still alive.
        A 200 response means the token is valid; 401/403 means it has expired.
    Input:
        project — active Project instance.
        args    — parsed args with: role_id (str), flow_id (str).
    Side effects:
        Validates role and flow exist; upserts role_auth row; prints confirmation.
        Exits 1 if role or flow not found.
    """
    db_path = project.db_path    # type: ignore[attr-defined]

    if not _role_exists(db_path, args.role_id):
        print(f"Error: Role '{args.role_id}' not found.", file=sys.stderr)
        sys.exit(1)

    if replay_db.get_flow_for_replay(db_path, args.flow_id) is None:
        print(f"Error: Flow '{args.flow_id}' not found.", file=sys.stderr)
        sys.exit(1)

    set_checkpoint_flow(db_path, args.role_id, args.flow_id)
    print(f"Checkpoint flow set for role {args.role_id}.")
    print(f"  flow : {args.flow_id}")


def cmd_generate(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Generate a session token for a role by replaying its login flow and
        extracting a JWT from the response body using a standard JWT regex.
        The extracted token is stored in role_session_tokens and marked active.
    Input:
        project — active Project instance.
        args    — parsed args with: role_id (str).
    Side effects:
        Replays login flow (outbound HTTP); inserts row in role_session_tokens.
        Prints token ID and masked token on success.
        Exits 1 on missing config, replay failure, or no token found in response.
    """
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    if not _role_exists(db_path, args.role_id):
        print(f"Error: Role '{args.role_id}' not found.", file=sys.stderr)
        sys.exit(1)

    role_auth_row = get_role_auth(db_path, args.role_id)
    if role_auth_row is None or not role_auth_row.get("login_flow_id"):
        print(
            f"Error: No login flow assigned to role '{args.role_id}'. "
            "Run 'talos auth mark-login <role_id> <flow_id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    login_flow_id: str = role_auth_row["login_flow_id"]
    print(f"Replaying login flow {login_flow_id} ...")

    outcome = asyncio.run(
        replay_flow(
            flow_id=login_flow_id,
            db_path=db_path,
            project_id=project_id,
            source="manual_replay",
            replay_reason="session_generate",
        )
    )

    if not outcome.success or outcome.replayed_flow_id is None:
        print(
            f"Error: Login flow replay failed — {outcome.failure_reason}.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Fetch the replay flow to inspect the response body.
    replayed = replay_db.get_flow_for_replay(db_path, outcome.replayed_flow_id)
    if replayed is None:
        print("Error: Replayed flow not found in DB after replay.", file=sys.stderr)
        sys.exit(1)

    response_body: bytes | None = replayed.get("response_body")
    body_text = ""
    if response_body:
        body_text = (
            response_body.decode("utf-8", errors="replace")
            if isinstance(response_body, bytes)
            else str(response_body)
        )

    match = _JWT_RE.search(body_text)
    if match is None:
        print(
            f"Error: No JWT found in response body of flow {outcome.replayed_flow_id}.\n"
            "The login response may not contain a JWT, or the token format differs.\n"
            f"  replay status : {outcome.status_code}",
            file=sys.stderr,
        )
        sys.exit(1)

    token = match.group(0)
    token_id = store_session_token(db_path, args.role_id, token)

    masked = token[:12] + "..." + token[-6:]
    print(f"Session token generated.")
    print(f"  token id     : {token_id}")
    print(f"  token        : {masked}")
    print(f"  replay flow  : {outcome.replayed_flow_id}")
    print(f"  replay status: {outcome.status_code}")


def cmd_inject_session_token(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Set a specific stored token as the active token for a role.
        All other tokens for the role are deactivated.
    Input:
        project — active Project instance.
        args    — parsed args with: role_id (str), session_token_id (str).
    Side effects:
        Updates active flag in role_session_tokens; prints confirmation.
        Exits 1 if role not found or token not found for this role.
    """
    db_path = project.db_path    # type: ignore[attr-defined]

    if not _role_exists(db_path, args.role_id):
        print(f"Error: Role '{args.role_id}' not found.", file=sys.stderr)
        sys.exit(1)

    activated = activate_session_token(db_path, args.role_id, args.session_token_id)
    if not activated:
        print(
            f"Error: Token '{args.session_token_id}' not found for role '{args.role_id}'.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Active token set for role {args.role_id}.")
    print(f"  token id : {args.session_token_id}")


def cmd_validate(project: object, args: argparse.Namespace) -> None:
    """
    Purpose:
        Validate the active session token for a role using its checkpoint flow.
        Workflow:
            1. Check whether an active token exists.
            2. If no token exists — generate one and exit.
            3. Replay the checkpoint flow.
            4. If the checkpoint returns 200 — token is valid; print status.
            5. If the checkpoint returns 401 or 403 — token is dead; generate
               a new one and store it.
        Exits 1 on hard errors (missing checkpoint flow, replay failure, or
        no JWT found during auto-generate).
    Input:
        project — active Project instance.
        args    — parsed args with: role_id (str).
    Side effects:
        May send outbound HTTP (checkpoint replay and/or login replay).
        May insert row in role_session_tokens.
        Exits 1 on hard errors.
    """
    db_path = project.db_path    # type: ignore[attr-defined]
    project_id = project.id      # type: ignore[attr-defined]

    if not _role_exists(db_path, args.role_id):
        print(f"Error: Role '{args.role_id}' not found.", file=sys.stderr)
        sys.exit(1)

    active_token = get_active_session_token(db_path, args.role_id)

    if active_token is None:
        print(f"No active token for role '{args.role_id}' — generating ...")
        _auto_generate(db_path, project_id, args.role_id)
        return

    # Active token exists — validate via checkpoint flow.
    role_auth_row = get_role_auth(db_path, args.role_id)
    if role_auth_row is None or not role_auth_row.get("checkpoint_flow_id"):
        print(
            f"Error: No checkpoint flow assigned to role '{args.role_id}'. "
            "Run 'talos auth mark-checkpoint <role_id> <flow_id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    checkpoint_flow_id: str = role_auth_row["checkpoint_flow_id"]
    print(f"Validating token via checkpoint flow {checkpoint_flow_id} ...")

    outcome = asyncio.run(
        replay_flow(
            flow_id=checkpoint_flow_id,
            db_path=db_path,
            project_id=project_id,
            source="auto_replay",
            replay_reason="session_validate",
        )
    )

    if not outcome.success:
        print(
            f"Error: Checkpoint replay failed — {outcome.failure_reason}.",
            file=sys.stderr,
        )
        sys.exit(1)

    if outcome.status_code not in _DEAD_SESSION_STATUSES:
        print(f"Token valid (checkpoint status: {outcome.status_code}).")
        print(f"  token id    : {active_token['id']}")
        print(f"  replay flow : {outcome.replayed_flow_id}")
        return

    # Checkpoint returned 401/403 — token is dead; generate a fresh one.
    print(
        f"Token expired (checkpoint status: {outcome.status_code}) — regenerating ..."
    )
    _auto_generate(db_path, project_id, args.role_id)


# ------------------------------------------------------------------ #
# Internal helpers                                                     #
# ------------------------------------------------------------------ #

def _role_exists(db_path: object, role_id: str) -> bool:
    """
    Purpose:
        Return True if a role with the given ID exists in the project database.
    Input:
        db_path — project db_path (Path).
        role_id — UUID string to look up.
    Output: bool
    Side effects: None (read-only).
    """
    import sqlite3 as _sqlite3
    with _sqlite3.connect(str(db_path)) as conn:
        row = conn.execute(
            "SELECT 1 FROM roles WHERE id = ?", (role_id,)
        ).fetchone()
    return row is not None


def _auto_generate(db_path: object, project_id: str, role_id: str) -> None:
    """
    Purpose:
        Replay the login flow for a role, extract a JWT, and store it as the
        active token.  Used internally by 'generate' and 'validate'.
    Input:
        db_path    — project db_path (Path).
        project_id — project UUID string.
        role_id    — UUID of the role to generate a token for.
    Side effects:
        Replays login flow (outbound HTTP); inserts row in role_session_tokens.
        Exits 1 on missing config, replay failure, or no JWT found.
    """
    from pathlib import Path as _Path
    _db_path = _Path(str(db_path))

    role_auth_row = get_role_auth(_db_path, role_id)
    if role_auth_row is None or not role_auth_row.get("login_flow_id"):
        print(
            f"Error: No login flow assigned to role '{role_id}'. "
            "Run 'talos auth mark-login <role_id> <flow_id>' first.",
            file=sys.stderr,
        )
        sys.exit(1)

    login_flow_id: str = role_auth_row["login_flow_id"]

    outcome = asyncio.run(
        replay_flow(
            flow_id=login_flow_id,
            db_path=_db_path,
            project_id=project_id,
            source="manual_replay",
            replay_reason="session_generate",
        )
    )

    if not outcome.success or outcome.replayed_flow_id is None:
        print(
            f"Error: Login flow replay failed — {outcome.failure_reason}.",
            file=sys.stderr,
        )
        sys.exit(1)

    replayed = replay_db.get_flow_for_replay(_db_path, outcome.replayed_flow_id)
    if replayed is None:
        print("Error: Replayed flow not found in DB after replay.", file=sys.stderr)
        sys.exit(1)

    response_body: bytes | None = replayed.get("response_body")
    body_text = ""
    if response_body:
        body_text = (
            response_body.decode("utf-8", errors="replace")
            if isinstance(response_body, bytes)
            else str(response_body)
        )

    match = _JWT_RE.search(body_text)
    if match is None:
        print(
            f"Error: No JWT found in response body of flow {outcome.replayed_flow_id}.\n"
            "The login response may not contain a JWT, or the token format differs.\n"
            f"  replay status : {outcome.status_code}",
            file=sys.stderr,
        )
        sys.exit(1)

    token = match.group(0)
    token_id = store_session_token(_db_path, role_id, token)

    masked = token[:12] + "..." + token[-6:]
    print(f"Session token generated.")
    print(f"  token id     : {token_id}")
    print(f"  token        : {masked}")
    print(f"  replay flow  : {outcome.replayed_flow_id}")
    print(f"  replay status: {outcome.status_code}")
