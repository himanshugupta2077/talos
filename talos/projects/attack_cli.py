"""
Module: talos.projects.attack_cli

Purpose:
    Command-line interface for the attack module root.
    Entry point for: talos attack unauth <subcommand>
                     talos attack bac <module>
                     talos attack auth-session <subcommand>

    Unauth commands (talos attack unauth):
      run     — Generate UNAUTH_ATTACK jobs for all testable endpoints using
                auth mutations × request mutations composition.
      config  — Show or set unauth auto-run (scheduler auth_test auto-enqueue).
      filter  — Manage unauth-decision-filter.yaml (init | show | validate).

    Auth-session commands (talos attack auth-session) — Phases 2–5 complete:
      bind | unbind | show-bindings | generate | candidates
      approve | reject | unapprove | suite list
      run | results list|show | status
      filter init | show | validate
      (WEAK_VALIDATION findings from scheduler settle / --right-now;
       full JWT alg-degradation matrix; --format json on list/show/actions)

    BAC modules (talos attack bac):
      session-swap   — Direct session swap (replace target-role token).
      method-fuzz    — HTTP Method Manipulation.
      content-type   — Content-Type Confusion.
      url-fuzz       — URL Manipulation.
      header-inject  — Header Manipulation.
      host-fuzz      — Host Header Changes.
      role-inject    — Role Parameter Injection.
      parser-confuse — Parser Confusion (duplicate params, HPP, TE/CL conflict).
      filter         — Manage BAC-decision-filter.yaml.

    Shared BAC flags (all modules):
      --role NAME|UUID     restrict to one attacker role
      --endpoint UUID      endpoint execution scope (xor --module)
      --module NAME|UUID   module execution scope (xor --endpoint)
      --auto-generate      auto-create missing attacker session tokens

    Endpoint inclusion/exclusion is owned by the Endpoint Policy system.
    BAC candidate generation only operates on get_testable_endpoints().
    Use 'talos endpoint exclude' to manage exclusions — no per-attack
    exclusion logic exists here.

Dependencies: argparse, sys, talos.projects.manager,
              talos.projects.unauth.cli, talos.projects.bac.cli,
              talos.auth_session.cli
Data flow:
    CLI args → active project lookup → unauth / bac / auth_session cli → stdout
Side effects:
    - unauth run: inserts into scheduler_jobs.
    - unauth config: reads/writes attack_config.unauth_auto_run.
    - bac modules: inserts into scheduler_jobs.
    - auth-session: bindings/candidates/results DB writes; run enqueues
      auth_session_attack jobs or --right-now HTTP.
"""

import argparse
import sys

from talos.projects.manager import ProjectManager


# ------------------------------------------------------------------ #
# Parser construction                                                  #
# ------------------------------------------------------------------ #

def _build_parser() -> argparse.ArgumentParser:
    """
    Purpose:
        Build the top-level 'talos attack' argument parser.
    Output:  Configured ArgumentParser.
    Side effects: Imports bac/unauth/auth_session cli for subparser registration.
    """
    parser = argparse.ArgumentParser(
        prog="talos attack",
        description=(
            "Attack modules: unauth (unauthenticated access), "
            "auth-session (token validation mutations), "
            "bac (broken access control)."
        ),
    )
    sub = parser.add_subparsers(dest="attack_type", metavar="<attack>")
    sub.required = True

    # ---- unauth ---- #
    from talos.projects.unauth.cli import build_unauth_parser
    build_unauth_parser(sub)

    # ---- auth-session ---- #
    from talos.auth_session.cli import build_auth_session_parser
    build_auth_session_parser(sub)

    # ---- bac ---- #
    from talos.projects.bac.cli import build_bac_parser
    build_bac_parser(sub)

    return parser


# ------------------------------------------------------------------ #
# Entry point                                                          #
# ------------------------------------------------------------------ #

def run_attack_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse argv and dispatch to the appropriate attack subcommand handler.
    Input:
        manager — ProjectManager instance (already constructed in __main__).
        argv    — Argument list after the 'attack' token has been consumed.
    Side effects:
        Delegates to subcommand handler; may sys.exit().
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.attack_type == "unauth":
        from talos.projects.unauth.cli import run_unauth_cli
        run_unauth_cli(manager, args)

    elif args.attack_type == "auth-session":
        from talos.auth_session.cli import run_auth_session_cli
        run_auth_session_cli(manager, args)

    elif args.attack_type == "bac":
        from talos.projects.bac.cli import run_bac_cli
        run_bac_cli(manager, args)
