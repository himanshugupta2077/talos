"""
Module: talos.intruder.cli

Purpose:
    CLI for Talos Intruder (Phase 1–5):

        talos intruder session create|list|show|configure|validate|run|
                               pause|resume|stop|status|delete|clone
        talos intruder template show|set-var|clear-var|from-params
        talos intruder payload set|list|clear
        talos intruder strategy set
        talos intruder timing set
        talos intruder storage set|show
        talos intruder match add|list|clear
        talos intruder grep add|list|clear
        talos intruder pool list|show|export|clear|delete
        talos intruder findings set|show|promote   # Phase 5
        talos intruder results list|show|export
        talos intruder generators list
        talos intruder suggest <session_id> [--apply]   # Phase 4

    Aliases: talos intruder run|status → session run|status

Dependencies: argparse, asyncio, json, sys
Data flow:
    argv → project gate → handlers → session/engine/db → stdout
Side effects:
    Session CRUD, scheduler enqueue, HTTP on --right-now / engine path,
    pool writes from grep extract; suggest --apply mutates config;
    optional findings promote (off by default).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Optional

from talos.cli_output import (
    EXIT_FAILURE,
    EXIT_OK,
    EXIT_PRECONDITION,
    EXIT_USAGE,
    add_force_argument,
    add_format_argument,
    cli_error,
    cli_json,
    cli_precondition_error,
    cli_success,
    cli_usage_error,
    confirm_or_exit,
    wants_json,
)
from talos.intruder import db as intruder_db
from talos.intruder.config_schema import (
    ValidationError,
    estimate_requires_confirm,
    merge_defaults,
    storage_requires_confirm,
    validate_config,
)
from talos.intruder.findings_bridge import (
    findings_config_from,
    promote_session_results,
)
from talos.intruder.grep import validate_grep_rule
from talos.intruder.models import (
    CLUSTER_BY_ENDPOINT,
    CLUSTER_BY_SESSION,
    DEFAULT_FINDINGS_MAX,
    ERR_CONFIRM_REQUIRED,
    ERR_ENDPOINT_ANNOTATED_DANGEROUS,
    ERR_ENDPOINT_ANNOTATED_LOGOUT,
    ERR_OUT_OF_SCOPE,
    ERR_SESSION_BUSY,
    FINDINGS_ON_INTERESTING,
    KNOWN_FINDINGS_CLUSTER_BY,
    KNOWN_GENERATORS,
    KNOWN_PROCESSORS,
    KNOWN_STORAGE_MODES,
    KNOWN_STRATEGIES,
    KNOWN_TIMING_MODES,
    PHASE4_GENERATORS,
    STATUS_DRAFT,
)
from talos.intruder.processors import is_known_processor
from talos.intruder.results import export_results_csv, export_results_jsonl
from talos.intruder.session import (
    clone_session,
    create_session_from_flow,
    pause_session,
    resume_session,
    run_session,
    stop_session,
)
from talos.intruder.suggest import apply_suggestions, build_suggestions
from talos.projects.manager import ProjectManager


def run_intruder_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Parse intruder subcommands and dispatch.
    """
    # Top-level aliases: run / status → session run / status
    if argv and argv[0] in ("run", "status") and (
        len(argv) == 1 or not argv[1].startswith("-") or argv[0] == "status"
    ):
        # Only alias when first token is bare run/status (not already under session)
        if argv[0] == "run":
            argv = ["session", "run"] + argv[1:]
        elif argv[0] == "status":
            argv = ["session", "status"] + argv[1:]

    parser = argparse.ArgumentParser(
        prog="talos intruder",
        description=(
            "Intruder: high-volume mutation attack engine (Phase 1–5). "
            "Template + payload sets + single/sniper/pitchfork/zip/cluster_bomb; "
            "grep extract pools; csv/json/uuid/example_values + dates/bruteforce/"
            "random/pattern generators; adaptive/token_bucket timing; AI suggest; "
            "param-intel template assist; storage modes; scheduler time-slices; "
            "optional findings promote (off by default). "
            "Distinct from 'talos send' (Repeater) and 'talos input-validation'."
        ),
    )
    sub = parser.add_subparsers(dest="intruder_cmd", metavar="<command>")
    sub.required = True

    # ---- session ----
    p_sess = sub.add_parser("session", help="Intruder session lifecycle.")
    sess_sub = p_sess.add_subparsers(dest="session_cmd", metavar="<action>")
    sess_sub.required = True

    p_create = sess_sub.add_parser("create", help="Create session from a baseline flow.")
    p_create.add_argument("--from", dest="from_flow", required=True, metavar="FLOW_ID")
    p_create.add_argument("--name", default="", help="Optional session name.")
    add_format_argument(p_create)

    p_list = sess_sub.add_parser("list", help="List sessions.")
    p_list.add_argument("--status", help="Filter by status.")
    p_list.add_argument("--limit", type=int, default=50)
    add_format_argument(p_list)

    p_show = sess_sub.add_parser("show", help="Show session detail + config.")
    p_show.add_argument("session_id")
    add_format_argument(p_show)

    p_cfg = sess_sub.add_parser("configure", help="Replace config_json from file.")
    p_cfg.add_argument("session_id")
    p_cfg.add_argument("--file", required=True, help="YAML/JSON config path.")
    add_force_argument(p_cfg)
    add_format_argument(p_cfg)

    p_val = sess_sub.add_parser("validate", help="Validate session config.")
    p_val.add_argument("session_id")
    add_force_argument(p_val)
    add_format_argument(p_val)

    p_run = sess_sub.add_parser("run", help="Validate and enqueue (or --right-now).")
    p_run.add_argument("session_id")
    p_run.add_argument(
        "--right-now",
        action="store_true",
        help="Run in this process (no scheduler job).",
    )
    add_force_argument(p_run)
    add_format_argument(p_run)

    p_pause = sess_sub.add_parser("pause", help="Cooperative pause.")
    p_pause.add_argument("session_id")
    add_format_argument(p_pause)

    p_resume = sess_sub.add_parser("resume", help="Resume paused session (new job).")
    p_resume.add_argument("session_id")
    add_format_argument(p_resume)

    p_stop = sess_sub.add_parser("stop", help="Cancel session.")
    p_stop.add_argument("session_id")
    add_format_argument(p_stop)

    p_status = sess_sub.add_parser("status", help="Poll session progress.")
    p_status.add_argument("session_id")
    add_format_argument(p_status)

    p_del = sess_sub.add_parser("delete", help="Delete session + results.")
    p_del.add_argument("session_id")
    add_force_argument(p_del)
    add_format_argument(p_del)

    p_clone = sess_sub.add_parser(
        "clone",
        help="Clone session config into a new draft (no results/checkpoint).",
    )
    p_clone.add_argument("session_id")
    p_clone.add_argument("--name", default="", help="Name for the cloned session.")
    add_format_argument(p_clone)

    # ---- template ----
    p_tmpl = sub.add_parser("template", help="Template variables.")
    tmpl_sub = p_tmpl.add_subparsers(dest="template_cmd", metavar="<action>")
    tmpl_sub.required = True

    p_tshow = tmpl_sub.add_parser("show", help="Show template + variables.")
    p_tshow.add_argument("session_id")
    add_format_argument(p_tshow)

    p_tvar = tmpl_sub.add_parser("set-var", help="Add/update a template variable.")
    p_tvar.add_argument("session_id")
    p_tvar.add_argument("--name", required=True)
    p_tvar.add_argument(
        "--location",
        required=True,
        choices=["path", "query", "body", "header", "cookie", "raw"],
    )
    p_tvar.add_argument("--path", dest="inject_path", help="Inject name (default: --name).")
    p_tvar.add_argument("--fixed-value", dest="fixed_value")
    p_tvar.add_argument("--original-value", dest="original_value")
    p_tvar.add_argument("--semantic-type", default="")
    add_format_argument(p_tvar)

    p_tclear = tmpl_sub.add_parser("clear-var", help="Remove a template variable.")
    p_tclear.add_argument("session_id")
    p_tclear.add_argument("--name", required=True)
    add_format_argument(p_tclear)

    p_tfrom = tmpl_sub.add_parser(
        "from-params",
        help="Phase 3: auto-add template variables from Parameter Intelligence.",
    )
    p_tfrom.add_argument("session_id")
    p_tfrom.add_argument(
        "--locations",
        default="",
        help="Comma-separated locations filter (path,query,body,header,cookie).",
    )
    p_tfrom.add_argument(
        "--set-payloads",
        action="store_true",
        help="Also wire example_values generators for each parameter.",
    )
    p_tfrom.add_argument(
        "--replace",
        action="store_true",
        help="Replace existing variables instead of merging by name.",
    )
    add_format_argument(p_tfrom)

    # ---- payload ----
    p_pay = sub.add_parser("payload", help="Payload sets.")
    pay_sub = p_pay.add_subparsers(dest="payload_cmd", metavar="<action>")
    pay_sub.required = True

    p_pset = pay_sub.add_parser("set", help="Configure a payload set for a variable.")
    p_pset.add_argument("session_id")
    p_pset.add_argument("--var", required=True, help="Payload set / variable name.")
    p_pset.add_argument(
        "--generator",
        required=True,
        choices=sorted(KNOWN_GENERATORS),
    )
    p_pset.add_argument(
        "--file",
        dest="wordlist",
        help="File path (wordlist / csv / json generators).",
    )
    p_pset.add_argument("--start", type=int, help="Numbers start.")
    p_pset.add_argument("--end", type=int, help="Numbers end.")
    p_pset.add_argument("--step", type=int, default=1, help="Numbers step.")
    p_pset.add_argument(
        "--value",
        action="append",
        dest="values",
        help="Static value (repeatable).",
    )
    p_pset.add_argument(
        "--count",
        type=int,
        help="Count for uuid / random generators.",
    )
    p_pset.add_argument(
        "--column",
        help="CSV column name or 0-based index (csv generator).",
    )
    p_pset.add_argument(
        "--delimiter",
        default=",",
        help="CSV delimiter (default ',').",
    )
    p_pset.add_argument(
        "--json-path",
        dest="json_path",
        help="JSON path (json generator), e.g. ids or users[].id",
    )
    p_pset.add_argument("--param-id", dest="param_id", help="parameters.id (example_values).")
    p_pset.add_argument(
        "--pool",
        dest="pool_name",
        help="Pool name (pool generator).",
    )
    # Phase 4 advanced generators
    p_pset.add_argument(
        "--start-date",
        dest="start_date",
        help="Dates generator start (ISO YYYY-MM-DD).",
    )
    p_pset.add_argument(
        "--end-date",
        dest="end_date",
        help="Dates generator end (ISO YYYY-MM-DD).",
    )
    p_pset.add_argument(
        "--step-days",
        type=int,
        dest="step_days",
        help="Dates generator step in days (default 1).",
    )
    p_pset.add_argument(
        "--date-format",
        dest="date_format",
        help="Dates generator strftime format (default %%Y-%%m-%%d).",
    )
    p_pset.add_argument(
        "--charset",
        help="Charset for bruteforce / random generators.",
    )
    p_pset.add_argument(
        "--min-len",
        type=int,
        dest="min_len",
        help="Min length (bruteforce / random).",
    )
    p_pset.add_argument(
        "--max-len",
        type=int,
        dest="max_len",
        help="Max length (bruteforce / random).",
    )
    p_pset.add_argument(
        "--length",
        type=int,
        help="Fixed length for random generator.",
    )
    p_pset.add_argument(
        "--pattern",
        help="Pattern template (pattern generator), e.g. user{n} or admin{n:04d}.",
    )
    p_pset.add_argument(
        "--seed",
        help="Seed for random / pattern {rand:N} (deterministic resume).",
    )
    p_pset.add_argument(
        "--processor",
        action="append",
        dest="processors",
        help=(
            "Processor chain (repeatable). Built-ins: "
            + ", ".join(sorted(KNOWN_PROCESSORS))
            + "; parameterized: prefix:<text>, suffix:<text>."
        ),
    )
    add_format_argument(p_pset)

    p_plist = pay_sub.add_parser("list", help="List payload sets.")
    p_plist.add_argument("session_id")
    add_format_argument(p_plist)

    p_pclear = pay_sub.add_parser("clear", help="Clear one or all payload sets.")
    p_pclear.add_argument("session_id")
    p_pclear.add_argument("--var", help="Clear only this set (default: all).")
    add_format_argument(p_pclear)

    # ---- strategy ----
    p_st = sub.add_parser("strategy", help="Attack strategy.")
    st_sub = p_st.add_subparsers(dest="strategy_cmd", metavar="<action>")
    st_sub.required = True
    p_stset = st_sub.add_parser("set", help="Set strategy type.")
    p_stset.add_argument("session_id")
    p_stset.add_argument(
        "--type",
        dest="stype",
        required=True,
        choices=sorted(KNOWN_STRATEGIES - {"cartesian"}),  # cartesian alias via cluster_bomb
        help="single|sniper|pitchfork|zip|cluster_bomb (cartesian accepted as alias of cluster_bomb in config).",
    )
    p_stset.add_argument("--primary", help="Primary variable for single strategy.")
    p_stset.add_argument(
        "--set",
        action="append",
        dest="sets",
        help="Ordered payload-set / variable names for multi-set strategies (repeatable).",
    )
    add_format_argument(p_stset)

    # ---- timing ----
    p_tm = sub.add_parser("timing", help="Timing / rate.")
    tm_sub = p_tm.add_subparsers(dest="timing_cmd", metavar="<action>")
    tm_sub.required = True
    p_tmset = tm_sub.add_parser("set", help="Set timing parameters.")
    p_tmset.add_argument("session_id")
    p_tmset.add_argument(
        "--mode",
        default="fixed",
        choices=sorted(KNOWN_TIMING_MODES),
        help="fixed | unlimited | token_bucket | adaptive (Phase 4).",
    )
    p_tmset.add_argument("--rps", type=float, help="Target RPS (fixed/token_bucket) or initial (adaptive).")
    p_tmset.add_argument("--concurrency", type=int, dest="max_concurrency")
    p_tmset.add_argument(
        "--concurrency-per-host",
        type=int,
        dest="max_concurrency_per_host",
        help="Phase 2: max in-flight attempts per host (optional host cap).",
    )
    p_tmset.add_argument("--jitter-ms", type=float, dest="jitter_ms")
    p_tmset.add_argument("--timeout-s", type=float, dest="timeout_s")
    p_tmset.add_argument(
        "--burst-size",
        type=int,
        dest="burst_size",
        help="Phase 4 token_bucket capacity (default 1).",
    )
    p_tmset.add_argument(
        "--min-rps",
        type=float,
        dest="min_rps",
        help="Phase 4 adaptive floor RPS.",
    )
    p_tmset.add_argument(
        "--max-rps",
        type=float,
        dest="max_rps",
        help="Phase 4 adaptive ceiling RPS.",
    )
    p_tmset.add_argument(
        "--slow-ms",
        type=float,
        dest="slow_ms",
        help="Phase 4 adaptive: duration_ms above this counts as pressure (default 2000).",
    )
    add_format_argument(p_tmset)

    # ---- storage ----
    p_stor = sub.add_parser("storage", help="Result / flow storage policy.")
    stor_sub = p_stor.add_subparsers(dest="storage_cmd", metavar="<action>")
    stor_sub.required = True
    p_storset = stor_sub.add_parser("set", help="Set storage mode.")
    p_storset.add_argument("session_id")
    p_storset.add_argument(
        "--mode",
        required=True,
        choices=sorted(KNOWN_STORAGE_MODES),
        help="metrics_only (default), sample_flows, or all_flows (confirm on run).",
    )
    p_storset.add_argument(
        "--sample-rate",
        type=float,
        dest="sample_rate",
        help="Bernoulli sample rate for sample_flows (0.0–1.0).",
    )
    p_storset.add_argument(
        "--store-interesting",
        dest="store_interesting",
        default=None,
        action=argparse.BooleanOptionalAction,
        help="Store flow bodies for match-tagged attempts (default true).",
    )
    p_storset.add_argument(
        "--max-body-bytes",
        type=int,
        dest="max_body_bytes",
        help="Cap stored response body size.",
    )
    add_format_argument(p_storset)
    p_storshow = stor_sub.add_parser("show", help="Show storage config.")
    p_storshow.add_argument("session_id")
    add_format_argument(p_storshow)

    # ---- match ----
    p_m = sub.add_parser("match", help="Match rules.")
    m_sub = p_m.add_subparsers(dest="match_cmd", metavar="<action>")
    m_sub.required = True

    p_madd = m_sub.add_parser("add", help="Add a match rule.")
    p_madd.add_argument("session_id")
    p_madd.add_argument("--tag", help="Rule tag label.")
    p_madd.add_argument("--status", type=int, help="Match status code.")
    p_madd.add_argument("--body-contains", dest="body_contains")
    p_madd.add_argument("--regex")
    p_madd.add_argument("--length-delta-gt", type=float, dest="length_delta_gt")
    p_madd.add_argument("--time-gt-ms", type=float, dest="time_gt_ms")
    add_format_argument(p_madd)

    p_mlist = m_sub.add_parser("list", help="List match rules.")
    p_mlist.add_argument("session_id")
    add_format_argument(p_mlist)

    p_mclear = m_sub.add_parser("clear", help="Clear all match rules.")
    p_mclear.add_argument("session_id")
    add_format_argument(p_mclear)

    # ---- grep (Phase 3) ----
    p_gr = sub.add_parser("grep", help="Extract / grep rules (Phase 3).")
    gr_sub = p_gr.add_subparsers(dest="grep_cmd", metavar="<action>")
    gr_sub.required = True

    p_gradd = gr_sub.add_parser("add", help="Add a grep extract rule.")
    p_gradd.add_argument("session_id")
    p_gradd.add_argument("--name", required=True, help="Extract name / pool name.")
    p_gradd.add_argument("--regex", required=True, help="Regex with capture group.")
    p_gradd.add_argument(
        "--group",
        type=int,
        default=1,
        help="Capture group (0=full match, default 1).",
    )
    p_gradd.add_argument(
        "--source",
        default="body",
        help="body | headers | header:<Name> (default body).",
    )
    p_gradd.add_argument("--ignore-case", action="store_true", dest="ignore_case")
    p_gradd.add_argument(
        "--max-matches",
        type=int,
        default=50,
        dest="max_matches",
        help="Max unique captures per response (default 50).",
    )
    p_gradd.add_argument(
        "--no-pool",
        action="store_true",
        help="Do not accumulate captures into project pool.",
    )
    p_gradd.add_argument(
        "--tag-interesting",
        action="store_true",
        dest="tag_interesting",
        help="Mark attempt interesting when this rule matches.",
    )
    add_format_argument(p_gradd)

    p_grlist = gr_sub.add_parser("list", help="List grep rules.")
    p_grlist.add_argument("session_id")
    add_format_argument(p_grlist)

    p_grclear = gr_sub.add_parser("clear", help="Clear all grep rules.")
    p_grclear.add_argument("session_id")
    add_format_argument(p_grclear)

    # ---- pool (Phase 3) ----
    p_pool = sub.add_parser("pool", help="Extracted value pools (Phase 3).")
    pool_sub = p_pool.add_subparsers(dest="pool_cmd", metavar="<action>")
    pool_sub.required = True

    p_pllist = pool_sub.add_parser("list", help="List project pools.")
    add_format_argument(p_pllist)

    p_plshow = pool_sub.add_parser("show", help="Show one pool (values).")
    p_plshow.add_argument("name")
    p_plshow.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Max values to display (default 100).",
    )
    add_format_argument(p_plshow)

    p_plexport = pool_sub.add_parser("export", help="Export pool values to a text file.")
    p_plexport.add_argument("name")
    p_plexport.add_argument("--out", required=True, help="Output file path.")
    add_format_argument(p_plexport)

    p_plclear = pool_sub.add_parser("clear", help="Empty pool values (keep row).")
    p_plclear.add_argument("name")
    add_format_argument(p_plclear)

    p_pldel = pool_sub.add_parser("delete", help="Delete a pool.")
    p_pldel.add_argument("name")
    add_force_argument(p_pldel)
    add_format_argument(p_pldel)

    # ---- results ----
    p_r = sub.add_parser("results", help="Session results.")
    r_sub = p_r.add_subparsers(dest="results_cmd", metavar="<action>")
    r_sub.required = True

    p_rlist = r_sub.add_parser("list", help="List attempt results.")
    p_rlist.add_argument("session_id")
    p_rlist.add_argument("--interesting", action="store_true")
    p_rlist.add_argument("--limit", type=int, default=100)
    p_rlist.add_argument("--offset", type=int, default=0)
    p_rlist.add_argument("--status-code", type=int, dest="status_code")
    add_format_argument(p_rlist)

    p_rshow = r_sub.add_parser("show", help="Show one attempt by index.")
    p_rshow.add_argument("session_id")
    p_rshow.add_argument("attempt_index", type=int)
    add_format_argument(p_rshow)

    p_rexp = r_sub.add_parser("export", help="Export results JSONL and/or CSV.")
    p_rexp.add_argument("session_id")
    p_rexp.add_argument("--out", required=True, help="Output directory or file stem.")
    p_rexp.add_argument("--jsonl", action="store_true", help="Write .jsonl")
    p_rexp.add_argument("--csv", action="store_true", help="Write .csv")
    p_rexp.add_argument("--interesting", action="store_true")
    add_format_argument(p_rexp)

    # ---- generators ----
    p_g = sub.add_parser("generators", help="List built-in generators/processors/strategies.")
    g_sub = p_g.add_subparsers(dest="generators_cmd", metavar="<action>")
    g_sub.required = True
    p_glist = g_sub.add_parser("list", help="List generators, processors, strategies.")
    add_format_argument(p_glist)

    # ---- findings (Phase 5) ----
    p_f = sub.add_parser(
        "findings",
        help="Optional findings promote (Phase 5; off by default).",
    )
    f_sub = p_f.add_subparsers(dest="findings_cmd", metavar="<action>")
    f_sub.required = True

    p_fset = f_sub.add_parser("set", help="Configure findings promote policy.")
    p_fset.add_argument("session_id")
    p_fset.add_argument(
        "--promote",
        choices=["on", "off", "true", "false", "1", "0"],
        help="Enable or disable promote (default off).",
    )
    p_fset.add_argument(
        "--max",
        type=int,
        dest="max_findings",
        help=f"Max findings per session (default {DEFAULT_FINDINGS_MAX}).",
    )
    p_fset.add_argument(
        "--on",
        dest="on_mode",
        choices=["interesting", "matched"],
        help="Which results to promote (default interesting).",
    )
    p_fset.add_argument(
        "--cluster-by",
        choices=sorted(KNOWN_FINDINGS_CLUSTER_BY),
        dest="cluster_by",
        help="Cluster key: session (default) or endpoint.",
    )
    p_fset.add_argument(
        "--only-success",
        choices=["on", "off", "true", "false", "1", "0"],
        dest="only_success",
        help="Only promote successful HTTP attempts (default on).",
    )
    add_force_argument(p_fset)
    add_format_argument(p_fset)

    p_fshow = f_sub.add_parser("show", help="Show findings promote config + counts.")
    p_fshow.add_argument("session_id")
    add_format_argument(p_fshow)

    p_fprom = f_sub.add_parser(
        "promote",
        help="Offline promote interesting results without finding_id (opt-in).",
    )
    p_fprom.add_argument("session_id")
    p_fprom.add_argument(
        "--enable",
        action="store_true",
        help="Treat promote as on for this call even if config has promote=false.",
    )
    add_force_argument(p_fprom)
    add_format_argument(p_fprom)

    # ---- suggest (Phase 4) ----
    p_sug = sub.add_parser(
        "suggest",
        help="AI/operator config suggestions for a session (heuristic, offline).",
    )
    p_sug.add_argument("session_id")
    p_sug.add_argument(
        "--apply",
        action="store_true",
        help="Write suggestions into session config (payloads only when unset).",
    )
    p_sug.add_argument(
        "--replace-payloads",
        action="store_true",
        dest="replace_payloads",
        help="With --apply, replace existing payload sets instead of filling gaps.",
    )
    p_sug.add_argument(
        "--no-match",
        action="store_true",
        dest="no_match",
        help="With --apply, do not append match rules.",
    )
    p_sug.add_argument(
        "--no-grep",
        action="store_true",
        dest="no_grep",
        help="With --apply, do not append grep rules.",
    )
    add_force_argument(p_sug)
    add_format_argument(p_sug)

    args = parser.parse_args(argv)
    project = _require_project(manager)

    cmd = args.intruder_cmd
    if cmd == "session":
        _dispatch_session(project, args)
    elif cmd == "template":
        _dispatch_template(project, args)
    elif cmd == "payload":
        _dispatch_payload(project, args)
    elif cmd == "strategy":
        _dispatch_strategy(project, args)
    elif cmd == "timing":
        _dispatch_timing(project, args)
    elif cmd == "storage":
        _dispatch_storage(project, args)
    elif cmd == "match":
        _dispatch_match(project, args)
    elif cmd == "grep":
        _dispatch_grep(project, args)
    elif cmd == "pool":
        _dispatch_pool(project, args)
    elif cmd == "results":
        _dispatch_results(project, args)
    elif cmd == "findings":
        _dispatch_findings(project, args)
    elif cmd == "generators":
        _dispatch_generators(args)
    elif cmd == "suggest":
        _dispatch_suggest(project, args)
    else:
        cli_usage_error(f"Unknown intruder command: {cmd}")


def _require_project(manager: ProjectManager):
    project = manager.active()
    if project is None:
        cli_precondition_error(
            "No active project. Use 'talos project open <id>' or '--project <id>'."
        )
    return project


def _get_session_or_exit(db_path: Path, session_id: str) -> dict[str, Any]:
    sess = intruder_db.get_session(db_path, session_id)
    if sess is None:
        cli_error(f"Session not found: {session_id}")
    return sess  # type: ignore[return-value]


def _save_config(db_path: Path, session_id: str, config: dict[str, Any], status: Optional[str] = None) -> dict:
    kwargs: dict[str, Any] = {"config": config}
    if status is not None:
        kwargs["status"] = status
    sess = intruder_db.update_session(db_path, session_id, **kwargs)
    assert sess is not None
    return sess


def _emit(data: Any, args: argparse.Namespace, human_fn) -> None:
    if wants_json(args):
        cli_json(data)
    else:
        human_fn(data)


# ------------------------------------------------------------------ #
# Session handlers                                                     #
# ------------------------------------------------------------------ #

def _dispatch_session(project, args: argparse.Namespace) -> None:
    db_path = project.db_path
    project_id = project.id
    action = args.session_cmd

    if action == "create":
        try:
            sess = create_session_from_flow(
                db_path, project_id, args.from_flow, name=args.name or ""
            )
        except LookupError as exc:
            cli_error(str(exc))
        def human(s):
            cli_success(
                "Created Intruder session.",
                {
                    "Session": s["id"],
                    "Name": s.get("name") or "—",
                    "Status": s["status"],
                    "Base flow": s.get("base_flow_id") or "—",
                },
            )
        _emit({
            "session_id": sess["id"],
            "name": sess.get("name"),
            "status": sess["status"],
            "base_flow_id": sess.get("base_flow_id"),
            "endpoint_id": sess.get("endpoint_id"),
        }, args, human)
        return

    if action == "list":
        rows = intruder_db.list_sessions(
            db_path, project_id, status=args.status, limit=args.limit
        )
        payload = [
            {
                "session_id": r["id"],
                "name": r["name"],
                "status": r["status"],
                "base_flow_id": r.get("base_flow_id"),
                "updated_at": r.get("updated_at"),
            }
            for r in rows
        ]
        def human(items):
            if not items:
                print("No Intruder sessions.")
                return
            print(f"{'SESSION':<38} {'STATUS':<12} {'NAME'}")
            for it in items:
                print(f"{it['session_id']:<38} {it['status']:<12} {it['name'] or '—'}")
        _emit(payload, args, human)
        return

    if action == "show":
        sess = _get_session_or_exit(db_path, args.session_id)
        payload = {
            "session_id": sess["id"],
            "name": sess["name"],
            "status": sess["status"],
            "base_flow_id": sess.get("base_flow_id"),
            "endpoint_id": sess.get("endpoint_id"),
            "job_id": sess.get("job_id"),
            "control_flag": sess.get("control_flag"),
            "progress": sess.get("progress"),
            "config": sess.get("config"),
            "created_at": sess.get("created_at"),
            "updated_at": sess.get("updated_at"),
            "started_at": sess.get("started_at"),
            "finished_at": sess.get("finished_at"),
            "failure_reason": sess.get("failure_reason"),
        }
        def human(s):
            print(f"Session: {s['session_id']}")
            print(f"  Name:     {s['name'] or '—'}")
            print(f"  Status:   {s['status']}")
            print(f"  Base:     {s.get('base_flow_id') or '—'}")
            print(f"  Job:      {s.get('job_id') or '—'}")
            print(f"  Control:  {s.get('control_flag') or '—'}")
        _emit(payload, args, human)
        return

    if action == "configure":
        sess = _get_session_or_exit(db_path, args.session_id)
        path = Path(args.file)
        if not path.is_file():
            cli_error(f"Config file not found: {path}")
        raw = path.read_text(encoding="utf-8")
        try:
            if path.suffix.lower() in (".yaml", ".yml"):
                try:
                    import yaml  # type: ignore
                    data = yaml.safe_load(raw)
                except ImportError:
                    cli_error("PyYAML not installed; use JSON config or install pyyaml.")
            else:
                data = json.loads(raw)
        except Exception as exc:  # noqa: BLE001
            cli_error(f"Failed to parse config: {exc}")
        if not isinstance(data, dict):
            cli_error("Config root must be an object.")
        # Preserve session identity fields
        merged = merge_defaults(data)
        old = sess.get("config") or {}
        merged["session"] = {
            **(old.get("session") or {}),
            **(merged.get("session") or {}),
            "base_flow_id": sess.get("base_flow_id"),
            "endpoint_id": sess.get("endpoint_id"),
            "project_id": project_id,
        }
        try:
            cfg, estimate = validate_config(
                merged,
                open_generators=True,
                force=args.force,
                db_path=db_path,
                project_id=project_id,
            )
        except ValidationError as exc:
            _validation_error(exc, args)
        _save_config(db_path, sess["id"], cfg, status="configured")
        payload = {"session_id": sess["id"], "status": "configured", "estimate_attempts": estimate}
        def human(p):
            cli_success("Session configured.", {"Session": p["session_id"], "Estimate": p["estimate_attempts"]})
        _emit(payload, args, human)
        return

    if action == "validate":
        sess = _get_session_or_exit(db_path, args.session_id)
        try:
            cfg, estimate = validate_config(
                sess.get("config") or {},
                open_generators=True,
                force=args.force,
                db_path=db_path,
                project_id=project_id,
            )
        except ValidationError as exc:
            _validation_error(exc, args)
        _save_config(db_path, sess["id"], cfg, status="configured")
        payload = {
            "session_id": sess["id"],
            "valid": True,
            "estimate_attempts": estimate,
            "status": "configured",
        }
        def human(p):
            cli_success(
                "Session valid.",
                {"Session": p["session_id"], "Estimate": p["estimate_attempts"]},
            )
        _emit(payload, args, human)
        return

    if action == "run":
        sess = _get_session_or_exit(db_path, args.session_id)
        try:
            cfg, estimate = validate_config(
                sess.get("config") or {},
                open_generators=True,
                force=args.force,
                db_path=db_path,
                project_id=project_id,
            )
        except ValidationError as exc:
            _validation_error(exc, args)

        # Safety: logout / dangerous / scope
        _check_run_safety(project, sess, cfg, force=args.force)

        if estimate_requires_confirm(estimate) and not args.force:
            confirm_or_exit(
                f"Estimated {estimate} attempts exceeds 1000. Continue?",
                force=False,
            )
        if storage_requires_confirm(cfg) and not args.force:
            confirm_or_exit(
                "Storage mode all_flows will write a full flow row per attempt. Continue?",
                force=False,
            )

        try:
            ack = run_session(
                db_path,
                project_id,
                sess["id"],
                force=args.force,
                right_now=args.right_now,
            )
        except RuntimeError as exc:
            if str(exc) == ERR_SESSION_BUSY or "session_busy" in str(exc):
                cli_error("Session is already running or queued.", exit_code=EXIT_FAILURE)
            cli_error(str(exc))
        except LookupError as exc:
            cli_error(str(exc))

        if args.right_now:
            from talos.intruder.engine import run_session_segment

            try:
                outcome = asyncio.run(
                    run_session_segment(
                        sess["id"],
                        db_path,
                        project_id,
                        job_id=None,
                        force=args.force,
                    )
                )
            except KeyboardInterrupt:
                # Pause on Ctrl-C
                from talos.intruder.session import pause_session as _pause
                intruder_db.set_control_flag(db_path, sess["id"], "pause")
                # Best-effort: engine may already have exited; mark paused
                intruder_db.update_session(
                    db_path, sess["id"], status="paused", control_flag=None, job_id=None
                )
                payload = {
                    "session_id": sess["id"],
                    "status": "paused",
                    "execution_mode": "foreground",
                    "interrupted": True,
                }
                if wants_json(args):
                    cli_json(payload)
                else:
                    cli_success("Interrupted — session paused.", {"Session": sess["id"]})
                sys.exit(EXIT_OK)

            final = intruder_db.get_session(db_path, sess["id"])
            payload = {
                "session_id": sess["id"],
                "status": (final or {}).get("status"),
                "execution_mode": "foreground",
                "reason": outcome.reason,
                "attempts_this_segment": outcome.attempts_this_segment,
                "progress": (final or {}).get("progress"),
            }
            def human(p):
                cli_success(
                    f"Intruder finished ({p['status']}).",
                    {
                        "Session": p["session_id"],
                        "Reason": p["reason"],
                        "Attempts": p["attempts_this_segment"],
                    },
                )
            _emit(payload, args, human)
            if (final or {}).get("status") == "failed":
                sys.exit(EXIT_FAILURE)
            sys.exit(EXIT_OK)

        def human(p):
            cli_success(
                "Intruder session queued.",
                {
                    "Session": p["session_id"],
                    "Job": p.get("job_id") or "—",
                    "Status": p["status"],
                    "Estimate": p.get("estimate_attempts"),
                },
            )
        _emit(ack, args, human)
        return

    if action == "pause":
        try:
            out = pause_session(db_path, args.session_id)
        except LookupError:
            cli_error("Session not found.")
        except RuntimeError as exc:
            cli_precondition_error(str(exc))
        def human(p):
            cli_success("Pause requested." if p.get("control_flag") else "Session paused.", p)
        _emit(out, args, human)
        return

    if action == "resume":
        try:
            out = resume_session(db_path, project_id, args.session_id)
        except LookupError:
            cli_error("Session not found.")
        except RuntimeError as exc:
            cli_precondition_error(str(exc))
        def human(p):
            cli_success("Session resume enqueued.", {
                "Session": p["session_id"],
                "Job": p.get("job_id"),
            })
        _emit(out, args, human)
        return

    if action == "stop":
        try:
            out = stop_session(db_path, args.session_id)
        except LookupError:
            cli_error("Session not found.")
        except RuntimeError as exc:
            cli_precondition_error(str(exc))
        def human(p):
            msg = "Already cancelled." if p.get("noop") else "Stop requested."
            cli_success(msg, {"Session": p["session_id"], "Status": p["status"]})
        _emit(out, args, human)
        return

    if action == "status":
        sess = _get_session_or_exit(db_path, args.session_id)
        progress = dict(sess.get("progress") or {})
        timing = (sess.get("config") or {}).get("timing") or {}
        results_count = intruder_db.count_results(db_path, sess["id"])
        payload = {
            "session_id": sess["id"],
            "name": sess.get("name"),
            "status": sess["status"],
            "job_id": sess.get("job_id"),
            "execution_mode": progress.get("execution_mode"),
            "base_flow_id": sess.get("base_flow_id"),
            "progress": {
                "sent": progress.get("sent", 0),
                "matched": progress.get("matched", 0),
                "errors": progress.get("errors", 0),
                "attempt_index": progress.get("attempt_index"),
                "estimate_total": progress.get("estimate_total"),
                "percent": progress.get("percent"),
                "rps_ema": progress.get("rps_ema"),
                "active_duration_s": progress.get("active_duration_s"),
                "stopped_reason": progress.get("stopped_reason"),
                "updated_at": progress.get("updated_at"),
                "segment": progress.get("segment"),
                "continuation_priority": progress.get("continuation_priority"),
                "results_count": results_count,
            },
            "control_flag": sess.get("control_flag"),
            "timing": {
                "mode": timing.get("mode"),
                "rps": timing.get("rps"),
                "max_concurrency": timing.get("max_concurrency"),
            },
            "started_at": sess.get("started_at"),
            "finished_at": sess.get("finished_at"),
            "failure_reason": sess.get("failure_reason"),
        }
        def human(p):
            pr = p["progress"]
            print(f"Session: {p['session_id']}")
            print(f"  Status:     {p['status']}")
            print(f"  Job:        {p.get('job_id') or '—'}")
            print(f"  Sent:       {pr.get('sent')} / {pr.get('estimate_total') or '?'}")
            print(f"  Matched:    {pr.get('matched')}")
            print(f"  Errors:     {pr.get('errors')}")
            print(f"  Segment:    {pr.get('segment')}")
            print(f"  Active s:   {pr.get('active_duration_s')}")
            print(f"  Stopped:    {pr.get('stopped_reason') or '—'}")
        _emit(payload, args, human)
        return

    if action == "delete":
        sess = _get_session_or_exit(db_path, args.session_id)
        count = intruder_db.count_results(db_path, sess["id"])
        if count and not args.force:
            confirm_or_exit(
                f"Delete session and {count} result(s)?",
                force=False,
            )
        if sess["status"] in ("running", "queued") and not args.force:
            cli_precondition_error(
                "Session is active; stop it first or pass --force."
            )
        ok = intruder_db.delete_session(db_path, sess["id"])
        payload = {"session_id": sess["id"], "deleted": ok}
        def human(p):
            cli_success("Session deleted." if p["deleted"] else "Nothing deleted.", p)
        _emit(payload, args, human)
        return

    if action == "clone":
        try:
            cloned = clone_session(
                db_path, project_id, args.session_id, name=args.name or ""
            )
        except LookupError:
            cli_error("Session not found.")
        payload = {
            "session_id": cloned["id"],
            "name": cloned.get("name"),
            "status": cloned["status"],
            "cloned_from": args.session_id,
            "base_flow_id": cloned.get("base_flow_id"),
        }
        def human(p):
            cli_success(
                "Session cloned.",
                {
                    "Session": p["session_id"],
                    "Name": p.get("name") or "—",
                    "From": p["cloned_from"],
                    "Status": p["status"],
                },
            )
        _emit(payload, args, human)
        return

    cli_usage_error(f"Unknown session action: {action}")


def _validation_error(exc: ValidationError, args: argparse.Namespace) -> None:
    if wants_json(args):
        print(
            json.dumps({"error": exc.message, "code": exc.code}, indent=2),
            file=sys.stderr,
        )
        sys.exit(EXIT_PRECONDITION)
    cli_precondition_error(f"[{exc.code}] {exc.message}")


def _check_run_safety(project, sess: dict, cfg: dict, *, force: bool) -> None:
    from talos.projects.annotations import get_annotations
    from talos.proxy.scope import is_url_in_scope
    from talos.projects.outscope import list_prefixes as list_outscope

    endpoint_id = sess.get("endpoint_id")
    db_path = project.db_path
    safety = cfg.get("safety") or {}

    if endpoint_id:
        ann = get_annotations(db_path, endpoint_id)
        if "logout" in ann and safety.get("respect_logout", True):
            cli_precondition_error(
                f"[{ERR_ENDPOINT_ANNOTATED_LOGOUT}] Endpoint is marked logout."
            )
        if "dangerous" in ann and safety.get("respect_dangerous", True) and not force:
            confirm_or_exit(
                "Endpoint is marked dangerous. Continue Intruder run?",
                force=False,
            )

    if safety.get("require_in_scope", True) and not force:
        url = (cfg.get("template") or {}).get("url") or ""
        try:
            scope = list(getattr(project, "scope", None) or [])
        except Exception:  # noqa: BLE001
            scope = []
        # Empty project scope → skip (nothing is in-scope; avoid hard-blocking
        # exploratory projects that never set scope).
        if scope:
            try:
                out_rows = list_outscope(db_path)
                out = [
                    (r.get("domain") or r.get("prefix") or r)
                    if isinstance(r, dict)
                    else r
                    for r in out_rows
                ]
            except Exception:  # noqa: BLE001
                out = []
            if not is_url_in_scope(url, scope, out):
                cli_precondition_error(
                    f"[{ERR_OUT_OF_SCOPE}] Baseline URL is out of project scope."
                )


# ------------------------------------------------------------------ #
# Template / payload / strategy / timing / match                       #
# ------------------------------------------------------------------ #

def _dispatch_template(project, args: argparse.Namespace) -> None:
    db_path = project.db_path
    sess = _get_session_or_exit(db_path, args.session_id)
    cfg = merge_defaults(sess.get("config") or {})
    action = args.template_cmd

    if action == "show":
        tmpl = cfg.get("template") or {}
        payload = {
            "session_id": sess["id"],
            "method": tmpl.get("method"),
            "url": tmpl.get("url"),
            "normalized_path": tmpl.get("normalized_path"),
            "variables": tmpl.get("variables") or [],
        }
        def human(p):
            print(f"{p['method']} {p['url']}")
            print(f"normalized_path: {p.get('normalized_path') or '—'}")
            for v in p["variables"]:
                print(f"  - {v.get('name')} loc={v.get('location')} fixed={v.get('fixed_value')!r}")
        _emit(payload, args, human)
        return

    if action == "set-var":
        variables = list((cfg.get("template") or {}).get("variables") or [])
        found = False
        new_var = {
            "name": args.name,
            "location": args.location,
            "path": args.inject_path,
            "fixed_value": args.fixed_value,
            "original_value": args.original_value,
            "semantic_type": args.semantic_type or "",
        }
        for i, v in enumerate(variables):
            if v.get("name") == args.name:
                variables[i] = {**v, **{k: val for k, val in new_var.items() if val is not None}}
                found = True
                break
        if not found:
            variables.append(new_var)
        cfg.setdefault("template", {})["variables"] = variables
        _save_config(db_path, sess["id"], cfg, status=STATUS_DRAFT if sess["status"] == "configured" else sess["status"])
        payload = {"session_id": sess["id"], "variable": new_var}
        def human(p):
            cli_success("Variable set.", {"Name": args.name, "Location": args.location})
        _emit(payload, args, human)
        return

    if action == "clear-var":
        variables = [
            v for v in ((cfg.get("template") or {}).get("variables") or [])
            if v.get("name") != args.name
        ]
        cfg.setdefault("template", {})["variables"] = variables
        _save_config(db_path, sess["id"], cfg)
        payload = {"session_id": sess["id"], "cleared": args.name}
        def human(p):
            cli_success("Variable cleared.", {"Name": args.name})
        _emit(payload, args, human)
        return

    if action == "from-params":
        endpoint_id = sess.get("endpoint_id") or (cfg.get("session") or {}).get("endpoint_id")
        if not endpoint_id:
            cli_precondition_error(
                "Session has no endpoint_id; Parameter Intelligence requires a linked endpoint."
            )
        loc_filter: list[str] | None = None
        if args.locations:
            loc_filter = [x.strip() for x in str(args.locations).split(",") if x.strip()]
        params = intruder_db.list_endpoint_parameters(
            db_path, str(endpoint_id), locations=loc_filter
        )
        if not params:
            cli_precondition_error(
                f"No parameters found for endpoint {endpoint_id}."
            )
        existing = list((cfg.get("template") or {}).get("variables") or [])
        by_name = {} if args.replace else {v.get("name"): v for v in existing if v.get("name")}
        added: list[dict[str, Any]] = []
        for p in params:
            name = str(p["name"])
            examples = p.get("example_values") or []
            original = str(examples[0]) if examples else None
            new_var = {
                "name": name,
                "location": p["location"],
                "path": name,
                "original_value": original,
                "semantic_type": p.get("semantic_type") or "",
                "param_id": p["id"],
                "fixed_value": None,
            }
            by_name[name] = new_var
            added.append(new_var)
            if args.set_payloads and examples:
                cfg.setdefault("payload_sets", {})[name] = {
                    "generator": "example_values",
                    "options": {"param_id": p["id"]},
                    "processors": [],
                }
        cfg.setdefault("template", {})["variables"] = list(by_name.values())
        _save_config(
            db_path,
            sess["id"],
            cfg,
            status=STATUS_DRAFT if sess["status"] == "configured" else sess["status"],
        )
        payload = {
            "session_id": sess["id"],
            "endpoint_id": endpoint_id,
            "added": len(added),
            "variables": added,
            "payloads_set": bool(args.set_payloads),
        }
        def human(p):
            cli_success(
                f"Template updated from {p['added']} parameter(s).",
                {"Endpoint": p["endpoint_id"], "Payloads": p["payloads_set"]},
            )
        _emit(payload, args, human)
        return

    cli_usage_error(f"Unknown template action: {action}")


def _dispatch_payload(project, args: argparse.Namespace) -> None:
    db_path = project.db_path
    sess = _get_session_or_exit(db_path, args.session_id)
    cfg = merge_defaults(sess.get("config") or {})
    action = args.payload_cmd

    if action == "set":
        options: dict[str, Any] = {}
        gen = args.generator
        if gen == "wordlist":
            if not args.wordlist:
                cli_usage_error("--file is required for wordlist generator.")
            options["path"] = args.wordlist
        elif gen == "numbers":
            if args.start is None or args.end is None:
                cli_usage_error("--start and --end are required for numbers generator.")
            options["start"] = args.start
            options["end"] = args.end
            options["step"] = args.step
        elif gen == "static":
            if not args.values:
                cli_usage_error("--value is required for static generator (repeatable).")
            options["values"] = list(args.values)
        elif gen == "uuid":
            if args.count is not None:
                options["count"] = args.count
        elif gen == "csv":
            if not args.wordlist:
                cli_usage_error("--file is required for csv generator.")
            options["path"] = args.wordlist
            if args.column is not None:
                # numeric index vs header name
                col = args.column
                options["column"] = int(col) if str(col).isdigit() else col
            if args.delimiter:
                options["delimiter"] = args.delimiter
        elif gen == "json":
            if not args.wordlist:
                cli_usage_error("--file is required for json generator.")
            options["path"] = args.wordlist
            if args.json_path is not None:
                options["json_path"] = args.json_path
        elif gen == "example_values":
            if not args.param_id:
                cli_usage_error("--param-id is required for example_values generator.")
            options["param_id"] = args.param_id
        elif gen == "pool":
            if not args.pool_name:
                cli_usage_error("--pool is required for pool generator.")
            options["name"] = args.pool_name
        elif gen == "dates":
            if not args.start_date or not args.end_date:
                cli_usage_error("--start-date and --end-date are required for dates generator.")
            options["start"] = args.start_date
            options["end"] = args.end_date
            if args.step_days is not None:
                options["step_days"] = args.step_days
            if args.date_format:
                options["format"] = args.date_format
        elif gen == "bruteforce":
            if args.charset:
                options["charset"] = args.charset
            if args.min_len is not None:
                options["min_len"] = args.min_len
            if args.max_len is not None:
                options["max_len"] = args.max_len
        elif gen == "random":
            if args.count is not None:
                options["count"] = args.count
            if args.length is not None:
                options["length"] = args.length
            if args.min_len is not None:
                options["min_len"] = args.min_len
            if args.max_len is not None:
                options["max_len"] = args.max_len
            if args.charset:
                options["charset"] = args.charset
            if args.seed is not None:
                # Prefer int seed when numeric
                try:
                    options["seed"] = int(args.seed)
                except ValueError:
                    options["seed"] = args.seed
        elif gen == "pattern":
            if not args.pattern:
                cli_usage_error("--pattern is required for pattern generator.")
            options["pattern"] = args.pattern
            if args.start is not None:
                options["start"] = args.start
            if args.end is not None:
                options["end"] = args.end
            if args.step is not None and args.step != 1:
                options["step"] = args.step
            if args.seed is not None:
                try:
                    options["seed"] = int(args.seed)
                except ValueError:
                    options["seed"] = args.seed

        processors = list(args.processors or [])
        for pname in processors:
            if not is_known_processor(pname):
                cli_usage_error(
                    f"Unknown processor: {pname}. "
                    f"Built-ins: {', '.join(sorted(KNOWN_PROCESSORS))}; "
                    "or prefix:<text> / suffix:<text>."
                )

        pset = {
            "generator": gen,
            "options": options,
            "processors": processors,
        }
        cfg.setdefault("payload_sets", {})[args.var] = pset
        _save_config(db_path, sess["id"], cfg)
        payload = {"session_id": sess["id"], "var": args.var, "payload_set": pset}
        def human(p):
            cli_success("Payload set configured.", {"Var": args.var, "Generator": gen})
        _emit(payload, args, human)
        return

    if action == "list":
        sets = (cfg.get("payload_sets") or {})
        payload = {"session_id": sess["id"], "payload_sets": sets}
        def human(p):
            if not p["payload_sets"]:
                print("No payload sets.")
                return
            for name, ps in p["payload_sets"].items():
                print(f"  {name}: generator={ps.get('generator')} processors={ps.get('processors')}")
        _emit(payload, args, human)
        return

    if action == "clear":
        if args.var:
            (cfg.get("payload_sets") or {}).pop(args.var, None)
        else:
            cfg["payload_sets"] = {}
        _save_config(db_path, sess["id"], cfg)
        payload = {"session_id": sess["id"], "cleared": args.var or "all"}
        def human(p):
            cli_success("Payload set(s) cleared.", p)
        _emit(payload, args, human)
        return


def _dispatch_strategy(project, args: argparse.Namespace) -> None:
    db_path = project.db_path
    sess = _get_session_or_exit(db_path, args.session_id)
    cfg = merge_defaults(sess.get("config") or {})
    opts = dict((cfg.get("strategy") or {}).get("options") or {})
    if args.primary:
        opts["primary"] = args.primary
    if getattr(args, "sets", None):
        opts["sets"] = list(args.sets)
    cfg["strategy"] = {"type": args.stype, "options": opts}
    _save_config(db_path, sess["id"], cfg)
    payload = {"session_id": sess["id"], "strategy": cfg["strategy"]}
    def human(p):
        cli_success("Strategy set.", {"Type": args.stype})
    _emit(payload, args, human)


def _dispatch_timing(project, args: argparse.Namespace) -> None:
    db_path = project.db_path
    sess = _get_session_or_exit(db_path, args.session_id)
    cfg = merge_defaults(sess.get("config") or {})
    timing = dict(cfg.get("timing") or {})
    timing["mode"] = args.mode
    if args.rps is not None:
        timing["rps"] = args.rps
    if args.max_concurrency is not None:
        timing["max_concurrency"] = args.max_concurrency
    if getattr(args, "max_concurrency_per_host", None) is not None:
        timing["max_concurrency_per_host"] = args.max_concurrency_per_host
    if args.jitter_ms is not None:
        timing["jitter_ms"] = args.jitter_ms
    if args.timeout_s is not None:
        timing["timeout_s"] = args.timeout_s
    if getattr(args, "burst_size", None) is not None:
        timing["burst_size"] = args.burst_size
    if getattr(args, "min_rps", None) is not None:
        timing["min_rps"] = args.min_rps
    if getattr(args, "max_rps", None) is not None:
        timing["max_rps"] = args.max_rps
    if getattr(args, "slow_ms", None) is not None:
        timing["slow_ms"] = args.slow_ms
    cfg["timing"] = timing
    _save_config(db_path, sess["id"], cfg)
    payload = {"session_id": sess["id"], "timing": timing}
    def human(p):
        cli_success("Timing updated.", timing)
    _emit(payload, args, human)


def _dispatch_storage(project, args: argparse.Namespace) -> None:
    db_path = project.db_path
    sess = _get_session_or_exit(db_path, args.session_id)
    cfg = merge_defaults(sess.get("config") or {})
    action = args.storage_cmd
    storage = dict(cfg.get("storage") or {})

    if action == "set":
        storage["mode"] = args.mode
        if args.sample_rate is not None:
            if args.sample_rate < 0.0 or args.sample_rate > 1.0:
                cli_usage_error("--sample-rate must be between 0.0 and 1.0.")
            storage["sample_rate"] = args.sample_rate
        if args.store_interesting is not None:
            storage["store_interesting_bodies"] = bool(args.store_interesting)
        if args.max_body_bytes is not None:
            storage["max_body_bytes"] = int(args.max_body_bytes)
        cfg["storage"] = storage
        _save_config(db_path, sess["id"], cfg)
        payload = {"session_id": sess["id"], "storage": storage}
        def human(p):
            cli_success("Storage updated.", storage)
        _emit(payload, args, human)
        return

    if action == "show":
        payload = {"session_id": sess["id"], "storage": storage}
        def human(p):
            print(json.dumps(p["storage"], indent=2))
        _emit(payload, args, human)
        return

    cli_usage_error(f"Unknown storage action: {action}")


def _dispatch_match(project, args: argparse.Namespace) -> None:
    db_path = project.db_path
    sess = _get_session_or_exit(db_path, args.session_id)
    cfg = merge_defaults(sess.get("config") or {})
    action = args.match_cmd

    if action == "add":
        rule: dict[str, Any] = {}
        if args.tag:
            rule["tag"] = args.tag
        if args.status is not None:
            rule["status"] = args.status
        if args.body_contains is not None:
            rule["body_contains"] = args.body_contains
        if args.regex is not None:
            rule["regex"] = args.regex
        if args.length_delta_gt is not None:
            rule["length_delta_gt"] = args.length_delta_gt
        if args.time_gt_ms is not None:
            rule["time_gt_ms"] = args.time_gt_ms
        if len(rule) <= (1 if "tag" in rule else 0):
            cli_usage_error("At least one match criterion is required.")
        rules = list(cfg.get("match") or [])
        rules.append(rule)
        cfg["match"] = rules
        _save_config(db_path, sess["id"], cfg)
        payload = {"session_id": sess["id"], "rule": rule, "count": len(rules)}
        def human(p):
            cli_success("Match rule added.", {"Rules": p["count"]})
        _emit(payload, args, human)
        return

    if action == "list":
        rules = cfg.get("match") or []
        payload = {"session_id": sess["id"], "match": rules}
        def human(p):
            if not p["match"]:
                print("No match rules.")
                return
            for i, r in enumerate(p["match"]):
                print(f"  [{i}] {r}")
        _emit(payload, args, human)
        return

    if action == "clear":
        cfg["match"] = []
        _save_config(db_path, sess["id"], cfg)
        payload = {"session_id": sess["id"], "match": []}
        def human(p):
            cli_success("Match rules cleared.", {})
        _emit(payload, args, human)
        return


def _dispatch_grep(project, args: argparse.Namespace) -> None:
    db_path = project.db_path
    sess = _get_session_or_exit(db_path, args.session_id)
    cfg = merge_defaults(sess.get("config") or {})
    action = args.grep_cmd

    if action == "add":
        rule: dict[str, Any] = {
            "name": args.name,
            "regex": args.regex,
            "group": int(args.group),
            "source": args.source or "body",
            "max_matches": int(args.max_matches),
            "to_pool": not bool(args.no_pool),
            "tag_interesting": bool(args.tag_interesting),
        }
        if args.ignore_case:
            rule["ignore_case"] = True
        try:
            validate_grep_rule(rule)
        except ValueError as exc:
            cli_usage_error(str(exc))
        rules = list(cfg.get("grep") or [])
        rules.append(rule)
        cfg["grep"] = rules
        _save_config(db_path, sess["id"], cfg)
        payload = {"session_id": sess["id"], "rule": rule, "count": len(rules)}
        def human(p):
            cli_success("Grep rule added.", {"Name": args.name, "Rules": p["count"]})
        _emit(payload, args, human)
        return

    if action == "list":
        rules = cfg.get("grep") or []
        payload = {"session_id": sess["id"], "grep": rules}
        def human(p):
            if not p["grep"]:
                print("No grep rules.")
                return
            for i, r in enumerate(p["grep"]):
                print(f"  [{i}] {r.get('name')}: {r.get('regex')!r} source={r.get('source')}")
        _emit(payload, args, human)
        return

    if action == "clear":
        cfg["grep"] = []
        _save_config(db_path, sess["id"], cfg)
        payload = {"session_id": sess["id"], "grep": []}
        def human(p):
            cli_success("Grep rules cleared.", {})
        _emit(payload, args, human)
        return

    cli_usage_error(f"Unknown grep action: {action}")


def _dispatch_pool(project, args: argparse.Namespace) -> None:
    db_path = project.db_path
    project_id = project.id
    action = args.pool_cmd

    if action == "list":
        pools = intruder_db.list_pools(db_path, project_id)
        payload = [
            {
                "name": p["name"],
                "count": p["count"],
                "session_id": p.get("session_id"),
                "source_rule": p.get("source_rule"),
                "updated_at": p.get("updated_at"),
            }
            for p in pools
        ]
        def human(items):
            if not items:
                print("No pools.")
                return
            print(f"{'NAME':<24} {'COUNT':>6}  UPDATED")
            for it in items:
                print(f"{it['name']:<24} {it['count']:>6}  {it.get('updated_at') or '—'}")
        _emit(payload, args, human)
        return

    if action == "show":
        pool = intruder_db.get_pool(db_path, project_id, args.name)
        if pool is None:
            cli_error(f"Pool not found: {args.name}")
        values = pool["values"]
        limit = max(0, int(args.limit))
        shown = values[:limit] if limit else values
        payload = {
            "name": pool["name"],
            "count": pool["count"],
            "session_id": pool.get("session_id"),
            "source_rule": pool.get("source_rule"),
            "values": shown,
            "truncated": len(values) > len(shown),
        }
        def human(p):
            print(f"Pool {p['name']} ({p['count']} values)")
            for v in p["values"]:
                print(f"  {v}")
            if p["truncated"]:
                print(f"  … truncated to {len(p['values'])}")
        _emit(payload, args, human)
        return

    if action == "export":
        pool = intruder_db.get_pool(db_path, project_id, args.name)
        if pool is None:
            cli_error(f"Pool not found: {args.name}")
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("\n".join(pool["values"]) + ("\n" if pool["values"] else ""), encoding="utf-8")
        payload = {"name": pool["name"], "count": pool["count"], "out": str(out)}
        def human(p):
            cli_success(f"Exported {p['count']} value(s).", {"Out": p["out"]})
        _emit(payload, args, human)
        return

    if action == "clear":
        ok = intruder_db.clear_pool(db_path, project_id, args.name)
        if not ok:
            cli_error(f"Pool not found: {args.name}")
        payload = {"name": args.name, "cleared": True}
        def human(p):
            cli_success("Pool cleared.", {"Name": args.name})
        _emit(payload, args, human)
        return

    if action == "delete":
        if not getattr(args, "force", False):
            confirm_or_exit(f"Delete pool '{args.name}'?", force=False)
        ok = intruder_db.delete_pool(db_path, project_id, args.name)
        if not ok:
            cli_error(f"Pool not found: {args.name}")
        payload = {"name": args.name, "deleted": True}
        def human(p):
            cli_success("Pool deleted.", {"Name": args.name})
        _emit(payload, args, human)
        return

    cli_usage_error(f"Unknown pool action: {action}")


def _dispatch_results(project, args: argparse.Namespace) -> None:
    db_path = project.db_path
    sess = _get_session_or_exit(db_path, args.session_id)
    action = args.results_cmd

    if action == "list":
        rows = intruder_db.list_results(
            db_path,
            sess["id"],
            interesting_only=args.interesting,
            limit=args.limit,
            offset=args.offset,
            status_code=args.status_code,
        )
        payload = [
            {
                "id": r["id"],
                "session_id": r["session_id"],
                "attempt_index": r["attempt_index"],
                "variables": r["variables"],
                "status_code": r["status_code"],
                "success": r["success"],
                "failure_reason": r["failure_reason"],
                "duration_ms": r["duration_ms"],
                "body_length": r["body_length"],
                "body_hash": r["body_hash"],
                "interesting": r["interesting"],
                "match_tags": r["match_tags"],
                "grepped": r.get("grepped") or {},
                "flow_id": r["flow_id"],
                "finding_id": r.get("finding_id"),
                "created_at": r["created_at"],
            }
            for r in rows
        ]
        def human(items):
            if not items:
                print("No results.")
                return
            print(f"{'IDX':>6} {'STATUS':>6} {'MS':>8} {'INT':>3} VARIABLES")
            for it in items:
                print(
                    f"{it['attempt_index']:>6} {str(it['status_code'] or '—'):>6} "
                    f"{it['duration_ms'] or 0:>8.1f} {'Y' if it['interesting'] else 'n':>3} "
                    f"{it['variables']}"
                )
        _emit(payload, args, human)
        return

    if action == "show":
        row = intruder_db.get_result(db_path, sess["id"], args.attempt_index)
        if row is None:
            cli_error(f"No result at attempt_index={args.attempt_index}")
        def human(r):
            print(json.dumps(r, indent=2, default=str))
        _emit(row, args, human)
        return

    if action == "export":
        if not args.jsonl and not args.csv:
            # default both
            args.jsonl = True
            args.csv = True
        rows = intruder_db.list_results(
            db_path,
            sess["id"],
            interesting_only=args.interesting,
            limit=1_000_000,
        )
        out = Path(args.out)
        written = {}
        if out.suffix in (".jsonl", ".csv"):
            # single file
            if out.suffix == ".jsonl" or args.jsonl:
                n = export_results_jsonl(rows, out if out.suffix == ".jsonl" else out.with_suffix(".jsonl"))
                written["jsonl"] = str(out if out.suffix == ".jsonl" else out.with_suffix(".jsonl"))
                written["jsonl_count"] = n
            if out.suffix == ".csv" or args.csv:
                n = export_results_csv(rows, out if out.suffix == ".csv" else out.with_suffix(".csv"))
                written["csv"] = str(out if out.suffix == ".csv" else out.with_suffix(".csv"))
                written["csv_count"] = n
        else:
            out.mkdir(parents=True, exist_ok=True)
            if args.jsonl:
                path = out / f"{sess['id'][:8]}.jsonl"
                written["jsonl"] = str(path)
                written["jsonl_count"] = export_results_jsonl(rows, path)
            if args.csv:
                path = out / f"{sess['id'][:8]}.csv"
                written["csv"] = str(path)
                written["csv_count"] = export_results_csv(rows, path)
        payload = {"session_id": sess["id"], "exported": len(rows), **written}
        def human(p):
            cli_success(f"Exported {p['exported']} result(s).", written)
        _emit(payload, args, human)
        return


def _dispatch_findings(project, args: argparse.Namespace) -> None:
    db_path = project.db_path
    project_id = project.id
    action = args.findings_cmd
    sess = _get_session_or_exit(db_path, args.session_id)
    cfg = merge_defaults(sess.get("config") or {})

    if action == "set":
        block = dict(cfg.get("findings") or {})
        if getattr(args, "promote", None) is not None:
            block["promote"] = str(args.promote).lower() in ("on", "true", "1")
        if getattr(args, "max_findings", None) is not None:
            block["max_findings"] = int(args.max_findings)
        if getattr(args, "on_mode", None) is not None:
            block["on"] = args.on_mode
        if getattr(args, "cluster_by", None) is not None:
            block["cluster_by"] = args.cluster_by
        if getattr(args, "only_success", None) is not None:
            block["only_success"] = str(args.only_success).lower() in (
                "on", "true", "1",
            )
        cfg["findings"] = block
        # Validate (promote on requires match rules)
        try:
            cfg, _ = validate_config(
                cfg,
                open_generators=False,
                force=bool(getattr(args, "force", False)),
                db_path=db_path,
                project_id=project_id,
            )
        except ValidationError as exc:
            cli_precondition_error(f"{exc.code}: {exc.message}")
        _save_config(db_path, sess["id"], cfg)
        fcfg = findings_config_from(cfg)
        payload = {"session_id": sess["id"], "findings": fcfg}
        def human(p):
            cli_success("Findings promote config updated.", {
                "Session": p["session_id"],
                "Promote": "on" if p["findings"]["promote"] else "off",
                "Max": p["findings"]["max_findings"],
                "On": p["findings"]["on"],
                "Cluster by": p["findings"]["cluster_by"],
            })
        _emit(payload, args, human)
        return

    if action == "show":
        fcfg = findings_config_from(cfg)
        already = intruder_db.count_results_with_findings(db_path, sess["id"])
        interesting = intruder_db.count_results(
            db_path, sess["id"], interesting_only=True
        )
        progress = sess.get("progress") or {}
        payload = {
            "session_id": sess["id"],
            "findings": fcfg,
            "results_interesting": interesting,
            "results_promoted": already,
            "progress_findings_promoted": progress.get("findings_promoted"),
        }
        def human(p):
            f = p["findings"]
            print(f"Session: {p['session_id']}")
            print(f"  Promote:     {'on' if f['promote'] else 'off'}")
            print(f"  On:          {f['on']}")
            print(f"  Max:         {f['max_findings']}")
            print(f"  Only success:{f['only_success']}")
            print(f"  Cluster by:  {f['cluster_by']}")
            print(f"  Interesting: {p['results_interesting']}")
            print(f"  Promoted:    {p['results_promoted']}")
        _emit(payload, args, human)
        return

    if action == "promote":
        force_enable = bool(getattr(args, "enable", False))
        fcfg = findings_config_from(cfg)
        if not fcfg.get("promote") and not force_enable:
            cli_precondition_error(
                "findings.promote is off. Use --enable for a one-shot offline "
                "promote, or: talos intruder findings set <id> --promote on"
            )
        # Hardening: confirm when many interesting unpromoted rows
        unpromoted = intruder_db.list_results(
            db_path,
            sess["id"],
            interesting_only=True,
            unpromoted_only=True,
            limit=10_000,
        )
        if len(unpromoted) > 50 and not getattr(args, "force", False):
            confirm_or_exit(
                f"Promote up to {min(len(unpromoted), fcfg['max_findings'])} "
                f"interesting result(s) to Findings?",
                force=False,
            )
        result = promote_session_results(
            db_path,
            project_id,
            {**sess, "config": cfg},
            fcfg=fcfg,
            force_enable=force_enable,
        )
        payload = {"session_id": sess["id"], **result}
        def human(p):
            cli_success(
                f"Promoted {p['promoted']} finding(s).",
                {
                    "Session": p["session_id"],
                    "Promoted": p["promoted"],
                    "Skipped": p["skipped"],
                    "Capped": p.get("capped"),
                    "Total promoted": p.get("findings_promoted_total"),
                },
            )
        _emit(payload, args, human)
        return

    cli_usage_error(f"Unknown findings action: {action}")


def _dispatch_generators(args: argparse.Namespace) -> None:
    payload = {
        "generators": sorted(KNOWN_GENERATORS),
        "processors": sorted(KNOWN_PROCESSORS),
        "processor_parameterized": ["prefix:<text>", "suffix:<text>"],
        "strategies": sorted(s for s in KNOWN_STRATEGIES if s != "cartesian"),
        "storage_modes": sorted(KNOWN_STORAGE_MODES),
        "timing_modes": sorted(KNOWN_TIMING_MODES),
        "phase3": {
            "generators": ["uuid", "csv", "json", "example_values", "pool"],
            "grep": True,
            "pools": True,
            "template_from_params": True,
        },
        "phase4": {
            "generators": sorted(PHASE4_GENERATORS),
            "timing_modes": ["token_bucket", "adaptive"],
            "suggest": True,
        },
        "phase5": {
            "findings_promote": True,
            "default_promote": False,
            "default_max_findings": DEFAULT_FINDINGS_MAX,
            "cluster_by": [CLUSTER_BY_SESSION, CLUSTER_BY_ENDPOINT],
            "on": [FINDINGS_ON_INTERESTING, "matched"],
        },
    }
    def human(p):
        print("Generators:", ", ".join(p["generators"]))
        print("Processors:", ", ".join(p["processors"]))
        print("Parameterized:", ", ".join(p["processor_parameterized"]))
        print("Strategies:", ", ".join(p["strategies"]))
        print("Storage:", ", ".join(p["storage_modes"]))
        print("Timing modes:", ", ".join(p["timing_modes"]))
        print("Phase 3:", ", ".join(p["phase3"]["generators"]), "+ grep/pools/from-params")
        print(
            "Phase 4:",
            ", ".join(p["phase4"]["generators"]),
            "+ adaptive/token_bucket timing + suggest",
        )
        print(
            "Phase 5: findings promote (default off, max",
            p["phase5"]["default_max_findings"],
            ")",
        )
    _emit(payload, args, human)


def _dispatch_suggest(project, args: argparse.Namespace) -> None:
    db_path = project.db_path
    sess = _get_session_or_exit(db_path, args.session_id)
    cfg = merge_defaults(sess.get("config") or {})
    suggestions = build_suggestions(
        sess,
        cfg,
        db_path=db_path,
        project_id=str(project.id),
    )

    applied = False
    if args.apply:
        new_cfg = apply_suggestions(
            cfg,
            suggestions,
            replace_payloads=bool(args.replace_payloads),
            apply_match=not bool(args.no_match),
            apply_grep=not bool(args.no_grep),
        )
        _save_config(
            db_path,
            sess["id"],
            new_cfg,
            status=STATUS_DRAFT if sess["status"] == "configured" else sess["status"],
        )
        applied = True
        suggestions = build_suggestions(
            {**sess, "config": new_cfg},
            new_cfg,
            db_path=db_path,
            project_id=str(project.id),
        )
        suggestions["applied"] = True

    payload = {**suggestions, "applied": applied}

    def human(p):
        title = "Suggestions applied." if p.get("applied") else "Suggestions (not applied)."
        cli_success(title, {
            "Session": p.get("session_id"),
            "Summary": p.get("summary"),
            "Strategy": (p.get("strategy") or {}).get("type"),
            "Timing": (p.get("timing") or {}).get("mode"),
            "Payloads": len(p.get("payloads") or []),
        })
        print("Notes:")
        for n in p.get("notes") or []:
            print(f"  - {n}")
        print("Commands:")
        for c in p.get("commands") or []:
            print(f"  {c}")

    _emit(payload, args, human)
