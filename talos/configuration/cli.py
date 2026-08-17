"""
Module: talos.configuration.cli

Purpose:
    CLI for the layered configuration system (CLI-022).

    Entry points:
        talos config show
        talos config effective
        talos config get <key>
        talos config set <key> <value> [--global]
        talos config unset <key> [--global]
        talos config edit [--global]
        talos config <section> [show|set|unset|edit] …

    Sections: proxy, capture, scheduler, attack, http, parameter_intel,
    url_sink, burp

    HTTP Manipulation Engine (``talos config http …``) manages declarative
    request/response rules under ``http.rules``. See ``http_cli.py``.

    Design intent:
        - Human operators use show / effective / get / set / unset / edit.
        - Automation uses get/set/unset with stable dotted keys and --format json.
        - Resource subcommands avoid the long `proxy.upstream.url` prefix when
          working inside one section.
        - Existing `proxy config`, `scheduler config`, etc. remain as
          compatibility wrappers that dual-write through the same model.

Dependencies: argparse, json, os, subprocess, sys, yaml
Data flow:
    argv → ConfigurationManager → stdout
Side effects:
    set/unset/edit write YAML (and may dual-write SQLite).
    Configures UTF-8 stdio so Windows cp1252 consoles can print schema arrows.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Optional

import yaml

from talos.cli_output import (
    add_format_argument,
    cli_error,
    cli_info,
    cli_json,
    cli_precondition_error,
    cli_success,
    cli_usage_error,
    configure_stdio,
    wants_json,
)
from talos.configuration.defaults import (
    CONFIG_SECTIONS,
    KNOWN_LEAF_PATHS,
    build_config_schema,
)
from talos.configuration.manager import ConfigError, ConfigurationManager
from talos.configuration.merge import flatten_leaves, get_path, parse_cli_value
from talos.configuration.model import EffectiveConfig, ValueSource
from talos.projects.manager import NO_ACTIVE_PROJECT_HINT, ProjectManager


# ------------------------------------------------------------------ #
# Entry                                                                #
# ------------------------------------------------------------------ #


def run_config_cli(manager: ProjectManager, argv: list[str]) -> None:
    """
    Purpose:
        Parse and dispatch `talos config` subcommands.
    Input:
        manager — ProjectManager (for project binding).
        argv    — args after `config`.
    Side effects:
        Reads/writes configuration; prints to stdout; may exit.
    """
    configure_stdio()
    parser = build_parser()
    if not argv or argv[0] in ("-h", "--help"):
        parser.print_help()
        return

    # HTTP Manipulation Engine has a dedicated rule CLI (not leaf get/set).
    if argv[0] == "http":
        from talos.configuration.http_cli import run_http_cli

        # Bare `talos config http` / `http show` for section summary still
        # useful; route rule verbs to http_cli, and `show`/empty to section.
        rest = argv[1:]
        if not rest or rest[0] in (
            "list",
            "show",
            "create",
            "delete",
            "enable",
            "disable",
            "set-priority",
            "set-match",
            "clear-match",
            "add-action",
            "remove-action",
            "reorder",
            "export",
            "import",
            "enable-engine",
            "disable-engine",
            "actions",
            "-h",
            "--help",
        ):
            # `http show` without an id is ambiguous with section show —
            # if next token looks like a rule id (or missing), use http_cli.
            # Section-style: `http set enabled true` handled below.
            if rest and rest[0] == "set":
                _dispatch_section(manager, "http", rest)
                return
            if rest and rest[0] == "unset":
                _dispatch_section(manager, "http", rest)
                return
            if rest and rest[0] == "edit":
                _dispatch_section(manager, "http", rest)
                return
            # `talos config http` with no args → list rules (more useful than empty section).
            if not rest:
                run_http_cli(manager, ["list"])
                return
            if rest[0] == "show" and len(rest) == 1:
                # Section effective view when no rule id.
                _dispatch_section(manager, "http", ["show"])
                return
            run_http_cli(manager, rest)
            return

    # Section resource: talos config proxy …
    if argv[0] in CONFIG_SECTIONS:
        _dispatch_section(manager, argv[0], argv[1:])
        return

    args = parser.parse_args(argv)
    handlers = {
        "show": cmd_show,
        "effective": cmd_effective,
        "get": cmd_get,
        "set": cmd_set,
        "unset": cmd_unset,
        "edit": cmd_edit,
        "schema": cmd_schema,
    }
    handler = handlers.get(args.config_command)
    if handler is None:
        parser.print_help()
        sys.exit(2)
    handler(manager, args)


def build_parser() -> argparse.ArgumentParser:
    """
    Purpose: Build argparse tree for top-level config verbs.
    Side effects: None.
    """
    parser = argparse.ArgumentParser(
        prog="talos config",
        description=(
            "Layered configuration (defaults → global → project → CLI). "
            "View and edit settings that apply across proxy, capture, "
            "scheduler, attack, and http."
        ),
    )
    sub = parser.add_subparsers(dest="config_command")

    p_show = sub.add_parser(
        "show",
        help="Show config file paths and a short summary of layers.",
    )
    add_format_argument(p_show)

    p_eff = sub.add_parser(
        "effective",
        help="Show the fully merged configuration with value sources.",
    )
    add_format_argument(p_eff)
    p_eff.add_argument(
        "--section",
        choices=CONFIG_SECTIONS,
        help="Limit output to one section.",
    )

    p_get = sub.add_parser(
        "get",
        help="Get one configuration value (with inheritance source).",
    )
    p_get.add_argument("key", help="Dotted key, e.g. scheduler.max_delay")
    add_format_argument(p_get)

    p_set = sub.add_parser(
        "set",
        help="Set a project override (or global with --global).",
    )
    p_set.add_argument("key", help="Dotted key, e.g. proxy.upstream.url")
    p_set.add_argument("value", help="Value (bool/int/float/string/JSON)")
    p_set.add_argument(
        "--global",
        dest="global_scope",
        action="store_true",
        help="Write to ~/.talos/config.yaml instead of project.yaml",
    )

    p_unset = sub.add_parser(
        "unset",
        help="Remove a project override so the lower layer is inherited.",
    )
    p_unset.add_argument("key", help="Dotted key to remove from the target layer")
    p_unset.add_argument(
        "--global",
        dest="global_scope",
        action="store_true",
        help="Remove from global config instead of project.yaml",
    )

    p_edit = sub.add_parser(
        "edit",
        help="Open the project (or global) config file in $EDITOR.",
    )
    p_edit.add_argument(
        "--global",
        dest="global_scope",
        action="store_true",
        help="Edit ~/.talos/config.yaml",
    )

    p_schema = sub.add_parser(
        "schema",
        help="Show machine-readable setting schema (types, defaults, sections).",
    )
    add_format_argument(p_schema)

    return parser


# ------------------------------------------------------------------ #
# Section resource dispatch                                            #
# ------------------------------------------------------------------ #


def _dispatch_section(
    manager: ProjectManager, section: str, argv: list[str]
) -> None:
    """
    Purpose:
        Handle talos config <section> [show|set|unset|edit] …
    Side effects: Same as top-level config commands.
    """
    if not argv or argv[0] in ("show", "-h", "--help"):
        if argv and argv[0] in ("-h", "--help"):
            print(
                f"Usage: talos config {section} [show|set|unset|edit] …\n"
                f"  show              Show effective {section} section\n"
                f"  set <key> <value> Set {section}.<key> (project override)\n"
                f"  unset <key>       Remove project override for {section}.<key>\n"
                f"  edit              Edit project.yaml in $EDITOR\n"
                f"  --global          With set/unset/edit: target global config\n"
            )
            return
        # bare section or explicit show
        rest = argv[1:] if argv and argv[0] == "show" else argv
        ns = argparse.Namespace(
            section=section,
            format=_extract_format(rest),
        )
        cmd_section_show(manager, ns)
        return

    action = argv[0]
    rest = argv[1:]
    global_scope = False
    if "--global" in rest:
        global_scope = True
        rest = [t for t in rest if t != "--global"]

    if action == "set":
        if len(rest) < 2:
            cli_usage_error(
                f"Usage: talos config {section} set <key> <value> [--global]"
            )
        key = f"{section}.{rest[0]}" if not rest[0].startswith(f"{section}.") else rest[0]
        value = rest[1]
        cmd_set(
            manager,
            argparse.Namespace(key=key, value=value, global_scope=global_scope),
        )
        return

    if action == "unset":
        if len(rest) < 1:
            cli_usage_error(
                f"Usage: talos config {section} unset <key> [--global]"
            )
        key = f"{section}.{rest[0]}" if not rest[0].startswith(f"{section}.") else rest[0]
        cmd_unset(
            manager,
            argparse.Namespace(key=key, global_scope=global_scope),
        )
        return

    if action == "edit":
        cmd_edit(
            manager,
            argparse.Namespace(global_scope=global_scope),
        )
        return

    cli_usage_error(
        f"Unknown action '{action}' for talos config {section}. "
        "Use show, set, unset, or edit."
    )


def _extract_format(tokens: list[str]) -> str:
    """Pull --format value from leftover tokens; default table."""
    for i, tok in enumerate(tokens):
        if tok == "--format" and i + 1 < len(tokens):
            return tokens[i + 1]
        if tok.startswith("--format="):
            return tok.split("=", 1)[1]
    return "table"


# ------------------------------------------------------------------ #
# Commands                                                             #
# ------------------------------------------------------------------ #


def cmd_show(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Show paths to global/project config and whether each exists.
    Side effects: Prints summary (or JSON).
    """
    cfg_mgr = _config_manager(manager)
    project = manager.active()
    effective = _load(cfg_mgr, project)

    payload = {
        "global": {
            "path": effective.global_path,
            "exists": Path(effective.global_path).exists()
            if effective.global_path
            else False,
        },
        "project": {
            "path": effective.project_path,
            "exists": (
                Path(effective.project_path).exists()
                if effective.project_path
                else False
            ),
            "bound": project is not None,
            "project_id": project.id if project else None,
        },
        "precedence": [
            "defaults",
            "global",
            "legacy (SQLite / headers_drop.txt / constraints)",
            "project.yaml",
            "CLI overrides",
        ],
        "sections": list(CONFIG_SECTIONS),
    }

    if wants_json(args):
        cli_json(payload)
        return

    print("Talos configuration layers\n")
    print("Global:")
    print(f"    {payload['global']['path']}")
    print(f"    {'(present)' if payload['global']['exists'] else '(not created yet)'}")
    print()
    print("Project:")
    if project is None:
        print("    (no project bound)")
    else:
        print(f"    {payload['project']['path']}")
        print(
            f"    {'(present)' if payload['project']['exists'] else '(not created yet)'}"
            f"  project={project.id}"
        )
    print()
    print("Effective:")
    print("    merged (use: talos config effective)")
    print()
    print("Precedence: defaults → global → legacy → project → CLI")
    print("Sections:   " + ", ".join(CONFIG_SECTIONS))


def cmd_effective(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Print the fully merged configuration with per-value sources.
    Side effects: Prints to stdout.
    """
    cfg_mgr = _config_manager(manager)
    project = manager.active()
    effective = _load(cfg_mgr, project)

    section_filter: Optional[str] = getattr(args, "section", None)
    raw = effective.raw
    if section_filter:
        raw = {section_filter: raw.get(section_filter, {})}

    if wants_json(args):
        leaves = flatten_leaves(raw)
        cli_json(
            {
                "values": leaves,
                "sources": {
                    k: effective.sources.get(k, ValueSource.DEFAULT).value
                    for k in leaves
                },
                "global_path": effective.global_path,
                "project_path": effective.project_path,
            }
        )
        return

    print("Effective configuration\n")
    for section in CONFIG_SECTIONS:
        if section_filter and section != section_filter:
            continue
        section_data = raw.get(section, {})
        # Dominant source for the section: most specific leaf source.
        section_source = _dominant_source(effective, section)
        print(f"{section.capitalize()}")
        print(f"Source: {_source_label(section_source)}")
        _print_section_body(section_data, effective.sources, prefix=section)
        print()


def cmd_get(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Resolve one dotted key and show value + inheritance source.
    Side effects: Prints to stdout; exits 2 on unknown empty path segments.
    """
    cfg_mgr = _config_manager(manager)
    project = manager.active()
    effective = _load(cfg_mgr, project)
    key = args.key.strip()

    if get_path(effective.raw, key, default=_MISSING) is _MISSING:
        # Allow known paths that resolve to None
        from talos.configuration.merge import path_exists

        if not path_exists(effective.raw, key):
            cli_error(
                f"Unknown configuration key: {key}\n\n"
                f"Known keys include:\n  "
                + "\n  ".join(KNOWN_LEAF_PATHS)
            )

    value = get_path(effective.raw, key)
    source = effective.source_of(key) or ValueSource.DEFAULT

    if wants_json(args):
        cli_json(
            {
                "key": key,
                "value": value,
                "source": source.value,
            }
        )
        return

    print(_source_label(source))
    print()
    print(_format_value(value))


def cmd_set(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Write a key to project.yaml (or global config with --global).
    Side effects: Writes YAML; may dual-write SQLite.
    """
    cfg_mgr = _config_manager(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    project = manager.active()

    if not global_scope and project is None:
        cli_precondition_error(NO_ACTIVE_PROJECT_HINT)

    try:
        parsed = parse_cli_value(args.value)
        # Special-case: setting upstream url implies enabling upstream.
        key = args.key
        if key == "proxy.upstream.url" and parsed:
            # Write url first, then ensure enabled.
            path = cfg_mgr.set_value(
                key,
                parsed,
                global_scope=global_scope,
                project_data_dir=Path(project.data_dir) if project else None,
                project_db_path=project.db_path if project and not global_scope else None,
            )
            cfg_mgr.set_value(
                "proxy.upstream.enabled",
                True,
                global_scope=global_scope,
                project_data_dir=Path(project.data_dir) if project else None,
                project_db_path=project.db_path if project and not global_scope else None,
            )
        elif key == "proxy.upstream.enabled" and parsed is False:
            path = cfg_mgr.set_value(
                key,
                False,
                global_scope=global_scope,
                project_data_dir=Path(project.data_dir) if project else None,
                project_db_path=project.db_path if project and not global_scope else None,
            )
        else:
            path = cfg_mgr.set_value(
                key,
                parsed,
                global_scope=global_scope,
                project_data_dir=Path(project.data_dir) if project else None,
                project_db_path=project.db_path if project and not global_scope else None,
            )
    except ConfigError as exc:
        cli_error(str(exc))

    scope_label = "global" if global_scope else "project"
    cli_success(f"Set {args.key} ({scope_label})")
    print(f"  file : {path}")
    print(f"  value: {_format_value(parse_cli_value(args.value))}")
    _notify_proxy_if_needed(project, args.key)


def cmd_unset(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Remove a key from project or global YAML so inheritance resumes.
    Side effects: May rewrite YAML.
    """
    cfg_mgr = _config_manager(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    project = manager.active()

    if not global_scope and project is None:
        cli_precondition_error(NO_ACTIVE_PROJECT_HINT)

    try:
        path, removed = cfg_mgr.unset_value(
            args.key,
            global_scope=global_scope,
            project_data_dir=Path(project.data_dir) if project else None,
            project_db_path=project.db_path if project and not global_scope else None,
        )
    except ConfigError as exc:
        cli_error(str(exc))

    scope_label = "global" if global_scope else "project"
    if not removed:
        cli_info(f"No {scope_label} override for {args.key} (already inherited).")
        return
    cli_success(f"Unset {args.key} ({scope_label}) — now inherited")
    print(f"  file: {path}")
    _notify_proxy_if_needed(project, args.key)


def cmd_edit(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Open the target config YAML in $EDITOR (or VISUAL / vi).
    Side effects:
        May create the file; launches an editor subprocess.
    """
    cfg_mgr = _config_manager(manager)
    global_scope = bool(getattr(args, "global_scope", False))
    project = manager.active()

    if global_scope:
        target = cfg_mgr.global_path
    else:
        if project is None:
            cli_precondition_error(NO_ACTIVE_PROJECT_HINT)
        from talos.configuration.io import ensure_empty_project_config

        target = ensure_empty_project_config(Path(project.data_dir))

    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            "# Talos configuration\n"
            "# docs: talos config effective\n",
            encoding="utf-8",
        )

    editor = os.environ.get("VISUAL") or os.environ.get("EDITOR") or "vi"
    try:
        subprocess.run([editor, str(target)], check=False)
    except OSError as exc:
        cli_error(f"Failed to launch editor {editor!r}: {exc}")

    # Validate YAML after edit
    try:
        from talos.configuration.io import load_yaml_file

        load_yaml_file(target)
    except Exception as exc:
        cli_error(f"Config file has invalid YAML after edit: {exc}")

    print(f"Edited: {target}")


def cmd_schema(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Emit configuration schema (sections, types, defaults) for UIs and tools.
    Side effects: Prints to stdout. Does not read project state.
    """
    del manager  # schema is static; no project binding required
    payload = build_config_schema()

    if wants_json(args):
        cli_json(payload)
        return

    print("Talos configuration schema\n")
    print("Precedence: " + " → ".join(payload["precedence"]))
    print("Sources:    " + ", ".join(payload["sources"]))
    print()
    for section in payload["sections"]:
        print(f"{section['label']} ({section['id']})")
        if section.get("description"):
            print(f"  {section['description']}")
        for setting in section.get("settings", []):
            unit = f" {setting['unit']}" if setting.get("unit") else ""
            print(
                f"  {setting['key']}"
                f"  type={setting['type']}"
                f"  default={_format_value(setting.get('default'))}{unit}"
            )
            if setting.get("description"):
                print(f"    {setting['description']}")
        print()


def cmd_section_show(manager: ProjectManager, args: argparse.Namespace) -> None:
    """
    Purpose:
        Show one section of the effective configuration.
    Side effects: Prints to stdout.
    """
    cfg_mgr = _config_manager(manager)
    project = manager.active()
    effective = _load(cfg_mgr, project)
    section = args.section
    data = effective.raw.get(section, {})
    source = _dominant_source(effective, section)

    if wants_json(args):
        leaves = flatten_leaves({section: data})
        cli_json(
            {
                "section": section,
                "source": source.value,
                "values": data,
                "sources": {
                    k: effective.sources.get(k, ValueSource.DEFAULT).value
                    for k in leaves
                },
            }
        )
        return

    print(f"{section.capitalize()}")
    print(f"Source: {_source_label(source)}")
    _print_section_body(data, effective.sources, prefix=section)


# ------------------------------------------------------------------ #
# Helpers                                                              #
# ------------------------------------------------------------------ #

_MISSING = object()


def _config_manager(manager: ProjectManager) -> ConfigurationManager:
    """
    Purpose:
        Build ConfigurationManager using the same data root as ProjectManager.
    Side effects: None.
    """
    # projects_root is <data_dir>/projects
    data_dir = Path(manager._root).parent  # noqa: SLF001 — intentional
    return ConfigurationManager(data_dir)


def _load(
    cfg_mgr: ConfigurationManager, project: Any
) -> EffectiveConfig:
    if project is None:
        return cfg_mgr.load()
    return cfg_mgr.load_for_project(project)


def _source_label(source: ValueSource) -> str:
    labels = {
        ValueSource.DEFAULT: "Default",
        ValueSource.GLOBAL: "Global",
        ValueSource.PROJECT: "Project override",
        ValueSource.LEGACY: "Legacy (project store)",
        ValueSource.CLI: "CLI override",
    }
    return labels.get(source, source.value)


def _dominant_source(effective: EffectiveConfig, section: str) -> ValueSource:
    """
    Purpose:
        Pick the most specific source among leaves under a section.
    Side effects: None.
    """
    order = [
        ValueSource.CLI,
        ValueSource.PROJECT,
        ValueSource.LEGACY,
        ValueSource.GLOBAL,
        ValueSource.DEFAULT,
    ]
    found = {
        src
        for path, src in effective.sources.items()
        if path == section or path.startswith(section + ".")
    }
    for candidate in order:
        if candidate in found:
            return candidate
    return ValueSource.DEFAULT


def _print_section_body(
    data: Any,
    sources: dict,
    *,
    prefix: str,
    indent: int = 4,
) -> None:
    """Pretty-print a section tree with optional per-leaf source tags."""
    pad = " " * indent
    if not isinstance(data, dict):
        print(f"{pad}{_format_value(data)}")
        return
    if not data:
        print(f"{pad}(empty)")
        return
    for key, value in data.items():
        path = f"{prefix}.{key}"
        if isinstance(value, dict) and value and not _looks_like_str_map(value):
            print(f"{pad}{key}:")
            _print_section_body(value, sources, prefix=path, indent=indent + 2)
        elif isinstance(value, list):
            print(f"{pad}{key}:")
            if not value:
                print(f"{pad}  (none)")
            else:
                for item in value:
                    print(f"{pad}  - {item}")
        else:
            src = sources.get(path)
            tag = f"  [{src.value}]" if src and src != ValueSource.DEFAULT else ""
            print(f"{pad}{key}: {_format_value(value)}{tag}")


def _looks_like_str_map(value: dict) -> bool:
    if not value:
        return True
    return all(not isinstance(v, (dict, list)) for v in value.values())


def _notify_proxy_if_needed(project: Any, key: str) -> None:
    """
    Purpose:
        Restart the managed proxy when a proxy-transport key changes.
    Side effects: May call notify_proxy_config_changed.
    """
    if project is None:
        return
    prefixes = (
        "proxy.http2",
        "proxy.keep_alive",
        "proxy.platform_auth",
        "proxy.upstream",
    )
    if not any(key == p or key.startswith(p + ".") for p in prefixes):
        return
    try:
        from talos.proxy.runtime.events import notify_proxy_config_changed

        notify_proxy_config_changed(project.id, f"config set {key}")
    except Exception:
        return


def _format_value(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return yaml.safe_dump(value, default_flow_style=True).strip()
    return str(value)
