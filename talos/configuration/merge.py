"""
Module: talos.configuration.merge

Purpose:
    Deep-merge and path get/set/unset helpers for configuration trees.
    Pure functions — no I/O.

Dependencies: copy
Data flow: ConfigurationManager → merge helpers → layered dict trees
Side effects: None (set_path / unset_path mutate a copy or the given tree).
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Optional


def deep_merge(base: dict, overlay: dict) -> dict:
    """
    Purpose:
        Recursively merge overlay onto a copy of base.
        Dict values are merged; all other values (including lists) replace.
    Input:
        base    — lower-precedence tree.
        overlay — higher-precedence tree (wins on conflict).
    Output:
        New dict; neither input is mutated.
    Side effects: None.
    """
    result = deepcopy(base)
    for key, value in overlay.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = deepcopy(value)
    return result


def get_path(tree: dict, path: str, default: Any = None) -> Any:
    """
    Purpose:
        Resolve a dotted path into a nested dict tree.
    Input:
        tree    — configuration dict.
        path    — dotted key (e.g. "proxy.upstream.url").
        default — returned when any segment is missing.
    Output:
        Value at path, or default.
    Side effects: None.
    """
    current: Any = tree
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def set_path(tree: dict, path: str, value: Any) -> dict:
    """
    Purpose:
        Set a dotted path in a deep copy of tree.
    Input:
        tree  — configuration dict.
        path  — dotted key.
        value — new leaf or subtree value.
    Output:
        New dict with the path set.
    Side effects: None (does not mutate tree).
    """
    result = deepcopy(tree)
    parts = path.split(".")
    cursor: dict = result
    for part in parts[:-1]:
        existing = cursor.get(part)
        if not isinstance(existing, dict):
            cursor[part] = {}
        cursor = cursor[part]
    cursor[parts[-1]] = deepcopy(value)
    return result


def unset_path(tree: dict, path: str) -> tuple[dict, bool]:
    """
    Purpose:
        Remove a dotted path from a deep copy of tree.
    Input:
        tree — configuration dict.
        path — dotted key to remove.
    Output:
        (new_tree, removed) where removed is True if the key existed.
    Side effects: None (does not mutate tree).
    """
    result = deepcopy(tree)
    parts = path.split(".")
    cursor: dict = result
    stack: list[tuple[dict, str]] = []
    for part in parts[:-1]:
        if part not in cursor or not isinstance(cursor[part], dict):
            return result, False
        stack.append((cursor, part))
        cursor = cursor[part]
    leaf = parts[-1]
    if leaf not in cursor:
        return result, False
    del cursor[leaf]
    # Prune empty intermediate dicts so YAML stays tidy.
    for parent, key in reversed(stack):
        child = parent[key]
        if isinstance(child, dict) and not child:
            del parent[key]
        else:
            break
    return result, True


def path_exists(tree: dict, path: str) -> bool:
    """
    Purpose:
        Return True when the dotted path is present in tree.
    Side effects: None.
    """
    current: Any = tree
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return False
        current = current[part]
    return True


def flatten_leaves(
    tree: dict,
    *,
    prefix: str = "",
) -> dict[str, Any]:
    """
    Purpose:
        Flatten a nested config tree to dotted leaf paths.
        Non-empty dicts are always recursed so partial section overlays
        (e.g. global only setting scheduler.min_delay) produce correct
        per-leaf source attribution. Empty dicts are leaves.
        Lists and scalars are leaves.
    Input:
        tree   — configuration dict.
        prefix — internal recursion prefix.
    Output:
        Mapping of dotted path → value.
    Side effects: None.
    """
    leaves: dict[str, Any] = {}
    for key, value in tree.items():
        full = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            if value:
                leaves.update(flatten_leaves(value, prefix=full))
            else:
                leaves[full] = value
        else:
            leaves[full] = value
    return leaves


def parse_cli_value(raw: str) -> Any:
    """
    Purpose:
        Coerce a CLI string into a JSON-ish Python value for config set.
        Supports bool, null, int, float, and JSON arrays/objects; otherwise
        returns the string unchanged.
    Input:
        raw — value token from the CLI.
    Output:
        Parsed Python value.
    Side effects: None.
    """
    stripped = raw.strip()
    lower = stripped.lower()
    if lower in ("true", "yes", "on"):
        return True
    if lower in ("false", "no", "off"):
        return False
    if lower in ("null", "none", "~"):
        return None
    # Integer
    try:
        if stripped.isdigit() or (
            stripped.startswith("-") and stripped[1:].isdigit()
        ):
            return int(stripped)
    except ValueError:
        pass
    # Float
    try:
        if "." in stripped:
            return float(stripped)
    except ValueError:
        pass
    # JSON list/object
    if stripped.startswith(("[", "{")):
        import json

        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
    return raw
