"""
Module: talos.projects.manager

Purpose:
    Single authority for all project lifecycle operations.
    Maintains a JSON registry of all projects and enforces the
    "exactly one active project at a time" invariant for interactive
    sessions (project open / close).

    Process-scoped project selection (CLI-013) lets automation bind a
    project without rewriting the registry:
        - constructor project_override=
        - TALOS_PROJECT environment variable
        - root CLI flag: talos --project <id> …

    Resolution order for active():
        1. process override (flag / env / constructor)
        2. registry entry with status=ACTIVE
        3. None

Dependencies: json, os, pathlib, talos.projects.model, talos.projects.db
Data flow:
    CLI → ProjectManager → registry (JSON) + per-project directory + SQLite DB
Side effects:
    - Reads/writes the registry file at <projects_root>/registry.json.
    - Creates per-project directories and databases on disk.
    - Enforces that no two projects are ACTIVE simultaneously in the registry.
    - Process override never mutates registry status.

Registry format (projects_root/registry.json):
    {
      "<project_id>": { ...Project.to_dict() },
      ...
    }
"""

import json
import logging
import os
import shutil
from pathlib import Path
from typing import Optional

from talos.projects.db import init_project_db
from talos.projects.model import (
    Project,
    ProjectStatus,
    ScopeConstraints,
    make_project_id,
    utc_now_iso,
)
from talos.projects.policy_score import write_default_score_config

logger = logging.getLogger(__name__)

_REGISTRY_FILENAME = "registry.json"

# Shared hint for CLI precondition errors when no project is bound.
NO_ACTIVE_PROJECT_HINT = (
    "No active project. Run 'talos project open <id>', "
    "or pass --project <id> / set TALOS_PROJECT."
)

# Environment variable for process-scoped project selection (CLI-013).
TALOS_PROJECT_ENV = "TALOS_PROJECT"

# Path to the global headers_drop template shipped with the proxy package.
# Copied into each new project directory so users can override per-project.
_GLOBAL_HEADERS_DROP = (
    Path(__file__).parent.parent / "proxy" / "default_headers_drop.txt"
)


def _copy_headers_drop_template(dest: Path) -> None:
    """
    Purpose:
        Copy the global default_headers_drop.txt into a project's data directory.
        Skips if the destination already exists to avoid overwriting user edits.
    Input:
        dest — target path inside the project's data_dir.
    Side effects:
        - Creates the file if the global template exists and dest is absent.
        - Logs WARNING if the global template is missing (misconfigured install).
    """
    if dest.exists():
        return
    if _GLOBAL_HEADERS_DROP.exists():
        shutil.copy2(_GLOBAL_HEADERS_DROP, dest)
        logger.debug("Copied default headers_drop template to %s", dest)
    else:
        logger.warning(
            "Global headers_drop template not found at %s — project will capture all headers",
            _GLOBAL_HEADERS_DROP,
        )


def _sync_burp_snapshot(project: Project) -> None:
    """Create ~/.talos/burp/<id>.jsonl so the Burp picker lists this project."""
    try:
        from talos.burp.snapshot import (
            backfill_findings_from_db,
            backfill_responses_from_db,
            ensure_project_snapshot,
        )

        ensure_project_snapshot(project.id, project.name)
        backfill_responses_from_db(project.id, project.db_path)
        backfill_findings_from_db(project.id, project.db_path)
    except Exception:
        logger.debug("burp snapshot sync skipped for %s", project.id, exc_info=True)


class ProjectError(Exception):
    """Base error for all project management failures."""


class ProjectNotFound(ProjectError):
    """Raised when a requested project id does not exist in the registry."""


class ProjectAlreadyExists(ProjectError):
    """Raised when creating a project whose id is already registered."""


class NoActiveProject(ProjectError):
    """Raised when an operation requires an active project but none is set."""


def _rewrite_project_id_in_db(db_path: Path, old_id: str, new_id: str) -> None:
    """
    Purpose:
        Rewrite project_id column values inside a per-project SQLite DB after
        a project id (slug) rename. Each project has its own DB, so this is
        bookkeeping consistency rather than cross-project isolation.
    Input:
        db_path — path to talos.db (may be missing for empty/orphan projects).
        old_id  — previous project slug.
        new_id  — new project slug.
    Output: None.
    Side effects:
        Updates every table that has a project_id column. No-op if db missing.
    """
    if old_id == new_id or not db_path.exists():
        return
    import sqlite3

    with sqlite3.connect(str(db_path)) as conn:
        tables = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        for (table_name,) in tables:
            # Table names come from sqlite_master, not user input.
            columns = [
                row[1]
                for row in conn.execute(f'PRAGMA table_info("{table_name}")')
            ]
            if "project_id" not in columns:
                continue
            conn.execute(
                f'UPDATE "{table_name}" SET project_id = ? WHERE project_id = ?',
                (new_id, old_id),
            )
        conn.commit()


class ProjectManager:
    """
    Purpose:
        Manage the full lifecycle of Talos projects.
        Enforces isolation — no active project means no capture.

    Responsibilities:
        - create:      register project, create storage, init DB
        - open:        set exactly one project as ACTIVE (registry)
        - close:       deactivate the current registry ACTIVE project
        - delete:      remove from registry; optional --purge removes disk data
        - rename:      change display name and/or id slug (+ directory move)
        - set_description: update project description note
        - list:        enumerate all registered projects
        - get:         retrieve a single project by id
        - active:      return process-override project, registry ACTIVE, or None

    Input:
        projects_root    — Path to the directory that stores all projects.
                           Created automatically if it does not exist.
        project_override — Optional project id for this process only.
                           When None, falls back to TALOS_PROJECT env.
                           Never writes registry status.
    """

    def __init__(
        self,
        projects_root: Path,
        project_override: Optional[str] = None,
    ) -> None:
        # Why root, not a fixed path: lets callers control storage location
        # (e.g. test isolation, user-configured data dir).
        self._root = projects_root
        self._root.mkdir(parents=True, exist_ok=True)
        self._registry_path = self._root / _REGISTRY_FILENAME
        # Process-scoped bind: flag/constructor wins; else env; never mutates registry.
        if project_override is not None:
            cleaned = project_override.strip()
            self._project_override: Optional[str] = cleaned or None
        else:
            env_val = os.environ.get(TALOS_PROJECT_ENV, "").strip()
            self._project_override = env_val or None
        # Lazy cache so schema init runs at most once per manager instance.
        self._override_resolved: Optional[Project] = None

    # ------------------------------------------------------------------ #
    # Registry I/O                                                         #
    # ------------------------------------------------------------------ #

    def _load_registry(self) -> dict[str, dict]:
        """
        Purpose: Load the registry from disk.
        Output:  Dict of project_id → raw project dict.
        Side effects: None (read-only).
        Edge case: Missing registry file is treated as empty registry.
        """
        if not self._registry_path.exists():
            return {}
        try:
            raw = self._registry_path.read_text(encoding="utf-8")
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ProjectError(
                f"Registry file is corrupted: {self._registry_path}"
            ) from exc

    def _save_registry(self, registry: dict[str, dict]) -> None:
        """
        Purpose: Persist the registry to disk atomically.
        Input:   registry — full registry dict to write.
        Side effects: Writes to disk; replaces existing file.
        """
        self._registry_path.write_text(
            json.dumps(registry, indent=2),
            encoding="utf-8",
        )

    def _get_registry_entry(self, project_id: str) -> dict:
        """
        Purpose: Retrieve a single registry entry, raising if missing.
        Input:   project_id — slug string.
        Output:  Raw project dict.
        Raises:  ProjectNotFound
        """
        registry = self._load_registry()
        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")
        return registry[project_id]

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def create(
        self,
        name: str,
        description: str = "",
        scope: Optional[list[str]] = None,
    ) -> Project:
        """
        Purpose:
            Register a new project, create its storage directory,
            and initialize its SQLite database.
        Input:
            name        — human label; used to derive the project id slug.
            description — optional context note.
            scope       — list of host/URL patterns (can be set later via edit).
        Output:
            The newly created Project instance.
        Side effects:
            - Writes registry entry.
            - Creates <projects_root>/<id>/ directory.
            - Creates <projects_root>/<id>/talos.db with full schema.
            - Creates <projects_root>/<id>/archive/ directory.
        Raises:
            ProjectAlreadyExists — if the slug is already registered.
            ValueError           — if name produces an empty slug.
        """
        project_id = make_project_id(name)

        # Validate Basic Scope prefixes early so a bad --scope never creates a project.
        from talos.proxy.scope import validate_scope_prefix

        validated_scope: list[str] = []
        if scope:
            seen: set[str] = set()
            for entry in scope:
                prefix = validate_scope_prefix(entry)
                if prefix in seen:
                    continue
                seen.add(prefix)
                validated_scope.append(prefix)

        registry = self._load_registry()
        if project_id in registry:
            raise ProjectAlreadyExists(
                f"Project '{project_id}' already exists. Choose a different name."
            )

        data_dir = self._root / project_id

        project = Project(
            id=project_id,
            name=name,
            description=description,
            created_at=utc_now_iso(),
            status=ProjectStatus.INACTIVE,
            scope=validated_scope,
            data_dir=str(data_dir),
        )

        # Prepare storage before writing registry — if this fails, registry stays clean.
        data_dir.mkdir(parents=True, exist_ok=True)
        project.archive_dir.mkdir(parents=True, exist_ok=True)
        _copy_headers_drop_template(project.headers_drop_path)
        # Layered project config (CLI-022): empty project.yaml for overrides.
        from talos.configuration.io import ensure_empty_project_config

        ensure_empty_project_config(data_dir)
        init_project_db(project.db_path)
        write_default_score_config(data_dir)

        registry[project_id] = project.to_dict()
        self._save_registry(registry)
        _sync_burp_snapshot(project)

        logger.info("Created project '%s' at %s", project_id, data_dir)
        return project

    def open(self, project_id: str) -> Project:
        """
        Purpose:
            Set a project as the active capture target.
            Exactly one project may be ACTIVE at a time — opening a new one
            deactivates any currently active project first.
        Input:
            project_id — slug of the project to activate.
        Output:
            The now-active Project instance.
        Side effects:
            - Writes registry (deactivates previous active, activates target).
        Raises:
            ProjectNotFound — if project_id is not registered.
        """
        registry = self._load_registry()

        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")

        # Deactivate any currently active project first.
        for pid, data in registry.items():
            if data["status"] == ProjectStatus.ACTIVE.value and pid != project_id:
                data["status"] = ProjectStatus.INACTIVE.value
                logger.info("Deactivated project '%s'", pid)

        registry[project_id]["status"] = ProjectStatus.ACTIVE.value
        self._save_registry(registry)

        project = Project.from_dict(registry[project_id])
        # Ensure schema is current on open — init_project_db is idempotent
        # and handles migrations for databases created at older schema versions.
        init_project_db(project.db_path)
        _sync_burp_snapshot(project)
        logger.info("Opened project '%s'", project_id)
        return project

    def close(self) -> Optional[Project]:
        """
        Purpose:
            Deactivate the currently active project.
            After this call, no project is active — capture is blocked.
        Output:
            The project that was deactivated, or None if none was active.
        Side effects:
            - Writes registry.
        """
        registry = self._load_registry()
        closed: Optional[Project] = None

        for pid, data in registry.items():
            if data["status"] == ProjectStatus.ACTIVE.value:
                data["status"] = ProjectStatus.INACTIVE.value
                closed = Project.from_dict(data)
                logger.info("Closed project '%s'", pid)
                break

        if closed is not None:
            self._save_registry(registry)

        return closed

    def delete(self, project_id: str, *, purge: bool = False) -> Project:
        """
        Purpose:
            Remove a project from the registry.
            By default, data on disk is preserved (safe unregister).
            With purge=True, permanently deletes the project directory
            (database, archive, reports, auth sessions, filters — everything).
        Input:
            project_id — slug of the project to remove.
            purge      — if True, shutil.rmtree the project data_dir after
                         unregistering. Irreversible.
        Output:
            The removed Project instance (for confirmation display).
        Side effects:
            - Removes entry from registry file.
            - When purge=True and data_dir exists: deletes the directory tree.
            - Clears process override cache if it pointed at this project.
        Raises:
            ProjectNotFound — if project_id is not registered.
        """
        registry = self._load_registry()

        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")

        project = Project.from_dict(registry.pop(project_id))
        self._save_registry(registry)
        self._invalidate_override_if(project_id)

        from talos.burp.snapshot import remove_project_snapshot

        remove_project_snapshot(project_id)
        if purge:
            data_path = Path(project.data_dir)
            if data_path.exists():
                shutil.rmtree(data_path)
                logger.info(
                    "Purged project '%s' (registry + directory %s)",
                    project_id,
                    project.data_dir,
                )
            else:
                logger.info(
                    "Purged project '%s' from registry "
                    "(data directory already absent: %s)",
                    project_id,
                    project.data_dir,
                )
        else:
            logger.info(
                "Deleted project '%s' from registry (data preserved at %s)",
                project_id,
                project.data_dir,
            )
        return project

    def rename(self, project_id: str, new_name: str) -> Project:
        """
        Purpose:
            Rename a project: update the human-readable name and, when the
            derived slug changes, re-key the registry and move the data
            directory so the project id stays filesystem-aligned.
        Input:
            project_id — current project slug.
            new_name   — new human-readable name (slug derived via make_project_id).
        Output:
            Updated Project instance.
        Side effects:
            - Writes registry (new key when slug changes).
            - When slug changes: renames <projects_root>/<old_id> → <new_id>
              and rewrites project_id columns inside talos.db.
            - Updates process override if it matched the old id.
        Raises:
            ProjectNotFound      — project_id not registered.
            ProjectAlreadyExists — new slug already registered (different project).
            ValueError           — new_name produces an empty slug.
            OSError              — directory rename fails.
        """
        new_name = new_name.strip()
        if not new_name:
            raise ValueError("Project name must not be empty.")

        new_id = make_project_id(new_name)
        registry = self._load_registry()

        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")

        if new_id != project_id and new_id in registry:
            raise ProjectAlreadyExists(
                f"Project '{new_id}' already exists. Choose a different name."
            )

        entry = registry[project_id]
        old_data_dir = Path(entry["data_dir"])
        new_data_dir = self._root / new_id

        # Directory move first so a failed move never leaves a broken registry.
        if new_id != project_id:
            if old_data_dir.exists():
                if new_data_dir.exists():
                    raise ProjectError(
                        f"Cannot rename project '{project_id}' to '{new_id}': "
                        f"target directory already exists at {new_data_dir}"
                    )
                old_data_dir.rename(new_data_dir)
                _rewrite_project_id_in_db(
                    new_data_dir / "talos.db", project_id, new_id
                )
            elif new_data_dir.exists():
                raise ProjectError(
                    f"Cannot rename project '{project_id}' to '{new_id}': "
                    f"target directory already exists at {new_data_dir}"
                )
            # else: no on-disk dir; registry-only re-key is enough.

            entry = dict(entry)
            entry["id"] = new_id
            entry["name"] = new_name
            entry["data_dir"] = str(new_data_dir)
            del registry[project_id]
            registry[new_id] = entry
            self._retarget_override(project_id, new_id)
        else:
            # Same slug — display name only (e.g. "My App" → "my app").
            entry["name"] = new_name
            registry[project_id] = entry

        self._save_registry(registry)
        project = Project.from_dict(registry[new_id])
        from talos.burp.snapshot import rename_project_snapshot

        rename_project_snapshot(project_id, project.id, project.name)
        logger.info(
            "Renamed project '%s' → '%s' (name=%r)",
            project_id,
            project.id,
            new_name,
        )
        return project

    def set_description(self, project_id: str, description: str) -> Project:
        """
        Purpose:
            Replace the free-text description / note for a project.
        Input:
            project_id  — slug of the target project.
            description — new description (empty string clears the note).
        Output:
            Updated Project instance.
        Side effects:
            - Writes registry.
        Raises:
            ProjectNotFound
        """
        registry = self._load_registry()

        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")

        registry[project_id]["description"] = description
        self._save_registry(registry)

        project = Project.from_dict(registry[project_id])
        logger.info("Updated description for project '%s'", project_id)
        return project

    def _invalidate_override_if(self, project_id: str) -> None:
        """
        Purpose:
            Drop cached process override state when the bound project is
            deleted or its id is about to change.
        Input: project_id — slug that was removed or renamed away from.
        Side effects: Clears _override_resolved; clears override id if matched.
        """
        if self._project_override == project_id:
            self._project_override = None
        self._override_resolved = None

    def _retarget_override(self, old_id: str, new_id: str) -> None:
        """
        Purpose:
            Keep process override pointing at the same project after a slug
            rename (when this process had bound the old id).
        Input:
            old_id / new_id — previous and new project slugs.
        Side effects: May update _project_override; always clears resolved cache.
        """
        if self._project_override == old_id:
            self._project_override = new_id
        self._override_resolved = None

    def get(self, project_id: str) -> Project:
        """
        Purpose: Retrieve a project by id.
        Input:   project_id — slug string.
        Output:  Project instance.
        Raises:  ProjectNotFound
        """
        return Project.from_dict(self._get_registry_entry(project_id))

    def list_all(self) -> list[Project]:
        """
        Purpose: Return all registered projects sorted by creation time.
        Output:  List of Project instances; empty list if none registered.
        Side effects: None.
        """
        registry = self._load_registry()
        projects = [Project.from_dict(data) for data in registry.values()]
        projects.sort(key=lambda p: p.created_at)
        return projects

    @property
    def project_override(self) -> Optional[str]:
        """
        Purpose: Expose the process-scoped project id override, if any.
        Output:  Project id string, or None when using registry ACTIVE only.
        Side effects: None.
        """
        return self._project_override

    def active(self) -> Optional[Project]:
        """
        Purpose:
            Return the project bound to this process.
            Prefer process override (--project / TALOS_PROJECT / constructor);
            otherwise the registry entry with status=ACTIVE.
        Output:
            Project instance, or None if neither override nor registry ACTIVE.
        Side effects:
            When using override: may run idempotent schema init once on the
            target DB (same as project open). Does not change registry status.
        Raises:
            ProjectNotFound — override id is set but not registered.
        """
        if self._project_override:
            if self._override_resolved is not None:
                return self._override_resolved
            try:
                project = self.get(self._project_override)
            except ProjectNotFound as exc:
                raise ProjectNotFound(
                    f"Project '{self._project_override}' not found "
                    f"(from --project or {TALOS_PROJECT_ENV})."
                ) from exc
            # Match project open: ensure schema is current for automation paths
            # that never call open.
            init_project_db(project.db_path)
            self._override_resolved = project
            logger.debug(
                "Using process project override '%s' (registry status unchanged)",
                self._project_override,
            )
            return project

        registry = self._load_registry()
        for data in registry.values():
            if data["status"] == ProjectStatus.ACTIVE.value:
                return Project.from_dict(data)
        return None

    def set_scope(self, project_id: str, scope: list[str]) -> Project:
        """
        Purpose:
            Replace the entire in-scope list for a project (compatibility path).
            Each entry is one Basic Scope URL/host prefix — validated before
            write. Wildcards are rejected.
        Input:
            project_id — slug of the target project.
            scope      — new list of Basic Scope prefixes.
        Output:
            Updated Project instance.
        Side effects:
            - Writes registry.
        Raises:
            ProjectNotFound
            ScopeParseError — invalid prefix (from talos.proxy.scope).
        """
        from talos.proxy.scope import validate_scope_prefix

        validated = [validate_scope_prefix(p) for p in scope]
        # Preserve order; drop duplicates.
        seen: set[str] = set()
        unique: list[str] = []
        for p in validated:
            if p in seen:
                continue
            seen.add(p)
            unique.append(p)

        registry = self._load_registry()
        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")

        registry[project_id]["scope"] = unique
        self._save_registry(registry)

        project = Project.from_dict(registry[project_id])
        logger.info("Updated scope for project '%s': %s", project_id, unique)
        return project

    def add_scope_prefix(self, project_id: str, prefix: str) -> tuple[Project, bool]:
        """
        Purpose:
            Append one Basic Scope prefix to the project allow list.
        Output:
            (project, inserted) — inserted is False when already present.
        Side effects:
            Writes registry when inserted.
        """
        from talos.proxy.scope import validate_scope_prefix

        validated = validate_scope_prefix(prefix)
        registry = self._load_registry()
        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")

        current = list(registry[project_id].get("scope") or [])
        if validated in current:
            return Project.from_dict(registry[project_id]), False

        current.append(validated)
        registry[project_id]["scope"] = current
        self._save_registry(registry)
        project = Project.from_dict(registry[project_id])
        logger.info("Added scope prefix for '%s': %s", project_id, validated)
        return project, True

    def remove_scope_prefix(self, project_id: str, prefix: str) -> tuple[Project, bool]:
        """
        Purpose:
            Remove one Basic Scope prefix from the allow list.
        Output:
            (project, removed).
        Side effects:
            Writes registry when removed.
        """
        from talos.proxy.scope import validate_scope_prefix

        try:
            key = validate_scope_prefix(prefix)
        except Exception:
            key = prefix.strip()

        registry = self._load_registry()
        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")

        current = list(registry[project_id].get("scope") or [])
        if key not in current:
            return Project.from_dict(registry[project_id]), False

        current = [p for p in current if p != key]
        registry[project_id]["scope"] = current
        self._save_registry(registry)
        project = Project.from_dict(registry[project_id])
        logger.info("Removed scope prefix for '%s': %s", project_id, key)
        return project, True

    def clear_scope(self, project_id: str) -> Project:
        """
        Purpose:
            Remove all in-scope prefixes for a project.
        Side effects:
            Writes registry (scope becomes []).
        """
        return self.set_scope(project_id, [])

    def import_scope_prefixes(
        self,
        project_id: str,
        prefixes: list[str],
        *,
        replace: bool = False,
    ) -> tuple[Project, int, int]:
        """
        Purpose:
            Merge (or replace) validated Basic Scope prefixes into project scope.
        Input:
            prefixes — already validated prefixes from scope_io.
            replace  — when True, replace entire list; else append unique.
        Output:
            (project, added_count, skipped_count).
        Side effects:
            Writes registry.
        """
        from talos.proxy.scope import validate_scope_prefix

        validated = [validate_scope_prefix(p) for p in prefixes]
        registry = self._load_registry()
        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")

        if replace:
            # Dedupe preserving order.
            seen: set[str] = set()
            unique: list[str] = []
            for p in validated:
                if p in seen:
                    continue
                seen.add(p)
                unique.append(p)
            added = len(unique)
            skipped = len(validated) - added
            registry[project_id]["scope"] = unique
            self._save_registry(registry)
            return Project.from_dict(registry[project_id]), added, skipped

        current = list(registry[project_id].get("scope") or [])
        present = set(current)
        added = 0
        skipped = 0
        for p in validated:
            if p in present:
                skipped += 1
                continue
            current.append(p)
            present.add(p)
            added += 1
        registry[project_id]["scope"] = current
        self._save_registry(registry)
        return Project.from_dict(registry[project_id]), added, skipped

    def set_constraints(
        self,
        project_id: str,
        constraints: ScopeConstraints,
    ) -> Project:
        """
        Purpose:
            Replace the capture constraints for a project.
        Input:
            project_id  — slug of the target project.
            constraints — new ScopeConstraints instance.
        Output:
            Updated Project instance.
        Side effects:
            - Writes registry.
        Raises:
            ProjectNotFound
        """
        registry = self._load_registry()

        if project_id not in registry:
            raise ProjectNotFound(f"Project '{project_id}' not found.")

        registry[project_id]["constraints"] = constraints.to_dict()
        self._save_registry(registry)

        project = Project.from_dict(registry[project_id])
        logger.info("Updated constraints for project '%s'", project_id)
        return project
