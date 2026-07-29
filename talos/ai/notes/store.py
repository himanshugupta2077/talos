"""
Module: talos.ai.notes.store

Purpose:
    Persist structured app notes with optimistic revision concurrency and
    revision history. Enforces size limits and basic control-char stripping.
    No credential redaction — Talos AI is intended for authorized public bug
    bounty / pentest engagements where target HTTP data is in scope.

Dependencies: json, sqlite3, uuid, talos.projects.db
Data flow:
    CLI / tools → store → ai_app_notes + ai_app_note_revisions
Side effects:
    INSERT/UPDATE notes tables; migrate_project_db.
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from talos.ai.notes.schema import (
    ALLOWLISTED_ROOT_KEYS,
    HYPOTHESIS_STATUSES,
    MAX_DOC_BYTES,
    MAX_FREE_TEXT_CHARS,
    MAX_HYPOTHESES,
    MAX_INTERESTING_ENDPOINTS,
    MAX_PATCH_OPS,
    empty_document,
    normalize_document,
)
from talos.projects.db import migrate_project_db

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

# High-signal prompt-injection patterns (still store; mark tainted for planner pack).
_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?", re.I),
    re.compile(r"\bsystem\s*:", re.I),
    re.compile(r"\b(project|role|module)\.(delete|create|rename)\b", re.I),
    re.compile(r"\byou\s+are\s+now\b", re.I),
    re.compile(r"\bdisregard\s+(your|the)\s+(rules|system)\b", re.I),
)


class NotesError(Exception):
    """Base notes store error."""


class NotesRevisionConflict(NotesError):
    """Optimistic concurrency mismatch (if_revision)."""

    def __init__(self, expected: int, actual: int):
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Notes revision conflict: expected {expected}, current is {actual}."
        )


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _strip_controls(text: str) -> str:
    if not text:
        return ""
    return _CONTROL_CHARS.sub("", str(text))


def _detect_injection(text: str) -> bool:
    if not text:
        return False
    for pat in _INJECTION_PATTERNS:
        if pat.search(text):
            return True
    return False


@dataclass
class NotesSnapshot:
    """Current notes row for a project."""

    project_id: str
    revision: int
    doc: dict[str, Any]
    updated_at: str
    updated_by: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_id": self.project_id,
            "revision": self.revision,
            "doc": self.doc,
            "updated_at": self.updated_at,
            "updated_by": self.updated_by,
        }


class NotesStore:
    """Thin class façade over module functions (optional DI)."""

    def __init__(self, db_path: Path, project_id: str) -> None:
        self.db_path = db_path
        self.project_id = project_id

    def get(self) -> NotesSnapshot:
        return get_notes(self.db_path, self.project_id)

    def replace(
        self,
        doc: dict[str, Any],
        *,
        if_revision: Optional[int] = None,
        updated_by: str = "operator",
    ) -> NotesSnapshot:
        return replace_notes(
            self.db_path,
            self.project_id,
            doc,
            if_revision=if_revision,
            updated_by=updated_by,
        )

    def patch(
        self,
        ops: list[dict[str, Any]],
        *,
        if_revision: int,
        updated_by: str = "ai",
    ) -> NotesSnapshot:
        return patch_notes(
            self.db_path,
            self.project_id,
            ops,
            if_revision=if_revision,
            updated_by=updated_by,
        )


def get_notes(db_path: Path, project_id: str) -> NotesSnapshot:
    """
    Purpose: Load current app notes (empty document if never written).
    Side effects: migrate_project_db.
    """
    migrate_project_db(db_path)
    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT project_id, revision, doc_json, updated_at, updated_by "
            "FROM ai_app_notes WHERE project_id = ?",
            (project_id,),
        ).fetchone()
    if row is None:
        return NotesSnapshot(
            project_id=project_id,
            revision=0,
            doc=empty_document(),
            updated_at="",
            updated_by="",
        )
    try:
        raw = json.loads(row["doc_json"] or "{}")
    except json.JSONDecodeError:
        raw = {}
    return NotesSnapshot(
        project_id=row["project_id"],
        revision=int(row["revision"]),
        doc=normalize_document(raw if isinstance(raw, dict) else {}),
        updated_at=row["updated_at"] or "",
        updated_by=row["updated_by"] or "",
    )


def _normalize_free_text(value: Any) -> str:
    text = _strip_controls(str(value or ""))
    if len(text) > MAX_FREE_TEXT_CHARS:
        text = text[:MAX_FREE_TEXT_CHARS]
    return text


def _sanitize_document(doc: dict[str, Any]) -> dict[str, Any]:
    """
    Enforce structure, size limits, control-char strip. No secret redaction.
    Marks tainted=True when high-signal injection phrases appear.
    """
    out = normalize_document(doc)
    tainted = bool(out.get("tainted"))
    blob_parts: list[str] = []

    def _s(value: Any) -> str:
        text = _normalize_free_text(value)
        blob_parts.append(text)
        return text

    out["app_class"] = _s(out.get("app_class", ""))
    out["auth_model"] = _s(out.get("auth_model", ""))
    out["summary"] = _s(out.get("summary", ""))

    tech: list[str] = []
    for item in out.get("tech_stack") or []:
        t = _s(item)
        if t:
            tech.append(t)
    out["tech_stack"] = tech[:50]

    endpoints: list[Any] = []
    for item in out.get("interesting_endpoints") or []:
        if isinstance(item, str):
            endpoints.append(_s(item))
        elif isinstance(item, dict):
            # Shallow string cleanup only — no credential masking.
            cleaned: dict[str, Any] = {}
            for k, v in item.items():
                if isinstance(v, str):
                    cleaned[str(k)] = _s(v)
                else:
                    cleaned[str(k)] = v
            endpoints.append(cleaned)
            blob_parts.append(json.dumps(cleaned, sort_keys=True, default=str))
        else:
            endpoints.append(_s(item))
    out["interesting_endpoints"] = endpoints[:MAX_INTERESTING_ENDPOINTS]

    hyps: list[dict[str, Any]] = []
    for item in out.get("hypotheses") or []:
        if not isinstance(item, dict):
            continue
        hid = str(item.get("id") or uuid.uuid4())
        status = str(item.get("status") or "open").lower()
        if status not in HYPOTHESIS_STATUSES:
            status = "open"
        try:
            conf = float(item.get("confidence", 0.0))
        except (TypeError, ValueError):
            conf = 0.0
        conf = max(0.0, min(1.0, conf))
        text = _s(item.get("text") or item.get("hypothesis") or "")
        evidence = item.get("evidence_refs") or {}
        if not isinstance(evidence, dict):
            evidence = {}
        hyps.append(
            {
                "id": hid,
                "text": text,
                "status": status,
                "confidence": conf,
                "evidence_refs": evidence,
            }
        )
    out["hypotheses"] = hyps[:MAX_HYPOTHESES]

    if _detect_injection("\n".join(blob_parts)):
        tainted = True
    out["tainted"] = tainted

    encoded = json.dumps(out, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > MAX_DOC_BYTES:
        raise NotesError(
            f"Notes document exceeds max size ({MAX_DOC_BYTES} bytes)."
        )
    return out


def replace_notes(
    db_path: Path,
    project_id: str,
    doc: dict[str, Any],
    *,
    if_revision: Optional[int] = None,
    updated_by: str = "operator",
) -> NotesSnapshot:
    """
    Purpose:
        Replace the full notes document (operator CLI edit). Optimistic
        concurrency when if_revision is set.
    """
    migrate_project_db(db_path)
    sanitized = _sanitize_document(doc)
    now = _now_iso()
    doc_json = json.dumps(sanitized, ensure_ascii=False, sort_keys=True)

    with _connect(db_path) as conn:
        row = conn.execute(
            "SELECT revision FROM ai_app_notes WHERE project_id = ?",
            (project_id,),
        ).fetchone()
        current_rev = int(row["revision"]) if row else 0
        if if_revision is not None and if_revision != current_rev:
            raise NotesRevisionConflict(if_revision, current_rev)

        if row is None:
            new_rev = 1
            conn.execute(
                "INSERT INTO ai_app_notes "
                "(project_id, revision, doc_json, updated_at, updated_by) "
                "VALUES (?, ?, ?, ?, ?)",
                (project_id, new_rev, doc_json, now, updated_by),
            )
        else:
            new_rev = current_rev + 1
            cur = conn.execute(
                "UPDATE ai_app_notes SET revision = ?, doc_json = ?, "
                "updated_at = ?, updated_by = ? WHERE project_id = ? AND revision = ?",
                (new_rev, doc_json, now, updated_by, project_id, current_rev),
            )
            if cur.rowcount == 0:
                raise NotesRevisionConflict(current_rev, current_rev)

        conn.execute(
            "INSERT INTO ai_app_note_revisions "
            "(id, project_id, revision, doc_json, updated_at, updated_by) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), project_id, new_rev, doc_json, now, updated_by),
        )
        conn.commit()

    return NotesSnapshot(
        project_id=project_id,
        revision=new_rev,
        doc=sanitized,
        updated_at=now,
        updated_by=updated_by,
    )


def _apply_ops(doc: dict[str, Any], ops: list[dict[str, Any]]) -> dict[str, Any]:
    """Apply allowlisted JSON-patch-like operations; raises NotesError."""
    if not isinstance(ops, list):
        raise NotesError("ops must be a list")
    if len(ops) > MAX_PATCH_OPS:
        raise NotesError(f"Too many patch ops (max {MAX_PATCH_OPS})")

    out = normalize_document(doc)

    for i, op in enumerate(ops):
        if not isinstance(op, dict):
            raise NotesError(f"ops[{i}] must be an object")
        action = str(op.get("op") or "").lower()
        path = str(op.get("path") or "")
        if not path.startswith("/"):
            raise NotesError(f"ops[{i}].path must start with /")
        parts = [p for p in path.split("/") if p != ""]
        if not parts:
            raise NotesError(f"ops[{i}].path is empty")
        root = parts[0]
        if root not in ALLOWLISTED_ROOT_KEYS:
            raise NotesError(f"ops[{i}].path root not allowlisted: /{root}")

        if action not in ("add", "replace", "remove"):
            raise NotesError(f"ops[{i}].op must be add|replace|remove")

        if root in ("tech_stack", "interesting_endpoints") and len(parts) == 1:
            if action == "remove":
                out[root] = []
            else:
                val = op.get("value")
                if not isinstance(val, list):
                    raise NotesError(f"ops[{i}].value must be array for /{root}")
                out[root] = list(val)
            continue

        if root in ("tech_stack", "interesting_endpoints") and parts[-1] == "-":
            if action not in ("add", "replace"):
                raise NotesError(f"ops[{i}]: append requires add/replace")
            if not isinstance(out[root], list):
                out[root] = []
            out[root].append(op.get("value"))
            continue

        if root in ("app_class", "auth_model", "summary") and len(parts) == 1:
            if action == "remove":
                out[root] = ""
            else:
                out[root] = op.get("value", "")
            continue

        if root == "hypotheses":
            if len(parts) == 1 and action in ("add", "replace"):
                val = op.get("value")
                if not isinstance(val, list):
                    raise NotesError("ops value for /hypotheses must be array")
                out["hypotheses"] = list(val)
                continue
            if len(parts) == 2 and parts[1] == "-":
                if action not in ("add", "replace"):
                    raise NotesError("hypothesis append requires add/replace")
                hyp = op.get("value")
                if not isinstance(hyp, dict):
                    raise NotesError("hypothesis value must be object")
                if "id" not in hyp:
                    hyp = {**hyp, "id": str(uuid.uuid4())}
                hyps = list(out.get("hypotheses") or [])
                hyps.append(hyp)
                out["hypotheses"] = hyps
                continue
            if len(parts) >= 2:
                hid = parts[1]
                hyps = list(out.get("hypotheses") or [])
                idx = next(
                    (j for j, h in enumerate(hyps) if str(h.get("id")) == hid),
                    None,
                )
                if action == "remove" and len(parts) == 2:
                    if idx is None:
                        raise NotesError(f"hypothesis not found: {hid}")
                    hyps.pop(idx)
                    out["hypotheses"] = hyps
                    continue
                if idx is None:
                    raise NotesError(f"hypothesis not found: {hid}")
                if len(parts) == 3:
                    field = parts[2]
                    if field not in (
                        "status",
                        "confidence",
                        "evidence_refs",
                        "text",
                    ):
                        raise NotesError(
                            f"ops[{i}]: hypothesis field not allowlisted: {field}"
                        )
                    if action == "remove":
                        if field == "text":
                            hyps[idx]["text"] = ""
                        elif field == "evidence_refs":
                            hyps[idx]["evidence_refs"] = {}
                        elif field == "confidence":
                            hyps[idx]["confidence"] = 0.0
                        elif field == "status":
                            hyps[idx]["status"] = "open"
                    else:
                        hyps[idx][field] = op.get("value")
                    out["hypotheses"] = hyps
                    continue
            raise NotesError(f"ops[{i}]: unsupported hypotheses path {path}")

        raise NotesError(f"ops[{i}]: unsupported path {path}")

    return out


def patch_notes(
    db_path: Path,
    project_id: str,
    ops: list[dict[str, Any]],
    *,
    if_revision: int,
    updated_by: str = "ai",
) -> NotesSnapshot:
    """
    Purpose:
        Apply allowlisted structural patches with mandatory if_revision.
    """
    current = get_notes(db_path, project_id)
    if current.revision != if_revision:
        raise NotesRevisionConflict(if_revision, current.revision)
    patched = _apply_ops(current.doc, ops)
    return replace_notes(
        db_path,
        project_id,
        patched,
        if_revision=if_revision if current.revision > 0 else None,
        updated_by=updated_by,
    )


def pack_for_planner(
    snapshot: NotesSnapshot,
    *,
    include_tainted: bool = False,
) -> dict[str, Any]:
    """
    Purpose:
        Build a summary for PlanRequest.notes_pack.
        Tainted notes are excluded unless include_tainted.
    """
    doc = snapshot.doc or empty_document()
    if doc.get("tainted") and not include_tainted:
        return {
            "revision": snapshot.revision,
            "excluded": True,
            "reason": "tainted",
            "tainted": True,
        }
    open_hyps = [
        {
            "id": h.get("id"),
            "text": (h.get("text") or "")[:500],
            "status": h.get("status"),
            "confidence": h.get("confidence"),
        }
        for h in (doc.get("hypotheses") or [])
        if isinstance(h, dict) and h.get("status") == "open"
    ][:20]
    return {
        "revision": snapshot.revision,
        "excluded": False,
        "tainted": bool(doc.get("tainted")),
        "app_class": (doc.get("app_class") or "")[:200],
        "auth_model": (doc.get("auth_model") or "")[:200],
        "tech_stack": list(doc.get("tech_stack") or [])[:20],
        "interesting_endpoints": list(doc.get("interesting_endpoints") or [])[:20],
        "open_hypotheses": open_hyps,
        "summary": (doc.get("summary") or "")[:1000],
    }


__all__ = [
    "NotesError",
    "NotesRevisionConflict",
    "NotesSnapshot",
    "NotesStore",
    "empty_document",
    "get_notes",
    "pack_for_planner",
    "patch_notes",
    "replace_notes",
]
