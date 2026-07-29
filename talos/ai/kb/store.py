"""
Module: talos.ai.kb.store

Purpose:
    Read-only Markdown knowledge base from a single directory.

    Layout (created empty on first access):
        ~/.talos/ai/kb/*.md

    Operators add/edit files manually (or with any editor). Talos only
    lists, shows, and keyword-searches them. No write tools in v1.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from talos.config import TalosConfig

# Soft cap so a runaway dir cannot flood planner/tool results.
MAX_DOCS = 500
MAX_BODY_CHARS = 64_000
MAX_SNIPPET = 400


@dataclass
class KbDoc:
    """One markdown document from the KB directory."""

    doc_id: str  # relative path without .md, e.g. "idor/checklist"
    path: str  # absolute path string
    title: str
    body: str
    size: int

    def to_dict(self, *, include_body: bool = True) -> dict[str, Any]:
        d: dict[str, Any] = {
            "doc_id": self.doc_id,
            "path": self.path,
            "title": self.title,
            "size": self.size,
        }
        if include_body:
            d["body"] = self.body
        else:
            d["snippet"] = _snippet(self.body)
        return d


def kb_dir(data_dir: Path | None = None) -> Path:
    """Resolve ~/.talos/ai/kb (or <TALOS_DATA_DIR>/ai/kb)."""
    root = data_dir if data_dir is not None else TalosConfig.from_env().data_dir
    return Path(root) / "ai" / "kb"


def ensure_kb_dir(data_dir: Path | None = None) -> Path:
    """Create the KB directory if missing; return it."""
    d = kb_dir(data_dir)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _title_from_body(stem: str, body: str) -> str:
    for line in body.splitlines():
        s = line.strip()
        if s.startswith("#"):
            return s.lstrip("#").strip() or stem
        if s:
            # First non-empty non-heading line as weak title
            return s[:120]
    return stem.replace("-", " ").replace("_", " ")


def _snippet(body: str, n: int = MAX_SNIPPET) -> str:
    text = " ".join(body.split())
    if len(text) <= n:
        return text
    return text[: n - 1] + "…"


def _iter_md_files(root: Path) -> list[Path]:
    if not root.is_dir():
        return []
    files = sorted(root.rglob("*.md"))
    # Skip hidden path segments
    out: list[Path] = []
    for p in files:
        try:
            rel = p.relative_to(root)
        except ValueError:
            continue
        if any(part.startswith(".") for part in rel.parts):
            continue
        out.append(p)
        if len(out) >= MAX_DOCS:
            break
    return out


def _doc_id_for(root: Path, path: Path) -> str:
    rel = path.relative_to(root)
    # Strip .md suffix; use posix-style id
    return rel.with_suffix("").as_posix()


def _load_doc(root: Path, path: Path) -> Optional[KbDoc]:
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    if len(raw) > MAX_BODY_CHARS:
        raw = raw[:MAX_BODY_CHARS]
    doc_id = _doc_id_for(root, path)
    return KbDoc(
        doc_id=doc_id,
        path=str(path.resolve()),
        title=_title_from_body(path.stem, raw),
        body=raw,
        size=len(raw),
    )


def list_docs(
    data_dir: Path | None = None,
    *,
    limit: int = 100,
) -> list[KbDoc]:
    """List markdown docs (body included for small files; use get for one)."""
    root = ensure_kb_dir(data_dir)
    limit = max(1, min(int(limit), MAX_DOCS))
    docs: list[KbDoc] = []
    for path in _iter_md_files(root)[:limit]:
        doc = _load_doc(root, path)
        if doc:
            docs.append(doc)
    return docs


def get_doc(
    doc_id: str,
    data_dir: Path | None = None,
) -> Optional[KbDoc]:
    """
    Load one doc by id (relative path without .md), basename, or absolute path
    under the KB root.
    """
    root = ensure_kb_dir(data_dir)
    needle = (doc_id or "").strip()
    if not needle:
        return None

    # Absolute path only if inside root
    p = Path(needle)
    if p.is_absolute():
        try:
            p.resolve().relative_to(root.resolve())
        except ValueError:
            return None
        if p.suffix.lower() != ".md":
            p = p.with_suffix(".md")
        return _load_doc(root, p) if p.is_file() else None

    # Relative id: "foo/bar" or "foo/bar.md"
    rel = needle[:-3] if needle.lower().endswith(".md") else needle
    candidate = (root / rel).with_suffix(".md")
    try:
        candidate.resolve().relative_to(root.resolve())
    except ValueError:
        return None
    if candidate.is_file():
        return _load_doc(root, candidate)

    # Basename match (first hit)
    base = Path(rel).name
    for path in _iter_md_files(root):
        if path.stem == base or path.name == f"{base}.md":
            return _load_doc(root, path)
    return None


def search_docs(
    query: str,
    data_dir: Path | None = None,
    *,
    limit: int = 10,
) -> list[dict[str, Any]]:
    """
    Purpose:
        Keyword search over title + body (case-insensitive).
        Empty query → list top docs by name (metadata only).
    Output:
        List of dicts with doc_id, title, score, snippet, path.
    """
    root = ensure_kb_dir(data_dir)
    limit = max(1, min(int(limit), 50))
    q = (query or "").strip().lower()
    tokens = [t for t in re.split(r"\s+", q) if t] if q else []

    hits: list[tuple[float, KbDoc]] = []
    for path in _iter_md_files(root):
        doc = _load_doc(root, path)
        if doc is None:
            continue
        if not tokens:
            hits.append((0.0, doc))
            continue
        blob = f"{doc.doc_id} {doc.title}\n{doc.body}".lower()
        score = 0.0
        for tok in tokens:
            if tok in doc.doc_id.lower():
                score += 3.0
            if tok in doc.title.lower():
                score += 2.0
            if tok in blob:
                score += 1.0 + blob.count(tok) * 0.1
        if score > 0:
            hits.append((score, doc))

    hits.sort(key=lambda x: (-x[0], x[1].doc_id))
    results: list[dict[str, Any]] = []
    for score, doc in hits[:limit]:
        results.append(
            {
                "doc_id": doc.doc_id,
                "title": doc.title,
                "score": round(score, 3),
                "snippet": _snippet(doc.body),
                "path": doc.path,
                "size": doc.size,
            }
        )
    return results
