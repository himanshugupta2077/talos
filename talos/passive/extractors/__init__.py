"""
Package: talos.passive.extractors

Purpose:
    Extract virtual SourceDocuments from composite response bodies
    (source maps, HTML inline scripts / bootstrap JSON) without outbound HTTP.

    Phase 10: sourcemap.sourcesContent → virtual javascript documents.
    Phase 11: HTML inline <script> without src + bootstrap JSON islands.

Dependencies: talos.passive.extractors.{sourcemap, html}
Data flow: body text → extract_*_virtual_docs → list[SourceDocument]
Side effects: None (pure extraction; worker persists results).
"""

from talos.passive.extractors.html import extract_html_virtual_docs
from talos.passive.extractors.sourcemap import (
    extract_sourcemap_virtual_docs,
    parse_sourcemap_json,
)

__all__ = [
    "extract_sourcemap_virtual_docs",
    "parse_sourcemap_json",
    "extract_html_virtual_docs",
]
