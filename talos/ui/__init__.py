"""
Module: talos.ui

Purpose:
    Web UI for Talos — inspection and control surface.
    Provides visibility into captured flows, endpoints, and project state.
    Completely isolated from core processing logic — reads storage directly.

Dependencies: fastapi, jinja2, uvicorn
Data flow:
    talos ui → uvicorn → FastAPI app → read registry.json + SQLite → HTML response
Side effects: None (read-only).
"""
