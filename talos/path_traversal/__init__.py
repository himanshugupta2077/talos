"""
Module: talos.path_traversal

Purpose:
    Path traversal / LFI attack module (v1 — simple).

    Operator picks one or more captured flows. The engine walks injectable
    entry points on that request (query, JSON body including array indexes,
    form fields, multipart filenames, and path parameters) and replaces the
    field with a catalogue of Unix, Windows, encoded, wrapper, null-byte,
    and filter-bypass payloads. ``--param`` optionally restricts the scan
    to one entry point. Each probe is one scheduler job and one unique
    replay flow.

    Detection:
        File-content signatures that are **new versus the captured baseline**
        (``/etc/passwd``, ``win.ini``, PHP filter base64 of those files,
        ``/proc/version``, ``web.config``, …). Pre-existing page text that
        happens to mention ``localhost`` is not itself a finding.

    Finding policy:
        - Create a finding on verdict PATH_TRAVERSAL only.
        - Cluster PATH_TRAVERSAL:<endpoint_id> (PRIMARY + later LINKED).

Dependencies:
    talos.replay.db
    talos.projects.annotations
    talos.scheduler
    talos.findings
    talos.input_validation.surface (injection only)
"""
