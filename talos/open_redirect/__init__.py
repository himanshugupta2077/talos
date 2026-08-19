"""
Module: talos.open_redirect

Purpose:
    Open-redirect attack module (v1 — simple).

    Operator picks one or more captured flows. The engine walks injectable
    entry points (query, JSON body, form fields, multipart filenames, path
    parameters) and replaces the field with a typed catalogue of absolute,
    protocol-relative, slash-bypass, encoded, userinfo, javascript/data,
    fragment, and CRLF redirect payloads. ``--param`` optionally restricts
    the scan to one entry point. Each probe is one scheduler job and one
    unique replay flow.

    Detection:
        A **new** 3xx Location / Refresh header, meta refresh, or
        JavaScript location assignment that points at the canary host
        (``talos-or.invalid``) or a javascript:/data: sink. Echoed payload
        text in the HTML body is not itself a finding.

    Finding policy:
        - Create a finding on verdict OPEN_REDIRECT only.
        - Cluster OPEN_REDIRECT:<endpoint_id> (PRIMARY + later LINKED).

Dependencies:
    talos.replay.db
    talos.projects.annotations
    talos.scheduler
    talos.findings
    talos.ssrf.inject (shared URL-sink surfaces)
"""
