"""
Module: talos.xss

Purpose:
    XSS / HTML injection attack module (v1 — simple).

    Operator picks one or more captured flows. The engine walks injectable
    entry points on that request (query, JSON body including array indexes,
    form fields, multipart filenames, and path parameters) and injects a
    catalogue of HTML/JS, HTMLI, attribute, event, JS-context, URI,
    encoded, WAF-bypass, and polyglot payloads. ``--param`` optionally
    restricts the scan to one entry point. Each probe is one scheduler
    job and one unique replay flow.

    Detection:
        The canary ``TalosXss`` must appear in the HTTP response. XSS
        requires an unencoded JS sink next to the canary (script, event
        handler, javascript:, alert). HTMLI requires unencoded HTML
        markup without a JS sink. HTML-entity / URL-encoded echo is not
        a finding. Pre-existing page ``<script>`` is not itself a finding.

    Finding policy:
        - Create a finding on verdict XSS or HTMLI.
        - Cluster XSS:<endpoint_id> (PRIMARY + later LINKED).

Dependencies:
    talos.replay.db
    talos.projects.annotations
    talos.scheduler
    talos.findings
    talos.input_validation.surface (injection only)
"""
