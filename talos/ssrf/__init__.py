"""
Module: talos.ssrf

Purpose:
    SSRF attack module (v1 — simple).

    Operator picks one or more captured flows. The engine walks injectable
    entry points on that request (query, JSON body including array indexes,
    form fields, multipart filenames, and path parameters) and replaces the
    field with a catalogue of loopback, cloud-metadata, protocol, encoding,
    filter-bypass, and (optionally) Burp Collaborator / OAST payloads.
    ``--param`` optionally restricts the scan to one entry point. Each probe
    is one scheduler job and one unique replay flow.

    Collaborator:
        Optional ``--collaborator`` (Burp Collaborator / OAST host or URL).
        When set, OAST-family payloads are included with a unique subdomain
        per probe so the operator can correlate hits in Burp. Talos does
        not poll Collaborator; HTTP-response filters still confirm in-band.

    Detection:
        Cloud-metadata documents, well-known file contents (file://),
        internal-service banners, and Collaborator HTTP bodies that are
        **new versus the captured baseline**. Echoed payload text is not
        itself a finding. Blind OAST is confirmed in Burp Collaborator.

    Finding policy:
        - Create a finding on verdict SSRF only.
        - Cluster SSRF:<endpoint_id> (PRIMARY + later LINKED).

Dependencies:
    talos.replay.db
    talos.projects.annotations
    talos.scheduler
    talos.findings
    talos.input_validation.surface (injection only)
"""
