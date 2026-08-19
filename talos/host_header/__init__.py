"""
Module: talos.host_header

Purpose:
    Host-header injection attack module (v1 — simple).

    Operator picks one or more captured flows. The engine mutates Host and
    related override headers (X-Forwarded-Host, X-Host, Forwarded, …) with a
    typed catalogue of absolute, port, ambiguous-parse, absolute-URL, encoded,
    bypass, and CRLF payloads. Connection always stays on the captured origin
    (unlike BAC host-fuzz, which is routing/bypass). ``--header`` / ``--param``
    optionally restricts the scan to one header. Each probe is one scheduler
    job and one unique replay flow.

    Detection:
        Attacker canary (``talos-hhi.invalid``) or other payload host appears
        **new versus the captured baseline** in URL-shaped HTTP response
        sinks: Location / Refresh / Link, CORS ACAO, Set-Cookie Domain, CSP,
        HTML href/src/action, JSON URLs. Raw payload echo that is not a URL
        is not itself a finding.

    Finding policy:
        - Create a finding on verdict HOST_HEADER only.
        - Cluster HOST_HEADER:<endpoint_id> (PRIMARY + later LINKED).

Dependencies:
    talos.replay.db
    talos.projects.annotations
    talos.scheduler
    talos.findings
"""
