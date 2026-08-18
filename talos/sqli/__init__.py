"""
Module: talos.sqli

Purpose:
    SQL injection attack module (v1 — simple).

    Operator picks one or more captured flows. The engine walks every
    injectable entry point on that request (query, JSON body including
    array indexes, form fields) and sends a small catalogue of error,
    UNION, boolean, and time payloads. Each probe is one scheduler job
    and one unique replay flow.

    Detection:
        - New DBMS error signatures vs the captured baseline
          (covers the common SQL Server / MySQL / Postgres / Oracle /
          SQLite leaks, including ODBC conversion / syntax errors).
        - UNION column-count error strings
        - Time delay on WAITFOR / SLEEP / pg_sleep payloads

    Finding policy:
        - Create a finding on verdict SQLI only.
        - Cluster SQLI:<endpoint_id> (PRIMARY + later LINKED).

Dependencies:
    talos.replay.db
    talos.projects.annotations
    talos.scheduler
    talos.findings
    talos.input_validation.surface (injection only)
"""
