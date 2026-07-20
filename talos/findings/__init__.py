"""
Package: talos.findings

Purpose:
    Central vulnerability management subsystem for Talos.
    Receives verdicts from attack modules, creates Finding records, manages
    analyst workflow (triage → confirm / reject / duplicate), organises
    findings into PRIMARY/LINKED clusters and user groups, and generates
    vulnerability reports.

    This package owns everything after a verdict is produced:
        - Determining whether a verdict triggers a finding.
        - Creating the finding as PRIMARY or LINKED (cluster identity).
        - Attaching evidence and maintaining the immutable timeline.
        - Managing finding groups (user-defined collections).
        - Generating Markdown vulnerability reports.

Public surface:
    talos.findings.creator  — create_finding_from_verdict()
    talos.findings.db       — all DB CRUD operations (incl. relationships)
    talos.findings.model    — FindingStatus, RelationType, EvidenceType constants
    talos.findings.cli      — run_finding_cli()
    talos.findings.report   — generate_finding_report()

Dependencies: talos.projects.db (schema initialisation)
"""
