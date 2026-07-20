"""
Module: talos.projects.unauth

Purpose:
    Unauthenticated Access (Unauth) attack module.

    Tests whether application endpoints can be reached without valid
    authentication.

Pipeline per job:
    baseline flow
          ↓
    remove all configured authentication
          ↓
    apply Unauth technique
          ↓
    apply optional request mutation
          ↓
    replay
          ↓
    decision filter
          ↓
    BYPASS | SECURE | UNKNOWN

Authentication removal is mandatory and is not a selectable technique.

The endpoint policy system owns inclusion and exclusion decisions.
No per-attack exclusion logic exists here.

Components:
    variants.py
        Unauth technique definitions.

    recipes.py
        Technique + optional request mutation combinations.

    engine.py
        Mandatory auth stripping, technique application,
        optional request mutation, replay, and verdict storage.

    decision_filter.py
        Load and evaluate unauth-decision-filter.yaml.

    filter_cli.py
        Manage the decision filter file.

    cli.py
        talos attack unauth run / filter subcommands.

Dependencies:
    talos.projects.bac.variants
    talos.replay.db
    talos.projects.db
    talos.projects.auth
"""