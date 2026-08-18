"""
Module: talos.smuggle

Purpose:
    HTTP request smuggling (desync) attack module.

    Operator names one or more captured flows. Each technique is one
    scheduler job and one unique replay flow. Probes are sent as raw
    HTTP/1.1 on a direct origin socket so Content-Length / Transfer-Encoding
    conflicts are not normalized by httpx.

    On NTLM / platform-auth hosts the engine completes the Type 1/2/3
    handshake on that same keep-alive connection, then sends the probe.

    Each probe is snapshotted into the Talos Burp tree (engine = smuggle).

Pipeline per job:
    captured flow
          ↓
    raw TCP/TLS to origin (NTLM handshake when configured)
          ↓
    baseline GET → one CL/TE technique → follow-up GET
          ↓
    SMUGGLE | SECURE | UNKNOWN

Finding policy:
    - Issue only on a confirmed desync (poisoned follow-up / canary).
    - Timeout-only is not a finding.
    - Cluster SMUGGLE:<scheme://netloc>.

Dependencies:
    talos.replay.db
    talos.projects.annotations
    talos.proxy.ntlm / platform_auth
    talos.scheduler
    talos.findings
    talos.burp
"""
