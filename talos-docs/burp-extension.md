# Burp Suite integration

**Source of truth:** `talos/burp/` and `burp-extension/`. When this document
disagrees with code, the code wins.

Talos is typically used with Burp as an **upstream proxy**. Attack engines
hand grouping metadata to the Talos Burp extension, which trees traffic
as Engine → Endpoint.

The tree is **not** stored with the Burp project. Talos writes a
per-project snapshot under `~/.talos/burp/<project-id>.jsonl` as
engines run. The extension hydrates that file when the tab is bound
to that Talos project.

Burp **HTTP history always records the original inbound request**.
Extensions cannot rewrite that view (PortSwigger Montoya issue #102).
So when the extension is loaded it listens on `127.0.0.1:17384` and
Talos posts the trace there. The proxied request has **no** `X-Talos-*`
headers — history, Logger, and the target stay clean.

If the extension is not listening, Talos falls back to `X-Talos-*`
headers. The extension still groups and strips those on the last mile,
but they will appear in HTTP history (original inbound).

## Topology

```text
Browser ──► Talos proxy :8080  (capture, MITM)
                 │
                 │  talos config set proxy.upstream.url http://127.0.0.1:8081
                 ▼
            Burp :8081  ──► target
                 │
                 └── Talos extension tab
                       Findings
                         Unauthenticated Execution (20)
                         CORS Misconfiguration (3)
                       Input Validation
                         GET /api/users/{id} (12)
                       Unauthenticated Execution
                       BAC
                       Auth-Session Testing
                       CORS Misconfiguration
                       Intruder
```

Replay / scheduler jobs (IV probes) use the same project upstream URL as
the proxy. They do **not** loop back through Talos :8080.

## Config section (`burp`)

Layered configuration (CLI-022). Defaults are on.

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `burp.enabled` | bool | `true` | Master switch for metadata headers |
| `burp.header_prefix` | string | `X-Talos` | Header name prefix; must match the extension |

```bash
talos config burp
talos config get burp.enabled
talos config set burp.enabled true
talos config set burp.header_prefix X-Talos
talos config set proxy.upstream.url http://127.0.0.1:8081
```

Control Panel: **Talos Config → Settings → Burp Suite**.

Metadata is sent only when **both** are true:

1. `burp.enabled`
2. The project has an upstream proxy URL

Direct mode (no upstream) never talks to the extension and never stamps
headers. Changing `burp.*` or reloading the extension requires a
proxy/scheduler restart so the process cache reloads.

## Input Validation grouping

Every IV probe job stamps `flow_meta["burp"]` before replay:

```text
engine         = input-validation     → tree: "Input Validation"
endpoint_label = METHOD + normalized_path
endpoint_id    = Talos endpoints.id
```

The extension does **not** show a separate "Endpoints" row. Live updates
refresh counts without stealing the selected request.

## Findings grouping

Findings is a first-class top-level node (always first when present):

```text
Findings
  Unauthenticated Execution (20)
  CORS Misconfiguration (3)
  Client-Side Secret Exposure (2)
```

Each child is an attack type. The table lists that type's finding
requests (replay flow when available). Rows persist in the same
per-project snapshot as other engines (`finding:<id>`). Opening a
Talos project backfills findings that were created before this tree
existed.

Wired engines and `X-Talos-Engine` tokens:

| Engine | Token |
|--------|--------|
| Findings | `findings` (always first; grouped by attack type) |
| Input Validation | `input-validation` |
| Unauthenticated Execution | `unauth` |
| BAC | `bac` |
| Auth-Session Testing | `auth-session` |
| CORS Misconfiguration | `cors` |
| Intruder | `intruder` |
| Secret Detection | `passive` |
| Error Intelligence | `error-intel` |

## Header contract

Prefix from `burp.header_prefix` (default `X-Talos`):

| Header | Required | Example |
|--------|----------|---------|
| `{prefix}-Engine` | yes | `input-validation` |
| `{prefix}-Group` | yes | `endpoints` |
| `{prefix}-Endpoint` | yes | `GET /api/users/{id}` |
| `{prefix}-Endpoint-Id` | when known | UUID |
| `{prefix}-Host` | recommended | `api.example.com` |
| `{prefix}-Param` | optional | `username` |
| `{prefix}-Location` | optional | `body` |
| `{prefix}-Analysis` | optional | `types` |
| `{prefix}-Payload-Type` | optional | `type:int` |
| `{prefix}-Technique` | optional | `bac_session_swap` / `reflected` |
| `{prefix}-Variant` | optional | technique variant / test id |
| `{prefix}-Detail` | optional | compact summary for the table |
| `{prefix}-Project` | recommended | Talos project id (gates the tab) |
| `{prefix}-Project-Name` | optional | display name |
| `{prefix}-Record-Id` | optional | stable snapshot / ingest row id |

Values are sanitized (no CR/LF, printable ASCII, max 512 chars).

## Extension

Source and build: `burp-extension/` (Montoya API, Java 17, Burp 2023.10+).

```bash
cd burp-extension && ./build.sh
# or: gradle jar
# Extender → Extensions → Add → Java → build/libs/talos-burp-1.2.2.jar
```

The extension starts a localhost ingest (`GET /health`, `POST /ingest`
on `127.0.0.1:17384`, or the next free port through `17389`; the bound
port is written to `~/.talos/burp-ingest.port`).

A **proxy** handler claims the matching ingest (method + host + path)
and records the clean request in the Talos tab. Legacy `{prefix}-*`
headers are still parsed and stripped if an older Talos process stamped
them. An **HTTP** handler is the last-mile strip for that fallback.

## Project binding

The Talos tab is bound to **one Talos project id**. Trees never mix.

- Snapshots: `~/.talos/burp/<project-id>.jsonl` (written by Talos as
  tests run; request + grouping metadata + response when the test
  completes). The Talos tab auto-refreshes that file about once a
  second, so new probes and their responses appear without clicking
  Refresh.
- **Burp Professional saved project:** the binding (`talos_project_id`)
  is stored in that Burp project's `extensionData`. Reopening the Burp
  project hydrates the matching snapshot.
- **Community / temp / unbound:** do not guess. Empty tree + project
  picker. Pick a snapshot, or accept the first inbound project's
  "Bind?" banner.
- Live traffic tagged with a **different** project id is not merged.
  A banner offers Switch / Ignore.

```text
~/.talos/burp/acme.jsonl    ← Input Validation, BAC, …
~/.talos/burp/beta.jsonl
```

## Code map

| Piece | Role |
|-------|------|
| `talos.configuration` `burp` section | Layered knobs + schema |
| `talos.burp.config` | Process-cached runtime knobs |
| `talos.burp.trace` | `flow_meta["burp"]` + attach helpers |
| `talos.burp.snapshot` | Per-project JSONL under `~/.talos/burp/` |
| `talos.burp.outbound` | `prepare_send_headers` for IV / unauth / BAC / auth-session / CORS / Intruder |
| `talos.burp.headers` | Build / sanitize / apply |
| `talos.scheduler.scheduler._execute_iv_job` | `attach_iv_burp_trace` |
| `talos.replay.engine._execute_replay` | Apply headers when policy allows |
| `burp-extension/` | Burp suite tab + strip handler |
