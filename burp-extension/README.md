# Talos Burp Suite extension

Groups Talos attack traffic that arrives through Burp (as Talos’s upstream
proxy) into a Site-map-style tree:

```text
Findings
  Unauthenticated Execution (20)
  CORS Misconfiguration (3)
Input Validation
  GET /api/users/{id} (12)
  POST /login (8)
Unauthenticated Execution
  GET /admin (3)
BAC
  POST /api/users/{id} (6)
```

When this extension is loaded it listens on `127.0.0.1:17384`. Talos
posts grouping metadata there so the proxied request has **no**
`X-Talos-*` headers. Burp HTTP history cannot be rewritten by an
extension, so the only way to keep it clean is not to send those
headers in the first place.

If Talos cannot reach the ingest port it falls back to `X-Talos-*`
headers (legacy). Those are still grouped and stripped before the
target, but they will show in HTTP history.

The tree is stored as a **Talos project snapshot**
(`~/.talos/burp/<project-id>.jsonl`), not in the Burp project file.
Each row includes the request and, once the test finishes, the HTTP
response. The tab auto-refreshes that file about once a second.
Bind the tab to one Talos project (picker, or the bind banner). A saved
Burp Professional project remembers that binding; Community / temp
projects start unbound. Traffic from a different Talos project never
merges into the current tree.

## Requirements

- Burp Suite 2023.10+ (Montoya API)
- Java 17+ to build the JAR
- Talos configured to send traffic through Burp

## Typical topology

```text
Browser  →  Talos :8080  (capture)
Talos replay / IV  →  Burp :8081  (upstream)  →  target
```

```bash
talos config set proxy.upstream.url http://127.0.0.1:8081
talos config set burp.enabled true          # default
# optional: talos config set burp.header_prefix X-Talos
```

Headers are attached only when `burp.enabled` is true **and** an upstream
proxy is set. Direct mode never sends `X-Talos-*` to the target.

Reload the JAR after rebuilding. Restart the Talos scheduler so new
probes use ingest instead of headers.

## Build

```bash
cd burp-extension
# Gradle (if installed):
gradle jar
# Or without Gradle (Java 17 + curl):
./build.sh
# JAR: build/libs/talos-burp-1.2.2.jar
```

## Load in Burp

1. Extender → Extensions → Add
2. Extension type: Java
3. Select `burp-extension/build/libs/talos-burp-1.2.2.jar`
4. A **Talos** suite tab appears

## Header contract

Default prefix `X-Talos` (must match `burp.header_prefix`):

| Header | Example | Tree role |
|--------|---------|-----------|
| `X-Talos-Engine` | `input-validation` | Top-level node |
| `X-Talos-Group` | `endpoints` | Group under the engine |
| `X-Talos-Endpoint` | `GET /api/users/{id}` | Endpoint leaf |
| `X-Talos-Endpoint-Id` | Talos endpoint UUID | Stable key |
| `X-Talos-Host` | `api.example.com` | Display |
| `X-Talos-Param` | `username` | Request table |
| `X-Talos-Location` | `body` | Request table |
| `X-Talos-Analysis` | `types` | Request table |
| `X-Talos-Payload-Type` | `type:int` | Request table |
| `X-Talos-Detail` | `parser sid query parser:array_repeat` | Request table |

See `docs/burp-extension.md` for the Talos-side config and operator flow.
