---
description: Describe when these instructions should be loaded by the agent based on task context
# applyTo: 'Describe when these instructions should be loaded by the agent based on task context' # when provided, instructions will automatically be added to the request context when the pattern matches an attached file
---

<!-- Tip: Use /create-instructions in chat to generate content with agent assistance -->

# TALOS — Full System Notes (MITM-Based Web App Pentest Automation)

---

# 1. Core Philosophy

* MITM proxy is the **central intelligence layer**
* Manual browser provides **real state + authenticated traffic**
* System converts traffic → **structured, replayable attack surface**
* Deterministic engine first, AI layered on top
* Focus:

  * state
  * identity
  * relationships
  * sequence

---

# 2. High-Level Architecture

```
Browser (manual)
    ↓
mitmproxy (mitmdump)
    ↓
Talos Addon (capture only)
    ↓
Queue
    ↓
Workers (processing engine)
    ↓
Storage (DB + raw archive)
    ↓
Replay Engine
    ↓
Diff Engine
    ↓
Attack Modules
    ↓
AI (MPC layer)
```

---

# 3. Technology Stack

## Core

* Python 3.11+
* mitmproxy (mitmdump mode)

## Storage

* Start: SQLite (WAL enabled)
* Later: PostgreSQL

## Replay

* httpx (async)

## Queue

* Start: Python queue
* Later: Redis + RQ / Celery

## Interface

* CLI first
* Later: FastAPI (thin UI layer)

---

# 4. Proxy Layer (mitmproxy)

## Responsibilities

* TLS interception
* capture request/response
* minimal processing only

## Hook

```python
def response(flow):
    if not in_scope(flow):
        return
    enqueue(flow)
```

## Strict rule

* NO heavy logic inside proxy thread

---

# 5. Queue System

## Purpose

Decouple:

* fast capture
* slow processing

## Flow

```
proxy → queue → workers
```

## Benefits

* prevents blocking
* handles traffic spikes
* enables scaling

## Evolution

* Stage 1: in-memory queue
* Stage 2: Redis-backed queue

---

# 6. Flow Capture Model

Capture:

* full request
* full response
* timestamps
* headers
* cookies
* body (truncate if large)

---

## Connection Grouping

Purpose: reconstruct flows

Signals:

* referer header
* redirect chains
* timing proximity
* shared parameters (e.g., order_id across requests)

---

# 7. Normalization Pipeline

## Steps

### 1. Strip Noise

#### Tracking Parameters

* utm_source
* utm_campaign
* fbclid
* gclid

#### Cache Busters

* `_t=timestamp`
* random query params

---

### 2. Canonicalize URLs

* remove trailing slashes
* sort query params
* normalize duplicate paths
* unify equivalent endpoints

---

### 3. Extract Data

* query params
* body params
* JSON structure
* headers
* cookies

---

# 8. Storage Design

## Do NOT use JSON as primary store

Problems:

* no indexing
* slow queries
* no relationships
* duplication
* concurrency issues

---

## Database (Primary)

Tables:

* flows
* endpoints
* parameters
* sessions
* replays
* anomalies

---

## Raw Archive (Secondary)

* compressed raw HTTP
* used for:

  * debugging
  * reprocessing
  * audit

Format:

* JSONL / blobs

---

# 9. Session System

## Purpose

Separate identities cleanly

## Detection

From:

* cookies
* Authorization headers
* tokens

---

## Model

```
session_id:
  auth_type
  token/cookie signature
```

---

## Manual Override

User defines:

* current role (admin, user, etc.)

---

# 10. Role + Module Tagging

User sets:

```
role = admin
module = billing
project = X
```

Each flow tagged accordingly.

---

## Important

* Role separation must be strict
* No mixing sessions across roles

---

# 11. Endpoint Model

Cluster using:

```
(method + normalized_path)
```

---

## Structure

```
endpoint:
  id
  method
  path
  normalized_path
  params
  auth_required
  roles_seen
  content_type
  examples
```

---

# 12. Parameter Intelligence

## For each parameter

### Type

* int
* uuid
* hash
* enum
* json
* bool

---

### Source

* user-controlled
* server-generated

---

### Volatility

* static
* dynamic

---

### Sensitivity

* identifier (user_id)
* control flag (role, is_admin)
* data field

---

### Relationship Tracking

* appears across endpoints?
* reused in sequences?

---

# 13. Replay Engine

## Requirements

* exact request replay
* async execution
* high reliability

---

## Tool

* httpx

---

## Capabilities

* modify params
* modify headers
* change session
* parallel execution

---

## Token Refresh Hooks

Dynamic values:

* CSRF tokens
* JWT rotation
* nonce

---

### Mechanism

Extract:

* regex / JSONPath

Inject:

* header / param

---

## Dependency Handling

Example:

* request A returns order_id
* request B uses order_id

System:

* auto extract
* auto inject during replay

---

# 14. Diff Engine

## Compare

* status code
* response length
* JSON structure
* key fields
* headers

---

## Anomaly Signals

* 403 → 200 (high)
* new fields appear (high)
* error → success (high)
* large length delta (medium)

---

# 15. Attack Modules

## 1. IDOR

* swap identifiers across sessions

---

## 2. Auth Bypass

* remove tokens
* modify tokens
* mix sessions

---

## 3. Parameter Tampering

* remove param
* null value
* duplicate param
* change type

---

## 4. Boundary Values

* 0
* -1
* max int
* empty string
* long strings

---

## 5. Method Switching

* GET ↔ POST
* PUT ↔ PATCH

---

## 6. Replay Attacks

* repeat sensitive requests
* detect idempotency issues

---

# 16. Role-Based Attack Logic

For each endpoint:

* identify allowed roles
* replay with:

  * other roles
  * no auth
  * mixed auth

---

## Goal

Detect broken access control

---

# 17. Module Strategy

Modules are:

* human-defined
* for organization only

Engine must:

* operate per endpoint
* not depend on module boundaries

---

# 18. Global vs Local Testcases

## Global

* login
* JWT issues
* password reset
* session flaws

---

## Local (per endpoint)

* access control
* injection
* validation
* file upload

---

# 19. State Graph (Critical)

## Structure

```
node = endpoint
edge = transition
```

---

## Tracks

* sequence
* dependencies
* auth state

---

## Purpose

* reconstruct workflows
* enable sequence attacks

---

# 20. MPC (AI Layer)

## Tools

* list_endpoints
* get_endpoint
* get_param_profile
* get_sessions
* replay
* cross_session_replay
* diff
* get_anomalies

---

## AI Responsibilities

* choose targets
* choose attack strategies
* interpret results
* chain attacks

---

## AI Restrictions

* no raw request building
* no blind fuzzing

---

## Resources Provided

* endpoint graph
* param intelligence
* session map
* anomaly history

---

# 21. Execution Phases

## Phase 1 — Capture

* manual browsing
* role defined
* module defined

---

## Phase 2 — Structuring

* endpoint clustering
* param analysis
* session mapping

---

## Phase 3 — Attack

* deterministic modules first
* AI-driven exploration later

---

# 22. CLI Interface (Primary)

Examples:

```
talos set-role admin
talos set-module billing
talos list-endpoints
talos replay --endpoint 12 --session user
talos run-test idor
```

---

## Principle

CLI = core interface

---

# 23. UI (Later)

* FastAPI backend
* thin frontend
* calls same core logic

---

# 24. Performance Constraints

* async replay
* multiprocessing workers
* indexed DB
* avoid large memory usage
* truncate large bodies

---

# 25. Critical Failure Modes

* processing inside proxy thread
* mixing sessions
* unreliable replay
* no normalization
* over-reliance on AI
* over-engineering modules

---

# 26. Minimum Viable Talos

System is valid when it can:

1. capture traffic reliably
2. normalize and store correctly
3. separate sessions cleanly
4. cluster endpoints
5. replay requests with valid tokens
6. perform cross-session replay
7. detect:

   * IDOR
   * missing auth
   * basic tampering effects

---

# 27. Long-Term Evolution

## Phase 2

* workflow reconstruction
* sequence attacks
* race conditions
* JS endpoint extraction

---

## Phase 3

* stealth browser integration
* partial automation

---

# 28. Core Principle (Final)

Deterministic system must work without AI.

AI operates on top of:

* clean data
* reliable replay
* structured state

Without that, system collapses.
