# BAC Decision Filter — Configuration Reference

## Overview

`BAC-decision-filter.yaml` is a per-project configuration file that tells Talos how to classify each replayed HTTP response during a BAC (Broken Access Control) attack.

Without this file, Talos falls back to a built-in status-code heuristic:
- `401` / `403` / `3xx` → `SECURE`
- `200` → `POSSIBLE_BAC`
- Anything else → `UNKNOWN`

With the filter, you define application-specific patterns so verdicts are accurate regardless of how your application signals authorization enforcement.

---

## File Location

```
~/.talos/projects/<project-id>/BAC-decision-filter.yaml
```

### Quick setup

```bash
talos attack bac filter init      # create starter file
# Edit the file
talos attack bac filter validate  # check syntax and structure
talos attack bac filter show      # review active config
```

---

## Evaluation Order

```
Replay Response
      │
      ▼
Evaluate failed_detection
      │
      ├── Match  →  POSSIBLE_BAC
      │
      ▼
Evaluate passed_detection
      │
      ├── Match  →  SECURE
      │
      ▼
UNKNOWN
```

`failed_detection` always has higher priority. If both sections match, `POSSIBLE_BAC` wins.

---

## Top-Level Structure

```yaml
version: 1

passed_detection:
  group_operator: OR
  groups: [...]

failed_detection:
  group_operator: OR
  groups: [...]
```

| Field | Required | Description |
|-------|----------|-------------|
| `version` | Yes | Config schema version. Always `1`. |
| `passed_detection` | No | Patterns that prove authorization was enforced → `SECURE`. |
| `failed_detection` | No | Patterns that prove authorization was bypassed → `POSSIBLE_BAC`. |

Both sections are optional, but a filter with neither configured always returns `UNKNOWN`.

---

## Detection Sections

Each section contains rule groups combined by `group_operator`.

```yaml
passed_detection:
  group_operator: OR     # any group can match
  groups:
    - ...
    - ...
```

| Field | Values | Default | Description |
|-------|--------|---------|-------------|
| `group_operator` | `OR` \| `AND` | `OR` | How groups within this section are combined. `OR` means any group matching is sufficient. `AND` means all groups must match (rarely needed). |
| `groups` | list | — | One or more rule groups. |

---

## Rule Groups

A group represents one authorization outcome pattern (e.g. "401 + Unauthorized body").

```yaml
- id: redirect_to_login          # optional — used in result explanation
  operator: AND
  rules:
    - ...
    - ...
```

| Field | Values | Default | Description |
|-------|--------|---------|-------------|
| `id` | string | `group_0`, `group_1`, ... | Optional name. Appears in `matched_group_id` in the result for explainability. |
| `operator` | `AND` \| `OR` | `AND` | How rules within the group are combined. |
| `rules` | list | — | One or more rules. |

---

## Rules

Every rule targets one part of the HTTP response.

```yaml
- id: access_denied_body         # optional — used in result explanation
  location: body
  operator: contains
  value: Access Denied
```

| Field | Required | Description |
|-------|----------|-------------|
| `id` | No | Optional name. Appears in `matched_rules` in the result. |
| `location` | Yes | Which part of the response to inspect. See [Locations](#locations). |
| `field` | Conditional | Header field name. Required when `location: header` and you want to target a specific header. |
| `operator` | Yes | How to compare the response value. See [Operators](#operators). |
| `value` | Conditional | The expected value. Not required for `exists` / `not_exists`. |

---

## Locations

| Location | Inspects | Notes |
|----------|----------|-------|
| `status` | HTTP status code (integer) | `equals` / `not_equals` only |
| `header` | Response header(s) | Use `field:` to target one header; omit to search all |
| `body` | Response body text | String / regex |
| `response` | Full response — headers + body combined | String / regex |
| `response_length` | Byte length of the response body | `equals` / `not_equals` only |

---

## Operators

| Operator | Type | Description |
|----------|------|-------------|
| `equals` | numeric / text | Exact match |
| `not_equals` | numeric / text | Not an exact match |
| `contains` | text | Substring present |
| `not_contains` | text | Substring absent |
| `regex` | text | Regex search matches (`re.search`) |
| `regex_not` | text | Regex search does NOT match |
| `exists` | header only | Header field is present (any value). No `value` required. |
| `not_exists` | header only | Header field is absent. No `value` required. |

> **`exists` / `not_exists`** work only with `location: header`.
> They do not require a `value` field.

---

## Rule Examples

### Status code

```yaml
- location: status
  operator: equals
  value: 403
```

### Body contains text

```yaml
- id: access_denied
  location: body
  operator: contains
  value: Access Denied
```

### Body matches regex

```yaml
- location: body
  operator: regex
  value: '"username"\s*:'
```

### Specific header value

```yaml
- location: header
  field: Location
  operator: contains
  value: /login
```

### Header exists (any value)

```yaml
- id: auth_header_present
  location: header
  field: WWW-Authenticate
  operator: exists
```

### Header does not exist

```yaml
- location: header
  field: X-Admin-Token
  operator: not_exists
```

### Search all header values

```yaml
# Omitting 'field' searches across all header values combined
- location: header
  operator: contains
  value: Bearer
```

### Full response regex

```yaml
- location: response
  operator: regex
  value: '"email"\s*:'
```

### Response body length

```yaml
- location: response_length
  operator: equals
  value: 1548
```

---

## Result Object

When a filter is configured, Talos returns a `DecisionResult` instead of just a string:

| Field | Type | Description |
|-------|------|-------------|
| `verdict` | `POSSIBLE_BAC` \| `SECURE` \| `UNKNOWN` | The final classification. Stored in the DB. |
| `matched_section` | `failed_detection` \| `passed_detection` \| `None` | Which section produced the verdict. |
| `matched_group_id` | string \| `None` | The `id` of the group that matched (or auto-label like `group_2`). |
| `matched_rules` | list of strings | Human-readable description of every rule that matched in the winning group. |

All four fields are stored in the `bac_results` DB table.

### Example result

```
Verdict:         POSSIBLE_BAC
Section:         failed_detection
Group:           dashboard_returned
Matched rules:
  [status_200] status == 200
  [body_dashboard] body contains 'Dashboard'
```

When using auto-generated IDs (no `id:` in YAML):

```
Verdict:         SECURE
Section:         passed_detection
Group:           group_2
Matched rules:
  status == 302
  header[Location] contains '/login'
```

---

## Logical Operator Reference

### group_operator: OR (default)

Any one group matching is sufficient to trigger the verdict.

```
Group 1  OR  Group 2  OR  Group 3
If any is True → section matches
```

### group_operator: AND

All groups must match. Rarely needed.

```
Group 1  AND  Group 2  AND  Group 3
All must be True → section matches
```

### operator: AND (default)

All rules in the group must match.

```
Rule 1  AND  Rule 2  AND  Rule 3
All must be True → group matches
```

### operator: OR

Any one rule matching is sufficient.

```
Rule 1  OR  Rule 2  OR  Rule 3
Any one True → group matches
```

---

## Complete Configuration Example

See [bac-decision-filter-sample.yaml](bac-decision-filter-sample.yaml) for a fully annotated example covering:

- Standard 401/403 responses
- Login redirects
- WWW-Authenticate header presence checks (`exists`)
- JSON body patterns
- Regex matching on response content

---

## Common Patterns

### Application returns 403 with JSON error

```yaml
passed_detection:
  group_operator: OR
  groups:
    - id: forbidden_json
      operator: AND
      rules:
        - location: status
          operator: equals
          value: 403
        - location: body
          operator: regex
          value: '"error"\s*:'
```

### Application always returns 200 but with an error page

```yaml
passed_detection:
  group_operator: OR
  groups:
    - id: error_page_200
      operator: AND
      rules:
        - location: status
          operator: equals
          value: 200
        - location: body
          operator: contains
          value: You do not have permission

failed_detection:
  group_operator: OR
  groups:
    - id: authenticated_content
      operator: AND
      rules:
        - location: status
          operator: equals
          value: 200
        - location: body
          operator: not_contains
          value: You do not have permission
        - location: body
          operator: contains
          value: Welcome
```

### SPA / API — detect by response length difference

```yaml
passed_detection:
  group_operator: OR
  groups:
    - id: empty_rejection
      operator: AND
      rules:
        - location: response_length
          operator: equals
          value: 0
        - location: status
          operator: equals
          value: 204
```

### Check that no session cookie is set in response

```yaml
passed_detection:
  group_operator: OR
  groups:
    - id: no_session_cookie
      operator: AND
      rules:
        - location: header
          field: Set-Cookie
          operator: not_exists
        - location: status
          operator: equals
          value: 401
```

---

## Validation

```bash
talos attack bac filter validate
```

On success:
```
OK  Filter is valid.  passed_detection: 4 group(s) [...], 9 rule(s)  |  failed_detection: 3 group(s) [...], 6 rule(s)
```

On error:
```
FAIL  Parse error: Rule at group[2].rule[0]: operator 'exists' is only valid for location='header'; got location='body'.
```

---

## Notes

- The filter is loaded fresh on every attack execution — no restart required after editing.
- If the file is absent or malformed, Talos falls back silently to the status-code heuristic.
- `value` is a YAML scalar; quote strings containing special characters.
- Regex patterns use Python `re.search` — no need to anchor with `^` / `$` unless you need exact-line matching.
- `exists` / `not_exists` do not require `value`. Including `value` is harmless but ignored.
