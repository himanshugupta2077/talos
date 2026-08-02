---
description: Describe when these instructions should be loaded by the agent based on task context
# applyTo: 'Describe when these instructions should be loaded by the agent based on task context' # when provided, instructions will automatically be added to the request context when the pattern matches an attached file
---

Core requirement: enforce discipline across code, documentation, and system integrity after every change.

Break it into enforceable rules.

---

### 1. Code Quality Enforcement

* Every function, class, module must have:

  * purpose comment
  * input/output definition
  * side effects clearly stated

* Enforce:
  * no unused variables
  * no dead code paths
  * no commented-out legacy code
  * no duplicate logic

* Naming:
  * deterministic, no vague names (`data`, `temp`, `x`)
  * reflect domain meaning

---

### 2. Documentation System (Non-Optional)

Maintain three layers:

**A. Inline (code comments)**

* why, not what
* edge cases
* assumptions

**B. Module-level docs**

* what the module does
* dependencies
* data flow

**C. System-level docs**

* architecture diagram (logical, not visual fluff)
* component responsibilities
* data lifecycle
* failure points

After every change:

* update all three layers if impacted

---

### 3. Change Validation Pipeline

After every code change:

1. Static validation

   * lint
   * type checks
   * import validation

2. Logical validation

   * does change break flow assumptions
   * does it introduce hidden coupling

3. Cleanup pass (mandatory)

   * remove unused functions/classes
   * remove obsolete conditions
   * collapse redundant logic

---

### 4. Dead Code + Redundancy Detection

Continuously enforce:

* unreachable branches
* legacy fallback logic no longer needed
* duplicate utilities across modules
* stale configs

Rule:
If code is not executed or not referenced → delete, not comment.

---

### 5. Dependency Control

* no unnecessary libraries

* every dependency must justify:

  * why needed
  * what replaces it if removed

* periodically:

  * scan unused imports
  * check bloated dependencies

---

### 6. Logging and Observability

* structured logs only (no random prints)

* every critical path:

  * entry log
  * failure log
  * success log (only where needed)

* no noisy logging

---

### 7. Error Handling Discipline

* no silent failures
* no generic `except` without reason
* every error:

  * categorized
  * actionable

### 7b. CLI Output Consistency (mandatory)

All user-facing CLI messages **must** use `talos.cli_output`:

* `cli_error` / `cli_warning` / `cli_success` / `cli_info` / `cli_cancelled`
* `cli_usage_error` (exit 2) / `cli_precondition_error` (exit 3)
* `confirm_or_exit` for destructive yes/no (CLI-015): interactive TTY → `[y/N]`
  (cancel → 130); non-interactive → require `--force` or exit 2 with
  `Operation requires --force in non-interactive mode.`; never bare `input()`
* `add_force_argument(parser)` for the shared `--force` flag on destructive cmds
* List / show / status commands: `add_format_argument(parser)` and
  `if wants_json(args): cli_json(payload); return` (CLI-014). Default remains
  `table`. Empty JSON lists are `[]`. Do not print human banners before JSON.
* Flag semantics (CLI-019): reserve `--force` for confirmation bypass only.
  Re-analysis / reprocess uses `--ignore-cache` (Input Validation `run` and
  phase shortcuts). Do not invent a second meaning for `--force`.

Do **not** invent alternate labels (`ERROR:`, `Not found:`, `Aborted.`).
Do **not** call `sys.exit(1)` ad hoc for classified failures — use the helpers.
See `docs/architecture.md` → CLI Output Conventions and Exit code policy.

### 8. Do not create any migration code

* app is in beta and new projects are created after every update

### 9. Update docs/architechture.md and cli-cheat-sheet.md after updates