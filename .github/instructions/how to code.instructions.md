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

### 8. Do not create any migration code

* app is in beta and new projects are created after every update

### 9. Update docs/architechture.md and cli-cheat-sheet.md after updates