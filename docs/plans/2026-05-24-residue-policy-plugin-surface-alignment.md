# Residue Policy Plugin Surface Alignment

### Alignment Report

**Status:** PASS

**Coverage:**

| Design Requirement | Plan Task(s) | Status |
|---|---|---|
| Add optional `protocol.ResiduePolicy` to shared task config. | Task 1, Task 2 | Covered |
| Validate malformed residue policy locally while leaving authority checks to core. | Task 1, Task 2 | Covered |
| Copy task residue policy into submitted `protocol.Task`. | Task 1, Task 2 | Covered |
| Support both dispatch and map steps through shared config. | Task 1, Task 2 | Covered |
| Keep `compute.provider_catalog` typed as `[]protocol.ProviderContract`. | Task 1 | Covered |
| Prove reusable residue is rejected for no-workspace runtime profiles. | Task 1 | Covered |
| Update to a current `workflow-compute` dependency and keep provider alignment check. | Task 3, Task 4 | Covered |
| Document optional usage and rollback by removing `residue_policy`. | Task 3 | Covered |
| Avoid new scheduler, lease, worker, product schema, or long-lived service behavior. | Scope Manifest, Task 2, Task 3 | Covered |

**Scope Check:**

| Plan Task | Design Requirement | Status |
|---|---|---|
| Task 1 | Tests for dispatch/map pass-through and provider runtime contract validation. | Justified |
| Task 2 | Shared task config validation and task submission pass-through. | Justified |
| Task 3 | Dependency freshness, SPEC invariant, and README optional usage. | Justified |
| Task 4 | Full verification, provider alignment, wfctl checks, and PR monitoring. | Justified |

**Drift Items:** None.

Manifest check: `plan-scope-check.sh --plan /Users/jon/workspace/workflow-plugin-compute/docs/plans/2026-05-24-residue-policy-plugin-surface.md` passed.
