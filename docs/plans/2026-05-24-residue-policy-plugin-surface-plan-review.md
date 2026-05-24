# Residue Policy Plugin Surface Plan Review

### Adversarial Review Report

**Phase:** plan
**Artifact:** docs/plans/2026-05-24-residue-policy-plugin-surface.md
**Status:** PASS

**Findings (Critical):**
- None.

**Findings (Important):**
- None.

**Findings (Minor):**
- [Verification-class mismatch] Task 4 runs `wfctl build`, which can fail for
  environment prerequisites outside the plugin. Recommendation: treat
  documented environment failures as non-blocking only after checking the output
  is not a plugin/config regression.
- [Over-decomposition] Task 3 combines dependency, SPEC, and README edits.
  Recommendation: acceptable for a one-PR plugin surface, but keep the commit
  scoped and do not add examples beyond the optional residue block.

**Bug-class scan transcript:**

| Class | Result | Note |
|---|---|---|
| Unstated assumptions | Clean | The design and plan state core protocol authority and dependency availability. |
| Repo-precedent conflicts | Clean | The plan follows `AGENTS.md` and `SPEC.md` by translating Workflow config only. |
| YAGNI violations | Clean | No new module, product schema, or scheduler behavior is planned. |
| Missing failure modes | Clean | Malformed residue, no-workspace reusable residue, stale core dependency, and CI failures have checks. |
| Security / privacy at architecture level | Clean | No new secret/logging surface; residue authority remains in core. |
| Rollback story | Clean | Runtime-affecting task steps include revert/remove-field rollback notes. |
| Simpler alternative not considered | Clean | Doing nothing and a residue-specific step were considered in the design and rejected. |
| User-intent drift | Clean | The plan keeps Workflow/plugin-first task intent support and avoids long-lived service changes. |
| Over-decomposition / under-decomposition | Finding | Task 3 groups docs/dependency/SPEC edits; acceptable because they are small and coupled. |
| Verification-class mismatch | Finding | `wfctl build` environment failures need output inspection before accepting as prerequisite-only. |
| Hidden serial dependencies | Clean | Tasks are intentionally serial and touch shared files in a single PR. |
| Missing rollback wiring | Clean | Rollback notes are present where the config surface and dependency can affect runtime behavior. |

**Options the author may not have considered:**
1. Split dependency update into a separate PR: cleaner rollback, but too much
   process overhead for a small field pass-through that must compile against the
   new protocol.
2. Skip README changes: lower churn, but makes rollback and usage less obvious
   for future plugin users.

**Verdict reasoning:** PASS. The plan is narrow, test-first, and uses the
existing provider-alignment script to catch protocol drift. Minor findings can
be handled during execution.
