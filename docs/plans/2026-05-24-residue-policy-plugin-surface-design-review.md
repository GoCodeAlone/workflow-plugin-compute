# Residue Policy Plugin Surface Design Review

### Adversarial Review Report

**Phase:** design
**Artifact:** docs/plans/2026-05-24-residue-policy-plugin-surface-design.md
**Status:** PASS

**Findings (Critical):**
- None.

**Findings (Important):**
- None. Initial dependency-staleness concern was resolved in the design by
  requiring a `workflow-compute` revision that includes the final residue
  guardrails and by keeping the existing local provider-alignment check.

**Findings (Minor):**
- [YAGNI] Tests section: A service-only network-product rejection test would
  imply this generic plugin owns product schemas, which conflicts with the
  existing provider-catalog-only module boundary. Recommendation: keep plugin
  tests focused on task pass-through and provider runtime contract validation.
- [Rollback] Rollback mentions removing `residue_policy` from configs but does
  not require a docs example. Recommendation: update README only with a small
  example so rollback remains "remove the optional field."

**Bug-class scan transcript:**

| Class | Result | Note |
|---|---|---|
| Unstated assumptions | Clean | The design now states protocol authority, provider-contract input shape, task intent boundaries, strict decode behavior, and dependency availability. |
| Repo-precedent conflicts | Clean | `AGENTS.md` and `SPEC.md` say this plugin translates Workflow schemas and must not own scheduler/provider semantics; the design keeps that boundary. |
| YAGNI violations | Finding | Product/service rejection tests would exceed this plugin's module boundary; narrowed to provider runtime contract validation. |
| Missing failure modes | Clean | Malformed residue config, stale dependency, and authority rejection are covered by plugin validation plus core validation. |
| Security / privacy at architecture level | Clean | The design does not add secret surfaces or local execution; reusable residue authority remains in core. |
| Rollback story | Finding | Rollback is additive and feasible, but docs should keep the optional field obvious. |
| Simpler alternative not considered | Clean | Doing nothing and adding a separate step/module were considered and rejected. |
| User-intent drift | Clean | The design supports provider/customer residue intent through plugin-first Workflow usage without changing long-lived service semantics. |

**Options the author may not have considered:**
1. Provider-catalog-only support: This would avoid task config changes, but it
   leaves customers unable to request session/provider/worker-bound behavior
   from Workflow steps.
2. Plugin-local residue schema: This could give nicer YAML docs, but it would
   duplicate core protocol validation and create drift risk.

**Verdict reasoning:** PASS. The design is narrow, aligned with the existing
plugin/core boundary, and security-sensitive enforcement stays in
`workflow-compute`. Minor findings can be handled in the implementation plan.
