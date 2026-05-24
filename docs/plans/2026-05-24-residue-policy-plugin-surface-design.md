# Residue Policy Plugin Surface Design

## Goal

Expose `workflow-compute` short-lived residue policy through the generic
Workflow compute plugin without moving scheduler, lease, worker, or provider
authority semantics into the plugin.

## Context

`workflow-compute` now models residue policy on provider runtime profiles,
network products, tasks, and leases. The generic plugin already accepts typed
`protocol.ProviderContract` records in `compute.provider_catalog`, so provider
and product policy can flow through that module without a plugin-local schema.
The remaining gap is task intent: `step.compute_dispatch` and
`step.compute_map` cannot currently submit a task-level `residue_policy`.

## Approaches

1. Add `protocol.ResiduePolicy` to the existing task config and pass it through
   to `protocol.Task`.
   This keeps the plugin thin, uses core validation types, and supports both
   dispatch and map steps through the shared `taskConfig`.
2. Add a new residue-specific step or module.
   This would make residue policy visible, but it would create a second task
   submission path and pressure the plugin toward scheduler policy ownership.
3. Leave the plugin unchanged and rely on direct core API/CLI users for residue
   policy.
   This preserves current behavior but fails the Workflow/plugin-first use case.

Use approach 1.

## Design

`taskConfig` gains an optional `residue_policy` field of type
`protocol.ResiduePolicy`. `taskConfig.validate` calls
`ResiduePolicy.Validate`, requiring explicit opt-in for `worker-bound` task
requests and allowing `session-bound` only when `session_key` is present. The
plugin does not calculate policy hashes or intersect provider/product allowed
modes; `workflow-compute` still resolves and tightens the effective lease
policy.

`buildTask` copies the configured policy into the submitted `protocol.Task`.
`step.compute_dispatch` and each `step.compute_map` task get the same behavior
because they already share `taskConfig`.

The plugin dependency should be updated to a `workflow-compute` revision that
contains the final residue policy guardrails, including long-lived
service-product rejection. The existing provider-alignment script keeps PR CI
checking the plugin against a local checkout of current `workflow-compute`.

`compute.provider_catalog` stays typed as `[]protocol.ProviderContract`.
Provider runtime profile residue policy and no-workspace validation are already
covered by `ProviderContract.Validate`, so the plugin only needs tests proving
that catalog configs carrying residue policy validate and that no-workspace
runtime profiles reject reusable residue.

## Assumptions

- `workflow-compute/pkg/protocol` is the stable source of truth for residue
  field names and validation rules.
- Provider plugins will emit `ProviderContract` and product definitions using
  core protocol types rather than plugin-local YAML shortcuts.
- Task-level residue policy is declarative intent; core remains responsible for
  admission, policy intersection, hashing, and lease enforcement.
- Existing Workflow strict decoding is sufficient for rejecting unknown residue
  fields because the field uses the core struct.
- A current `workflow-compute` module revision is available to the plugin CI via
  private module auth or the existing local alignment checkout.

## Self-Challenge

- The lazy option is to do nothing because provider catalog already accepts
  typed contracts. That misses task-level customer intent, which was part of the
  residue model.
- The fragile assumption is that provider/product definitions arrive as core
  protocol records. If that changes, this plugin should still reject local
  shortcuts rather than inventing a second schema.
- The main partial-failure case is malformed residue policy reaching the core
  API after Workflow validation. Early plugin validation catches local shape and
  mode errors, while core still rejects authority violations.
- A stale core dependency would make the plugin appear to support residue while
  missing later guardrails. The plan must include a dependency update plus the
  existing local alignment check.

## Tests

- Dispatch submits a `residue_policy` unchanged.
- Map submits per-task residue policies unchanged.
- Dispatch rejects unsupported residue modes and implicit `worker-bound`.
- Provider catalog accepts runtime profiles with allowed residue modes and host
  workspace support.
- Provider catalog rejects reusable residue on no-workspace runtime profiles.

## Rollback

This is an additive config surface. Roll back by removing `residue_policy` from
Workflow configs and reverting the plugin commit. Already submitted tasks keep
their core task policy; operators can use the core residue wipe procedures if
reusable workspace state was created.
