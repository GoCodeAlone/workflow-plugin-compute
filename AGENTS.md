# workflow-plugin-compute Agent Guide

This repo owns Workflow integration for `workflow-compute`. Keep scheduler,
ledger, proof, reward, worker, and dashboard semantics in
`GoCodeAlone/workflow-compute`; this plugin should translate Workflow modules
and steps into calls against that core API.

Use `wfctl` for local validation/build paths where supported. Generic lifecycle
gaps belong in `GoCodeAlone/workflow`; provider-specific cloud behavior belongs
in the relevant `workflow-plugin-*` provider repo.

Contracts are strict by default. Reject unknown or ambiguous config fields in
plugin-owned schemas unless compatibility behavior is explicit and tested.

Before each commit, perform antagonistic and security review steps. Fix
critical findings before committing, and record deferred findings in `SPEC.md`.
Review prompts must check whether POC shortcuts become product architecture,
especially shared secrets, client identity, authorization scope, token
rotation/revocation, proof/reward trust, workload execution policy, network
egress, and deploy credential wiring.
