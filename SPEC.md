# workflow-plugin-compute SPEC

§G

Workflow external plugin adapter for `workflow-compute`: expose strict Workflow
modules/steps that submit, wait for, and map compute tasks while core compute
keeps scheduler/ledger/proof/reward ownership.

§C

C1: Plugin delegates execution semantics to `workflow-compute` API.
C2: Plugin owns Workflow schemas, validation, and step/module translation only.
C3: Unknown config fields rejected by default.
C4: Secrets are refs, not raw values; Workflow secrets surface owns resolution.
C5: GitHub runner adapter is demo integration, not core plugin assumption.
C6: wfctl used for validate/build/CI where supported.
C7: Standalone repo verification uses `GOWORK=off` unless parent `go.work` includes repo.
C8: `wfctl compute` CLI adapter owns operator UX only; scheduler/ledger/proof semantics stay core.
C9: External Workflow apps may use plugin outside wfcompute deployment/network if they can reach scoped control-plane client APIs.
C10: Public client control-plane access ≠ provider/admin mutation ingress.
C11: Plugin provider catalog details track `workflow-compute`'s typed `ProviderContract`, not a parallel plugin-local provider shape.

§I

repo: `workflow-plugin-compute` → Workflow external plugin adapter
core: `workflow-compute` → scheduler, worker, ledger, proof, reward, dashboard
module: `compute.provider` → control-plane connection + auth refs
module: `compute.pool` → org/pool/policy defaults
module: `compute.provider_catalog` → core `protocol.ProviderContract` declarations
step: `step.compute_dispatch` → submit task
step: `step.compute_wait` → wait/read proof
step: `step.compute_map` → fanout deterministic task set
cmd: `workflow-plugin-compute` → external SDK entrypoint
wfctl: `wfctl compute enroll|pools|run|submit|audit|accounting export|github-runner register|github-runner bridge-job` → plugin CLI → core API

§V

V1: plugin does not implement scheduler/ledger/proof/reward semantics
V2: plugin-owned config decode rejects unknown fields
V3: plugin passes secret/config refs through; raw secret values are not logged
V4: step outputs include task/proof ids and statuses, not full secret-bearing payloads
V5: local wfctl build/test commands run with `GOWORK=off` while repo is outside workspace `go.work`
V6: plugin CI uses `RELEASES_TOKEN` + `GOPRIVATE` before fetching private GoCodeAlone modules
V7: `step.compute_wait` stops on task failure/stall using task API state; proof API outage cannot mask failed/stalled task status
V8: `step.compute_wait` proof success requires verifier status `accepted`; rejected/unknown proof metadata never satisfies required proof
V9: `step.compute_map` timeout output is deterministic even if context expires during an HTTP poll
V10: `wfctl compute` output never includes bootstrap API token or raw secret values
V11: `wfctl compute run` uses same v0 task signature envelope as dispatch step until scoped client signing lands
V12: token-bearing compute client rejects cleartext non-loopback server URLs
V13: `wfctl compute run` emits compact receipt only; workload + signature omitted from stdout
V14: `wfctl compute github-runner bridge-job` requires registration id and emits compact receipt only
V15: `wfctl compute submit` supports command/container-build without leaking workload/signature/token to stdout
V16: `wfctl compute accounting export` includes raw contribution units and policy reward outputs without leaking token
V17: docs/examples distinguish `compute.provider` Workflow connection from wfcompute provider/worker node
V18: plugin guidance for public control-plane use excludes bootstrap token, provider mutation, package/campaign/trust-root mutation, and raw agent/supervisor control APIs
V19: PR CI checks plugin provider catalog tests against current `GoCodeAlone/workflow-compute` main with a local module replace

§T

id|status|task|cites
T1|x|repo skeleton: AGENTS, README, SPEC, plugin manifest, SDK entrypoint|C1,C2,I.repo,I.cmd,V1
T2|x|implement `compute.provider` + `compute.pool` strict schemas|I.module,V2,V3
T3|x|implement `step.compute_dispatch` strict schema + API client|I.step,V2,V3,V4
T4|x|implement `step.compute_wait` polling/proof output|I.step,V4
T5|x|implement `step.compute_map` fanout submit/wait behavior|I.step,V4,V9
T6|x|implement `wfctl compute` plugin CLI provider + manifest declaration|I.cmd,I.wfctl,C8,V1,V10,V11,V12,V13
T7|x|add `wfctl compute github-runner` adapter commands for runner register/job bridge|I.cmd,I.wfctl,C5,C8,V10,V12,V14
T8|x|add `wfctl compute submit command|container-build` for ad hoc workload demos|I.cmd,I.wfctl,C8,V10,V12,V15
T9|x|include rewards in `wfctl compute accounting export`|I.cmd,I.wfctl,C8,V10,V16
T10|x|document external Workflow client use cases and public client-surface boundary|C9,C10,V17,V18
T11|x|align provider catalog details with workflow-compute `ProviderContract` and gate drift in PR CI|C11,I.module,V19

§B

id|date|cause|fix
B1|2026-05-09|local `wfctl build` inherited parent `go.work` that excludes new module|C7,V5
B2|2026-05-09|CI could not fetch private `workflow-compute` Go module until private module auth was wired|V6
B3|2026-05-09|review found wait-step failed tasks depended on proof API and discarded task stall flags|V7
B4|2026-05-09|review found wait-step accepted any proof receipt status as satisfying proof|V8
B5|2026-05-09|CI exposed `compute_map` timeout test receiving raw context-deadline transport error|V9
B6|2026-05-10|live `wfctl compute run` task used CLI-specific signature key rejected by core v0 verifier|V11
B7|2026-05-10|review found token-bearing CLI could post to cleartext non-loopback `http://` server|V12
B8|2026-05-10|review found `wfctl compute run` stdout included full workload + signature envelope|V13
B9|2026-05-20|plugin provider catalog draft used grouped executor/dependency/proof/reward/network details while workflow-compute had moved to typed `ProviderContract`; plugin manifest also omitted the new module|C11,V19
