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

§I

repo: `workflow-plugin-compute` → Workflow external plugin adapter
core: `workflow-compute` → scheduler, worker, ledger, proof, reward, dashboard
module: `compute.provider` → control-plane connection + auth refs
module: `compute.pool` → org/pool/policy defaults
step: `step.compute_dispatch` → submit task
step: `step.compute_wait` → wait/read proof
step: `step.compute_map` → fanout deterministic task set
cmd: `workflow-plugin-compute` → external SDK entrypoint

§V

V1: plugin does not implement scheduler/ledger/proof/reward semantics
V2: plugin-owned config decode rejects unknown fields
V3: plugin passes secret/config refs through; raw secret values are not logged
V4: step outputs include task/proof ids and statuses, not full secret-bearing payloads
V5: local wfctl build/test commands run with `GOWORK=off` while repo is outside workspace `go.work`
V6: plugin CI uses `RELEASES_TOKEN` + `GOPRIVATE` before fetching private GoCodeAlone modules

§T

id|status|task|cites
T1|x|repo skeleton: AGENTS, README, SPEC, plugin manifest, SDK entrypoint|C1,C2,I.repo,I.cmd,V1
T2|x|implement `compute.provider` + `compute.pool` strict schemas|I.module,V2,V3
T3|x|implement `step.compute_dispatch` strict schema + API client|I.step,V2,V3,V4
T4|.|implement `step.compute_wait` polling/proof output|I.step,V4
T5|.|implement `step.compute_map` fanout submit/wait behavior|I.step,V4

§B

id|date|cause|fix
B1|2026-05-09|local `wfctl build` inherited parent `go.work` that excludes new module|C7,V5
B2|2026-05-09|CI could not fetch private `workflow-compute` Go module until private module auth was wired|V6
