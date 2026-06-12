# workflow-plugin-compute

Workflow external plugin for dispatching work to
[`workflow-compute`](https://github.com/GoCodeAlone/workflow-compute).

The plugin is the Workflow-facing adapter. It should provide modules and steps
for compute providers, pools, provider contract catalogs, dispatch, waiting, and
fanout while delegating orchestration, leasing, proof verification, accounting,
and dashboard state to the core compute service.

## Intended Use

Use this plugin when a Workflow app needs a result from `workflow-compute` but
should not embed wfcompute scheduler, proof, reward, or agent lifecycle logic.
The app may live outside the wfcompute deployment and outside the worker
network. It only needs a route to a wfcompute control plane plus a scoped
credential.

Examples:

- A product CI workflow submits a protected container build to a private
  wfcompute pool, waits for an accepted proof, then deploys only after the
  proof is accepted.
- A repository workflow fans out deterministic test shards with
  `step.compute_map`, then fails the pipeline if any task stalls, fails, or
  returns a rejected proof.
- A data or game build workflow submits a long-running command workload to
  eligible enrolled agents, records the resulting task/proof ids, and uses the
  core ledger for accounting.
- A provider plugin, such as product capture or edge compute, exposes a typed
  `workflow-plugin-compute-core/protocol.ProviderContract`; this plugin submits
  or waits on the resulting generic workflow-compute task without embedding
  provider business logic.

`compute.provider` in this repository means "Workflow connection to a
wfcompute control plane." It is not a wfcompute worker/provider node. Provider
nodes, supervisors, package updates, proof verification, rewards, and dashboard
state belong to `workflow-compute`.

`compute.provider_catalog` consumes
`workflow-plugin-compute-core/protocol.ProviderContract` records. It
intentionally does not define a separate plugin-local executor, dependency,
verification, reward, or network provider shape.

Provider-specific contracts belong in the owning provider plugin. For example,
product capture owns product URL semantics and edge compute owns edge
lambda/CDN semantics; this plugin accepts their `ProviderContract` records
through `compute.provider_catalog` without redefining them locally.

If the wfcompute control plane exposes a public client surface, it should expose
only the scoped APIs needed by external Workflow clients, such as task submit,
task status, proof reads, credential lifecycle, and readiness. Provider
mutation APIs, bootstrap-token flows, package/campaign/trust-root mutation, and
raw agent/supervisor control should remain private or separately admin-gated.

## Example

```yaml
modules:
  compute:
    type: compute.provider
    config:
      server_url: https://compute.example.com
      auth_token_ref: secret:WFCOMPUTE_TOKEN
      request_timeout: 30s

  build_pool:
    type: compute.pool
    config:
      provider_ref: compute
      org_id: gocodealone
      pool_id: builders
      policy_id: protected-container-build
      mode: private

steps:
  build_image:
    type: step.compute_dispatch
    config:
      server_url: https://compute.example.com
      auth_token_ref: secret:WFCOMPUTE_TOKEN
      org_id: gocodealone
      pool_id: builders
      policy_id: protected-container-build
      timeout_seconds: 1800
      labels:
        app: example-api
      residue_policy:
        mode: session-bound
        allowed_modes:
          - isolated
          - session-bound
        session_key: ci-main
        max_age_seconds: 1800
        max_reuse_count: 3
        wipe_on_failure: true
      workload:
        kind: container-build
        container_build:
          context_directory: .
          dockerfile: Dockerfile
          tags:
            - registry.example.com/example-api:${GIT_SHA}

  wait_for_build:
    type: step.compute_wait
    config:
      server_url: https://compute.example.com
      auth_token_ref: secret:WFCOMPUTE_TOKEN
      task_id: ${steps.build_image.output.task_id}
      require_proof: true
      poll_interval: 2s
      timeout: 30m
```

`residue_policy` is optional task intent for short-lived workloads, useful for
bounded CI dependency caches. The wfcompute provider runtime profile and network
product must also allow the requested mode; core `workflow-compute` resolves the
effective lease policy and enforces workspace reuse or isolation.

For fanout work, use `step.compute_map` with a deterministic `tasks` list. The
step submits every task, polls the core task/proof APIs, and stops the Workflow
pipeline if any task fails, stalls, times out, or produces a non-accepted proof.

## Projectless Agent Setup

Agent setup can run through the plugin CLI without a Workflow project,
`workflow.yaml`, or pre-known worker/org/pool/token values. The wfcompute
control plane issues a setup invite, and the plugin claims it through the public
invite APIs:

`wfctl v0.78.2` or newer is required for first-run projectless
`wfctl plugin run --ensure-installed` usage. The projectless path can be used
directly from wfctl:

```sh
wfctl plugin run --ensure-installed workflow-plugin-compute -- \
  compute agent setup \
  --server https://compute.example.com \
  --invite-url 'https://compute.example.com/install?invite_id=...&redeem_code=...' \
  --install-session-id "$(hostname)-setup" \
  --runtime auto \
  --install \
  --verify \
  --dry-run \
  --token-env COMPUTE_AGENT_TOKEN \
  --non-interactive \
  --json
```

Use `--dry-run` to render the equivalent `compute agent setup` command without
claiming the invite. Dry-run output redacts secret-bearing invite URL query
values by default; pass `--show-secrets` only when you need a local
copy-pasteable command containing the redeem code. The rendered command targets
the `compute` binary from workflow-compute; wfctl provides the projectless
plugin entrypoint that produces that command. `--runtime auto` lets wfcompute
choose a supported local runtime; `--runtime none` registers without protected
workload availability.

Use `--runtime managed-containerd` when the operator wants the compute agent to
install and verify the managed containerd runtime path supplied by
`workflow-plugin-compute-container` `v0.5.1` or newer. In dry-run JSON this
plugin includes the requested runtime, managed runtime plugin dependency,
installer contract name, lifecycle actions, and a `wfctl plugin run` command
prefix for the container plugin. It does not copy backend IDs, bundle IDs,
download URLs, signature policy, probe logic, or support decisions from the
runtime catalog. Until workflow-compute accepts a first-class managed-containerd
runtime selector, the rendered downstream command uses `--runtime auto`.
Download, extraction, signature verification, runtime probing,
support/degraded decisions, and catalog details remain inside the
workflow-compute agent/runtime path and the container plugin installer contract.

Without `--dry-run`, the command claims the setup invite and returns sanitized
setup metadata, including the claimed worker id, credential id/ref, install
session id, and whether a one-time token was present. It intentionally does not
print the raw token, redeem code, org id, or pool id. Installation, service
start, runtime selection, verification, and credential persistence remain
agent-runtime responsibilities; this plugin owns the projectless wfctl
entrypoint and invite-scoped control-plane calls.

## Development

```sh
GOWORK=off go test ./...
wfctl validate --allow-no-entry-points workflow.yaml
GOWORK=off wfctl build --config workflow.yaml --no-push --tag local
```

The repository is private while the protocol and security model are still
settling.
