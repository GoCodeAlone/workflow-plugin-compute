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
- A commerce workflow submits a typed product-capture URL workload to an
  enrolled browser-capture pool and uses the accepted proof preview to show a
  user-confirmed product snapshot.

`compute.provider` in this repository means "Workflow connection to a
wfcompute control plane." It is not a wfcompute worker/provider node. Provider
nodes, supervisors, package updates, proof verification, rewards, and dashboard
state belong to `workflow-compute`.

`compute.provider_catalog` consumes `workflow-compute/pkg/protocol.ProviderContract`
records. It intentionally does not define a separate plugin-local executor,
dependency, verification, reward, or network provider shape.

The built-in edge catalog presets are examples of that boundary: edge lambda and
edge CDN filter entries are plain `ProviderContract` records for
`wasm-component` execution. They do not embed product capture, BMW, or any other
application-specific workflow logic.

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

For fanout work, use `step.compute_map` with a deterministic `tasks` list. The
step submits every task, polls the core task/proof APIs, and stops the Workflow
pipeline if any task fails, stalls, times out, or produces a non-accepted proof.

For product capture, use `step.compute_product_capture`. It requires explicit
`allowed_hosts`, `product_id`, and either a static `url` or dynamic `url_field`.
The step submits generic `provider` work using the
`workflow-plugin-product-capture` browser contract, waits for proof, and exposes
the bounded `result_preview` fields returned by workflow-compute.

## Development

```sh
GOWORK=off go test ./...
wfctl validate workflow.yaml
GOWORK=off wfctl build --config workflow.yaml --no-push --tag local
```

The repository is private while the protocol and security model are still
settling.
