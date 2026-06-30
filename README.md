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
- A content workflow submits a generic provider chain that fetches media
  through a storage provider, transforms it through a media provider, and then
  forwards artifact/content/stream references to the next provider without
  embedding storage or media semantics in this plugin.
- A live-video workflow submits `step.compute_stream` to create a
  `video-stream` task, while `workflow-plugin-stream` owns the MediaMTX provider
  contract, runtime adapter, ingest descriptor, auth hook, and stream proof
  manifest behavior.

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
lambda/CDN semantics; `workflow-plugin-stream` owns video-stream and MediaMTX
semantics. This plugin accepts their `ProviderContract` records through
`compute.provider_catalog` without redefining them locally.

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

## Composable Provider Chains

`step.compute_chain` submits an ordered list of workflow-compute tasks and waits
for each task by default. It is for workflows where one provider step produces a
proof preview that later provider steps consume, such as S3 content fetch,
media transform, and stream publish.

Each chain entry has an explicit `id`, workload routing fields, optional
`depends_on`, optional `wait: false`, and optional `input_mappings`. Mappings
only copy prior step output into generic provider handoff fields:

- `provider.artifact_refs`
- `provider.content_inputs`
- `provider.stream_inputs`

The compute plugin does not fetch S3 objects, run ffmpeg, mint stream tokens,
or implement provider SDKs. S3 behavior belongs in `workflow-plugin-aws`, media
behavior belongs in `workflow-plugin-media`, stream transport belongs in
`workflow-plugin-stream`, and the wfcompute runtime enforces task/proof
authorization for forwarded refs. Secrets and credentials must remain scoped
refs such as `secret://...`, `content://...`, `stream://...`, or
`artifact://...`; raw AWS keys, publish tokens, and bearer credentials do not
belong in chain config.

Example:

```yaml
steps:
  transcode_and_publish:
    type: step.compute_chain
    config:
      server_url: https://compute.example.com
      auth_token_ref: secret:WFCOMPUTE_TOKEN
      poll_interval: 2s
      timeout: 30m
      require_proof: true
      steps:
        - id: fetch_media
          task_id: fetch-media-1
          org_id: gocodealone
          pool_id: media
          policy_id: content-fetch
          timeout_seconds: 300
          workload:
            kind: provider
            provider:
              provider_config:
                plugin_id: workflow-plugin-aws
                provider_id: s3-content-source
                contract_id: workflow-plugin-aws.s3-content-source.v1
                version: v1.0.0
                config_ref: config://providers/aws/media
              operation: fetch
              image_ref: ghcr.io/gocodealone/workflow-plugin-aws-provider@sha256:...
              input:
                bucket_ref: config://media/source-bucket
                object_key: inputs/source.mp4

        - id: transcode
          task_id: transcode-1
          org_id: gocodealone
          pool_id: media
          policy_id: media-transform
          timeout_seconds: 1800
          depends_on:
            - fetch_media
          input_mappings:
            - from_step: fetch_media
              from: result_preview.content_inputs
              to: provider.content_inputs
          workload:
            kind: provider
            provider:
              provider_config:
                plugin_id: workflow-plugin-media
                provider_id: media-batch-transform
                contract_id: workflow-plugin-media.batch-transform.v1
                version: v1.0.0
                config_ref: config://providers/media/ffmpeg
              operation: batch_transform
              image_ref: ghcr.io/gocodealone/workflow-plugin-media-provider@sha256:...
              input:
                outputs:
                  - name: hls_720p
                    preset: hls-720p

        - id: publish_stream
          task_id: publish-stream-1
          org_id: gocodealone
          pool_id: streamers
          policy_id: stream-publish
          timeout_seconds: 600
          depends_on:
            - transcode
          input_mappings:
            - from_step: transcode
              from: result_preview.artifact_refs
              to: provider.artifact_refs
            - from_step: transcode
              from: result_preview.stream_inputs
              to: provider.stream_inputs
          workload:
            kind: provider
            provider:
              provider_config:
                plugin_id: workflow-plugin-stream
                provider_id: mediamtx
                contract_id: workflow-plugin-stream.video-stream.v1
                version: v1.0.0
                config_ref: config://providers/stream/main
              operation: publish
              image_ref: ghcr.io/gocodealone/workflow-plugin-stream-provider@sha256:...
              input:
                rendition: 720p
```

## Stream Workloads

`step.compute_stream` submits a `workflow-plugin-compute-core` `video-stream`
task to a wfcompute control plane. Use it when a Workflow pipeline wants
compute scheduling, leases, proof accounting, and provider selection for a live
stream workload.

Use `workflow-plugin-stream` direct steps (`stream.start` and
`stream.restream`) only when an application is intentionally addressing that
plugin surface directly. Use `step.compute_stream` when the stream should be
dispatched through workflow-compute and matched against a registered
`video-stream` provider contract such as
`workflow-plugin-stream.video-stream.v1`.

The compute plugin does not implement MediaMTX, publish-token minting, stream
auth hooks, ffmpeg transforms, or CDN routing. Those capabilities belong in the
owning provider plugin or the wfcompute runtime. This step validates the
Workflow-facing request, builds a core task with workload kind `video-stream`,
and submits it to `/v1/tasks`.

Example:

```yaml
modules:
  compute:
    type: compute.provider
    config:
      server_url: https://compute.example.com
      auth_token_ref: secret:WFCOMPUTE_TOKEN
      request_timeout: 30s

  stream_catalog:
    type: compute.provider_catalog
    config:
      contracts:
        - ${file:./providers/workflow-plugin-stream.video-stream.v1.json}

steps:
  start_live_stream:
    type: step.compute_stream
    config:
      server_url: https://compute.example.com
      auth_token_ref: secret:WFCOMPUTE_TOKEN
      id: stream-task-1
      org_id: gocodealone
      pool_id: streamers
      policy_id: video-stream-hardened
      timeout_seconds: 3600
      labels:
        workflow: live-event
      stream:
        ingest_protocols:
          - rtmp
          - srt
          - whip
        viewer_egress:
          hls: true
        destinations:
          - target_ref: stream://destinations/archive
            rendition: 720p
```

`target_ref` and other destination credentials should remain references. Do not
put raw publish, restream, or CDN credentials into the Workflow config.

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

## Network Audit Wrapper

The plugin also exposes the public Workflow-facing operator wrapper for
workflow-compute network-audit readiness and dry-run checks:

```sh
wfctl plugin run --ensure-installed workflow-plugin-compute -- \
  compute network-audits audit-state \
  --config workflow.yaml \
  --provider-ref compute \
  --projection release-a \
  --expected-ref-key-epoch network-audit-ref-v1
```

`--config` and `--provider-ref` load the `compute.provider` module, including
`server_url`, `auth_token_ref`, and `request_timeout`. The token ref is resolved
from environment variables derived from the ref key, such as
`secret:compute-token` resolving from `COMPUTE_TOKEN`; `--server`,
`--token-env`, and `COMPUTE_API_TOKEN` remain available for projectless
operator use. Output is sanitized: raw bearer tokens, secret refs, dry-run
handles, raw destinations, DSNs, credential strings, projection labels, and
unsafe diagnostic reasons are not printed.

Use `compute network-audits raw-compat-dry-run` for server-backed mint/use/revoke
preflight checks. The plugin sends the expected ref-key epoch with every dry-run
request and refuses to call the server when the requested epoch does not match
the plugin's protocol constant.

## Development

```sh
GOWORK=off go test ./...
wfctl validate --allow-no-entry-points workflow.yaml
GOWORK=off wfctl build --config workflow.yaml --no-push --tag local
```

The repository is private while the protocol and security model are still
settling.
