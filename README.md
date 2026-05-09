# workflow-plugin-compute

Workflow external plugin for dispatching work to
[`workflow-compute`](https://github.com/GoCodeAlone/workflow-compute).

The plugin is the Workflow-facing adapter. It should provide modules and steps
for compute providers, pools, dispatch, waiting, and fanout while delegating
orchestration, leasing, proof verification, accounting, and dashboard state to
the core compute service.

## Development

```sh
GOWORK=off go test ./...
wfctl validate workflow.yaml
GOWORK=off wfctl build --config workflow.yaml --no-push --tag local
```

The repository is private while the protocol and security model are still
settling.
