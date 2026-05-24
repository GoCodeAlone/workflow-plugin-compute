# Residue Policy Plugin Surface Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Let Workflow compute dispatch/map steps submit task-level `residue_policy` while keeping authority and enforcement in `workflow-compute`.

**Architecture:** Add optional `protocol.ResiduePolicy` to the shared task config used by `step.compute_dispatch` and `step.compute_map`. Validate local shape with core protocol validation, copy the policy into submitted tasks, and keep provider runtime policy in typed `ProviderContract` catalog records.

**Tech Stack:** Go, `workflow-compute/pkg/protocol`, Workflow external plugin SDK, `wfctl`.

**Base branch:** main

---

## Scope Manifest

**PR Count:** 1
**Tasks:** 4
**Estimated Lines of Change:** ~180

**Out of scope:**
- New residue-specific steps/modules.
- Plugin-local provider/product schemas.
- Scheduler, lease, worker workspace, or residue cleanup semantics.
- Long-lived service runtime behavior changes.

**PR Grouping:**

| PR # | Title | Tasks | Branch |
|------|-------|-------|--------|
| 1 | Expose residue policy in compute plugin tasks | Task 1, Task 2, Task 3, Task 4 | feat/residue-policy-plugin-surface |

**Status:** Locked 2026-05-24T06:50:18Z

### Task 1: Add Failing Task Residue Tests

**Files:**
- Modify: `internal/steps_test.go`
- Modify: `internal/module_test.go`

**Step 1: Add dispatch and map pass-through tests**

In `internal/steps_test.go`, add:

```go
func TestDispatchStepSubmitsResiduePolicy(t *testing.T) {
	var got protocol.Task
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode task: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"task": got})
	}))
	defer srv.Close()

	cfg := dispatchConfigMap(srv.URL)
	cfg["residue_policy"] = map[string]any{
		"mode":            "session-bound",
		"allowed_modes":   []any{"isolated", "session-bound"},
		"session_key":     "ci-main",
		"max_age_seconds": float64(600),
		"max_reuse_count": float64(2),
		"wipe_on_failure": true,
	}
	step, err := newDispatchStep("dispatch", cfg)
	if err != nil {
		t.Fatalf("newDispatchStep: %v", err)
	}
	if _, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets()); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if got.ResiduePolicy.Mode != protocol.ResidueModeSessionBound ||
		got.ResiduePolicy.SessionKey != "ci-main" ||
		got.ResiduePolicy.MaxAgeSeconds != 600 ||
		got.ResiduePolicy.MaxReuseCount != 2 ||
		!got.ResiduePolicy.WipeOnFailure {
		t.Fatalf("residue policy not submitted: %+v", got.ResiduePolicy)
	}
}
```

Add a map-step test that submits two tasks with different valid policies and
asserts the server receives the expected modes.

**Step 2: Add validation tests**

In `internal/steps_test.go`, add tests that:

- set `residue_policy.mode` to `bogus` and expect `newDispatchStep` to fail;
- set `residue_policy.mode` to `worker-bound` without
  `explicit_worker_bound` and expect `newDispatchStep` to fail.

In `internal/module_test.go`, add provider catalog tests that:

- accept a runtime profile with `host_workspace_supported: true` and reusable
  allowed residue modes;
- reject reusable residue on a runtime profile with host workspace support
  disabled.

**Step 3: Run tests and confirm failure**

Run: `GOWORK=off go test ./internal -run 'Residue|ProviderCatalog' -count=1`

Expected: FAIL with compile/runtime errors because `taskConfig` does not expose
or submit `ResiduePolicy`.

### Task 2: Implement Residue Policy Pass-Through

**Files:**
- Modify: `internal/steps.go`
- Modify: `internal/sign.go`

**Step 1: Add task config field and validation**

Add to `taskConfig`:

```go
ResiduePolicy protocol.ResiduePolicy `json:"residue_policy,omitzero"`
```

In `taskConfig.validate`, call:

```go
if err := c.ResiduePolicy.Validate(protocol.ResiduePolicyValidation{
	RequireExplicitWorkerBound: c.ResiduePolicy.Mode == protocol.ResidueModeWorkerBound,
}); err != nil {
	errs = append(errs, fmt.Errorf("residue_policy: %w", err))
}
```

**Step 2: Submit the policy**

In `buildTask`, set:

```go
ResiduePolicy: cfg.ResiduePolicy,
```

**Step 3: Run focused tests**

Run: `GOWORK=off go test ./internal -run 'Residue|ProviderCatalog' -count=1`

Expected: PASS.

Rollback: revert this commit and remove `residue_policy` from Workflow configs;
no persistent plugin state is created.

### Task 3: Update Dependency, SPEC, and Docs

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`
- Modify: `SPEC.md`
- Modify: `README.md`

**Step 1: Update workflow-compute dependency**

Run: `GOWORK=off go get github.com/GoCodeAlone/workflow-compute@main`

Expected: `go.mod` references a pseudo-version at or after the residue service
guardrail merge.

**Step 2: Record plugin contract**

In `SPEC.md`, add:

- a constraint that task residue policy is submitted as task intent only;
- an invariant that plugin dispatch/map reject malformed residue policy and do
  not compute policy hashes or override provider/product authority;
- a completed task for residue policy plugin surface.

**Step 3: Add README example**

Add a short optional `residue_policy` block under `step.compute_dispatch`,
showing a bounded session cache for CI dependency fetching. State that
provider/product policy in `workflow-compute` must also allow the requested
mode.

**Step 4: Run docs/schema checks**

Run: `GOWORK=off go test ./internal -run 'Residue|ProviderCatalog' -count=1`

Expected: PASS.

Rollback: revert this commit and re-run `GOWORK=off go mod tidy`; Workflow
configs using `residue_policy` should remove that optional field.

### Task 4: Full Verification and PR

**Files:**
- No direct source edits unless verification finds a defect.

**Step 1: Run full tests**

Run: `GOWORK=off go test ./...`

Expected: package `cmd/workflow-plugin-compute` reports no test files and
package `internal` passes.

**Step 2: Run provider alignment**

Run: `./scripts/check-workflow-compute-alignment.sh /Users/jon/workspace/workflow-compute`

Expected: exits 0 after `go test ./internal -run 'Test(ModuleTypes|PluginManifestModuleTypesMatchRuntime|ProviderCatalog)' -count=1`.

**Step 3: Run wfctl validation/build if available**

Run: `wfctl validate workflow.yaml`

Expected: exits 0.

Run: `GOWORK=off wfctl build --config workflow.yaml --no-push --tag local`

Expected: exits 0 or fails only for documented environment prerequisites; fix
real plugin/config failures.

**Step 4: Commit and open PR**

```bash
git add .
git commit -m "feat: expose residue policy in compute steps"
git push -u origin feat/residue-policy-plugin-surface
gh pr create --repo GoCodeAlone/workflow-plugin-compute --base main --head feat/residue-policy-plugin-surface --title "Expose residue policy in compute steps" --body-file /tmp/residue-policy-plugin-pr.md
```

Expected: PR is open against `main`. Monitor CI and fix failures rather than
bypassing them.
