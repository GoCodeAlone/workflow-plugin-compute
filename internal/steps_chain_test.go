package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-compute/pkg/protocol"
)

func TestComputeChainSubmitsSequentialProviderTasksAndMapsInputs(t *testing.T) {
	var submitted []protocol.Task
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks":
			var task protocol.Task
			if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
				t.Fatalf("decode task: %v", err)
			}
			submitted = append(submitted, task)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"task": task})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks":
			tasks := make([]protocol.Task, len(submitted))
			copy(tasks, submitted)
			for i := range tasks {
				tasks[i].Status = protocol.TaskSucceeded
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": tasks})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/proofs":
			proofs := make([]protocol.ProofReceipt, 0, len(submitted))
			for _, task := range submitted {
				proof := proofReceipt(task.ID)
				proof.ID = task.ID + "-proof"
				if task.ID == "fetch-task" {
					proof.ResultPreview = map[string]any{
						"artifact_refs": []any{"artifact://pool-1/tasks/fetch-task/proofs/fetch-task-proof/source.mp4"},
						"content_inputs": []any{map[string]any{
							"name":         "source-file",
							"ref":          "content://workloads/source.mp4",
							"target_path":  "inputs/source.mp4",
							"content_type": "video/mp4",
						}},
						"stream_inputs": []any{map[string]any{
							"name": "live-source",
							"handle": map[string]any{
								"url":            "rtmp://stream.example.test/live/source",
								"protocol":       "rtmp",
								"auth_token_ref": "secret://streams/live-source",
								"codecs":         []any{"h264", "aac"},
								"expires_at":     "2026-06-30T22:00:00Z",
							},
						}},
					}
				}
				proofs = append(proofs, proof)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"proofs": proofs})
		default:
			t.Fatalf("request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	step, err := newComputeChainStep("chain", chainConfigMap(srv.URL))
	if err != nil {
		t.Fatalf("newComputeChainStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.StopPipeline {
		t.Fatalf("unexpected stop: %+v", result.Output)
	}
	if len(submitted) != 2 {
		t.Fatalf("submitted tasks: got %d", len(submitted))
	}
	transform := submitted[1].Workload.Provider
	if transform == nil {
		t.Fatalf("second task provider workload: %+v", submitted[1].Workload)
	}
	if len(transform.ArtifactRefs) != 1 || transform.ArtifactRefs[0] != "artifact://pool-1/tasks/fetch-task/proofs/fetch-task-proof/source.mp4" {
		t.Fatalf("artifact refs: %+v", transform.ArtifactRefs)
	}
	if len(transform.ContentInputs) != 1 || transform.ContentInputs[0].Ref != "content://workloads/source.mp4" {
		t.Fatalf("content inputs: %+v", transform.ContentInputs)
	}
	if len(transform.StreamInputs) != 1 || transform.StreamInputs[0].Handle.URL != "rtmp://stream.example.test/live/source" {
		t.Fatalf("stream inputs: %+v", transform.StreamInputs)
	}

	steps := result.Output["steps"].([]map[string]any)
	if len(steps) != 2 || steps[0]["step_id"] != "fetch" || steps[1]["step_id"] != "transform" {
		t.Fatalf("chain output: %+v", result.Output)
	}
}

func TestComputeChainRejectsUnknownConfig(t *testing.T) {
	cfg := chainConfigMap("https://compute.example.test")
	cfg["unknown"] = true
	if _, err := newComputeChainStep("chain", cfg); err == nil {
		t.Fatal("expected strict unknown-field error")
	}
}

func TestComputeChainRequiresMappingSourcesInDependsOn(t *testing.T) {
	cfg := chainConfigMap("https://compute.example.test")
	steps := cfg["steps"].([]any)
	transform := steps[1].(map[string]any)
	delete(transform, "depends_on")
	_, err := newComputeChainStep("chain", cfg)
	if err == nil || !strings.Contains(err.Error(), "must be listed in depends_on") {
		t.Fatalf("expected depends_on validation error, got %v", err)
	}
}

func TestComputeChainWaitFalseSkipsProofPolling(t *testing.T) {
	var proofRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks":
			var task protocol.Task
			if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
				t.Fatalf("decode task: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"task": task})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/proofs":
			proofRequests++
			_ = json.NewEncoder(w).Encode(map[string]any{"proofs": []any{}})
		default:
			t.Fatalf("request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	cfg := chainConfigMap(srv.URL)
	cfg["steps"] = []any{map[string]any{
		"id":              "enqueue",
		"task_id":         "enqueue-task",
		"org_id":          "org-1",
		"pool_id":         "pool-1",
		"policy_id":       "policy-1",
		"timeout_seconds": 60,
		"wait":            false,
		"workload":        commandWorkloadMap(),
	}}
	step, err := newComputeChainStep("chain", cfg)
	if err != nil {
		t.Fatalf("newComputeChainStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.StopPipeline {
		t.Fatalf("unexpected stop: %+v", result.Output)
	}
	if proofRequests != 0 {
		t.Fatalf("wait=false should not poll proofs, got %d requests", proofRequests)
	}
}

func TestComputeChainFailureOutputKeepsStepID(t *testing.T) {
	var submitted []protocol.Task
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks":
			var task protocol.Task
			if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
				t.Fatalf("decode task: %v", err)
			}
			submitted = append(submitted, task)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"task": task})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks":
			tasks := make([]protocol.Task, len(submitted))
			copy(tasks, submitted)
			for i := range tasks {
				tasks[i].Status = protocol.TaskFailed
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": tasks})
		default:
			t.Fatalf("request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer srv.Close()

	cfg := chainConfigMap(srv.URL)
	cfg["steps"] = []any{map[string]any{
		"id":              "failing",
		"task_id":         "failing-task",
		"org_id":          "org-1",
		"pool_id":         "pool-1",
		"policy_id":       "policy-1",
		"timeout_seconds": 60,
		"workload":        commandWorkloadMap(),
	}}
	step, err := newComputeChainStep("chain", cfg)
	if err != nil {
		t.Fatalf("newComputeChainStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.StopPipeline {
		t.Fatalf("expected stop pipeline, got %+v", result.Output)
	}
	steps := result.Output["steps"].([]map[string]any)
	if len(steps) != 1 || steps[0]["step_id"] != "failing" {
		t.Fatalf("failure output must retain step_id, got %+v", result.Output)
	}
}

func chainConfigMap(serverURL string) map[string]any {
	return map[string]any{
		"server_url":     serverURL,
		"auth_token_ref": "secret:compute-token",
		"poll_interval":  "1ms",
		"timeout":        "5s",
		"require_proof":  true,
		"steps": []any{
			map[string]any{
				"id":              "fetch",
				"task_id":         "fetch-task",
				"org_id":          "org-1",
				"pool_id":         "pool-1",
				"policy_id":       "policy-1",
				"timeout_seconds": 60,
				"workload":        providerWorkloadMap("fetch"),
			},
			map[string]any{
				"id":              "transform",
				"task_id":         "transform-task",
				"org_id":          "org-1",
				"pool_id":         "pool-1",
				"policy_id":       "policy-1",
				"timeout_seconds": 60,
				"depends_on":      []any{"fetch"},
				"input_mappings": []any{
					map[string]any{
						"from_step": "fetch",
						"from":      "result_preview.artifact_refs",
						"to":        "provider.artifact_refs",
					},
					map[string]any{
						"from_step": "fetch",
						"from":      "result_preview.content_inputs",
						"to":        "provider.content_inputs",
					},
					map[string]any{
						"from_step": "fetch",
						"from":      "result_preview.stream_inputs",
						"to":        "provider.stream_inputs",
					},
				},
				"workload": providerWorkloadMap("transform"),
			},
		},
	}
}

func providerWorkloadMap(operation string) map[string]any {
	return map[string]any{
		"kind": "provider",
		"provider": map[string]any{
			"provider_config": map[string]any{
				"plugin_id":   "workflow-plugin-generic-provider",
				"provider_id": "transformer",
				"contract_id": "generic-transform.v1",
				"version":     "v1.0.0",
				"config_ref":  "config://providers/generic-transformer/main",
			},
			"operation": operation,
			"image_ref": testProviderImageRef,
			"input": map[string]any{
				"value": operation,
			},
		},
	}
}

func commandWorkloadMap() map[string]any {
	return map[string]any{
		"kind": "command",
		"command": map[string]any{
			"args": []any{"true"},
		},
	}
}
