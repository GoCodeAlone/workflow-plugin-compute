package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GoCodeAlone/workflow-compute/pkg/protocol"
)

func TestStepTypes(t *testing.T) {
	steps := NewPlugin().(interface{ StepTypes() []string })
	got := steps.StepTypes()
	if len(got) != 3 || got[0] != "step.compute_dispatch" || got[2] != "step.compute_map" {
		t.Fatalf("step types: got %#v", got)
	}
}

func TestDispatchStepSubmitsTask(t *testing.T) {
	var got protocol.Task
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tasks" {
			t.Fatalf("request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("auth header: got %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode task: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"task": got})
	}))
	defer srv.Close()

	step, err := newDispatchStep("dispatch", dispatchConfigMap(srv.URL))
	if err != nil {
		t.Fatalf("newDispatchStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.StopPipeline {
		t.Fatalf("unexpected stop: %+v", result.Output)
	}
	if got.OrgID != "org-1" || got.Workload.Kind != protocol.WorkloadCommand {
		t.Fatalf("task: got %+v", got)
	}
	if got.Signature.Verified || got.Signature.Value == "" {
		t.Fatalf("signature must be submitted for server-side verification: %+v", got.Signature)
	}
	if result.Output["task_id"] != "task-1" {
		t.Fatalf("output: got %+v", result.Output)
	}
}

func TestDispatchStepRejectsUnknownConfig(t *testing.T) {
	cfg := dispatchConfigMap("https://compute.example.test")
	cfg["unknown"] = true
	if _, err := newDispatchStep("dispatch", cfg); err == nil {
		t.Fatal("expected strict unknown-field error")
	}
}

func TestWaitStepReadsTaskStatus(t *testing.T) {
	var taskCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method: %s", r.Method)
		}
		switch r.URL.Path {
		case "/v1/tasks":
			taskCalls++
			status := protocol.TaskQueued
			if taskCalls > 1 {
				status = protocol.TaskSucceeded
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []protocol.Task{{
				ID:     "task-1",
				OrgID:  "org-1",
				PoolID: "pool-1",
				Status: status,
			}}, "stalls": []any{}})
		case "/v1/proofs":
			_ = json.NewEncoder(w).Encode(map[string]any{"proofs": []protocol.ProofReceipt{proofReceipt("task-1")}})
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	step, err := newWaitStep("wait", map[string]any{
		"server_url":     srv.URL,
		"auth_token_ref": "secret:compute-token",
		"task_id":        "task-1",
		"poll_interval":  "1ms",
		"timeout":        "100ms",
	})
	if err != nil {
		t.Fatalf("newWaitStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Output["status"] != string(protocol.TaskSucceeded) {
		t.Fatalf("output: got %+v", result.Output)
	}
	if result.Output["proof_id"] != "proof-1" || result.Output["artifact_hash"] != "artifact-sha256" {
		t.Fatalf("proof output: got %+v", result.Output)
	}
	if taskCalls < 2 {
		t.Fatalf("wait step should poll until terminal status, calls=%d", taskCalls)
	}
}

func TestWaitStepCanReturnTerminalTaskWithoutProof(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []protocol.Task{{
				ID:     "task-1",
				OrgID:  "org-1",
				PoolID: "pool-1",
				Status: protocol.TaskSucceeded,
			}}, "stalls": []taskStall{{
				TaskID: "task-1",
				Reason: "proof_missing",
			}}})
		case "/v1/proofs":
			_ = json.NewEncoder(w).Encode(map[string]any{"proofs": []protocol.ProofReceipt{}})
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	requireProof := false
	step, err := newWaitStep("wait", map[string]any{
		"server_url":     srv.URL,
		"auth_token_ref": "secret:compute-token",
		"task_id":        "task-1",
		"require_proof":  requireProof,
	})
	if err != nil {
		t.Fatalf("newWaitStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.StopPipeline || result.Output["proof_id"] != nil || result.Output["status"] != string(protocol.TaskSucceeded) {
		t.Fatalf("output: got %+v", result.Output)
	}
}

func TestWaitStepFailedTaskStopsPipeline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []protocol.Task{{
				ID:     "task-1",
				OrgID:  "org-1",
				PoolID: "pool-1",
				Status: protocol.TaskFailed,
			}}, "stalls": []any{}})
		case "/v1/proofs":
			http.Error(w, "proofs unavailable", http.StatusInternalServerError)
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	step, err := newWaitStep("wait", map[string]any{
		"server_url":     srv.URL,
		"auth_token_ref": "secret:compute-token",
		"task_id":        "task-1",
	})
	if err != nil {
		t.Fatalf("newWaitStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.StopPipeline || result.Output["status"] != string(protocol.TaskFailed) {
		t.Fatalf("failed task should stop pipeline, got %+v", result.Output)
	}
}

func TestWaitStepStopsOnTaskStallFlag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []protocol.Task{{
				ID:     "task-1",
				OrgID:  "org-1",
				PoolID: "pool-1",
				Status: protocol.TaskQueued,
			}}, "stalls": []taskStall{{
				TaskID: "task-1",
				Reason: "queued_sla_exceeded",
				AgeMS:  120000,
			}}})
		case "/v1/proofs":
			http.Error(w, "proofs should not be read for stalled task", http.StatusInternalServerError)
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	step, err := newWaitStep("wait", map[string]any{
		"server_url":     srv.URL,
		"auth_token_ref": "secret:compute-token",
		"task_id":        "task-1",
	})
	if err != nil {
		t.Fatalf("newWaitStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.StopPipeline || result.Output["stall_reason"] != "queued_sla_exceeded" {
		t.Fatalf("stall should stop pipeline with metadata, got %+v", result.Output)
	}
}

func TestWaitStepRejectsNonAcceptedProofStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []protocol.Task{{
				ID:     "task-1",
				OrgID:  "org-1",
				PoolID: "pool-1",
				Status: protocol.TaskSucceeded,
			}}, "stalls": []any{}})
		case "/v1/proofs":
			proof := proofReceipt("task-1")
			proof.Verifier.Status = protocol.VerificationRejected
			_ = json.NewEncoder(w).Encode(map[string]any{"proofs": []protocol.ProofReceipt{proof}})
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	step, err := newWaitStep("wait", map[string]any{
		"server_url":     srv.URL,
		"auth_token_ref": "secret:compute-token",
		"task_id":        "task-1",
	})
	if err != nil {
		t.Fatalf("newWaitStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.StopPipeline || result.Output["proof_status"] != string(protocol.VerificationRejected) {
		t.Fatalf("rejected proof should stop pipeline, got %+v", result.Output)
	}
}

func TestMapStepSubmitsEachTask(t *testing.T) {
	var count int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		var task protocol.Task
		if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
			t.Fatalf("decode task: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"task": task})
	}))
	defer srv.Close()

	cfg := map[string]any{
		"server_url":     srv.URL,
		"auth_token_ref": "secret:compute-token",
		"tasks": []any{
			taskConfigMap("task-1"),
			taskConfigMap("task-2"),
		},
	}
	step, err := newMapStep("map", cfg)
	if err != nil {
		t.Fatalf("newMapStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.StopPipeline || count != 2 {
		t.Fatalf("result=%+v count=%d", result, count)
	}
}

func dispatchConfigMap(serverURL string) map[string]any {
	cfg := taskConfigMap("task-1")
	cfg["server_url"] = serverURL
	cfg["auth_token_ref"] = "secret:compute-token"
	return cfg
}

func taskConfigMap(id string) map[string]any {
	return map[string]any{
		"id":              id,
		"org_id":          "org-1",
		"pool_id":         "pool-1",
		"policy_id":       "policy-1",
		"timeout_seconds": 60,
		"workload": map[string]any{
			"kind": "command",
			"command": map[string]any{
				"args": []any{"true"},
			},
		},
	}
}

func runtimeSecrets() map[string]any {
	return map[string]any{
		"secrets": map[string]any{
			"compute-token": "token",
		},
	}
}

func proofReceipt(taskID string) protocol.ProofReceipt {
	return protocol.ProofReceipt{
		ID:           "proof-1",
		OrgID:        "org-1",
		TaskID:       taskID,
		WorkerID:     "worker-1",
		ArtifactHash: "artifact-sha256",
		Verifier: protocol.VerifierResult{
			Provider: "signed-receipt",
			Status:   protocol.VerificationAccepted,
		},
	}
}
