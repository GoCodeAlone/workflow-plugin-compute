package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-compute/pkg/protocol"
)

const testProviderImageRef = "ghcr.io/gocodealone/generic-provider@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestStepTypes(t *testing.T) {
	steps := NewPlugin().(interface{ StepTypes() []string })
	got := steps.StepTypes()
	want := []string{"step.compute_dispatch", "step.compute_wait", "step.compute_map"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("step types: got %#v", got)
	}
}

func TestComputePluginDoesNotExposeProviderSpecificProductCapture(t *testing.T) {
	plugin := NewPlugin().(*computePlugin)
	for _, stepType := range plugin.StepTypes() {
		if strings.Contains(stepType, "product") || strings.Contains(stepType, "capture") {
			t.Fatalf("compute plugin leaked provider-specific step type %q", stepType)
		}
	}
	if _, err := plugin.CreateStep("step.compute_product_capture", "capture", map[string]any{}); err == nil {
		t.Fatal("compute plugin accepted provider-specific product capture step")
	}
}

func TestPluginManifestStepTypesMatchRuntime(t *testing.T) {
	data, err := os.ReadFile("../plugin.json")
	if err != nil {
		t.Fatalf("read plugin manifest: %v", err)
	}
	var manifest struct {
		Capabilities struct {
			StepTypes []string `json:"stepTypes"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode plugin manifest: %v", err)
	}
	steps := NewPlugin().(interface{ StepTypes() []string })
	if strings.Join(manifest.Capabilities.StepTypes, ",") != strings.Join(steps.StepTypes(), ",") {
		t.Fatalf("manifest step types %v do not match runtime %v", manifest.Capabilities.StepTypes, steps.StepTypes())
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

func TestDispatchStepRejectsUnknownNestedWorkloadConfig(t *testing.T) {
	cfg := dispatchConfigMap("https://compute.example.test")
	workload := cfg["workload"].(map[string]any)
	command := workload["command"].(map[string]any)
	command["extra"] = true
	if _, err := newDispatchStep("dispatch", cfg); err == nil {
		t.Fatal("expected strict nested unknown-field error")
	}
}

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

func TestDispatchStepRejectsMalformedResiduePolicy(t *testing.T) {
	cfg := dispatchConfigMap("https://compute.example.test")
	cfg["residue_policy"] = map[string]any{"mode": "bogus"}
	if _, err := newDispatchStep("dispatch", cfg); err == nil || !strings.Contains(err.Error(), "residue_policy") {
		t.Fatalf("expected residue_policy validation error, got %v", err)
	}
}

func TestDispatchStepRejectsImplicitWorkerBoundResiduePolicy(t *testing.T) {
	cfg := dispatchConfigMap("https://compute.example.test")
	cfg["residue_policy"] = map[string]any{"mode": "worker-bound"}
	if _, err := newDispatchStep("dispatch", cfg); err == nil || !strings.Contains(err.Error(), "explicit_worker_bound") {
		t.Fatalf("expected explicit_worker_bound validation error, got %v", err)
	}
}

func TestDispatchStepAcceptsProviderWorkload(t *testing.T) {
	var got protocol.Task
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tasks" {
			t.Fatalf("request: %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode task: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"task": got})
	}))
	defer srv.Close()

	step, err := newDispatchStep("dispatch", genericProviderConfigMap(srv.URL))
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
	if got.ProductID != "" {
		t.Fatalf("dispatch should not inject product identity: got %+v", got)
	}
	if got.Workload.Kind != protocol.WorkloadProvider || got.Workload.Provider == nil {
		t.Fatalf("workload: got %+v", got.Workload)
	}
	if got.Workload.Provider.ProviderConfig != genericProviderConfig() {
		t.Fatalf("provider config: %+v", got.Workload.Provider.ProviderConfig)
	}
	if got.Workload.Provider.Operation != "transform" {
		t.Fatalf("operation: %q", got.Workload.Provider.Operation)
	}
	if got.Workload.Provider.ImageRef != testProviderImageRef {
		t.Fatalf("image ref: %q", got.Workload.Provider.ImageRef)
	}
	if !strings.Contains(string(got.Workload.Provider.Input), `"value":"hello"`) {
		t.Fatalf("provider input: %s", got.Workload.Provider.Input)
	}
}

func TestDispatchStepRejectsUnknownNestedProviderConfig(t *testing.T) {
	cfg := genericProviderConfigMap("https://compute.example.test")
	workload := cfg["workload"].(map[string]any)
	provider := workload["provider"].(map[string]any)
	provider["extra"] = true
	if _, err := newDispatchStep("dispatch", cfg); err == nil {
		t.Fatal("expected strict nested provider unknown-field error")
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

func TestMapStepSubmitsEachTaskAndWaits(t *testing.T) {
	var submitCount int
	var listCount int
	var proofCount int
	var submitted []protocol.Task
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			switch r.Method {
			case http.MethodPost:
				submitCount++
				var task protocol.Task
				if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
					t.Fatalf("decode task: %v", err)
				}
				submitted = append(submitted, task)
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{"task": task})
			case http.MethodGet:
				listCount++
				tasks := append([]protocol.Task(nil), submitted...)
				for i := range tasks {
					tasks[i].Status = protocol.TaskQueued
					if listCount > 1 {
						tasks[i].Status = protocol.TaskSucceeded
					}
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"tasks": tasks, "stalls": []any{}})
			default:
				t.Fatalf("method: %s", r.Method)
			}
		case "/v1/proofs":
			proofCount++
			proofs := make([]protocol.ProofReceipt, 0, len(submitted))
			for _, task := range submitted {
				proofs = append(proofs, proofReceipt(task.ID))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"proofs": proofs})
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	cfg := map[string]any{
		"server_url":     srv.URL,
		"auth_token_ref": "secret:compute-token",
		"tasks": []any{
			taskConfigMap("task-1"),
			taskConfigMap("task-2"),
		},
		"poll_interval": "1ms",
		"timeout":       "100ms",
	}
	step, err := newMapStep("map", cfg)
	if err != nil {
		t.Fatalf("newMapStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.StopPipeline || submitCount != 2 || listCount < 2 || proofCount == 0 {
		t.Fatalf("result=%+v submit=%d list=%d proofs=%d", result, submitCount, listCount, proofCount)
	}
	tasks, ok := result.Output["tasks"].([]map[string]any)
	if !ok || len(tasks) != 2 {
		t.Fatalf("tasks output: got %+v", result.Output)
	}
	if tasks[0]["proof_id"] != "proof-1" || tasks[1]["status"] != string(protocol.TaskSucceeded) {
		t.Fatalf("task outputs: got %+v", tasks)
	}
}

func TestMapStepSubmitsPerTaskResiduePolicies(t *testing.T) {
	var submitted []protocol.Task
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			switch r.Method {
			case http.MethodPost:
				var task protocol.Task
				if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
					t.Fatalf("decode task: %v", err)
				}
				submitted = append(submitted, task)
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{"task": task})
			case http.MethodGet:
				tasks := append([]protocol.Task(nil), submitted...)
				for i := range tasks {
					tasks[i].Status = protocol.TaskSucceeded
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"tasks": tasks, "stalls": []any{}})
			default:
				t.Fatalf("method: %s", r.Method)
			}
		case "/v1/proofs":
			proofs := make([]protocol.ProofReceipt, 0, len(submitted))
			for _, task := range submitted {
				proofs = append(proofs, proofReceipt(task.ID))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"proofs": proofs})
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	first := taskConfigMap("task-1")
	first["residue_policy"] = map[string]any{
		"mode":          "provider-bound",
		"allowed_modes": []any{"isolated", "provider-bound"},
	}
	second := taskConfigMap("task-2")
	second["residue_policy"] = map[string]any{"mode": "isolated"}
	step, err := newMapStep("map", map[string]any{
		"server_url":     srv.URL,
		"auth_token_ref": "secret:compute-token",
		"tasks":          []any{first, second},
		"poll_interval":  "1ms",
		"timeout":        "100ms",
	})
	if err != nil {
		t.Fatalf("newMapStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.StopPipeline {
		t.Fatalf("unexpected stop: %+v", result.Output)
	}
	if len(submitted) != 2 ||
		submitted[0].ResiduePolicy.Mode != protocol.ResidueModeProviderBound ||
		submitted[1].ResiduePolicy.Mode != protocol.ResidueModeIsolated {
		t.Fatalf("submitted residue policies: %+v", submitted)
	}
}

func TestMapStepRejectsUnknownConfig(t *testing.T) {
	cfg := map[string]any{
		"server_url":     "https://compute.example.test",
		"auth_token_ref": "secret:compute-token",
		"tasks":          []any{taskConfigMap("task-1")},
		"unknown":        true,
	}
	if _, err := newMapStep("map", cfg); err == nil {
		t.Fatal("expected strict unknown-field error")
	}
}

func TestMapStepRejectsUnknownNestedTaskWorkloadConfig(t *testing.T) {
	task := taskConfigMap("task-1")
	workload := task["workload"].(map[string]any)
	command := workload["command"].(map[string]any)
	command["extra"] = true
	cfg := map[string]any{
		"server_url":     "https://compute.example.test",
		"auth_token_ref": "secret:compute-token",
		"tasks":          []any{task},
	}
	if _, err := newMapStep("map", cfg); err == nil {
		t.Fatal("expected strict nested unknown-field error")
	}
}

func TestMapStepFailedTaskStopsPipeline(t *testing.T) {
	var submitted []protocol.Task
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			switch r.Method {
			case http.MethodPost:
				var task protocol.Task
				if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
					t.Fatalf("decode task: %v", err)
				}
				submitted = append(submitted, task)
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{"task": task})
			case http.MethodGet:
				tasks := append([]protocol.Task(nil), submitted...)
				for i := range tasks {
					tasks[i].Status = protocol.TaskSucceeded
				}
				tasks[0].Status = protocol.TaskFailed
				_ = json.NewEncoder(w).Encode(map[string]any{"tasks": tasks, "stalls": []any{}})
			default:
				t.Fatalf("method: %s", r.Method)
			}
		case "/v1/proofs":
			http.Error(w, "proofs should not be read for failed task", http.StatusInternalServerError)
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	step, err := newMapStep("map", map[string]any{
		"server_url":     srv.URL,
		"auth_token_ref": "secret:compute-token",
		"tasks":          []any{taskConfigMap("task-1"), taskConfigMap("task-2")},
		"poll_interval":  "1ms",
		"timeout":        "100ms",
	})
	if err != nil {
		t.Fatalf("newMapStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.StopPipeline {
		t.Fatalf("failed task should stop pipeline, got %+v", result.Output)
	}
	tasks := result.Output["tasks"].([]map[string]any)
	if tasks[0]["status"] != string(protocol.TaskFailed) {
		t.Fatalf("failed task output: got %+v", result.Output)
	}
}

func TestMapStepRejectsNonAcceptedProofStatus(t *testing.T) {
	var submitted []protocol.Task
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			switch r.Method {
			case http.MethodPost:
				var task protocol.Task
				if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
					t.Fatalf("decode task: %v", err)
				}
				submitted = append(submitted, task)
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{"task": task})
			case http.MethodGet:
				tasks := append([]protocol.Task(nil), submitted...)
				for i := range tasks {
					tasks[i].Status = protocol.TaskSucceeded
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"tasks": tasks, "stalls": []any{}})
			default:
				t.Fatalf("method: %s", r.Method)
			}
		case "/v1/proofs":
			proofs := make([]protocol.ProofReceipt, 0, len(submitted))
			for i, task := range submitted {
				proof := proofReceipt(task.ID)
				if i == 1 {
					proof.Verifier.Status = protocol.VerificationRejected
				}
				proofs = append(proofs, proof)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"proofs": proofs})
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	step, err := newMapStep("map", map[string]any{
		"server_url":     srv.URL,
		"auth_token_ref": "secret:compute-token",
		"tasks":          []any{taskConfigMap("task-1"), taskConfigMap("task-2")},
	})
	if err != nil {
		t.Fatalf("newMapStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.StopPipeline {
		t.Fatalf("rejected proof should stop pipeline, got %+v", result.Output)
	}
	tasks := result.Output["tasks"].([]map[string]any)
	if tasks[1]["proof_status"] != string(protocol.VerificationRejected) {
		t.Fatalf("rejected proof output: got %+v", result.Output)
	}
}

func TestMapStepWaitsForRequiredProof(t *testing.T) {
	var submitted []protocol.Task
	var proofCalls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			switch r.Method {
			case http.MethodPost:
				var task protocol.Task
				if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
					t.Fatalf("decode task: %v", err)
				}
				submitted = append(submitted, task)
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{"task": task})
			case http.MethodGet:
				tasks := append([]protocol.Task(nil), submitted...)
				for i := range tasks {
					tasks[i].Status = protocol.TaskSucceeded
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"tasks": tasks, "stalls": []any{}})
			default:
				t.Fatalf("method: %s", r.Method)
			}
		case "/v1/proofs":
			proofCalls++
			proofs := []protocol.ProofReceipt{}
			if proofCalls > 1 {
				for _, task := range submitted {
					proofs = append(proofs, proofReceipt(task.ID))
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"proofs": proofs})
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	step, err := newMapStep("map", map[string]any{
		"server_url":     srv.URL,
		"auth_token_ref": "secret:compute-token",
		"tasks":          []any{taskConfigMap("task-1")},
		"poll_interval":  "1ms",
		"timeout":        "100ms",
	})
	if err != nil {
		t.Fatalf("newMapStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.StopPipeline || proofCalls < 2 {
		t.Fatalf("map should wait for delayed proof, result=%+v proofCalls=%d", result.Output, proofCalls)
	}
	tasks := result.Output["tasks"].([]map[string]any)
	if tasks[0]["proof_id"] != "proof-1" {
		t.Fatalf("delayed proof output: got %+v", result.Output)
	}
}

func TestMapStepMissingTaskStopsPipeline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			switch r.Method {
			case http.MethodPost:
				var task protocol.Task
				if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
					t.Fatalf("decode task: %v", err)
				}
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{"task": task})
			case http.MethodGet:
				_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []protocol.Task{}, "stalls": []any{}})
			default:
				t.Fatalf("method: %s", r.Method)
			}
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	step, err := newMapStep("map", map[string]any{
		"server_url":     srv.URL,
		"auth_token_ref": "secret:compute-token",
		"tasks":          []any{taskConfigMap("task-1")},
	})
	if err != nil {
		t.Fatalf("newMapStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.StopPipeline || result.Output["error"] != `task "task-1" not found` {
		t.Fatalf("missing task should stop pipeline, got %+v", result.Output)
	}
}

func TestMapStepStallStopsPipelineWithMetadata(t *testing.T) {
	var submitted []protocol.Task
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			switch r.Method {
			case http.MethodPost:
				var task protocol.Task
				if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
					t.Fatalf("decode task: %v", err)
				}
				submitted = append(submitted, task)
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{"task": task})
			case http.MethodGet:
				tasks := append([]protocol.Task(nil), submitted...)
				for i := range tasks {
					tasks[i].Status = protocol.TaskQueued
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"tasks": tasks, "stalls": []taskStall{{
					TaskID:  "task-1",
					LeaseID: "lease-1",
					AgentID: "agent-1",
					Reason:  "queued_sla_exceeded",
					AgeMS:   120000,
				}}})
			default:
				t.Fatalf("method: %s", r.Method)
			}
		case "/v1/proofs":
			http.Error(w, "proofs should not be read for stalled task", http.StatusInternalServerError)
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	step, err := newMapStep("map", map[string]any{
		"server_url":     srv.URL,
		"auth_token_ref": "secret:compute-token",
		"tasks":          []any{taskConfigMap("task-1")},
	})
	if err != nil {
		t.Fatalf("newMapStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.StopPipeline {
		t.Fatalf("stall should stop pipeline, got %+v", result.Output)
	}
	tasks := result.Output["tasks"].([]map[string]any)
	if tasks[0]["stall_reason"] != "queued_sla_exceeded" || tasks[0]["lease_id"] != "lease-1" {
		t.Fatalf("stall output: got %+v", result.Output)
	}
}

func TestMapStepTimeoutStopsPipeline(t *testing.T) {
	var submitted []protocol.Task
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			switch r.Method {
			case http.MethodPost:
				var task protocol.Task
				if err := json.NewDecoder(r.Body).Decode(&task); err != nil {
					t.Fatalf("decode task: %v", err)
				}
				submitted = append(submitted, task)
				w.WriteHeader(http.StatusCreated)
				_ = json.NewEncoder(w).Encode(map[string]any{"task": task})
			case http.MethodGet:
				tasks := append([]protocol.Task(nil), submitted...)
				for i := range tasks {
					tasks[i].Status = protocol.TaskQueued
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"tasks": tasks, "stalls": []any{}})
			default:
				t.Fatalf("method: %s", r.Method)
			}
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	step, err := newMapStep("map", map[string]any{
		"server_url":     srv.URL,
		"auth_token_ref": "secret:compute-token",
		"tasks":          []any{taskConfigMap("task-1")},
		"poll_interval":  "1ms",
		"timeout":        "5ms",
	})
	if err != nil {
		t.Fatalf("newMapStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !result.StopPipeline || result.Output["error"] != "timed out waiting for 1 compute tasks" {
		t.Fatalf("timeout should stop pipeline, got %+v", result.Output)
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

func genericProviderConfigMap(serverURL string) map[string]any {
	cfg := map[string]any{
		"id":              "provider-1",
		"org_id":          "org-1",
		"pool_id":         "pool-1",
		"policy_id":       "policy-1",
		"timeout_seconds": 60,
		"server_url":      serverURL,
		"auth_token_ref":  "secret:compute-token",
		"workload": map[string]any{
			"kind": "provider",
			"provider": map[string]any{
				"provider_config": map[string]any{
					"plugin_id":   "workflow-plugin-generic-provider",
					"provider_id": "transformer",
					"contract_id": "generic-transform.v1",
					"version":     "v1.0.0",
					"config_ref":  "config://providers/generic-transformer/main",
				},
				"operation": "transform",
				"image_ref": testProviderImageRef,
				"input": map[string]any{
					"value": "hello",
				},
			},
		},
	}
	return cfg
}

func genericProviderConfig() protocol.ProviderConfig {
	return protocol.ProviderConfig{
		PluginID:   "workflow-plugin-generic-provider",
		ProviderID: "transformer",
		ContractID: "generic-transform.v1",
		Version:    "v1.0.0",
		ConfigRef:  "config://providers/generic-transformer/main",
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
