package internal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	coreprotocol "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestStepComputeStreamSubmitsVideoStreamTask(t *testing.T) {
	var got coreprotocol.Task
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

	step, err := NewPlugin().(*computePlugin).CreateStep("step.compute_stream", "stream", streamConfigMap(srv.URL))
	if err != nil {
		t.Fatalf("CreateStep: %v", err)
	}
	result, err := step.Execute(context.Background(), nil, nil, nil, nil, runtimeSecrets())
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.StopPipeline {
		t.Fatalf("unexpected stop: %+v", result.Output)
	}
	if result.Output["task_id"] != "stream-task-1" {
		t.Fatalf("output: got %+v", result.Output)
	}
	if got.OrgID != "org-1" || got.PoolID != "pool-1" || got.PolicyID != "policy-1" {
		t.Fatalf("routing fields: %+v", got)
	}
	if got.Workload.Kind != coreprotocol.WorkloadVideoStream || got.Workload.VideoStream == nil {
		t.Fatalf("workload: got %+v", got.Workload)
	}
	if len(got.Workload.VideoStream.IngestProtocols) != 1 || got.Workload.VideoStream.IngestProtocols[0] != "rtmp" || !got.Workload.VideoStream.ViewerEgress.HLS {
		t.Fatalf("stream spec: %+v", got.Workload.VideoStream)
	}
	if got.Signature.Value == "" || got.InputHash == "" {
		t.Fatalf("task must be locally signed and hashed: %+v", got)
	}
}

func TestStepComputeStreamRejectsMissingStreamSpec(t *testing.T) {
	cfg := streamConfigMap("https://compute.example.test")
	delete(cfg, "stream")
	if _, err := newComputeStreamStep("stream", cfg); err == nil {
		t.Fatal("expected missing stream spec to fail validation")
	}
}

func TestStepComputeStreamRejectsUnknownNestedStreamConfig(t *testing.T) {
	cfg := streamConfigMap("https://compute.example.test")
	stream := cfg["stream"].(map[string]any)
	stream["unknown"] = true
	if _, err := newComputeStreamStep("stream", cfg); err == nil {
		t.Fatal("expected strict nested stream unknown-field error")
	}
}

func streamConfigMap(serverURL string) map[string]any {
	cfg := map[string]any{
		"id":              "stream-task-1",
		"org_id":          "org-1",
		"pool_id":         "pool-1",
		"policy_id":       "policy-1",
		"timeout_seconds": 120,
		"server_url":      serverURL,
		"auth_token_ref":  "secret:compute-token",
		"stream": map[string]any{
			"ingest_protocols": []any{"rtmp"},
			"viewer_egress": map[string]any{
				"hls": true,
			},
			"destinations": []any{map[string]any{
				"target_ref": "stream://destinations/main",
				"rendition":  "720p",
			}},
		},
	}
	return cfg
}

func TestStepTypesIncludeComputeStream(t *testing.T) {
	got := NewPlugin().(interface{ StepTypes() []string }).StepTypes()
	want := []string{"step.compute_dispatch", "step.compute_wait", "step.compute_map", "step.compute_stream", "step.compute_chain"}
	if len(got) != len(want) {
		t.Fatalf("step types: got %#v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("step types: got %#v", got)
		}
	}
}
