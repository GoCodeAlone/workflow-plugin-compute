package internal

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/GoCodeAlone/workflow-compute/pkg/protocol"
)

func TestT6_CLIProviderRunsComputeCommand(t *testing.T) {
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

	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "run",
		"--server", srv.URL,
		"--token", "token",
		"--id", "task-1",
		"--org", "org-1",
		"--pool", "pool-1",
		"true",
	})

	if code != 0 {
		t.Fatalf("RunCLI code=%d stderr=%s", code, stderr.String())
	}
	if got.ID != "task-1" || got.Workload.Kind != protocol.WorkloadCommand || got.Signature.Value == "" {
		t.Fatalf("task: got %+v", got)
	}
	if got.Signature.Algorithm != "dev-local-sha256" || got.Signature.KeyID != "local-dev" {
		t.Fatalf("signature envelope must match v0 core verifier: %+v", got.Signature)
	}
	var receipt taskReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if receipt.TaskID != "task-1" || receipt.InputHash == "" {
		t.Fatalf("receipt: got %+v", receipt)
	}
	for _, forbidden := range [][]byte{[]byte("token"), []byte("signature"), []byte("workload"), []byte("true")} {
		if bytes.Contains(stdout.Bytes(), forbidden) {
			t.Fatalf("stdout leaked %q: %s", forbidden, stdout.String())
		}
	}
}

func TestT6_CLIRunValidatesTaskBeforeAPICall(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "run",
		"--server", srv.URL,
		"true",
	})

	if code == 0 {
		t.Fatal("expected missing org/pool to fail")
	}
	if calls != 0 {
		t.Fatalf("expected local validation before API call, calls=%d", calls)
	}
}

func TestT6_CLIEnrollRequiresExplicitMemory(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "enroll",
		"--server", "http://127.0.0.1:1",
		"--id", "worker-1",
		"--org", "org-1",
		"--pool", "pool-1",
		"--machine-id", "machine-1",
	})

	if code == 0 {
		t.Fatal("expected missing memory to fail enrollment before API call")
	}
	if bytes.Contains(stderr.Bytes(), []byte("Bearer")) || bytes.Contains(stdout.Bytes(), []byte("Bearer")) {
		t.Fatalf("output leaked auth material: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestT6_CLIPoolsSummarizeObservedState(t *testing.T) {
	summaries := summarizePools([]protocol.Worker{{
		ID:     "worker-1",
		OrgID:  "org-1",
		PoolID: "pool-1",
		Status: protocol.WorkerOnline,
	}}, []protocol.Task{{
		ID:     "task-1",
		OrgID:  "org-1",
		PoolID: "pool-1",
		Status: protocol.TaskQueued,
	}})

	if len(summaries) != 1 || summaries[0].OnlineAgents != 1 || summaries[0].QueuedTasks != 1 {
		t.Fatalf("summaries: got %+v", summaries)
	}
}

func TestT6_CLIAuditCountsProofStates(t *testing.T) {
	summary := auditProofs([]protocol.ProofReceipt{
		{Verifier: protocol.VerifierResult{Status: protocol.VerificationAccepted}},
		{Verifier: protocol.VerifierResult{Status: protocol.VerificationRejected}},
		{},
	})

	if summary.Proofs != 3 || summary.Accepted != 1 || summary.Rejected != 1 || summary.Unknown != 1 {
		t.Fatalf("summary: got %+v", summary)
	}
}

func TestV12_TokenRequiresHTTPSOrLoopback(t *testing.T) {
	if _, err := newComputeClient("http://compute.example.test", "token", 0); err == nil {
		t.Fatal("expected token-bearing non-loopback http URL to fail")
	}
	if _, err := newComputeClient("http://127.0.0.1:8080", "token", 0); err != nil {
		t.Fatalf("loopback http should be allowed for local dev: %v", err)
	}
	if _, err := newComputeClient("https://compute.example.test", "token", 0); err != nil {
		t.Fatalf("https should be allowed with token: %v", err)
	}
}
