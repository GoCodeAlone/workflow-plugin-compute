package internal

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/GoCodeAlone/workflow-compute/pkg/protocol"
)

func TestT542_CLIAgentSetupHelpWorksProjectlessly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{"compute", "agent", "setup", "-help"})

	if code != 0 {
		t.Fatalf("RunCLI code=%d stderr=%s", code, stderr.String())
	}
	help := stderr.String()
	for _, required := range []string{
		"compute agent setup",
		"-server",
		"-invite-url",
		"-install-session-id",
		"-non-interactive",
		"-json",
	} {
		if !strings.Contains(help, required) {
			t.Fatalf("help missing %q in %s", required, help)
		}
	}
	if strings.Contains(help, "\n  -token string") {
		t.Fatalf("setup invite help must not expose broad API token flags: %s", help)
	}
}

func TestT542_CLIAgentSetupClaimsInviteWithoutProjectManifestOrSecretOutput(t *testing.T) {
	var paths []string
	var previewReq protocol.AgentSetupInvitePreviewRequest
	var claimReq protocol.AgentSetupInviteClaimRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") != "" {
			t.Fatalf("agent setup invite flow must not require broad bearer auth, got %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1/onboarding/setup-invites/preview":
			if r.Method != http.MethodPost {
				t.Fatalf("preview method: %s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&previewReq); err != nil {
				t.Fatalf("decode preview: %v", err)
			}
			_ = json.NewEncoder(w).Encode(protocol.AgentSetupInvitePreviewResponse{
				Invite: protocol.AgentSetupInvite{ID: "invite-1", Policy: protocol.AgentOnboardingRequest{AgentID: "worker-1", OrgID: "org-1", PoolID: "pool-1", AccountID: "acct-operator"}},
			})
		case "/v1/onboarding/setup-invites/claim":
			if r.Method != http.MethodPost {
				t.Fatalf("claim method: %s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&claimReq); err != nil {
				t.Fatalf("decode claim: %v", err)
			}
			_ = json.NewEncoder(w).Encode(protocol.AgentSetupInviteClaimResponse{
				Invite:       protocol.AgentSetupInvite{ID: "invite-1", Policy: protocol.AgentOnboardingRequest{AgentID: "worker-1", OrgID: "org-1", PoolID: "pool-1", AccountID: "acct-operator"}},
				Session:      protocol.AgentSetupInstallSession{ID: claimReq.InstallSessionID, InviteID: "invite-1", WorkerID: "worker-1", OrgID: "org-1", PoolID: "pool-1", CredentialID: "cred-1"},
				Onboarding:   protocol.AgentOnboardingRequest{AgentID: "worker-1", OrgID: "org-1", PoolID: "pool-1", AccountID: "acct-operator"},
				OneTimeToken: "raw-secret-token",
			})
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "agent", "setup",
		"--server", srv.URL,
		"--invite-url", srv.URL + "/install?invite_id=invite-1&redeem_code=code-1",
		"--install-session-id", "session-1",
		"--token-env", "COMPUTE_AGENT_TOKEN",
		"--non-interactive",
		"--json",
	})

	if code != 0 {
		t.Fatalf("RunCLI code=%d stderr=%s", code, stderr.String())
	}
	if strings.Join(paths, ",") != "/v1/onboarding/setup-invites/preview,/v1/onboarding/setup-invites/claim" {
		t.Fatalf("paths: %v", paths)
	}
	if previewReq.InviteURL == "" || claimReq.InviteURL == "" || claimReq.InstallSessionID != "session-1" || claimReq.ServerURL != srv.URL {
		t.Fatalf("preview=%+v claim=%+v", previewReq, claimReq)
	}
	out := stdout.String()
	for _, required := range []string{
		`"worker_id": "worker-1"`,
		`"credential_id": "cred-1"`,
		`"token_env": "COMPUTE_AGENT_TOKEN"`,
		`"token_present": true`,
	} {
		if !strings.Contains(out, required) {
			t.Fatalf("stdout missing %q in %s", required, out)
		}
	}
	for _, forbidden := range []string{"raw-secret-token", "code-1", "redeem_code", "org-1", "pool-1"} {
		if strings.Contains(out, forbidden) || strings.Contains(stderr.String(), forbidden) {
			t.Fatalf("output leaked %q: stdout=%s stderr=%s", forbidden, out, stderr.String())
		}
	}
}

func TestT542_CLIAgentSetupVerifyFinalizesInviteWithoutSecretOutput(t *testing.T) {
	var paths []string
	var finalizeReq protocol.AgentSetupInviteFinalizeRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/v1/onboarding/setup-invites/preview":
			_ = json.NewEncoder(w).Encode(protocol.AgentSetupInvitePreviewResponse{
				Invite: protocol.AgentSetupInvite{ID: "invite-verify", Policy: protocol.AgentOnboardingRequest{AgentID: "worker-verify"}},
			})
		case "/v1/onboarding/setup-invites/claim":
			_ = json.NewEncoder(w).Encode(protocol.AgentSetupInviteClaimResponse{
				Invite:  protocol.AgentSetupInvite{ID: "invite-verify", Policy: protocol.AgentOnboardingRequest{AgentID: "worker-verify"}},
				Session: protocol.AgentSetupInstallSession{ID: "session-verify", InviteID: "invite-verify", WorkerID: "worker-verify", CredentialID: "cred-verify"},
			})
		case "/v1/onboarding/setup-invites/finalize":
			if err := json.NewDecoder(r.Body).Decode(&finalizeReq); err != nil {
				t.Fatalf("decode finalize: %v", err)
			}
			_ = json.NewEncoder(w).Encode(protocol.AgentSetupInviteClaimResponse{
				Invite:       protocol.AgentSetupInvite{ID: "invite-verify", Policy: protocol.AgentOnboardingRequest{AgentID: "worker-verify"}},
				Session:      protocol.AgentSetupInstallSession{ID: "session-verify", InviteID: "invite-verify", WorkerID: "worker-verify", CredentialID: "cred-verify", FinalizedAt: time.Now().UTC()},
				OneTimeToken: "finalize-secret",
			})
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "agent", "setup",
		"--server", srv.URL,
		"--invite", "invite-verify",
		"--install-session-id", "session-verify",
		"--non-interactive",
		"--verify",
		"--json",
	})

	if code != 0 {
		t.Fatalf("RunCLI code=%d stderr=%s", code, stderr.String())
	}
	if strings.Join(paths, ",") != "/v1/onboarding/setup-invites/preview,/v1/onboarding/setup-invites/claim,/v1/onboarding/setup-invites/finalize" {
		t.Fatalf("paths: %v", paths)
	}
	if finalizeReq.InviteID != "invite-verify" || finalizeReq.InstallSessionID != "session-verify" || finalizeReq.WorkerID != "worker-verify" || !finalizeReq.Verified {
		t.Fatalf("finalize request: %+v", finalizeReq)
	}
	out := stdout.String()
	if !strings.Contains(out, `"verified": true`) {
		t.Fatalf("stdout missing verified=true: %s", out)
	}
	if strings.Contains(out, "finalize-secret") || strings.Contains(stderr.String(), "finalize-secret") {
		t.Fatalf("output leaked finalize token: stdout=%s stderr=%s", out, stderr.String())
	}
}

func TestT542_CLIAgentSetupRejectsMalformedClaimResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/onboarding/setup-invites/preview":
			_ = json.NewEncoder(w).Encode(protocol.AgentSetupInvitePreviewResponse{
				Invite: protocol.AgentSetupInvite{ID: "invite-bad"},
			})
		case "/v1/onboarding/setup-invites/claim":
			_ = json.NewEncoder(w).Encode(protocol.AgentSetupInviteClaimResponse{
				Invite:       protocol.AgentSetupInvite{ID: "invite-bad"},
				OneTimeToken: "malformed-secret",
			})
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "agent", "setup",
		"--server", srv.URL,
		"--invite", "invite-bad",
		"--non-interactive",
		"--json",
	})

	if code == 0 {
		t.Fatal("RunCLI succeeded with malformed claim response")
	}
	if !strings.Contains(stderr.String(), "missing worker_id") {
		t.Fatalf("stderr: %s", stderr.String())
	}
	if strings.Contains(stdout.String(), "malformed-secret") || strings.Contains(stderr.String(), "malformed-secret") {
		t.Fatalf("output leaked malformed claim token: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

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

func TestT8_CLISubmitCommandUsesCompactReceipt(t *testing.T) {
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

	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "submit", "command",
		"--server", srv.URL,
		"--token", "token",
		"--id", "task-1",
		"--org", "org-1",
		"--pool", "pool-1",
		"--workdir", "repo",
		"--env", "TOKEN=secret:github-token",
		"--artifact", "artifacts/result.json",
		"true",
	})

	if code != 0 {
		t.Fatalf("RunCLI code=%d stderr=%s", code, stderr.String())
	}
	if got.Workload.Kind != protocol.WorkloadCommand || got.Workload.Command.WorkingDirectory != "repo" {
		t.Fatalf("task: got %+v", got)
	}
	if got.Workload.Command.Env[0].SecretRef != "secret:github-token" || got.Workload.Command.ArtifactAllowlist[0] != "artifacts/result.json" {
		t.Fatalf("command refs: got %+v", got.Workload.Command)
	}
	for _, forbidden := range [][]byte{[]byte("token"), []byte("signature"), []byte("workload"), []byte("secret:github-token")} {
		if bytes.Contains(stdout.Bytes(), forbidden) {
			t.Fatalf("stdout leaked %q: %s", forbidden, stdout.String())
		}
	}
}

func TestT8_CLISubmitContainerBuild(t *testing.T) {
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

	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "submit", "container-build",
		"--server", srv.URL,
		"--token", "token",
		"--id", "image-1",
		"--org", "org-1",
		"--pool", "pool-1",
		"--context", "repo/services/api",
		"--dockerfile", "Dockerfile",
		"--tag", "registry.example/api:sha",
		"--push-target-ref", "registry:docr-shared",
	})

	if code != 0 {
		t.Fatalf("RunCLI code=%d stderr=%s", code, stderr.String())
	}
	if got.Workload.Kind != protocol.WorkloadContainerBuild || got.Workload.ContainerBuild.ContextDirectory != "repo/services/api" {
		t.Fatalf("task: got %+v", got)
	}
	if got.Workload.ContainerBuild.PushTargetRef != "registry:docr-shared" {
		t.Fatalf("push target: got %+v", got.Workload.ContainerBuild)
	}
	for _, forbidden := range [][]byte{[]byte("token"), []byte("signature"), []byte("workload"), []byte("registry:docr-shared")} {
		if bytes.Contains(stdout.Bytes(), forbidden) {
			t.Fatalf("stdout leaked %q: %s", forbidden, stdout.String())
		}
	}
}

func TestCLISubmitRejectsProviderSpecificProductCapture(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{"compute", "submit", "product-capture"})
	if code == 0 {
		t.Fatal("product-capture submit must belong to workflow-plugin-product-capture, not workflow-plugin-compute")
	}
	if !strings.Contains(stderr.String(), `unknown wfctl compute submit workload "product-capture"`) {
		t.Fatalf("stderr: %s", stderr.String())
	}
}

func TestT8_CLISubmitValidatesBeforeAPICall(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "submit", "container-build",
		"--server", srv.URL,
		"--token", "token",
		"--org", "org-1",
		"--pool", "pool-1",
	})

	if code == 0 {
		t.Fatal("expected missing tag to fail")
	}
	if calls != 0 {
		t.Fatalf("expected local validation before API call, calls=%d", calls)
	}
}

func TestT8_CLISubmitCommandRejectsRawEnvBeforeAPICall(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "submit", "command",
		"--server", srv.URL,
		"--token", "token",
		"--org", "org-1",
		"--pool", "pool-1",
		"--env", "TOKEN=raw-secret",
		"true",
	})

	if code == 0 {
		t.Fatal("expected raw env value to fail")
	}
	if calls != 0 {
		t.Fatalf("expected local validation before API call, calls=%d", calls)
	}
	if bytes.Contains(stdout.Bytes(), []byte("raw-secret")) || bytes.Contains(stderr.Bytes(), []byte("raw-secret")) {
		t.Fatalf("output leaked raw env: stdout=%s stderr=%s", stdout.String(), stderr.String())
	}
}

func TestT9_CLIAccountingExportIncludesRewards(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("auth header: got %q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1/accounts/worker-1/contributions":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"events": []protocol.ContributionEvent{{
					ID:        "contrib-1",
					Type:      protocol.ContributionRecorded,
					OrgID:     "org-1",
					AccountID: "worker-1",
					TaskID:    "task-1",
					ProofID:   "proof-1",
					Units:     protocol.ContributionUnits{CPUMillis: 1000},
				}},
				"total": protocol.ContributionUnits{CPUMillis: 1000},
			})
		case "/v1/rewards":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"rewards": []map[string]any{{
					"org_id":     "org-1",
					"account_id": "worker-1",
					"units":      protocol.ContributionUnits{CPUMillis: 1000},
					"policy":     "points",
					"points":     1,
					"badge":      "night-builder",
				}, {
					"org_id":     "org-1",
					"account_id": "other-worker",
					"units":      protocol.ContributionUnits{CPUMillis: 2000},
					"policy":     "points",
					"points":     2,
				}},
			})
		default:
			t.Fatalf("path: %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "accounting", "export",
		"--server", srv.URL,
		"--token", "token",
		"--account", "worker-1",
	})

	if code != 0 {
		t.Fatalf("RunCLI code=%d stderr=%s", code, stderr.String())
	}
	var got struct {
		AccountID string                       `json:"account_id"`
		Events    []protocol.ContributionEvent `json:"events"`
		Total     protocol.ContributionUnits   `json:"total"`
		Rewards   []map[string]any             `json:"rewards"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode accounting export: %v", err)
	}
	if got.AccountID != "worker-1" || got.Total.CPUMillis != 1000 || len(got.Events) != 1 {
		t.Fatalf("raw contribution output: got %+v", got)
	}
	if len(got.Rewards) != 1 || got.Rewards[0]["account_id"] != "worker-1" || got.Rewards[0]["points"] != float64(1) {
		t.Fatalf("reward output: got %+v", got.Rewards)
	}
	if got.Rewards[0]["badge"] != "night-builder" {
		t.Fatalf("policy-specific reward field was not preserved: %+v", got.Rewards[0])
	}
	for _, want := range []string{"/v1/accounts/worker-1/contributions", "/v1/rewards"} {
		found := false
		for _, path := range paths {
			if path == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing request to %s; paths=%v", want, paths)
		}
	}
	if bytes.Contains(stdout.Bytes(), []byte("token")) {
		t.Fatalf("stdout leaked token: %s", stdout.String())
	}
}

func TestT7_CLIGitHubRunnerBridgeUsesCompactReceipt(t *testing.T) {
	var got githubRunnerJobRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/adapters/github-runner/jobs" {
			t.Fatalf("request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("auth header: got %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode bridge request: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"task": protocol.Task{
			ID:        "github-1",
			OrgID:     "org-1",
			PoolID:    "pool-1",
			PolicyID:  "policy-1",
			Status:    protocol.TaskQueued,
			InputHash: "sha256:input",
			Workload: protocol.WorkloadSpec{
				Kind:    protocol.WorkloadCommand,
				Command: &protocol.CommandWorkload{Args: []string{"go", "test", "./..."}},
			},
			Labels: map[string]string{
				"adapter":                       "github-runner",
				"github.repository":             "GoCodeAlone/workflow-compute",
				"github.runner_registration_id": "ghr-1",
			},
			Signature: protocol.SignatureEnvelope{
				Algorithm: "dev-local-sha256",
				KeyID:     "local-dev",
				Value:     "sig",
				Verified:  true,
			},
		}})
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "github-runner", "bridge-job",
		"--server", srv.URL,
		"--token", "token",
		"--registration", "ghr-1",
		"--repo", "GoCodeAlone/workflow-compute",
		"--run-id", "42",
		"--run-attempt", "2",
		"--job-id", "99",
		"--job-name", "build",
		"--policy", "policy-1",
		"--label", "demo=true",
		"go", "test", "./...",
	})

	if code != 0 {
		t.Fatalf("RunCLI code=%d stderr=%s", code, stderr.String())
	}
	if got.RegistrationID != "ghr-1" || got.WorkflowRunAttempt != 2 || got.Labels["demo"] != "true" {
		t.Fatalf("bridge request: got %+v", got)
	}
	var receipt taskReceipt
	if err := json.Unmarshal(stdout.Bytes(), &receipt); err != nil {
		t.Fatalf("decode receipt: %v", err)
	}
	if receipt.TaskID != "github-1" || receipt.InputHash != "sha256:input" {
		t.Fatalf("receipt: got %+v", receipt)
	}
	for _, forbidden := range [][]byte{
		[]byte("token"),
		[]byte("signature"),
		[]byte("workload"),
		[]byte("labels"),
		[]byte("github."),
		[]byte("registration"),
		[]byte("go test"),
	} {
		if bytes.Contains(stdout.Bytes(), forbidden) {
			t.Fatalf("stdout leaked %q: %s", forbidden, stdout.String())
		}
	}
}

func TestT7_CLIGitHubRunnerRegister(t *testing.T) {
	var got githubRunnerRegistrationRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/adapters/github-runner/registrations" {
			t.Fatalf("request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("auth header: got %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode registration request: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{"registration": githubRunnerRegistration{
			ID:         "ghr-1",
			AgentID:    got.AgentID,
			Repository: got.Repository,
			RunnerName: "compute-" + got.AgentID,
		}})
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "github-runner", "register",
		"--server", srv.URL,
		"--token", "token",
		"--agent", "worker-1",
		"--repo", "GoCodeAlone/workflow-compute",
		"--label", "arm64",
	})

	if code != 0 {
		t.Fatalf("RunCLI code=%d stderr=%s", code, stderr.String())
	}
	if got.AgentID != "worker-1" || got.Repository != "GoCodeAlone/workflow-compute" || len(got.Labels) != 1 {
		t.Fatalf("registration request: got %+v", got)
	}
	if bytes.Contains(stdout.Bytes(), []byte("token")) {
		t.Fatalf("stdout leaked token: %s", stdout.String())
	}
}

func TestT7_CLIGitHubRunnerBridgeValidatesBeforeAPICall(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		calls++
	}))
	defer srv.Close()

	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "github-runner", "bridge-job",
		"--server", srv.URL,
		"--token", "token",
		"--registration", "ghr-1",
		"--run-id", "42",
		"--job-id", "99",
		"--job-name", "build",
		"--timeout", "0",
		"true",
	})

	if code == 0 {
		t.Fatal("expected invalid timeout to fail")
	}
	if calls != 0 {
		t.Fatalf("expected local validation before API call, calls=%d", calls)
	}
}

func TestT7_CLIGitHubRunnerRejectsTokenOverCleartextRemote(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI([]string{
		"compute", "github-runner", "register",
		"--server", "http://compute.example.test",
		"--token", "token",
		"--agent", "worker-1",
		"--repo", "GoCodeAlone/workflow-compute",
	})

	if code == 0 {
		t.Fatal("expected token-bearing cleartext remote server to fail")
	}
	if bytes.Contains(stdout.Bytes(), []byte("Bearer token")) || bytes.Contains(stderr.Bytes(), []byte("Bearer token")) {
		t.Fatalf("output leaked auth material: stdout=%s stderr=%s", stdout.String(), stderr.String())
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
