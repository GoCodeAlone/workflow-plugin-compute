package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/GoCodeAlone/workflow-compute/pkg/protocol"
)

type computeClient struct {
	baseURL *url.URL
	token   string
	http    *http.Client
}

type agentList struct {
	Agents []protocol.Worker `json:"agents"`
}

type taskList struct {
	Tasks  []protocol.Task `json:"tasks"`
	Stalls []taskStall     `json:"stalls,omitempty"`
}

type taskStall struct {
	TaskID  string `json:"task_id,omitempty"`
	LeaseID string `json:"lease_id,omitempty"`
	AgentID string `json:"agent_id,omitempty"`
	Reason  string `json:"reason"`
	AgeMS   int64  `json:"age_ms"`
}

type contributionList struct {
	Events []protocol.ContributionEvent `json:"events"`
	Total  protocol.ContributionUnits   `json:"total"`
}

type rewardList struct {
	Rewards []map[string]any `json:"rewards"`
}

type networkAuditsQuery struct {
	Projection string
	Schema     string
	Decision   string
}

type networkAuditsResponse struct {
	Projections       []protocol.NetworkAuditRecordProjection `json:"projections,omitempty"`
	Summary           networkAuditsSummary                    `json:"summary"`
	ProjectionSummary networkAuditProjectionSummary           `json:"projection_summary,omitempty"`
}

type networkAuditsSummary struct {
	Total   int `json:"total"`
	Allowed int `json:"allowed"`
	Blocked int `json:"blocked"`
}

type networkAuditProjectionSummary struct {
	Projected int `json:"projected"`
	Unsafe    int `json:"unsafe,omitempty"`
}

type networkAuditRawCompatDryRunRequest struct {
	Action              string   `json:"action"`
	ExpectedRefKeyEpoch string   `json:"expected_ref_key_epoch"`
	Handle              string   `json:"handle,omitempty"`
	OrgID               string   `json:"org_id,omitempty"`
	PoolID              string   `json:"pool_id,omitempty"`
	Scopes              []string `json:"scopes,omitempty"`
	TargetBearerToken   string   `json:"target_bearer_token,omitempty"`
	RawCredential       string   `json:"raw_credential,omitempty"`
	TargetSubject       string   `json:"target_subject,omitempty"`
}

type networkAuditRawCompatDryRunResponse struct {
	ProjectionReady bool                                    `json:"projection_ready"`
	RefKeyEpoch     string                                  `json:"ref_key_epoch,omitempty"`
	Handle          string                                  `json:"handle,omitempty"`
	HandleRef       string                                  `json:"handle_ref,omitempty"`
	ExpiresAt       time.Time                               `json:"expires_at,omitempty"`
	Summary         networkAuditsSummary                    `json:"summary,omitempty"`
	Findings        []networkAuditDryRunFinding             `json:"findings,omitempty"`
	Error           string                                  `json:"error,omitempty"`
	Projections     []protocol.NetworkAuditRecordProjection `json:"projections,omitempty"`
}

type networkAuditDryRunFinding struct {
	Code      string `json:"code"`
	RecordRef string `json:"record_ref,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

type httpStatusError struct {
	method string
	path   string
	status int
	want   []int
}

func (e httpStatusError) Error() string {
	return fmt.Sprintf("%s %s: got status %d", e.method, e.path, e.status)
}

func isHTTPStatusError(err error, status int) bool {
	var statusErr httpStatusError
	return errors.As(err, &statusErr) && statusErr.status == status
}

type githubRunnerRegistrationRequest struct {
	AgentID    string   `json:"agent_id"`
	Repository string   `json:"repository"`
	Labels     []string `json:"labels,omitempty"`
}

type githubRunnerRegistration struct {
	ID           string    `json:"id"`
	AgentID      string    `json:"agent_id"`
	OrgID        string    `json:"org_id"`
	PoolID       string    `json:"pool_id"`
	Repository   string    `json:"repository"`
	RunnerName   string    `json:"runner_name"`
	Labels       []string  `json:"labels"`
	RegisteredAt time.Time `json:"registered_at"`
}

type githubRunnerJobRequest struct {
	Repository         string            `json:"repository,omitempty"`
	RegistrationID     string            `json:"registration_id"`
	WorkflowRunID      int64             `json:"workflow_run_id"`
	WorkflowRunAttempt int64             `json:"workflow_run_attempt,omitempty"`
	WorkflowJobID      int64             `json:"workflow_job_id"`
	WorkflowJobName    string            `json:"workflow_job_name"`
	Ref                string            `json:"ref,omitempty"`
	SHA                string            `json:"sha,omitempty"`
	PolicyID           string            `json:"policy_id"`
	TimeoutSeconds     int               `json:"timeout_seconds,omitempty"`
	CommandArgs        []string          `json:"command_args"`
	Labels             map[string]string `json:"labels,omitempty"`
}

func newComputeClient(serverURL, token string, timeout time.Duration) (*computeClient, error) {
	parsed, err := url.ParseRequestURI(serverURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return nil, fmt.Errorf("server_url must be absolute http(s) URL")
	}
	if token != "" && parsed.Scheme != "https" && !isLoopbackHost(parsed.Hostname()) {
		return nil, fmt.Errorf("server_url must use https when auth token is set")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &computeClient{
		baseURL: parsed,
		token:   token,
		http:    &http.Client{Timeout: timeout},
	}, nil
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *computeClient) submitTask(ctx context.Context, task protocol.Task) (protocol.Task, error) {
	var out struct {
		Task protocol.Task `json:"task"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/tasks", task, http.StatusCreated, &out); err != nil {
		return protocol.Task{}, err
	}
	return out.Task, nil
}

func (c *computeClient) enrollAgent(ctx context.Context, req enrollRequest) (protocol.Worker, error) {
	var out struct {
		Agent protocol.Worker `json:"agent"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/agents/enroll", req, http.StatusCreated, &out); err != nil {
		return protocol.Worker{}, err
	}
	return out.Agent, nil
}

func (c *computeClient) listAgents(ctx context.Context) (agentList, error) {
	var out agentList
	if err := c.doJSON(ctx, http.MethodGet, "/v1/agents", nil, http.StatusOK, &out); err != nil {
		return agentList{}, err
	}
	return out, nil
}

func (c *computeClient) listTasks(ctx context.Context) (taskList, error) {
	var out taskList
	if err := c.doJSON(ctx, http.MethodGet, "/v1/tasks", nil, http.StatusOK, &out); err != nil {
		return taskList{}, err
	}
	return out, nil
}

func (c *computeClient) taskSnapshot(ctx context.Context, id string) (protocol.Task, bool, []taskStall, error) {
	list, err := c.listTasks(ctx)
	if err != nil {
		return protocol.Task{}, false, nil, err
	}
	matchingStalls := make([]taskStall, 0)
	for _, stall := range list.Stalls {
		if stall.TaskID == id {
			matchingStalls = append(matchingStalls, stall)
		}
	}
	for _, task := range list.Tasks {
		if task.ID == id {
			return task, true, matchingStalls, nil
		}
	}
	return protocol.Task{}, false, matchingStalls, nil
}

func (c *computeClient) listProofs(ctx context.Context) ([]protocol.ProofReceipt, error) {
	var out struct {
		Proofs []protocol.ProofReceipt `json:"proofs"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/v1/proofs", nil, http.StatusOK, &out); err != nil {
		return nil, err
	}
	return out.Proofs, nil
}

func (c *computeClient) findProof(ctx context.Context, taskID string) (protocol.ProofReceipt, bool, error) {
	proofs, err := c.listProofs(ctx)
	if err != nil {
		return protocol.ProofReceipt{}, false, err
	}
	for _, proof := range proofs {
		if proof.TaskID == taskID {
			return proof, true, nil
		}
	}
	return protocol.ProofReceipt{}, false, nil
}

func (c *computeClient) contributions(ctx context.Context, accountID string) (contributionList, error) {
	var out contributionList
	if err := c.doJSON(ctx, http.MethodGet, "/v1/accounts/"+url.PathEscape(accountID)+"/contributions", nil, http.StatusOK, &out); err != nil {
		return contributionList{}, err
	}
	return out, nil
}

func (c *computeClient) rewards(ctx context.Context) (rewardList, error) {
	var out rewardList
	if err := c.doJSON(ctx, http.MethodGet, "/v1/rewards", nil, http.StatusOK, &out); err != nil {
		return rewardList{}, err
	}
	return out, nil
}

func (c *computeClient) listNetworkAudits(ctx context.Context, query networkAuditsQuery) (networkAuditsResponse, error) {
	if strings.TrimSpace(query.Schema) == "" {
		query.Schema = protocol.NetworkAuditListSchemaProjectionV1
	}
	values := make(url.Values)
	setQueryValue(values, "projection", query.Projection)
	setQueryValue(values, "schema", query.Schema)
	setQueryValue(values, "decision", query.Decision)
	path := "/v1/network-audits"
	if encoded := values.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var out networkAuditsResponse
	if err := c.doJSONWithHeaders(ctx, http.MethodGet, path, nil, http.StatusOK, &out, map[string]string{
		protocol.NetworkAuditClientCompatHeader: "workflow-plugin-compute",
		protocol.NetworkAuditListSchemaHeader:   protocol.NetworkAuditListSchemaProjectionV1,
	}); err != nil {
		return networkAuditsResponse{}, err
	}
	return out, nil
}

func (c *computeClient) networkAuditRawCompatDryRun(ctx context.Context, req networkAuditRawCompatDryRunRequest) (networkAuditRawCompatDryRunResponse, error) {
	var out networkAuditRawCompatDryRunResponse
	err := c.doJSONOneOf(ctx, http.MethodPost, "/v1/network-audits/raw-compat-dry-run", req, []int{http.StatusOK, http.StatusCreated}, &out, map[string]string{
		protocol.NetworkAuditClientCompatHeader: "workflow-plugin-compute",
	})
	if err != nil {
		return networkAuditRawCompatDryRunResponse{}, err
	}
	return out, nil
}

func (c *computeClient) registerGitHubRunner(ctx context.Context, req githubRunnerRegistrationRequest) (githubRunnerRegistration, error) {
	var out struct {
		Registration githubRunnerRegistration `json:"registration"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/adapters/github-runner/registrations", req, http.StatusCreated, &out); err != nil {
		return githubRunnerRegistration{}, err
	}
	return out.Registration, nil
}

func (c *computeClient) bridgeGitHubRunnerJob(ctx context.Context, req githubRunnerJobRequest) (protocol.Task, error) {
	var out struct {
		Task protocol.Task `json:"task"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/adapters/github-runner/jobs", req, http.StatusCreated, &out); err != nil {
		return protocol.Task{}, err
	}
	return out.Task, nil
}

func (c *computeClient) agentSetupPreview(ctx context.Context, req protocol.AgentSetupInvitePreviewRequest) (protocol.AgentSetupInvitePreviewResponse, error) {
	var out protocol.AgentSetupInvitePreviewResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/onboarding/setup-invites/preview", req, http.StatusOK, &out); err != nil {
		return protocol.AgentSetupInvitePreviewResponse{}, err
	}
	return out, nil
}

func (c *computeClient) agentSetupClaim(ctx context.Context, req protocol.AgentSetupInviteClaimRequest) (protocol.AgentSetupInviteClaimResponse, error) {
	var out protocol.AgentSetupInviteClaimResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/onboarding/setup-invites/claim", req, http.StatusOK, &out); err != nil {
		return protocol.AgentSetupInviteClaimResponse{}, err
	}
	return out, nil
}

func (c *computeClient) agentSetupFinalize(ctx context.Context, req protocol.AgentSetupInviteFinalizeRequest) (protocol.AgentSetupInviteClaimResponse, error) {
	var out protocol.AgentSetupInviteClaimResponse
	if err := c.doJSON(ctx, http.MethodPost, "/v1/onboarding/setup-invites/finalize", req, http.StatusOK, &out); err != nil {
		return protocol.AgentSetupInviteClaimResponse{}, err
	}
	return out, nil
}

func (c *computeClient) doJSON(ctx context.Context, method, path string, body any, want int, out any) error {
	return c.doJSONWithHeaders(ctx, method, path, body, want, out, nil)
}

func (c *computeClient) doJSONWithHeaders(ctx context.Context, method, path string, body any, want int, out any, headers map[string]string) error {
	return c.doJSONOneOf(ctx, method, path, body, []int{want}, out, headers)
}

func (c *computeClient) doJSONOneOf(ctx context.Context, method, path string, body any, wants []int, out any, headers map[string]string) error {
	var requestBody *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("marshal request: %w", err)
		}
		requestBody = bytes.NewReader(data)
	} else {
		requestBody = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.requestURL(path), requestBody)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for key, value := range headers {
		if strings.TrimSpace(value) != "" {
			req.Header.Set(key, value)
		}
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if !statusWanted(resp.StatusCode, wants) {
		return httpStatusError{method: method, path: path, status: resp.StatusCode, want: wants}
	}
	if out == nil {
		return nil
	}
	return protocol.DecodeStrict(resp.Body, out)
}

func (c *computeClient) requestURL(path string) string {
	pathOnly, rawQuery, _ := strings.Cut(path, "?")
	endpoint := c.baseURL.JoinPath(strings.TrimPrefix(pathOnly, "/"))
	endpoint.RawQuery = rawQuery
	return endpoint.String()
}

func setQueryValue(values url.Values, key, value string) {
	if strings.TrimSpace(value) != "" {
		values.Set(key, strings.TrimSpace(value))
	}
}

func statusWanted(status int, wants []int) bool {
	for _, want := range wants {
		if status == want {
			return true
		}
	}
	return false
}
