package internal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/GoCodeAlone/workflow-compute/pkg/protocol"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type connectionConfig struct {
	ServerURL      string `json:"server_url"`
	AuthTokenRef   string `json:"auth_token_ref"`
	RequestTimeout string `json:"request_timeout,omitempty"`
}

func (c connectionConfig) validate() error {
	var errs []error
	if c.ServerURL == "" {
		errs = append(errs, errors.New("server_url is required"))
	}
	if c.AuthTokenRef == "" {
		errs = append(errs, errors.New("auth_token_ref is required"))
	} else if !isRef(c.AuthTokenRef) {
		errs = append(errs, errors.New("auth_token_ref must be a secret: or config: ref"))
	}
	if c.RequestTimeout != "" {
		if _, err := time.ParseDuration(c.RequestTimeout); err != nil {
			errs = append(errs, fmt.Errorf("request_timeout must be duration: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (c connectionConfig) client(ctx context.Context, metadata, runtimeConfig map[string]any) (*computeClient, error) {
	_ = ctx
	token, err := resolveRuntimeRef(c.AuthTokenRef, metadata, runtimeConfig)
	if err != nil {
		return nil, err
	}
	timeout := 30 * time.Second
	if c.RequestTimeout != "" {
		timeout, err = time.ParseDuration(c.RequestTimeout)
		if err != nil {
			return nil, err
		}
	}
	return newComputeClient(c.ServerURL, token, timeout)
}

type taskConfig struct {
	ID             string            `json:"id,omitempty"`
	OrgID          string            `json:"org_id"`
	PoolID         string            `json:"pool_id"`
	PolicyID       string            `json:"policy_id"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	Labels         map[string]string `json:"labels,omitempty"`
}

func (c taskConfig) validate() error {
	var errs []error
	if c.OrgID == "" {
		errs = append(errs, errors.New("org_id is required"))
	}
	if c.PoolID == "" {
		errs = append(errs, errors.New("pool_id is required"))
	}
	if c.PolicyID == "" {
		errs = append(errs, errors.New("policy_id is required"))
	}
	if c.TimeoutSeconds <= 0 {
		errs = append(errs, errors.New("timeout_seconds must be positive"))
	}
	return errors.Join(errs...)
}

type dispatchConfig struct {
	connectionConfig
	taskConfig
	Workload protocol.WorkloadSpec `json:"workload"`
}

type dispatchStep struct {
	name   string
	config dispatchConfig
}

func newDispatchStep(name string, raw map[string]any) (*dispatchStep, error) {
	var cfg dispatchConfig
	if err := decodeStrictMap(raw, &cfg); err != nil {
		return nil, fmt.Errorf("step.compute_dispatch %q: %w", name, err)
	}
	if err := errors.Join(cfg.connectionConfig.validate(), cfg.taskConfig.validate()); err != nil {
		return nil, fmt.Errorf("step.compute_dispatch %q: %w", name, err)
	}
	return &dispatchStep{name: name, config: cfg}, nil
}

func (s *dispatchStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, metadata map[string]any, runtimeConfig map[string]any) (*sdk.StepResult, error) {
	client, err := s.config.connectionConfig.client(ctx, metadata, runtimeConfig)
	if err != nil {
		return errorResult(err.Error()), nil
	}
	task, err := client.submitTask(ctx, buildTask(s.config.taskConfig, s.config.Workload))
	if err != nil {
		return errorResult(err.Error()), nil
	}
	return &sdk.StepResult{Output: taskOutput(task)}, nil
}

type waitConfig struct {
	connectionConfig
	TaskID       string `json:"task_id"`
	PollInterval string `json:"poll_interval,omitempty"`
	Timeout      string `json:"timeout,omitempty"`
	RequireProof *bool  `json:"require_proof,omitempty"`
}

type waitStep struct {
	name   string
	config waitConfig
}

func newWaitStep(name string, raw map[string]any) (*waitStep, error) {
	var cfg waitConfig
	if err := decodeStrictMap(raw, &cfg); err != nil {
		return nil, fmt.Errorf("step.compute_wait %q: %w", name, err)
	}
	if cfg.TaskID == "" {
		return nil, fmt.Errorf("step.compute_wait %q: task_id is required", name)
	}
	if cfg.PollInterval != "" {
		if d, err := time.ParseDuration(cfg.PollInterval); err != nil {
			return nil, fmt.Errorf("step.compute_wait %q: poll_interval must be duration: %w", name, err)
		} else if d <= 0 {
			return nil, fmt.Errorf("step.compute_wait %q: poll_interval must be positive", name)
		}
	}
	if cfg.Timeout != "" {
		if d, err := time.ParseDuration(cfg.Timeout); err != nil {
			return nil, fmt.Errorf("step.compute_wait %q: timeout must be duration: %w", name, err)
		} else if d <= 0 {
			return nil, fmt.Errorf("step.compute_wait %q: timeout must be positive", name)
		}
	}
	if err := cfg.connectionConfig.validate(); err != nil {
		return nil, fmt.Errorf("step.compute_wait %q: %w", name, err)
	}
	return &waitStep{name: name, config: cfg}, nil
}

func (s *waitStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, metadata map[string]any, runtimeConfig map[string]any) (*sdk.StepResult, error) {
	client, err := s.config.connectionConfig.client(ctx, metadata, runtimeConfig)
	if err != nil {
		return errorResult(err.Error()), nil
	}
	pollInterval := durationOrDefault(s.config.PollInterval, time.Second)
	timeout := durationOrDefault(s.config.Timeout, 5*time.Minute)
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		task, found, stalls, err := client.taskSnapshot(waitCtx, s.config.TaskID)
		if err != nil {
			return errorResult(err.Error()), nil
		}
		if !found {
			return errorResult(fmt.Sprintf("task %q not found", s.config.TaskID)), nil
		}

		actionableStalls := s.config.actionableStalls(stalls)
		if task.Status == protocol.TaskFailed || task.Status == protocol.TaskStalled || len(actionableStalls) > 0 {
			output := taskOutput(task)
			if len(actionableStalls) > 0 {
				addStallOutput(output, actionableStalls[0])
			}
			output["error"] = taskWaitError(task, actionableStalls)
			return &sdk.StepResult{StopPipeline: true, Output: output}, nil
		}

		if isTerminalTaskStatus(task.Status) {
			proof, hasProof, err := client.findProof(waitCtx, task.ID)
			if err != nil {
				return errorResult(err.Error()), nil
			}
			output := taskOutput(task)
			if hasProof {
				addProofOutput(output, proof)
			}
			if hasProof && proof.Verifier.Status != protocol.VerificationAccepted {
				output["error"] = fmt.Sprintf("task %q proof %q is %s", task.ID, proof.ID, proof.Verifier.Status)
				return &sdk.StepResult{StopPipeline: true, Output: output}, nil
			}
			if hasProof || !s.config.requireProof() {
				return &sdk.StepResult{Output: output}, nil
			}
		}

		timer := time.NewTimer(pollInterval)
		select {
		case <-waitCtx.Done():
			timer.Stop()
			return errorResult(fmt.Sprintf("timed out waiting for task %q", s.config.TaskID)), nil
		case <-timer.C:
		}
	}
}

func (c waitConfig) requireProof() bool {
	return c.RequireProof == nil || *c.RequireProof
}

func (c waitConfig) actionableStalls(stalls []taskStall) []taskStall {
	if c.requireProof() {
		return stalls
	}
	actionable := make([]taskStall, 0, len(stalls))
	for _, stall := range stalls {
		if stall.Reason == "proof_missing" {
			continue
		}
		actionable = append(actionable, stall)
	}
	return actionable
}

type mapConfig struct {
	connectionConfig
	Tasks []mapTaskConfig `json:"tasks"`
}

type mapTaskConfig struct {
	taskConfig
	Workload protocol.WorkloadSpec `json:"workload"`
}

type mapStep struct {
	name   string
	config mapConfig
}

func newMapStep(name string, raw map[string]any) (*mapStep, error) {
	var cfg mapConfig
	if err := decodeStrictMap(raw, &cfg); err != nil {
		return nil, fmt.Errorf("step.compute_map %q: %w", name, err)
	}
	if err := cfg.connectionConfig.validate(); err != nil {
		return nil, fmt.Errorf("step.compute_map %q: %w", name, err)
	}
	if len(cfg.Tasks) == 0 {
		return nil, fmt.Errorf("step.compute_map %q: tasks is required", name)
	}
	for i, task := range cfg.Tasks {
		if err := task.taskConfig.validate(); err != nil {
			return nil, fmt.Errorf("step.compute_map %q: tasks[%d]: %w", name, i, err)
		}
	}
	return &mapStep{name: name, config: cfg}, nil
}

func (s *mapStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, metadata map[string]any, runtimeConfig map[string]any) (*sdk.StepResult, error) {
	client, err := s.config.connectionConfig.client(ctx, metadata, runtimeConfig)
	if err != nil {
		return errorResult(err.Error()), nil
	}
	outputs := make([]map[string]any, 0, len(s.config.Tasks))
	for _, cfg := range s.config.Tasks {
		task, err := client.submitTask(ctx, buildTask(cfg.taskConfig, cfg.Workload))
		if err != nil {
			return errorResult(err.Error()), nil
		}
		outputs = append(outputs, taskOutput(task))
	}
	return &sdk.StepResult{Output: map[string]any{"tasks": outputs}}, nil
}

func taskOutput(task protocol.Task) map[string]any {
	return map[string]any{
		"task_id": task.ID,
		"org_id":  task.OrgID,
		"pool_id": task.PoolID,
		"status":  string(task.Status),
	}
}

func addProofOutput(output map[string]any, proof protocol.ProofReceipt) {
	output["proof_id"] = proof.ID
	output["proof_status"] = string(proof.Verifier.Status)
	output["proof_provider"] = proof.Verifier.Provider
	output["worker_id"] = proof.WorkerID
	output["artifact_hash"] = proof.ArtifactHash
}

func addStallOutput(output map[string]any, stall taskStall) {
	output["stall_reason"] = stall.Reason
	if stall.LeaseID != "" {
		output["lease_id"] = stall.LeaseID
	}
	if stall.AgentID != "" {
		output["agent_id"] = stall.AgentID
	}
	if stall.AgeMS != 0 {
		output["stall_age_ms"] = stall.AgeMS
	}
}

func taskWaitError(task protocol.Task, stalls []taskStall) string {
	if len(stalls) > 0 {
		return fmt.Sprintf("task %q stalled: %s", task.ID, stalls[0].Reason)
	}
	return fmt.Sprintf("task %q %s", task.ID, task.Status)
}

func isTerminalTaskStatus(status protocol.TaskStatus) bool {
	switch status {
	case protocol.TaskSucceeded, protocol.TaskFailed, protocol.TaskStalled:
		return true
	default:
		return false
	}
}

func durationOrDefault(raw string, fallback time.Duration) time.Duration {
	if raw == "" {
		return fallback
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

func errorResult(msg string) *sdk.StepResult {
	return &sdk.StepResult{
		StopPipeline: true,
		Output: map[string]any{
			"error": msg,
		},
	}
}
