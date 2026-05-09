package internal

import (
	"context"
	"errors"
	"fmt"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"time"
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
	Workload workloadSpec `json:"workload"`
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
	TaskID string `json:"task_id"`
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
	tasks, err := client.listTasks(ctx)
	if err != nil {
		return errorResult(err.Error()), nil
	}
	for _, task := range tasks {
		if task.ID == s.config.TaskID {
			return &sdk.StepResult{Output: taskOutput(task)}, nil
		}
	}
	return errorResult(fmt.Sprintf("task %q not found", s.config.TaskID)), nil
}

type mapConfig struct {
	connectionConfig
	Tasks []mapTaskConfig `json:"tasks"`
}

type mapTaskConfig struct {
	taskConfig
	Workload workloadSpec `json:"workload"`
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

func taskOutput(task computeTask) map[string]any {
	return map[string]any{
		"task_id": task.ID,
		"org_id":  task.OrgID,
		"pool_id": task.PoolID,
		"status":  string(task.Status),
	}
}

func errorResult(msg string) *sdk.StepResult {
	return &sdk.StepResult{
		StopPipeline: true,
		Output: map[string]any{
			"error": msg,
		},
	}
}
