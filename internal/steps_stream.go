package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	coreprotocol "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type computeStreamConfig struct {
	connectionConfig
	taskConfig
	Stream coreprotocol.StreamSpec `json:"stream"`
}

type computeStreamStep struct {
	name   string
	config computeStreamConfig
}

func newComputeStreamStep(name string, raw map[string]any) (*computeStreamStep, error) {
	var cfg computeStreamConfig
	if err := decodeStrictMap(raw, &cfg); err != nil {
		return nil, fmt.Errorf("step.compute_stream %q: %w", name, err)
	}
	if err := errors.Join(cfg.connectionConfig.validate(), cfg.taskConfig.validate(), cfg.Stream.Validate()); err != nil {
		return nil, fmt.Errorf("step.compute_stream %q: %w", name, err)
	}
	return &computeStreamStep{name: name, config: cfg}, nil
}

func (s *computeStreamStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, metadata map[string]any, runtimeConfig map[string]any) (*sdk.StepResult, error) {
	client, err := s.config.connectionConfig.client(ctx, metadata, runtimeConfig)
	if err != nil {
		return errorResult(err.Error()), nil
	}
	task, err := client.submitCoreTask(ctx, buildCoreStreamTask(s.config.taskConfig, s.config.Stream))
	if err != nil {
		return errorResult(err.Error()), nil
	}
	return &sdk.StepResult{Output: coreTaskOutput(task)}, nil
}

func buildCoreStreamTask(cfg taskConfig, stream coreprotocol.StreamSpec) coreprotocol.Task {
	id := cfg.ID
	if id == "" {
		id = "task-" + shortHash(time.Now().UTC().Format(time.RFC3339Nano))
	}
	workload := coreprotocol.WorkloadSpec{
		Kind:        coreprotocol.WorkloadVideoStream,
		VideoStream: &stream,
	}
	inputHash := coreWorkloadHash(workload)
	return coreprotocol.Task{
		ProtocolVersion: coreprotocol.Version,
		ID:              id,
		ProductID:       cfg.ProductID,
		OrgID:           cfg.OrgID,
		PoolID:          cfg.PoolID,
		PolicyID:        cfg.PolicyID,
		Status:          coreprotocol.TaskQueued,
		Workload:        workload,
		ResiduePolicy:   cfg.ResiduePolicy,
		InputHash:       inputHash,
		RequestedAt:     time.Now().UTC(),
		TimeoutSeconds:  cfg.TimeoutSeconds,
		Labels:          cfg.Labels,
		Signature: coreprotocol.SignatureEnvelope{
			Algorithm: "dev-local-sha256",
			KeyID:     "local-dev",
			Value:     shortHash(id + ":" + inputHash),
		},
	}
}

func coreWorkloadHash(workload coreprotocol.WorkloadSpec) string {
	data, _ := json.Marshal(workload)
	return "sha256:" + shortHash(string(data))
}

func (c *computeClient) submitCoreTask(ctx context.Context, task coreprotocol.Task) (coreprotocol.Task, error) {
	var out struct {
		Task coreprotocol.Task `json:"task"`
	}
	if err := c.doJSON(ctx, http.MethodPost, "/v1/tasks", task, http.StatusCreated, &out); err != nil {
		return coreprotocol.Task{}, err
	}
	return out.Task, nil
}

func coreTaskOutput(task coreprotocol.Task) map[string]any {
	return map[string]any{
		"task_id": task.ID,
		"org_id":  task.OrgID,
		"pool_id": task.PoolID,
		"status":  string(task.Status),
	}
}
