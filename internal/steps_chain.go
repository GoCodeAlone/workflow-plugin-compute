package internal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/GoCodeAlone/workflow-compute/pkg/protocol"
	coreprotocol "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type computeChainConfig struct {
	connectionConfig
	Steps        []computeChainTaskConfig `json:"steps"`
	PollInterval string                   `json:"poll_interval,omitempty"`
	Timeout      string                   `json:"timeout,omitempty"`
	RequireProof *bool                    `json:"require_proof,omitempty"`
}

type computeChainTaskConfig struct {
	ID             string                     `json:"id"`
	TaskID         string                     `json:"task_id,omitempty"`
	ProductID      string                     `json:"product_id,omitempty"`
	OrgID          string                     `json:"org_id"`
	PoolID         string                     `json:"pool_id"`
	PolicyID       string                     `json:"policy_id"`
	TimeoutSeconds int                        `json:"timeout_seconds"`
	Labels         map[string]string          `json:"labels,omitempty"`
	ResiduePolicy  protocol.ResiduePolicy     `json:"residue_policy,omitzero"`
	DependsOn      []string                   `json:"depends_on,omitempty"`
	InputMappings  []computeChainInputMapping `json:"input_mappings,omitempty"`
	Wait           *bool                      `json:"wait,omitempty"`
	Workload       protocol.WorkloadSpec      `json:"workload"`
}

type computeChainInputMapping struct {
	FromStep string `json:"from_step"`
	From     string `json:"from"`
	To       string `json:"to"`
}

type computeChainStep struct {
	name   string
	config computeChainConfig
}

func newComputeChainStep(name string, raw map[string]any) (*computeChainStep, error) {
	var cfg computeChainConfig
	if err := decodeStrictMap(raw, &cfg); err != nil {
		return nil, fmt.Errorf("step.compute_chain %q: %w", name, err)
	}
	if err := cfg.validate(name); err != nil {
		return nil, err
	}
	return &computeChainStep{name: name, config: cfg}, nil
}

func (c computeChainConfig) validate(name string) error {
	if err := c.connectionConfig.validate(); err != nil {
		return fmt.Errorf("step.compute_chain %q: %w", name, err)
	}
	if len(c.Steps) == 0 {
		return fmt.Errorf("step.compute_chain %q: steps is required", name)
	}
	if c.PollInterval != "" {
		if d, err := time.ParseDuration(c.PollInterval); err != nil {
			return fmt.Errorf("step.compute_chain %q: poll_interval must be duration: %w", name, err)
		} else if d <= 0 {
			return fmt.Errorf("step.compute_chain %q: poll_interval must be positive", name)
		}
	}
	if c.Timeout != "" {
		if d, err := time.ParseDuration(c.Timeout); err != nil {
			return fmt.Errorf("step.compute_chain %q: timeout must be duration: %w", name, err)
		} else if d <= 0 {
			return fmt.Errorf("step.compute_chain %q: timeout must be positive", name)
		}
	}
	seen := make(map[string]struct{}, len(c.Steps))
	for i, step := range c.Steps {
		if step.ID == "" {
			return fmt.Errorf("step.compute_chain %q: steps[%d].id is required", name, i)
		}
		if _, ok := seen[step.ID]; ok {
			return fmt.Errorf("step.compute_chain %q: duplicate step id %q", name, step.ID)
		}
		taskCfg := step.taskConfig()
		if err := taskCfg.validate(); err != nil {
			return fmt.Errorf("step.compute_chain %q: steps[%d] %q: %w", name, i, step.ID, err)
		}
		if err := step.Workload.Validate(); err != nil {
			return fmt.Errorf("step.compute_chain %q: steps[%d] %q workload: %w", name, i, step.ID, err)
		}
		for _, dep := range step.DependsOn {
			if _, ok := seen[dep]; !ok {
				return fmt.Errorf("step.compute_chain %q: steps[%d] %q depends_on %q must reference an earlier step", name, i, step.ID, dep)
			}
		}
		deps := stringSet(step.DependsOn)
		for j, mapping := range step.InputMappings {
			if err := mapping.validate(); err != nil {
				return fmt.Errorf("step.compute_chain %q: steps[%d] %q input_mappings[%d]: %w", name, i, step.ID, j, err)
			}
			if _, ok := seen[mapping.FromStep]; !ok {
				return fmt.Errorf("step.compute_chain %q: steps[%d] %q input_mappings[%d].from_step %q must reference an earlier step", name, i, step.ID, j, mapping.FromStep)
			}
			if _, ok := deps[mapping.FromStep]; !ok {
				return fmt.Errorf("step.compute_chain %q: steps[%d] %q input_mappings[%d].from_step %q must be listed in depends_on", name, i, step.ID, j, mapping.FromStep)
			}
		}
		seen[step.ID] = struct{}{}
	}
	return nil
}

func (c computeChainConfig) requireProof() bool {
	return c.RequireProof == nil || *c.RequireProof
}

func (c computeChainTaskConfig) taskConfig() taskConfig {
	return taskConfig{
		ID:             c.TaskID,
		ProductID:      c.ProductID,
		OrgID:          c.OrgID,
		PoolID:         c.PoolID,
		PolicyID:       c.PolicyID,
		TimeoutSeconds: c.TimeoutSeconds,
		Labels:         c.Labels,
		ResiduePolicy:  c.ResiduePolicy,
	}
}

func (c computeChainTaskConfig) wait() bool {
	return c.Wait == nil || *c.Wait
}

func (m computeChainInputMapping) validate() error {
	var errs []error
	if m.FromStep == "" {
		errs = append(errs, errors.New("from_step is required"))
	}
	if m.From == "" {
		errs = append(errs, errors.New("from is required"))
	}
	switch m.To {
	case "provider.artifact_refs", "provider.content_inputs", "provider.stream_inputs":
	default:
		errs = append(errs, fmt.Errorf("unsupported to value %q", m.To))
	}
	return errors.Join(errs...)
}

func (s *computeChainStep) Execute(ctx context.Context, _ map[string]any, _ map[string]map[string]any, _ map[string]any, metadata map[string]any, runtimeConfig map[string]any) (*sdk.StepResult, error) {
	client, err := s.config.connectionConfig.client(ctx, metadata, runtimeConfig)
	if err != nil {
		return errorResult(err.Error()), nil
	}

	timeout := durationOrDefault(s.config.Timeout, 30*time.Minute)
	chainCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	outputs := make([]map[string]any, 0, len(s.config.Steps))
	outputsByID := make(map[string]map[string]any, len(s.config.Steps))
	for _, chainTask := range s.config.Steps {
		workload := chainTask.Workload
		if err := applyComputeChainInputMappings(&workload, chainTask.InputMappings, outputsByID); err != nil {
			return chainErrorResult(outputs, chainTask.ID, err.Error()), nil
		}
		if err := workload.Validate(); err != nil {
			return chainErrorResult(outputs, chainTask.ID, fmt.Sprintf("workload: %v", err)), nil
		}
		task, err := client.submitTask(chainCtx, buildTask(chainTask.taskConfig(), workload))
		if err != nil {
			return chainErrorResult(outputs, chainTask.ID, err.Error()), nil
		}

		output := taskOutput(task)
		output["step_id"] = chainTask.ID
		if chainTask.wait() {
			output, err = s.waitForTask(chainCtx, client, task.ID)
			output["step_id"] = chainTask.ID
			if err != nil {
				return chainErrorResult(append(outputs, output), chainTask.ID, err.Error()), nil
			}
		}
		outputs = append(outputs, output)
		outputsByID[chainTask.ID] = output
	}

	return &sdk.StepResult{Output: map[string]any{"steps": outputs}}, nil
}

func (s *computeChainStep) waitForTask(ctx context.Context, client *computeClient, taskID string) (map[string]any, error) {
	pollInterval := durationOrDefault(s.config.PollInterval, time.Second)
	for {
		task, found, stalls, err := client.taskSnapshot(ctx, taskID)
		if err != nil {
			return taskOutput(protocol.Task{ID: taskID}), err
		}
		if !found {
			return taskOutput(protocol.Task{ID: taskID}), fmt.Errorf("task %q not found", taskID)
		}
		output := taskOutput(task)
		actionableStalls := actionableStalls(stalls, s.config.requireProof())
		if task.Status == protocol.TaskFailed || task.Status == protocol.TaskStalled || len(actionableStalls) > 0 {
			if len(actionableStalls) > 0 {
				addStallOutput(output, actionableStalls[0])
			}
			msg := taskWaitError(task, actionableStalls)
			output["error"] = msg
			return output, errors.New(msg)
		}
		if isTerminalTaskStatus(task.Status) {
			proof, hasProof, err := client.findProof(ctx, task.ID)
			if err != nil {
				return output, err
			}
			if hasProof {
				addProofOutput(output, proof)
			}
			if hasProof && proof.Verifier.Status != protocol.VerificationAccepted {
				msg := fmt.Sprintf("task %q proof %q is %s", task.ID, proof.ID, proof.Verifier.Status)
				output["error"] = msg
				return output, errors.New(msg)
			}
			if hasProof || !s.config.requireProof() {
				return output, nil
			}
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return output, fmt.Errorf("timed out waiting for task %q", taskID)
		case <-timer.C:
		}
	}
}

func applyComputeChainInputMappings(workload *protocol.WorkloadSpec, mappings []computeChainInputMapping, outputs map[string]map[string]any) error {
	if len(mappings) == 0 {
		return nil
	}
	if workload.Kind != protocol.WorkloadProvider || workload.Provider == nil {
		return errors.New("input_mappings require provider workload")
	}
	for _, mapping := range mappings {
		source, ok := outputs[mapping.FromStep]
		if !ok {
			return fmt.Errorf("source step %q has no output", mapping.FromStep)
		}
		value, ok := lookupChainValue(source, mapping.From)
		if !ok {
			return fmt.Errorf("source step %q output %q is missing", mapping.FromStep, mapping.From)
		}
		switch mapping.To {
		case "provider.artifact_refs":
			refs, err := stringSliceFromAny(value)
			if err != nil {
				return fmt.Errorf("%s: %w", mapping.To, err)
			}
			workload.Provider.ArtifactRefs = append(workload.Provider.ArtifactRefs, refs...)
		case "provider.content_inputs":
			inputs, err := typedSliceFromAny[coreprotocol.ContentInputRef](value)
			if err != nil {
				return fmt.Errorf("%s: %w", mapping.To, err)
			}
			workload.Provider.ContentInputs = append(workload.Provider.ContentInputs, inputs...)
		case "provider.stream_inputs":
			inputs, err := typedSliceFromAny[coreprotocol.StreamInputRef](value)
			if err != nil {
				return fmt.Errorf("%s: %w", mapping.To, err)
			}
			workload.Provider.StreamInputs = append(workload.Provider.StreamInputs, inputs...)
		default:
			return fmt.Errorf("unsupported mapping destination %q", mapping.To)
		}
	}
	return nil
}

func lookupChainValue(values map[string]any, path string) (any, bool) {
	current := any(values)
	for _, part := range splitDottedPath(path) {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = object[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func splitDottedPath(path string) []string {
	parts := make([]string, 0, 1)
	start := 0
	for i, r := range path {
		if r == '.' {
			parts = append(parts, path[start:i])
			start = i + 1
		}
	}
	return append(parts, path[start:])
}

func stringSliceFromAny(value any) ([]string, error) {
	switch v := value.(type) {
	case string:
		return []string{v}, nil
	case []string:
		return append([]string(nil), v...), nil
	case []any:
		out := make([]string, 0, len(v))
		for i, item := range v {
			ref, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("[%d] must be string", i)
			}
			out = append(out, ref)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("must be string or string array")
	}
}

func typedSliceFromAny[T any](value any) ([]T, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var out []T
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func stringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func chainErrorResult(steps []map[string]any, stepID, msg string) *sdk.StepResult {
	output := map[string]any{
		"error":   fmt.Sprintf("step %q: %s", stepID, msg),
		"step_id": stepID,
		"steps":   steps,
	}
	return &sdk.StepResult{StopPipeline: true, Output: output}
}
