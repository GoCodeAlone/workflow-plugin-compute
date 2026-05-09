package internal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"time"
)

const computeProtocolVersion = "compute.v1alpha1"

type computeTask struct {
	ProtocolVersion string            `json:"protocol_version"`
	ID              string            `json:"id"`
	OrgID           string            `json:"org_id"`
	PoolID          string            `json:"pool_id"`
	PolicyID        string            `json:"policy_id"`
	Status          string            `json:"status,omitempty"`
	Workload        workloadSpec      `json:"workload"`
	InputHash       string            `json:"input_hash"`
	RequestedAt     time.Time         `json:"requested_at"`
	TimeoutSeconds  int               `json:"timeout_seconds"`
	Labels          map[string]string `json:"labels,omitempty"`
	Signature       signatureEnvelope `json:"signature"`
}

type signatureEnvelope struct {
	Algorithm string `json:"algorithm"`
	KeyID     string `json:"key_id"`
	Value     string `json:"value"`
	Verified  bool   `json:"verified,omitempty"`
}

type workloadSpec struct {
	Kind           string                       `json:"kind"`
	Command        *commandWorkload             `json:"command,omitempty"`
	ContainerBuild *containerBuildWorkload      `json:"container_build,omitempty"`
	Params         map[string]map[string]string `json:"params,omitempty"`
}

type commandWorkload struct {
	Args              []string `json:"args"`
	WorkingDirectory  string   `json:"working_directory,omitempty"`
	Env               []envRef `json:"env,omitempty"`
	ArtifactAllowlist []string `json:"artifact_allowlist,omitempty"`
}

type envRef struct {
	Name      string `json:"name"`
	ValueRef  string `json:"value_ref,omitempty"`
	SecretRef string `json:"secret_ref,omitempty"`
}

type containerBuildWorkload struct {
	ContextDirectory string   `json:"context_directory"`
	Dockerfile       string   `json:"dockerfile,omitempty"`
	Tags             []string `json:"tags,omitempty"`
	PushTargetRef    string   `json:"push_target_ref,omitempty"`
}

func buildTask(cfg taskConfig, workload workloadSpec) computeTask {
	id := cfg.ID
	if id == "" {
		id = "task-" + shortHash(time.Now().UTC().Format(time.RFC3339Nano))
	}
	inputHash := workloadHash(workload)
	return computeTask{
		ProtocolVersion: computeProtocolVersion,
		ID:              id,
		OrgID:           cfg.OrgID,
		PoolID:          cfg.PoolID,
		PolicyID:        cfg.PolicyID,
		Status:          "queued",
		Workload:        workload,
		InputHash:       inputHash,
		RequestedAt:     time.Now().UTC(),
		TimeoutSeconds:  cfg.TimeoutSeconds,
		Labels:          cfg.Labels,
		Signature: signatureEnvelope{
			Algorithm: "dev-local-sha256",
			KeyID:     "local-dev",
			Value:     shortHash(id + ":" + inputHash),
		},
	}
}

func workloadHash(workload workloadSpec) string {
	data, _ := json.Marshal(workload)
	return "sha256:" + shortHash(string(data))
}

func shortHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func decodeStrictJSON(r io.Reader, v any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return io.ErrUnexpectedEOF
}
