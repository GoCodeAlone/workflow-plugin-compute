package internal

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/GoCodeAlone/workflow-compute/pkg/protocol"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type computeCLI struct {
	stdout io.Writer
	stderr io.Writer
}

type enrollRequest struct {
	ID           string                `json:"id"`
	OrgID        string                `json:"org_id"`
	PoolID       string                `json:"pool_id"`
	Capabilities protocol.Capabilities `json:"capabilities"`
}

type cliCommon struct {
	serverURL string
	token     string
	timeout   time.Duration
}

func NewCLI() sdk.CLIProvider {
	return newCLI(os.Stdout, os.Stderr)
}

func newCLI(stdout, stderr io.Writer) *computeCLI {
	return &computeCLI{stdout: stdout, stderr: stderr}
}

func (c *computeCLI) RunCLI(args []string) int {
	if err := c.run(context.Background(), args); err != nil {
		_, _ = fmt.Fprintln(c.stderr, err)
		return 1
	}
	return 0
}

func (c *computeCLI) run(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "compute" {
		return errors.New("usage: wfctl compute <enroll|pools|run|audit|accounting|github-runner>")
	}
	if len(args) == 1 {
		return errors.New("usage: wfctl compute <enroll|pools|run|audit|accounting|github-runner>")
	}
	switch args[1] {
	case "enroll":
		return c.runEnroll(ctx, args[2:])
	case "pools":
		return c.runPools(ctx, args[2:])
	case "run":
		return c.runRun(ctx, args[2:])
	case "submit":
		return c.runSubmit(ctx, args[2:])
	case "audit":
		return c.runAudit(ctx, args[2:])
	case "accounting":
		return c.runAccounting(ctx, args[2:])
	case "github-runner":
		return c.runGitHubRunner(ctx, args[2:])
	default:
		return fmt.Errorf("unknown wfctl compute command %q", args[1])
	}
}

func (c *computeCLI) runEnroll(ctx context.Context, args []string) error {
	fs := c.newFlagSet("compute enroll")
	common := addCLICommonFlags(fs)
	workerID := fs.String("id", "", "worker id")
	orgID := fs.String("org", "", "organization id")
	poolID := fs.String("pool", "", "pool id")
	machineID := fs.String("machine-id", "", "stable machine id")
	memoryBytes := fs.Int64("memory-bytes", 0, "memory bytes")
	executorProviders := csvFlag{"native-signed"}
	workloadKinds := csvFlag{string(protocol.WorkloadCommand)}
	fs.Var(&executorProviders, "executor", "executor provider; repeatable or comma-separated")
	fs.Var(&workloadKinds, "workload-kind", "workload kind; repeatable or comma-separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *workerID == "" || *orgID == "" || *poolID == "" {
		return errors.New("--id, --org, and --pool are required")
	}
	if *machineID == "" {
		hostname, _ := os.Hostname()
		*machineID = hostname
	}
	caps := protocol.Capabilities{
		MachineID:         *machineID,
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		CPUCount:          runtime.NumCPU(),
		MemoryBytes:       *memoryBytes,
		ExecutorProviders: executorProviders.values(),
		WorkloadKinds:     workloadKinds.values(),
		HardwareSecurity: protocol.Security{
			Signing: []protocol.SigningCapability{{
				Provider:  "wfctl-cli",
				Algorithm: "dev-local-sha256",
				Available: true,
			}},
		},
	}
	if err := caps.Validate(); err != nil {
		return fmt.Errorf("invalid enrollment capabilities: %w", err)
	}
	client, err := common.client()
	if err != nil {
		return err
	}
	agent, err := client.enrollAgent(ctx, enrollRequest{
		ID:           *workerID,
		OrgID:        *orgID,
		PoolID:       *poolID,
		Capabilities: caps,
	})
	if err != nil {
		return err
	}
	return writeJSON(c.stdout, map[string]any{"agent": agent})
}

func (c *computeCLI) runPools(ctx context.Context, args []string) error {
	fs := c.newFlagSet("compute pools")
	common := addCLICommonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	client, err := common.client()
	if err != nil {
		return err
	}
	agents, err := client.listAgents(ctx)
	if err != nil {
		return err
	}
	tasks, err := client.listTasks(ctx)
	if err != nil {
		return err
	}
	return writeJSON(c.stdout, map[string]any{"pools": summarizePools(agents.Agents, tasks.Tasks)})
}

func (c *computeCLI) runRun(ctx context.Context, args []string) error {
	fs := c.newFlagSet("compute run")
	common := addCLICommonFlags(fs)
	taskFlags := addCLITaskFlags(fs)
	workdir := fs.String("workdir", "", "working directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("command args are required after flags")
	}
	if err := taskFlags.validate(); err != nil {
		return err
	}
	client, err := common.client()
	if err != nil {
		return err
	}
	task := taskFlags.task(protocol.WorkloadSpec{
		Kind: protocol.WorkloadCommand,
		Command: &protocol.CommandWorkload{
			Args:             fs.Args(),
			WorkingDirectory: *workdir,
		},
	})
	submitted, err := client.submitTask(ctx, task)
	if err != nil {
		return err
	}
	return writeJSON(c.stdout, taskReceipt{
		TaskID:    submitted.ID,
		Status:    submitted.Status,
		OrgID:     submitted.OrgID,
		PoolID:    submitted.PoolID,
		PolicyID:  submitted.PolicyID,
		InputHash: submitted.InputHash,
	})
}

func (c *computeCLI) runSubmit(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: wfctl compute submit <command|container-build>")
	}
	switch args[0] {
	case "command":
		return c.runSubmitCommand(ctx, args[1:])
	case "container-build":
		return c.runSubmitContainerBuild(ctx, args[1:])
	default:
		return fmt.Errorf("unknown wfctl compute submit workload %q", args[0])
	}
}

func (c *computeCLI) runSubmitCommand(ctx context.Context, args []string) error {
	fs := c.newFlagSet("compute submit command")
	common := addCLICommonFlags(fs)
	taskFlags := addCLITaskFlags(fs)
	workdir := fs.String("workdir", "", "working directory")
	envRefs := csvFlag{}
	artifacts := csvFlag{}
	fs.Var(&envRefs, "env", "env ref NAME=valueRef or NAME=secret:ref")
	fs.Var(&artifacts, "artifact", "artifact allowlist path")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("command args are required after flags")
	}
	if err := taskFlags.validate(); err != nil {
		return err
	}
	env, err := parseEnvRefs(envRefs.values())
	if err != nil {
		return err
	}
	client, err := common.client()
	if err != nil {
		return err
	}
	task := taskFlags.task(protocol.WorkloadSpec{
		Kind: protocol.WorkloadCommand,
		Command: &protocol.CommandWorkload{
			Args:              fs.Args(),
			WorkingDirectory:  *workdir,
			Env:               env,
			ArtifactAllowlist: artifacts.values(),
		},
	})
	return c.writeTaskReceipt(ctx, client, task)
}

func (c *computeCLI) runSubmitContainerBuild(ctx context.Context, args []string) error {
	fs := c.newFlagSet("compute submit container-build")
	common := addCLICommonFlags(fs)
	taskFlags := addCLITaskFlags(fs)
	contextDir := fs.String("context", ".", "container build context")
	dockerfile := fs.String("dockerfile", "Dockerfile", "Dockerfile path relative to context")
	pushTargetRef := fs.String("push-target-ref", "", "allowed registry push target ref")
	tags := csvFlag{}
	fs.Var(&tags, "tag", "image tag; repeatable or comma-separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := taskFlags.validate(); err != nil {
		return err
	}
	if len(tags.values()) == 0 {
		return errors.New("at least one --tag is required")
	}
	client, err := common.client()
	if err != nil {
		return err
	}
	task := taskFlags.task(protocol.WorkloadSpec{
		Kind: protocol.WorkloadContainerBuild,
		ContainerBuild: &protocol.ContainerBuildWorkload{
			ContextDirectory: *contextDir,
			Dockerfile:       *dockerfile,
			Tags:             tags.values(),
			PushTargetRef:    *pushTargetRef,
		},
	})
	return c.writeTaskReceipt(ctx, client, task)
}

func (c *computeCLI) writeTaskReceipt(ctx context.Context, client *computeClient, task protocol.Task) error {
	submitted, err := client.submitTask(ctx, task)
	if err != nil {
		return err
	}
	return writeJSON(c.stdout, taskReceipt{
		TaskID:    submitted.ID,
		Status:    submitted.Status,
		OrgID:     submitted.OrgID,
		PoolID:    submitted.PoolID,
		PolicyID:  submitted.PolicyID,
		InputHash: submitted.InputHash,
	})
}

func (c *computeCLI) runAudit(ctx context.Context, args []string) error {
	fs := c.newFlagSet("compute audit")
	common := addCLICommonFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	client, err := common.client()
	if err != nil {
		return err
	}
	proofs, err := client.listProofs(ctx)
	if err != nil {
		return err
	}
	return writeJSON(c.stdout, auditProofs(proofs))
}

func (c *computeCLI) runAccounting(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] != "export" {
		return errors.New("usage: wfctl compute accounting export --account <id>")
	}
	fs := c.newFlagSet("compute accounting export")
	common := addCLICommonFlags(fs)
	accountID := fs.String("account", "", "account id")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *accountID == "" {
		return errors.New("--account is required")
	}
	client, err := common.client()
	if err != nil {
		return err
	}
	contributions, err := client.contributions(ctx, *accountID)
	if err != nil {
		return err
	}
	return writeJSON(c.stdout, map[string]any{
		"account_id": *accountID,
		"events":     contributions.Events,
		"total":      contributions.Total,
	})
}

func (c *computeCLI) runGitHubRunner(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: wfctl compute github-runner <register|bridge-job>")
	}
	switch args[0] {
	case "register":
		return c.runGitHubRunnerRegister(ctx, args[1:])
	case "bridge-job":
		return c.runGitHubRunnerBridgeJob(ctx, args[1:])
	default:
		return fmt.Errorf("unknown wfctl compute github-runner command %q", args[0])
	}
}

func (c *computeCLI) runGitHubRunnerRegister(ctx context.Context, args []string) error {
	fs := c.newFlagSet("compute github-runner register")
	common := addCLICommonFlags(fs)
	agentID := fs.String("agent", "", "enrolled compute agent id")
	repository := fs.String("repo", "", "GitHub repository owner/name")
	labels := csvFlag{}
	fs.Var(&labels, "label", "runner label; repeatable or comma-separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agentID == "" || *repository == "" {
		return errors.New("--agent and --repo are required")
	}
	client, err := common.client()
	if err != nil {
		return err
	}
	registration, err := client.registerGitHubRunner(ctx, githubRunnerRegistrationRequest{
		AgentID:    *agentID,
		Repository: *repository,
		Labels:     labels.values(),
	})
	if err != nil {
		return err
	}
	return writeJSON(c.stdout, map[string]any{"registration": registration})
}

func (c *computeCLI) runGitHubRunnerBridgeJob(ctx context.Context, args []string) error {
	fs := c.newFlagSet("compute github-runner bridge-job")
	common := addCLICommonFlags(fs)
	repository := fs.String("repo", "", "GitHub repository owner/name")
	registrationID := fs.String("registration", "", "compute GitHub runner registration id")
	runID := fs.Int64("run-id", 0, "GitHub workflow run id")
	runAttempt := fs.Int64("run-attempt", 1, "GitHub workflow run attempt")
	jobID := fs.Int64("job-id", 0, "GitHub workflow job id")
	jobName := fs.String("job-name", "", "GitHub workflow job name")
	ref := fs.String("ref", "", "Git ref")
	sha := fs.String("sha", "", "Git commit sha")
	policyID := fs.String("policy", "policy-1", "policy id")
	timeoutSeconds := fs.Int("timeout", 60, "timeout seconds")
	labels := csvFlag{}
	fs.Var(&labels, "label", "task label KEY=VALUE; repeatable or comma-separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *registrationID == "" || *runID <= 0 || *jobID <= 0 || *jobName == "" || *policyID == "" {
		return errors.New("--registration, --run-id, --job-id, --job-name, and --policy are required")
	}
	if *timeoutSeconds <= 0 {
		return errors.New("--timeout must be positive")
	}
	if fs.NArg() == 0 {
		return errors.New("command args are required after flags")
	}
	labelMap, err := parseLabelMap(labels.values())
	if err != nil {
		return err
	}
	client, err := common.client()
	if err != nil {
		return err
	}
	task, err := client.bridgeGitHubRunnerJob(ctx, githubRunnerJobRequest{
		Repository:         *repository,
		RegistrationID:     *registrationID,
		WorkflowRunID:      *runID,
		WorkflowRunAttempt: *runAttempt,
		WorkflowJobID:      *jobID,
		WorkflowJobName:    *jobName,
		Ref:                *ref,
		SHA:                *sha,
		PolicyID:           *policyID,
		TimeoutSeconds:     *timeoutSeconds,
		CommandArgs:        fs.Args(),
		Labels:             labelMap,
	})
	if err != nil {
		return err
	}
	return writeJSON(c.stdout, map[string]any{
		"task_id":    task.ID,
		"status":     task.Status,
		"org_id":     task.OrgID,
		"pool_id":    task.PoolID,
		"policy_id":  task.PolicyID,
		"input_hash": task.InputHash,
	})
}

func (c *computeCLI) newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	return fs
}

func addCLICommonFlags(fs *flag.FlagSet) *cliCommon {
	common := &cliCommon{}
	fs.StringVar(&common.serverURL, "server", defaultServerURL(), "workflow-compute server URL")
	fs.StringVar(&common.token, "token", os.Getenv("COMPUTE_API_TOKEN"), "API bearer token")
	fs.DurationVar(&common.timeout, "request-timeout", 30*time.Second, "request timeout")
	return common
}

func (c *cliCommon) client() (*computeClient, error) {
	return newComputeClient(c.serverURL, c.token, c.timeout)
}

func defaultServerURL() string {
	if value := strings.TrimSpace(os.Getenv("COMPUTE_SERVER_URL")); value != "" {
		return value
	}
	return "http://localhost:8080"
}

type cliTaskFlags struct {
	id      string
	orgID   string
	poolID  string
	policy  string
	timeout int
}

type taskReceipt struct {
	TaskID    string              `json:"task_id"`
	Status    protocol.TaskStatus `json:"status"`
	OrgID     string              `json:"org_id"`
	PoolID    string              `json:"pool_id"`
	PolicyID  string              `json:"policy_id"`
	InputHash string              `json:"input_hash"`
}

func addCLITaskFlags(fs *flag.FlagSet) *cliTaskFlags {
	flags := &cliTaskFlags{}
	fs.StringVar(&flags.id, "id", "", "task id")
	fs.StringVar(&flags.orgID, "org", "", "organization id")
	fs.StringVar(&flags.poolID, "pool", "", "pool id")
	fs.StringVar(&flags.policy, "policy", "policy-1", "policy id")
	fs.IntVar(&flags.timeout, "timeout", 60, "timeout seconds")
	return flags
}

func (f *cliTaskFlags) validate() error {
	var errs []error
	if f.orgID == "" {
		errs = append(errs, errors.New("--org is required"))
	}
	if f.poolID == "" {
		errs = append(errs, errors.New("--pool is required"))
	}
	if f.policy == "" {
		errs = append(errs, errors.New("--policy is required"))
	}
	if f.timeout <= 0 {
		errs = append(errs, errors.New("--timeout must be positive"))
	}
	return errors.Join(errs...)
}

func (f *cliTaskFlags) task(workload protocol.WorkloadSpec) protocol.Task {
	id := f.id
	if id == "" {
		id = "task-" + shortHash(time.Now().UTC().Format(time.RFC3339Nano))
	}
	inputHash := workloadHash(workload)
	return protocol.Task{
		ProtocolVersion: protocol.Version,
		ID:              id,
		OrgID:           f.orgID,
		PoolID:          f.poolID,
		PolicyID:        f.policy,
		Status:          protocol.TaskQueued,
		Workload:        workload,
		InputHash:       inputHash,
		RequestedAt:     time.Now().UTC(),
		TimeoutSeconds:  f.timeout,
		Signature: protocol.SignatureEnvelope{
			Algorithm: "dev-local-sha256",
			KeyID:     "local-dev",
			Value:     shortHash(id + ":" + inputHash),
		},
	}
}

type csvFlag []string

func (f *csvFlag) String() string {
	return strings.Join(*f, ",")
}

func (f *csvFlag) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*f = append(*f, part)
		}
	}
	return nil
}

func (f csvFlag) values() []string {
	values := slices.Clone([]string(f))
	slices.Sort(values)
	return slices.Compact(values)
}

type poolSummary struct {
	OrgID        string `json:"org_id"`
	PoolID       string `json:"pool_id"`
	Agents       int    `json:"agents"`
	OnlineAgents int    `json:"online_agents"`
	QueuedTasks  int    `json:"queued_tasks"`
	LeasedTasks  int    `json:"leased_tasks"`
	RunningTasks int    `json:"running_tasks"`
	FailedTasks  int    `json:"failed_tasks"`
	StalledTasks int    `json:"stalled_tasks"`
}

func summarizePools(agents []protocol.Worker, tasks []protocol.Task) []poolSummary {
	byKey := make(map[string]*poolSummary)
	get := func(orgID, poolID string) *poolSummary {
		key := orgID + "\x00" + poolID
		if byKey[key] == nil {
			byKey[key] = &poolSummary{OrgID: orgID, PoolID: poolID}
		}
		return byKey[key]
	}
	for _, agent := range agents {
		summary := get(agent.OrgID, agent.PoolID)
		summary.Agents++
		if agent.Status == protocol.WorkerOnline {
			summary.OnlineAgents++
		}
	}
	for _, task := range tasks {
		summary := get(task.OrgID, task.PoolID)
		switch task.Status {
		case protocol.TaskQueued:
			summary.QueuedTasks++
		case protocol.TaskLeased:
			summary.LeasedTasks++
		case protocol.TaskRunning:
			summary.RunningTasks++
		case protocol.TaskFailed:
			summary.FailedTasks++
		case protocol.TaskStalled:
			summary.StalledTasks++
		}
	}
	out := make([]poolSummary, 0, len(byKey))
	for _, summary := range byKey {
		out = append(out, *summary)
	}
	slices.SortFunc(out, func(a, b poolSummary) int {
		if a.OrgID != b.OrgID {
			return strings.Compare(a.OrgID, b.OrgID)
		}
		return strings.Compare(a.PoolID, b.PoolID)
	})
	return out
}

func parseLabelMap(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	labels := make(map[string]string, len(values))
	for _, value := range values {
		name, label, ok := strings.Cut(value, "=")
		if !ok || name == "" || label == "" {
			return nil, fmt.Errorf("label %q must be KEY=VALUE", value)
		}
		labels[name] = label
	}
	return labels, nil
}

func parseEnvRefs(values []string) ([]protocol.EnvRef, error) {
	refs := make([]protocol.EnvRef, 0, len(values))
	for _, value := range values {
		name, ref, ok := strings.Cut(value, "=")
		if !ok || name == "" || ref == "" {
			return nil, fmt.Errorf("env ref %q must be NAME=ref", value)
		}
		env := protocol.EnvRef{Name: name}
		if strings.HasPrefix(ref, "secret:") {
			env.SecretRef = ref
		} else if strings.HasPrefix(ref, "config:") {
			env.ValueRef = ref
		} else {
			return nil, fmt.Errorf("env %q must reference secret: or config:", name)
		}
		refs = append(refs, env)
	}
	return refs, nil
}

type auditSummary struct {
	Proofs   int `json:"proofs"`
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
	Unknown  int `json:"unknown"`
}

func auditProofs(proofs []protocol.ProofReceipt) auditSummary {
	var summary auditSummary
	summary.Proofs = len(proofs)
	for _, proof := range proofs {
		switch proof.Verifier.Status {
		case protocol.VerificationAccepted:
			summary.Accepted++
		case protocol.VerificationRejected:
			summary.Rejected++
		default:
			summary.Unknown++
		}
	}
	return summary
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
