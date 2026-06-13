package internal

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/GoCodeAlone/workflow-compute/pkg/protocol"
	workflowconfig "github.com/GoCodeAlone/workflow/config"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

const (
	agentSetupRuntimeAuto              = "auto"
	agentSetupRuntimeNone              = "none"
	agentSetupRuntimePodman            = "podman"
	agentSetupRuntimeDocker            = "docker"
	agentSetupRuntimeNerdctl           = "nerdctl"
	agentSetupRuntimeManagedContainerd = "managed-containerd"
	managedRuntimeContainerPlugin      = "workflow-plugin-compute-container"
	managedRuntimeContainerMinimum     = "v0.5.1"
	managedRuntimeInstallerContract    = "ManagedRuntimeBundleInstaller"
	managedRuntimeCommandPrefix        = "wfctl plugin run --ensure-installed " + managedRuntimeContainerPlugin + "@" + managedRuntimeContainerMinimum + " -- managed-runtime"
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
		return errors.New("usage: wfctl compute <agent|enroll|pools|run|submit|audit|accounting|github-runner|network-audits>")
	}
	if len(args) == 1 {
		return errors.New("usage: wfctl compute <agent|enroll|pools|run|submit|audit|accounting|github-runner|network-audits>")
	}
	switch args[1] {
	case "agent":
		return c.runAgent(ctx, args[2:])
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
	case "network-audits":
		return c.runNetworkAudits(ctx, args[2:])
	default:
		return fmt.Errorf("unknown wfctl compute command %q", args[1])
	}
}

func (c *computeCLI) runAgent(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: wfctl compute agent <setup>")
	}
	switch args[0] {
	case "setup":
		return c.runAgentSetup(ctx, args[1:])
	default:
		return fmt.Errorf("unknown wfctl compute agent command %q", args[0])
	}
}

type agentSetupPlan struct {
	InviteID          string                               `json:"invite_id,omitempty"`
	InstallSessionID  string                               `json:"install_session_id,omitempty"`
	WorkerID          string                               `json:"worker_id,omitempty"`
	CredentialID      string                               `json:"credential_id,omitempty"`
	CredentialRef     string                               `json:"credential_ref,omitempty"`
	TokenEnv          string                               `json:"token_env,omitempty"`
	TokenPresent      bool                                 `json:"token_present,omitempty"`
	PackageCandidate  *protocol.AgentSetupPackageCandidate `json:"package_candidate,omitempty"`
	RequestedRuntime  string                               `json:"requested_runtime,omitempty"`
	RuntimeSelection  string                               `json:"runtime_selection,omitempty"`
	DryRun            bool                                 `json:"dry_run,omitempty"`
	InstallRequested  bool                                 `json:"install_requested,omitempty"`
	StartRequested    bool                                 `json:"start_requested,omitempty"`
	VerifyRequested   bool                                 `json:"verify_requested,omitempty"`
	Verified          bool                                 `json:"verified,omitempty"`
	ManagedRuntime    *agentSetupManagedRuntimePlan        `json:"managed_runtime,omitempty"`
	AgentSetupCommand string                               `json:"agent_setup_command,omitempty"`
}

type agentSetupManagedRuntimePlan struct {
	Plugin           string   `json:"plugin"`
	MinimumVersion   string   `json:"minimum_version"`
	Contract         string   `json:"contract"`
	CommandPrefix    string   `json:"command_prefix"`
	LifecycleActions []string `json:"lifecycle_actions"`
}

func (c *computeCLI) runAgentSetup(ctx context.Context, args []string) error {
	fs := c.newFlagSet("compute agent setup")
	serverURL := fs.String("server", defaultServerURL(), "workflow-compute server URL")
	requestTimeout := fs.Duration("request-timeout", 30*time.Second, "request timeout")
	inviteID := fs.String("invite", "", "setup invite id")
	inviteURL := fs.String("invite-url", "", "setup invite URL")
	installSessionID := fs.String("install-session-id", "", "stable install session id")
	credentialStore := fs.String("credential-store", "", "credential store name")
	tokenEnv := fs.String("token-env", "", "environment variable name reserved for downstream token handoff")
	tokenCredentialRef := fs.String("token-credential-ref", "", "credential reference for durable token storage")
	runtimeSelection := fs.String("runtime", agentSetupRuntimeAuto, "dry-run only: runtime backend selection for the workflow-compute setup command: auto, none, podman, docker, nerdctl, or managed-containerd")
	install := fs.Bool("install", false, "dry-run only: render install intent for the workflow-compute setup command")
	start := fs.Bool("start", false, "dry-run only: render start intent for the workflow-compute setup command")
	verify := fs.Bool("verify", false, "dry-run only: render verification intent for the workflow-compute setup command")
	dryRun := fs.Bool("dry-run", false, "render the compute agent setup command without claiming the invite")
	showSecrets := fs.Bool("show-secrets", false, "include secret-bearing invite values in dry-run command output")
	jsonOutput := fs.Bool("json", false, "write sanitized JSON output")
	nonInteractive := fs.Bool("non-interactive", false, "fail instead of prompting")
	runtimeSpecified := flagSpecified(args, "runtime")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *inviteID == "" && *inviteURL == "" {
		return errors.New("--invite or --invite-url is required")
	}
	if !*nonInteractive {
		return errors.New("--non-interactive is required; interactive setup belongs to the compute agent binary")
	}
	normalizedRuntime, err := normalizeAgentSetupRuntimeSelection(*runtimeSelection)
	if err != nil {
		return err
	}
	if *installSessionID == "" {
		*installSessionID = "session-" + shortHash(time.Now().UTC().Format(time.RFC3339Nano))
	}
	if *dryRun {
		commandRuntime := downstreamAgentSetupRuntimeSelection(normalizedRuntime)
		plan := agentSetupPlan{
			InstallSessionID:  *installSessionID,
			RequestedRuntime:  requestedAgentSetupRuntimeSelection(normalizedRuntime, commandRuntime),
			RuntimeSelection:  commandRuntime,
			DryRun:            true,
			InstallRequested:  *install,
			StartRequested:    *start,
			VerifyRequested:   *verify,
			ManagedRuntime:    managedRuntimeSetupPlan(normalizedRuntime),
			AgentSetupCommand: renderAgentSetupCommand(*serverURL, sanitizeInviteArgForDryRun(*inviteID, *showSecrets), sanitizeInviteURLForDryRun(*inviteURL, *showSecrets), *installSessionID, commandRuntime, *credentialStore, *tokenEnv, *tokenCredentialRef, *install, *start, *verify, *jsonOutput),
		}
		if *jsonOutput {
			return writeJSON(c.stdout, plan)
		}
		return writeJSON(c.stdout, map[string]any{"agent_setup": plan})
	}
	if *install || *start || *verify {
		return errors.New("--install, --start, and --verify are only supported with --dry-run; run the rendered workflow-compute setup command to perform install/start/verify")
	}
	if runtimeSpecified {
		return errors.New("--runtime is only supported with --dry-run; run the rendered workflow-compute setup command to apply runtime selection")
	}
	client, err := newComputeClient(*serverURL, "", *requestTimeout)
	if err != nil {
		return err
	}
	preview, err := client.agentSetupPreview(ctx, protocol.AgentSetupInvitePreviewRequest{
		InviteID:  *inviteID,
		InviteURL: *inviteURL,
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Format:    protocol.PackageArtifactBinary,
	})
	if err != nil {
		return err
	}
	claim, err := client.agentSetupClaim(ctx, protocol.AgentSetupInviteClaimRequest{
		InviteID:         *inviteID,
		InviteURL:        *inviteURL,
		InstallSessionID: *installSessionID,
		ServerURL:        *serverURL,
		OS:               runtime.GOOS,
		Arch:             runtime.GOARCH,
		Format:           protocol.PackageArtifactBinary,
	})
	if err != nil {
		return err
	}
	if claim.Session.WorkerID == "" {
		return errors.New("setup claim response missing worker_id")
	}
	if claim.Session.CredentialID == "" && claim.CredentialRef == "" {
		return errors.New("setup claim response missing credential id/ref")
	}
	plan := agentSetupPlan{
		InviteID:         firstNonEmpty(preview.Invite.ID, claim.Invite.ID, *inviteID),
		InstallSessionID: *installSessionID,
		WorkerID:         claim.Session.WorkerID,
		CredentialID:     claim.Session.CredentialID,
		CredentialRef:    firstNonEmpty(*tokenCredentialRef, claim.CredentialRef),
		TokenEnv:         firstNonEmpty(*tokenEnv, claim.TokenEnv, "COMPUTE_AGENT_TOKEN"),
		TokenPresent:     claim.OneTimeToken != "" || claim.TokenPresent,
		PackageCandidate: firstAgentSetupPackageCandidate(claim.PackageCandidates, preview.PackageCandidates),
		Verified:         claim.Session.FinalizedAt.IsZero() == false,
	}
	if *credentialStore != "" && plan.CredentialRef == "" {
		plan.CredentialRef = *credentialStore + ":" + plan.WorkerID
	}
	if *jsonOutput {
		return writeJSON(c.stdout, plan)
	}
	return writeJSON(c.stdout, map[string]any{"agent_setup": plan})
}

func flagSpecified(args []string, name string) bool {
	long := "--" + name
	short := "-" + name
	for _, arg := range args {
		if arg == long || arg == short || strings.HasPrefix(arg, long+"=") || strings.HasPrefix(arg, short+"=") {
			return true
		}
	}
	return false
}

func normalizeAgentSetupRuntimeSelection(selection string) (string, error) {
	selection = strings.ToLower(strings.TrimSpace(selection))
	if selection == "" {
		selection = agentSetupRuntimeAuto
	}
	switch selection {
	case agentSetupRuntimeAuto,
		agentSetupRuntimeNone,
		agentSetupRuntimePodman,
		agentSetupRuntimeDocker,
		agentSetupRuntimeNerdctl,
		agentSetupRuntimeManagedContainerd:
		return selection, nil
	default:
		return "", errors.New("--runtime must be auto, none, podman, docker, nerdctl, or managed-containerd")
	}
}

func downstreamAgentSetupRuntimeSelection(runtimeSelection string) string {
	if runtimeSelection == agentSetupRuntimeManagedContainerd {
		return agentSetupRuntimeAuto
	}
	return runtimeSelection
}

func requestedAgentSetupRuntimeSelection(runtimeSelection, commandRuntime string) string {
	if runtimeSelection == commandRuntime {
		return ""
	}
	return runtimeSelection
}

func managedRuntimeSetupPlan(runtimeSelection string) *agentSetupManagedRuntimePlan {
	if runtimeSelection != agentSetupRuntimeManagedContainerd {
		return nil
	}
	return &agentSetupManagedRuntimePlan{
		Plugin:           managedRuntimeContainerPlugin,
		MinimumVersion:   managedRuntimeContainerMinimum,
		Contract:         managedRuntimeInstallerContract,
		CommandPrefix:    managedRuntimeCommandPrefix,
		LifecycleActions: []string{"install", "doctor", "uninstall", "reinstall"},
	}
}

func renderAgentSetupCommand(serverURL, inviteID, inviteURL, installSessionID, runtimeSelection, credentialStore, tokenEnv, tokenCredentialRef string, install, start, verify, jsonOutput bool) string {
	args := []string{"compute", "agent", "setup"}
	appendFlag := func(name, value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			args = append(args, name, value)
		}
	}
	appendFlag("--server", serverURL)
	appendFlag("--invite", inviteID)
	appendFlag("--invite-url", inviteURL)
	appendFlag("--install-session-id", installSessionID)
	appendFlag("--runtime", runtimeSelection)
	appendFlag("--credential-store", credentialStore)
	appendFlag("--token-env", tokenEnv)
	appendFlag("--token-credential-ref", tokenCredentialRef)
	if install {
		args = append(args, "--install")
	}
	if start {
		args = append(args, "--start")
	}
	if verify {
		args = append(args, "--verify")
	}
	args = append(args, "--non-interactive")
	if jsonOutput {
		args = append(args, "--json")
	}
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}
	return strings.Join(quoted, " ")
}

func sanitizeInviteArgForDryRun(invite string, showSecrets bool) string {
	invite = strings.TrimSpace(invite)
	if invite == "" || showSecrets {
		return invite
	}
	if strings.Contains(invite, "://") {
		return sanitizeInviteURLForDryRun(invite, false)
	}
	for _, sep := range []string{":", ".", "/"} {
		left, right, ok := strings.Cut(invite, sep)
		if ok && strings.TrimSpace(left) != "" && strings.TrimSpace(right) != "" {
			return strings.TrimSpace(left) + sep + "<redacted>"
		}
	}
	if inviteValueSensitive(invite) {
		return "<redacted-invite>"
	}
	return invite
}

func sanitizeInviteURLForDryRun(inviteURL string, showSecrets bool) string {
	inviteURL = strings.TrimSpace(inviteURL)
	if inviteURL == "" || showSecrets {
		return inviteURL
	}
	parsed, err := url.Parse(inviteURL)
	if err != nil {
		return redactInviteValue(inviteURL)
	}
	q := parsed.Query()
	redacted := false
	for key := range q {
		if !agentSetupInviteURLKeySensitive(key) {
			continue
		}
		q.Set(key, "<redacted>")
		redacted = true
	}
	if parsed.Fragment != "" {
		fragment, err := url.ParseQuery(parsed.Fragment)
		if err != nil {
			if inviteValueSensitive(parsed.Fragment) {
				parsed.Fragment = "<redacted>"
				redacted = true
			}
		} else {
			fragmentRedacted := false
			for key := range fragment {
				if !agentSetupInviteURLKeySensitive(key) {
					continue
				}
				fragment.Set(key, "<redacted>")
				fragmentRedacted = true
			}
			if fragmentRedacted {
				parsed.Fragment = strings.NewReplacer("%3C", "<", "%3E", ">").Replace(fragment.Encode())
				redacted = true
			}
		}
	}
	if !redacted {
		return inviteURL
	}
	parsed.RawQuery = q.Encode()
	return parsed.String()
}

func agentSetupInviteURLKeySensitive(key string) bool {
	key = strings.ToLower(strings.TrimSpace(key))
	for _, marker := range []string{"redeem", "code", "token", "secret"} {
		if strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func inviteValueSensitive(value string) bool {
	value = strings.ToLower(value)
	for _, marker := range []string{"redeem", "code=", "token", "secret"} {
		if strings.Contains(value, marker) {
			return true
		}
	}
	return false
}

func redactInviteValue(value string) string {
	lowered := strings.ToLower(value)
	for _, marker := range []string{"redeem", "code=", "token", "secret"} {
		if strings.Contains(lowered, marker) {
			return "<redacted-invite-url>"
		}
	}
	return value
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'A' && r <= 'Z') &&
			!(r >= 'a' && r <= 'z') &&
			!(r >= '0' && r <= '9') &&
			!strings.ContainsRune("@%_+=:,./-", r)
	}) == -1 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func firstAgentSetupPackageCandidate(candidateSets ...[]protocol.AgentSetupPackageCandidate) *protocol.AgentSetupPackageCandidate {
	for _, candidates := range candidateSets {
		if len(candidates) == 0 {
			continue
		}
		candidate := candidates[0]
		return &candidate
	}
	return nil
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
	rewards, err := client.rewards(ctx)
	if err != nil {
		return err
	}
	return writeJSON(c.stdout, map[string]any{
		"account_id": *accountID,
		"events":     contributions.Events,
		"total":      contributions.Total,
		"rewards":    rewardsForAccount(rewards.Rewards, *accountID),
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

func (c *computeCLI) runNetworkAudits(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: wfctl compute network-audits <list|audit-state|raw-compat-dry-run>")
	}
	switch args[0] {
	case "list":
		return c.runNetworkAuditsList(ctx, args[1:])
	case "audit-state":
		return c.runNetworkAuditsAuditState(ctx, args[1:])
	case "raw-compat-dry-run":
		return c.runNetworkAuditsRawCompatDryRun(ctx, args[1:])
	default:
		return fmt.Errorf("unknown wfctl compute network-audits command %q", args[0])
	}
}

func (c *computeCLI) runNetworkAuditsList(ctx context.Context, args []string) error {
	fs := c.newFlagSet("compute network-audits list")
	common := addCLINetworkAuditFlags(fs)
	projection := fs.String("projection", "", "projection mode, such as release-a")
	schema := fs.String("schema", protocol.NetworkAuditListSchemaProjectionV1, "response schema, such as projection.v1")
	decision := fs.String("decision", "", "decision filter: allowed or blocked")
	_ = fs.Bool("json", false, "write sanitized JSON output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := requireExpectedNetworkAuditRefKeyEpoch(common.expectedRefKeyEpoch); err != nil {
		return err
	}
	client, err := common.client(args)
	if err != nil {
		return err
	}
	resp, err := client.listNetworkAudits(ctx, networkAuditsQuery{
		Projection: strings.TrimSpace(*projection),
		Schema:     strings.TrimSpace(*schema),
		Decision:   strings.TrimSpace(*decision),
	})
	if err != nil {
		return sanitizeNetworkAuditRequestError(err, "network audit list request failed")
	}
	return writeJSON(c.stdout, sanitizeNetworkAuditsResponse(resp))
}

func (c *computeCLI) runNetworkAuditsAuditState(ctx context.Context, args []string) error {
	fs := c.newFlagSet("compute network-audits audit-state")
	common := addCLINetworkAuditFlags(fs)
	projection := fs.String("projection", "release-a", "projection mode for server-backed audit evidence")
	schema := fs.String("schema", protocol.NetworkAuditListSchemaProjectionV1, "response schema, such as projection.v1")
	decision := fs.String("decision", "", "decision filter: allowed or blocked")
	_ = fs.Bool("json", false, "write sanitized JSON output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := requireExpectedNetworkAuditRefKeyEpoch(common.expectedRefKeyEpoch); err != nil {
		return err
	}
	client, err := common.client(args)
	if err != nil {
		return err
	}
	resp, err := client.listNetworkAudits(ctx, networkAuditsQuery{
		Projection: strings.TrimSpace(*projection),
		Schema:     strings.TrimSpace(*schema),
		Decision:   strings.TrimSpace(*decision),
	})
	if err != nil {
		return sanitizeNetworkAuditRequestError(err, "network audit audit-state request failed")
	}
	return writeJSON(c.stdout, networkAuditStateEvidence{
		Source:               "server",
		ProjectionReady:      true,
		RefKeyEpochRequired:  common.expectedRefKeyEpoch,
		RefKeyEpochMismatch:  false,
		Summary:              resp.Summary,
		ProjectionSummary:    resp.ProjectionSummary,
		Projected:            resp.ProjectionSummary.Projected,
		Unsafe:               resp.ProjectionSummary.Unsafe,
		ProjectionSampleRefs: projectionSampleRefs(resp.Projections, 3),
		Projections:          sanitizeNetworkAuditProjections(resp.Projections),
	})
}

func (c *computeCLI) runNetworkAuditsRawCompatDryRun(ctx context.Context, args []string) error {
	fs := c.newFlagSet("compute network-audits raw-compat-dry-run")
	common := addCLINetworkAuditFlags(fs)
	action := fs.String("action", "use", "dry-run action: mint, use, or revoke")
	handle := fs.String("handle", "", "opaque dry-run handle for use or revoke")
	orgID := fs.String("org", "", "target org id for mint/use scope check")
	poolID := fs.String("pool", "", "target pool id for mint/use scope check")
	_ = fs.Bool("json", false, "write sanitized JSON output")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if err := requireExpectedNetworkAuditRefKeyEpoch(common.expectedRefKeyEpoch); err != nil {
		return err
	}
	client, err := common.client(args)
	if err != nil {
		return err
	}
	resp, err := client.networkAuditRawCompatDryRun(ctx, networkAuditRawCompatDryRunRequest{
		Action:              strings.TrimSpace(*action),
		ExpectedRefKeyEpoch: common.expectedRefKeyEpoch,
		Handle:              strings.TrimSpace(*handle),
		OrgID:               strings.TrimSpace(*orgID),
		PoolID:              strings.TrimSpace(*poolID),
	})
	if err != nil {
		return sanitizeNetworkAuditRequestError(err, "network audit raw-compat dry-run request failed")
	}
	return writeJSON(c.stdout, sanitizeNetworkAuditDryRunResponse(resp))
}

type cliNetworkAuditFlags struct {
	serverURL           string
	token               string
	tokenEnv            string
	configPath          string
	providerRef         string
	timeout             time.Duration
	expectedRefKeyEpoch string
}

func addCLINetworkAuditFlags(fs *flag.FlagSet) *cliNetworkAuditFlags {
	common := &cliNetworkAuditFlags{}
	fs.StringVar(&common.serverURL, "server", "", "workflow-compute server URL")
	fs.StringVar(&common.token, "token", "", "API bearer token")
	fs.StringVar(&common.tokenEnv, "token-env", "", "environment variable containing the API bearer token")
	fs.StringVar(&common.configPath, "config", "", "Workflow config file containing a compute.provider module")
	fs.StringVar(&common.providerRef, "provider-ref", "", "compute.provider module name in --config")
	fs.DurationVar(&common.timeout, "request-timeout", 30*time.Second, "request timeout")
	fs.StringVar(&common.expectedRefKeyEpoch, "expected-ref-key-epoch", protocol.NetworkAuditRefKeyEpoch, "expected network audit ref-key epoch")
	return common
}

func (f *cliNetworkAuditFlags) client(args []string) (*computeClient, error) {
	serverURL := strings.TrimSpace(f.serverURL)
	token := strings.TrimSpace(f.token)
	timeout := f.timeout
	var provider *providerConfig
	if strings.TrimSpace(f.configPath) != "" {
		resolved, err := resolveProviderConfig(f.configPath, f.providerRef)
		if err != nil {
			return nil, err
		}
		provider = &resolved
		if !flagSpecified(args, "server") {
			serverURL = provider.ServerURL
		}
		if !flagSpecified(args, "request-timeout") && provider.RequestTimeout != "" {
			parsed, err := time.ParseDuration(provider.RequestTimeout)
			if err != nil {
				return nil, fmt.Errorf("provider request_timeout: %w", err)
			}
			timeout = parsed
		}
	}
	if token == "" && strings.TrimSpace(f.tokenEnv) != "" {
		tokenEnv := strings.TrimSpace(f.tokenEnv)
		token = strings.TrimSpace(os.Getenv(tokenEnv))
		if token == "" {
			return nil, fmt.Errorf("--token-env is set but the environment variable is empty")
		}
	}
	if token == "" && provider != nil {
		resolved, err := resolveCLIRefFromEnvironment(provider.AuthTokenRef)
		if err != nil {
			return nil, err
		}
		token = resolved
	}
	if token == "" {
		token = strings.TrimSpace(os.Getenv("COMPUTE_API_TOKEN"))
	}
	if serverURL == "" {
		serverURL = defaultServerURL()
	}
	return newComputeClient(serverURL, token, timeout)
}

func resolveProviderConfig(configPath, providerRef string) (providerConfig, error) {
	cfg, err := workflowconfig.LoadFromFile(configPath)
	if err != nil {
		return providerConfig{}, fmt.Errorf("load Workflow config: %w", err)
	}
	providerRef = strings.TrimSpace(providerRef)
	var matches []workflowconfig.ModuleConfig
	for _, module := range cfg.Modules {
		if module.Type != "compute.provider" {
			continue
		}
		if providerRef == "" || module.Name == providerRef {
			matches = append(matches, module)
		}
	}
	if providerRef != "" && len(matches) == 0 {
		return providerConfig{}, fmt.Errorf("compute.provider module not found")
	}
	if providerRef == "" && len(matches) == 0 {
		return providerConfig{}, fmt.Errorf("Workflow config does not define a compute.provider module")
	}
	if providerRef == "" && len(matches) > 1 {
		return providerConfig{}, fmt.Errorf("--provider-ref is required when config has multiple compute.provider modules")
	}
	module, err := newProviderModule(matches[0].Name, matches[0].Config)
	if err != nil {
		return providerConfig{}, err
	}
	return module.config, nil
}

func resolveCLIRefFromEnvironment(ref string) (string, error) {
	prefix, key, ok := strings.Cut(strings.TrimSpace(ref), ":")
	if !ok || (prefix != "secret" && prefix != "config") || strings.TrimSpace(key) == "" {
		return "", fmt.Errorf("auth token ref must use secret: or config:")
	}
	for _, candidate := range cliRefEnvCandidates(key) {
		if value := strings.TrimSpace(os.Getenv(candidate)); value != "" {
			return value, nil
		}
	}
	return "", fmt.Errorf("auth token ref could not be resolved from environment")
}

func cliRefEnvCandidates(key string) []string {
	normalized := strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return unicode.ToUpper(r)
		}
		return '_'
	}, strings.TrimSpace(key))
	normalized = strings.Trim(normalized, "_")
	if normalized == "" {
		return nil
	}
	candidates := []string{normalized}
	if !strings.HasPrefix(normalized, "COMPUTE_") {
		candidates = append(candidates, "COMPUTE_"+normalized)
	}
	return candidates
}

func requireExpectedNetworkAuditRefKeyEpoch(expected string) error {
	if strings.TrimSpace(expected) != protocol.NetworkAuditRefKeyEpoch {
		return fmt.Errorf("expected network audit ref-key epoch does not match this plugin")
	}
	return nil
}

type networkAuditStateEvidence struct {
	Source               string                                  `json:"source"`
	ProjectionReady      bool                                    `json:"projection_ready"`
	RefKeyEpochRequired  string                                  `json:"ref_key_epoch_required"`
	RefKeyEpochMismatch  bool                                    `json:"ref_key_epoch_mismatch"`
	Summary              networkAuditsSummary                    `json:"summary"`
	ProjectionSummary    networkAuditProjectionSummary           `json:"projection_summary,omitempty"`
	Projected            int                                     `json:"projected"`
	Unsafe               int                                     `json:"unsafe,omitempty"`
	ProjectionSampleRefs []string                                `json:"projection_sample_refs,omitempty"`
	Findings             []networkAuditDryRunFinding             `json:"findings,omitempty"`
	Projections          []protocol.NetworkAuditRecordProjection `json:"projections,omitempty"`
}

func projectionSampleRefs(projections []protocol.NetworkAuditRecordProjection, limit int) []string {
	refs := make([]string, 0, min(len(projections), limit))
	for _, projection := range projections {
		if strings.TrimSpace(projection.RecordRef) == "" {
			continue
		}
		refs = append(refs, projection.RecordRef)
		if len(refs) == limit {
			break
		}
	}
	return refs
}

func sanitizeNetworkAuditsResponse(resp networkAuditsResponse) networkAuditsResponse {
	resp.Projections = sanitizeNetworkAuditProjections(resp.Projections)
	return resp
}

func sanitizeNetworkAuditDryRunResponse(resp networkAuditRawCompatDryRunResponse) networkAuditRawCompatDryRunResponse {
	resp.Handle = ""
	resp.Error = ""
	for i := range resp.Findings {
		resp.Findings[i].Reason = ""
	}
	resp.Projections = sanitizeNetworkAuditProjections(resp.Projections)
	return resp
}

func sanitizeNetworkAuditProjections(projections []protocol.NetworkAuditRecordProjection) []protocol.NetworkAuditRecordProjection {
	safe := make([]protocol.NetworkAuditRecordProjection, len(projections))
	copy(safe, projections)
	for i := range safe {
		safe[i].Labels = nil
		safe[i].ResourceUsage.LimitHit = ""
	}
	return safe
}

func sanitizeNetworkAuditRequestError(err error, message string) error {
	for status := 400; status < 600; status++ {
		if isHTTPStatusError(err, status) {
			return fmt.Errorf("%s with status %d", message, status)
		}
	}
	return errors.New(message)
}

func rewardsForAccount(rewards []map[string]any, accountID string) []map[string]any {
	matching := make([]map[string]any, 0, len(rewards))
	for _, reward := range rewards {
		if reward["account_id"] == accountID {
			matching = append(matching, reward)
		}
	}
	return matching
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
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
