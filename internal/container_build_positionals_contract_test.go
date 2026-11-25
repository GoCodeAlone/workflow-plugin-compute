package internal

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-compute/pkg/protocol"
)

type standaloneContainerTransport func(*http.Request) (*http.Response, error)

func (f standaloneContainerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

// This helper is only for an isolated, serial test process. The real CLI,
// parser, task builder, client and receipt encoder remain unchanged.
func standaloneContainerCLI(t *testing.T, args []string) (int, string, string, int, protocol.Task) {
	t.Helper()
	t.Setenv("COMPUTE_API_TOKEN", "")
	t.Setenv("COMPUTE_SERVER_URL", "")
	previous := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = previous })
	calls := 0
	var got protocol.Task
	http.DefaultTransport = standaloneContainerTransport(func(req *http.Request) (*http.Response, error) {
		calls++
		if req.Body != nil {
			defer req.Body.Close()
		}
		if req.Method != http.MethodPost || req.URL.Scheme != "https" ||
			req.URL.Host != "compute.invalid" || req.URL.Path != "/v1/tasks" ||
			req.URL.RawQuery != "" || req.Header.Get("Authorization") != "" || req.Body == nil {
			return nil, errors.New("inert sink rejected an unexpected request")
		}
		body, err := io.ReadAll(io.LimitReader(req.Body, (64<<10)+1))
		if err != nil || len(body) > 64<<10 {
			return nil, errors.New("inert sink rejected an oversized or unreadable task")
		}
		decoder := json.NewDecoder(bytes.NewReader(body))
		if err := decoder.Decode(&got); err != nil {
			return nil, errors.New("inert sink could not decode the task")
		}
		if decoder.Decode(new(any)) != io.EOF {
			return nil, errors.New("inert sink requires one JSON task")
		}
		data, err := json.Marshal(struct {
			Task protocol.Task `json:"task"`
		}{Task: got})
		if err != nil {
			return nil, errors.New("inert sink could not encode its receipt")
		}
		return &http.Response{
			StatusCode:    http.StatusCreated,
			Header:        make(http.Header),
			Body:          io.NopCloser(bytes.NewReader(data)),
			ContentLength: int64(len(data)),
			Request:       req,
		}, nil
	})
	var stdout, stderr bytes.Buffer
	code := newCLI(&stdout, &stderr).RunCLI(args)
	return code, stdout.String(), stderr.String(), calls, got
}

// Do not call t.Parallel: the disposable test process owns DefaultTransport.
func TestStandaloneContainerBuildPositionalsContract(t *testing.T) {
	base := []string{
		"--server", "https://compute.invalid", "--id", "fixture-image",
		"--org", "fixture-org", "--pool", "fixture-pool", "--policy", "fixture-policy",
		"--timeout", "15", "--context", "repo/public", "--dockerfile", "Dockerfile",
		"--tag", "local/fixture:job",
	}
	const operand = "inert-positional-marker"
	const suffix = "unparsed-context-marker"
	const refusal = "unexpected positional arguments for compute submit container-build\n"
	cases := []struct {
		name string
		args []string
		ok   bool
	}{
		{"valid-no-push", slices.Clone(base), true},
		{"positional-before-flags", append([]string{operand}, base...), false},
		{"positional-after-required-flags", append(slices.Clone(base), operand), false},
		{"positional-then-flag-suffix", append(slices.Clone(base), operand, "--context", suffix), false},
		{"separator-then-positional", append(slices.Clone(base), "--", operand), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"compute", "submit", "container-build"}, tc.args...)
			code, out, diagnostic, calls, task := standaloneContainerCLI(t, args)
			if strings.Contains(out+diagnostic, operand) || strings.Contains(out+diagnostic, suffix) {
				t.Error("CLI output exposed an argument value")
			}
			if !tc.ok {
				if code == 0 || calls != 0 || strings.TrimSpace(out) != "" {
					t.Error("unexpected positional input was not refused before submission")
				}
				if diagnostic != refusal {
					t.Error("missing constant actionable positional-input diagnostic")
				}
				return
			}
			if code != 0 || calls != 1 || diagnostic != "" {
				t.Fatal("valid arguments did not yield exactly one inert submission")
			}
			build := task.Workload.ContainerBuild
			if task.Workload.Kind != protocol.WorkloadContainerBuild || build == nil ||
				build.ContextDirectory != "repo/public" || build.Dockerfile != "Dockerfile" ||
				build.PushTargetRef != "" || !slices.Equal(build.Tags, []string{"local/fixture:job"}) {
				t.Error("valid no-push workload fields changed")
			}
			var receipt map[string]any
			if json.Unmarshal([]byte(out), &receipt) != nil || len(receipt) != 6 ||
				receipt["task_id"] != "fixture-image" || receipt["status"] != "queued" ||
				receipt["org_id"] != "fixture-org" || receipt["pool_id"] != "fixture-pool" ||
				receipt["policy_id"] != "fixture-policy" {
				t.Error("CLI receipt is missing the expected bounded task fields")
			}
			inputHash, ok := receipt["input_hash"].(string)
			if !ok || inputHash == "" || inputHash != task.InputHash {
				t.Error("CLI receipt input hash does not match the captured task")
			}
			for _, field := range []string{"signature", "workload", "token", "authorization"} {
				if strings.Contains(out, field) {
					t.Error("CLI receipt exposed a non-receipt field")
				}
			}
		})
	}
	t.Run("command-keeps-free-form-argv", func(t *testing.T) {
		argv := []string{"printf", "inert-command-marker", "--literal-command-flag"}
		args := []string{"compute", "submit", "command", "--server", "https://compute.invalid",
			"--id", "fixture-command", "--org", "fixture-org", "--pool", "fixture-pool", "--"}
		code, _, _, calls, task := standaloneContainerCLI(t, append(args, argv...))
		if code != 0 || calls != 1 || task.Workload.Command == nil || !slices.Equal(task.Workload.Command.Args, argv) {
			t.Error("command free-form argv behavior changed")
		}
	})
}
