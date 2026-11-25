package main

import (
	"os"
	"strings"
	"testing"
)

func readBuildConfig(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestBuildCompilerPins(t *testing.T) {
	for _, name := range []string{"build", "release"} {
		t.Run(name, func(t *testing.T) {
			config := readBuildConfig(t, ".github/workflows/"+name+".yml")
			if strings.Contains(config, "go-version-file:") || strings.Count(config, "go-version: '1.27.4'") != 1 {
				t.Error("build compiler must be exactly Go 1.27.4 independently of the library floor")
			}
			job := config[strings.Index(config, "jobs:"):]
			steps := strings.Index(job, "    steps:")
			if steps < 0 || !strings.Contains(job[:steps], "    env:\n      GOTOOLCHAIN: local\n") {
				t.Error("job must disable automatic toolchain switching")
			}
			check := strings.Index(config, "run: go run ./scripts/check-build-toolchain.go")
			if check < strings.Index(config, "uses: actions/setup-go@") || check > strings.Index(config, "- name: Configure private Go modules") {
				t.Error("compiler check must precede build steps")
			}
		})
	}
	mod := readBuildConfig(t, "go.mod")
	if !strings.Contains(mod, "\ngo 1.26.4\n") || strings.Contains(mod, "\ntoolchain ") {
		t.Error("library minimum must be Go 1.26.4 without automatic toolchain selection")
	}
}

func TestBuiltArtifactCompilerGuards(t *testing.T) {
	config := readBuildConfig(t, ".github/workflows/build.yml")
	guard := "go run ./scripts/check-build-toolchain.go ./workflow-plugin-compute"
	direct := strings.Index(config, "-o workflow-plugin-compute ./cmd/workflow-plugin-compute")
	first := strings.Index(config, guard)
	consumer := strings.Index(config, "plugin_dir=\"$(mktemp -d)\"")
	if direct < 0 || first < direct || first > consumer {
		t.Error("direct artifact must be checked before plugin execution")
	}
	wfctl := strings.Index(config, "wfctl build --config workflow.yaml --no-push --tag ci")
	last := strings.LastIndex(config, guard)
	if wfctl < 0 || last < wfctl || first == last {
		t.Error("wfctl artifact must be checked after its build")
	}
}

func TestReleaseArtifactCompilerGuards(t *testing.T) {
	config := readBuildConfig(t, ".goreleaser.yaml")
	if !strings.Contains(config, "env:\n  - GOTOOLCHAIN=local\n") {
		t.Error("release hooks and builds must disable automatic toolchain switching")
	}
	if !strings.Contains(config, "before:\n  hooks:\n    - go run ./scripts/check-build-toolchain.go\n    - go mod tidy") {
		t.Error("release compiler check must run before tidy/build")
	}
	if !strings.Contains(config, "    hooks:\n      post:\n        - cmd: 'env GOOS= GOARCH= go run ./scripts/check-build-toolchain.go \"{{ .Path }}\"'\n          output: true\n") {
		t.Error("each release artifact must be checked by a native host checker before publication")
	}
}

func TestAuxiliaryComputeCompilerSelection(t *testing.T) {
	config := readBuildConfig(t, ".github/workflows/build.yml")
	const (
		binary  = `"$RUNNER_TEMP/workflow-compute-ci-$GITHUB_RUN_ID-$GITHUB_RUN_ATTEMPT"`
		runtime = "timeout --kill-after=5s 20s " + binary
	)
	// Auxiliary Go commands inherit the job's pinned local compiler. Runtime
	// checks reuse the built CLI and keep their isolated host-tool path.
	if strings.Count(config, "GOTOOLCHAIN:") != 1 || strings.Contains(config, "GOTOOLCHAIN=") {
		t.Error("auxiliary commands must inherit the pinned job compiler without toolchain overrides")
	}
	checks := []struct {
		name string
		want []string
	}{
		{"Build workflow-compute CLI for setup checks", []string{
			"        working-directory: workflow-compute\n",
			"        env:\n          GOWORK: \"off\"\n",
			"        run: timeout --kill-after=5s 3m go build -o " + binary + " ./cmd/compute\n",
		}},
		{"Verify workflow-compute setup runtime surface", []string{
			"help_output=\"$(" + runtime + " agent setup --help 2>&1)\"",
		}},
		{"Verify projectless agent setup CLI", []string{
			`mkdir "$plugin_dir/runtime-probe-path"`,
			`compat_output="$(timeout --kill-after=5s 20s env PATH="$plugin_dir/runtime-probe-path" ` + binary + " \\",
		}},
		{"Check workflow-compute provider alignment", []string{
			`        run: scripts/check-workflow-compute-alignment.sh "$GITHUB_WORKSPACE/workflow-compute"`,
		}},
	}
	previous := -1
	for _, check := range checks {
		start := strings.Index(config, "      - name: "+check.name+"\n")
		if start <= previous {
			t.Fatalf("missing or out-of-order auxiliary check: %s", check.name)
		}
		previous = start
		t.Run(check.name, func(t *testing.T) {
			step := config[start:]
			if next := strings.Index(step[1:], "\n      - "); next >= 0 {
				step = step[:next+2]
			}
			for _, want := range check.want {
				if !strings.Contains(step, want) {
					t.Errorf("auxiliary check must contain %q", want)
				}
			}
		})
	}
}
