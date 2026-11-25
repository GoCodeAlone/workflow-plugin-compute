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
			if strings.Contains(config, "go-version-file:") || strings.Count(config, "go-version: '1.26.11'") != 1 {
				t.Error("build compiler must be exactly Go 1.26.11 independently of the library floor")
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
	if !strings.Contains(mod, "\ngo 1.26.3\n") || strings.Contains(mod, "\ntoolchain ") {
		t.Error("library minimum must remain unchanged without automatic toolchain selection")
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
	if strings.Contains(config, "GOTOOLCHAIN: go1.27.2+auto") || strings.Contains(config, "GOTOOLCHAIN=go1.27.2+auto") || strings.Count(config, "GOTOOLCHAIN: go1.27.2\n") != 2 || strings.Count(config, "GOTOOLCHAIN=go1.27.2 ") != 1 {
		t.Error("named auxiliary compiler must be limited to the three existing Compute checks without auto mode")
	}
	// Current Compute main declares Go 1.27.2. Its source-alignment checks are
	// separate from the released provider's lower library floor/compiler pin.
	for _, name := range []string{"Verify workflow-compute setup runtime surface", "Check workflow-compute provider alignment"} {
		t.Run(name, func(t *testing.T) {
			start := strings.Index(config, "      - name: "+name+"\n")
			if start < 0 {
				t.Fatal("existing auxiliary check missing")
			}
			step := config[start+1:]
			if next := strings.Index(step, "\n      - "); next >= 0 {
				step = step[:next]
			}
			if !strings.Contains(step, "        env:\n          GOTOOLCHAIN: go1.27.2\n") {
				t.Error("auxiliary Compute check must select its own exact named compiler without auto mode")
			}
		})
	}
	if !strings.Contains(config, "compat_output=\"$(cd workflow-compute && \"${timeout_prefix[@]}\" env GOTOOLCHAIN=go1.27.2 GOWORK=off go run ./cmd/compute") {
		t.Error("compatibility probe must select the auxiliary compiler only at its go invocation")
	}
}
