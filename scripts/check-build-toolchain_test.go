package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
)

func TestCompilerSelection(t *testing.T) {
	for _, tc := range []struct {
		name, version, mode string
		ok                  bool
	}{
		{"pinned", "go1.27.4", "local", true},
		{"old-patch", "go1.26.3", "local", false},
		{"previous-patch", "go1.27.3", "local", false},
		{"legacy-build", "go1.26.11", "local", false},
		{"legacy-auxiliary", "go1.27.2", "local", false},
		{"other-minor", "go1.28.0", "local", false},
		{"development", "devel go1.27.4", "local", false},
		{"auto", "go1.27.4", "auto", false},
		{"unset", "go1.27.4", "", false},
		{"explicit-switch", "go1.27.4", "go1.27.4", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkCompiler(tc.version, tc.mode); (err == nil) != tc.ok {
				t.Fatalf("checkCompiler = %v; want success=%v", err, tc.ok)
			}
		})
	}
}

func TestArtifactBuildInfoPolicy(t *testing.T) {
	for _, tc := range []struct {
		name, version, path, module string
		ok                          bool
	}{
		{"pinned-plugin", "go1.27.4", pluginMain, pluginModule, true},
		{"old-compiler", "go1.26.3", pluginMain, pluginModule, false},
		{"previous-patch", "go1.27.3", pluginMain, pluginModule, false},
		{"legacy-build", "go1.26.11", pluginMain, pluginModule, false},
		{"legacy-auxiliary", "go1.27.2", pluginMain, pluginModule, false},
		{"other-minor", "go1.28.0", pluginMain, pluginModule, false},
		{"development", "devel go1.27.4", pluginMain, pluginModule, false},
		{"other-command", "go1.27.4", pluginModule + "/cmd/other", pluginModule, false},
		{"missing-main", "go1.27.4", "", pluginModule, false},
		{"other-module", "go1.27.4", pluginMain, "example.invalid/other", false},
		{"missing-module", "go1.27.4", pluginMain, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			info := &debug.BuildInfo{GoVersion: tc.version, Path: tc.path, Main: debug.Module{Path: tc.module}}
			if err := checkBuildInfo(info); (err == nil) != tc.ok {
				t.Fatalf("checkBuildInfo = %v; want success=%v", err, tc.ok)
			}
		})
	}
}

func TestArtifactReadRefusals(t *testing.T) {
	dir := t.TempDir()
	text := filepath.Join(dir, "not-a-binary")
	if err := os.WriteFile(text, []byte("inert fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(text, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{"missing": filepath.Join(dir, "absent"), "directory": dir, "non-Go": text, "symlink": link} {
		t.Run(name, func(t *testing.T) {
			if _, err := inspectArtifact(path); err == nil {
				t.Fatal("invalid artifact accepted")
			}
		})
	}
}

func TestCheckerOutput(t *testing.T) {
	t.Setenv("GOTOOLCHAIN", "local")
	var out bytes.Buffer
	// Library consumers may use the lower go.mod floor; the build checker must
	// refuse that compiler rather than making the library tests depend on it.
	if runtime.Version() != buildCompiler {
		if err := run(nil, &out); err == nil || out.Len() != 0 {
			t.Fatalf("non-build compiler accepted: %q; %v", out.String(), err)
		}
		return
	}
	if err := run(nil, &out); err != nil {
		t.Fatal(err)
	}
	var got report
	if err := json.Unmarshal(out.Bytes(), &got); err != nil || got.Compiler != "go1.27.4" || got.Artifact != nil {
		t.Fatalf("unexpected compiler report: %s; %v", out.String(), err)
	}
	for _, args := range [][]string{{"missing-artifact"}, {"one", "two"}} {
		out.Reset()
		if err := run(args, &out); err == nil || out.Len() != 0 {
			t.Fatalf("failed check emitted success output: %q; %v", out.String(), err)
		}
	}
	t.Setenv("GOTOOLCHAIN", "auto")
	out.Reset()
	if err := run(nil, &out); err == nil || out.Len() != 0 {
		t.Fatalf("automatic switching accepted: %q; %v", out.String(), err)
	}
}

type failingWriter struct{}

var errOutput = errors.New("inert output failure")

func (failingWriter) Write([]byte) (int, error) { return 0, errOutput }

func TestCheckerOutputError(t *testing.T) {
	t.Setenv("GOTOOLCHAIN", "local")
	err := run(nil, failingWriter{})
	if runtime.Version() != buildCompiler {
		if err == nil || errors.Is(err, errOutput) {
			t.Fatalf("compiler refusal must precede output: %v", err)
		}
		return
	}
	if !errors.Is(err, errOutput) {
		t.Fatalf("output error lost: %v", err)
	}
}
