// Run with no arguments to check the selected build compiler, or with one
// artifact path to identify and check its embedded compiler without executing it.
package main

import (
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
)

const (
	buildCompiler = "go1.27.4"
	pluginModule  = "github.com/GoCodeAlone/workflow-plugin-compute"
	pluginMain    = pluginModule + "/cmd/workflow-plugin-compute"
)

type artifactReport struct {
	Path      string           `json:"path"`
	Size      int64            `json:"size"`
	SHA256    string           `json:"sha256"`
	BuildInfo *debug.BuildInfo `json:"build_info"`
}

type report struct {
	Compiler string          `json:"compiler"`
	Artifact *artifactReport `json:"artifact,omitempty"`
}

func checkCompiler(version, mode string) error {
	if mode != "local" {
		return fmt.Errorf("GOTOOLCHAIN must be local")
	}
	if version != buildCompiler {
		return fmt.Errorf("build compiler must be %s; got %s", buildCompiler, version)
	}
	return nil
}

func checkBuildInfo(info *debug.BuildInfo) error {
	if info.GoVersion != buildCompiler || info.Path != pluginMain || info.Main.Path != pluginModule {
		return fmt.Errorf("artifact must be %s built with %s", pluginMain, buildCompiler)
	}
	return nil
}

func inspectArtifact(path string) (*artifactReport, error) {
	stat, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !stat.Mode().IsRegular() {
		return nil, fmt.Errorf("artifact must be a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := buildinfo.Read(f)
	if err != nil {
		return nil, err
	}
	if err := checkBuildInfo(info); err != nil {
		return nil, err
	}
	hash := sha256.New()
	size, err := io.Copy(hash, f)
	if err != nil {
		return nil, err
	}
	return &artifactReport{Path: path, Size: size, SHA256: hex.EncodeToString(hash.Sum(nil)), BuildInfo: info}, nil
}

func run(args []string, out io.Writer) error {
	if err := checkCompiler(runtime.Version(), os.Getenv("GOTOOLCHAIN")); err != nil {
		return err
	}
	if len(args) > 1 {
		return fmt.Errorf("usage: check-build-toolchain [artifact]")
	}
	result := report{Compiler: runtime.Version()}
	if len(args) == 1 {
		var err error
		result.Artifact, err = inspectArtifact(args[0])
		if err != nil {
			return err
		}
	}
	return json.NewEncoder(out).Encode(result)
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "build toolchain:", err)
		os.Exit(1)
	}
}
