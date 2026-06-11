package internal

import (
	"encoding/json"
	"os"
	"testing"
)

func TestManifest(t *testing.T) {
	plugin := NewPlugin()
	manifest := plugin.Manifest()
	if manifest.Name != "workflow-plugin-compute" {
		t.Fatalf("name: got %q", manifest.Name)
	}
	if manifest.Version == "" {
		t.Fatal("version is required")
	}
	if manifest.Author != "GoCodeAlone" {
		t.Fatalf("author: got %q", manifest.Author)
	}
}

func TestT6_PluginManifestDeclaresComputeCLI(t *testing.T) {
	data, err := os.ReadFile("../plugin.json")
	if err != nil {
		t.Fatalf("read plugin.json: %v", err)
	}
	var manifest struct {
		Capabilities struct {
			CLICommands []struct {
				Name string `json:"name"`
			} `json:"cliCommands"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode plugin.json: %v", err)
	}
	if len(manifest.Capabilities.CLICommands) != 1 || manifest.Capabilities.CLICommands[0].Name != "compute" {
		t.Fatalf("cli commands: got %+v", manifest.Capabilities.CLICommands)
	}
}

func TestT545_PluginManifestDeclaresManagedRuntimeDependencies(t *testing.T) {
	data, err := os.ReadFile("../plugin.json")
	if err != nil {
		t.Fatalf("read plugin.json: %v", err)
	}
	var manifest struct {
		Dependencies []struct {
			Name       string `json:"name"`
			Constraint string `json:"constraint"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode plugin.json: %v", err)
	}
	want := map[string]string{
		"workflow-plugin-compute-core":      ">=0.6.0",
		"workflow-plugin-compute-container": ">=0.4.0",
	}
	for _, dependency := range manifest.Dependencies {
		if _, ok := want[dependency.Name]; !ok {
			continue
		}
		if dependency.Constraint != want[dependency.Name] {
			t.Fatalf("%s constraint = %q, want %q", dependency.Name, dependency.Constraint, want[dependency.Name])
		}
		delete(want, dependency.Name)
	}
	if len(want) != 0 {
		t.Fatalf("missing managed runtime dependencies: %+v", want)
	}
}
