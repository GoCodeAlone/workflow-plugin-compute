package internal

import "testing"

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
