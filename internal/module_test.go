package internal

import (
	"strings"
	"testing"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func TestModuleTypes(t *testing.T) {
	modules, ok := NewPlugin().(sdk.ModuleProvider)
	if !ok {
		t.Fatal("plugin must implement ModuleProvider")
	}
	got := modules.ModuleTypes()
	if len(got) != 2 || got[0] != "compute.provider" || got[1] != "compute.pool" {
		t.Fatalf("module types: got %#v", got)
	}
}

func TestProviderModuleStrictConfig(t *testing.T) {
	_, err := newProviderModule("bad", map[string]any{
		"server_url":     "https://compute.example.test",
		"auth_token_ref": "secret:compute-token",
		"unknown":        true,
	})
	if err == nil || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestProviderModuleValidatesRefs(t *testing.T) {
	module, err := newProviderModule("main", map[string]any{
		"server_url":      "https://compute.example.test",
		"auth_token_ref":  "secret:compute-token",
		"request_timeout": "5s",
	})
	if err != nil {
		t.Fatalf("newProviderModule: %v", err)
	}
	if module.config.AuthTokenRef != "secret:compute-token" {
		t.Fatalf("auth token ref: got %q", module.config.AuthTokenRef)
	}
}

func TestProviderModuleRejectsRawToken(t *testing.T) {
	_, err := newProviderModule("main", map[string]any{
		"server_url":     "https://compute.example.test",
		"auth_token_ref": "plain-token-value",
	})
	if err == nil || !strings.Contains(err.Error(), "auth_token_ref") {
		t.Fatalf("expected auth_token_ref error, got %v", err)
	}
}

func TestPoolModuleStrictConfig(t *testing.T) {
	_, err := newPoolModule("pool", map[string]any{
		"provider_ref": "compute-main",
		"org_id":       "org-1",
		"pool_id":      "pool-1",
		"policy_id":    "policy-1",
		"mode":         "private",
		"extra":        "nope",
	})
	if err == nil || !strings.Contains(err.Error(), "extra") {
		t.Fatalf("expected unknown field error, got %v", err)
	}
}

func TestPoolModuleValidatesMode(t *testing.T) {
	_, err := newPoolModule("pool", map[string]any{
		"provider_ref": "compute-main",
		"org_id":       "org-1",
		"pool_id":      "pool-1",
		"policy_id":    "policy-1",
		"mode":         "botnet",
	})
	if err == nil || !strings.Contains(err.Error(), "mode") {
		t.Fatalf("expected mode error, got %v", err)
	}
}

func TestModuleSchemas(t *testing.T) {
	schemas, ok := NewPlugin().(sdk.SchemaProvider)
	if !ok {
		t.Fatal("plugin must implement SchemaProvider")
	}
	got := schemas.ModuleSchemas()
	if len(got) != 2 {
		t.Fatalf("schema count: got %d", len(got))
	}
	if got[0].Type != "compute.provider" || got[1].Type != "compute.pool" {
		t.Fatalf("schemas: got %#v", got)
	}
}
