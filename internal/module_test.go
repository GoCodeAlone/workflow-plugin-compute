package internal

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	coreprotocol "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func TestModuleTypes(t *testing.T) {
	modules, ok := NewPlugin().(sdk.ModuleProvider)
	if !ok {
		t.Fatal("plugin must implement ModuleProvider")
	}
	got := modules.ModuleTypes()
	if len(got) != 3 || got[0] != "compute.provider" || got[1] != "compute.pool" || got[2] != "compute.provider_catalog" {
		t.Fatalf("module types: got %#v", got)
	}
}

func TestPluginManifestModuleTypesMatchRuntime(t *testing.T) {
	modules := NewPlugin().(sdk.ModuleProvider)
	data, err := os.ReadFile("../plugin.json")
	if err != nil {
		t.Fatalf("read plugin.json: %v", err)
	}
	var manifest struct {
		Capabilities struct {
			ModuleTypes []string `json:"moduleTypes"`
		} `json:"capabilities"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode plugin.json: %v", err)
	}
	if strings.Join(manifest.Capabilities.ModuleTypes, ",") != strings.Join(modules.ModuleTypes(), ",") {
		t.Fatalf("manifest module types %v do not match runtime %v", manifest.Capabilities.ModuleTypes, modules.ModuleTypes())
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
	if len(got) != 3 {
		t.Fatalf("schema count: got %d", len(got))
	}
	if got[0].Type != "compute.provider" || got[1].Type != "compute.pool" || got[2].Type != "compute.provider_catalog" {
		t.Fatalf("schemas: got %#v", got)
	}
}

func TestProviderCatalogUsesComputeCoreProviderContracts(t *testing.T) {
	contract := validProviderContract()
	raw := map[string]any{
		"contracts": []any{toMap(t, contract)},
	}
	module, err := newProviderCatalogModule("catalog", raw)
	if err != nil {
		t.Fatalf("newProviderCatalogModule: %v", err)
	}
	if got := module.config.Contracts[0]; got.PluginID != "workflow-plugin-compute" || got.ProviderID != "workflow-compute-control-plane" {
		t.Fatalf("contract tuple: got plugin=%q provider=%q", got.PluginID, got.ProviderID)
	}
}

func TestProviderCatalogRejectsLegacyGroupedProviderDetails(t *testing.T) {
	_, err := newProviderCatalogModule("catalog", map[string]any{
		"executor_providers": []any{map[string]any{
			"name":           "command",
			"type":           "command",
			"workload_kinds": []any{"command"},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "executor_providers") {
		t.Fatalf("expected strict rejection for legacy grouped provider details, got %v", err)
	}
}

func TestProviderCatalogRejectsMalformedComputeCoreContract(t *testing.T) {
	contract := validProviderContract()
	contract.ConfigSchemaDigest = "sha256:not-hex"
	_, err := newProviderCatalogModule("catalog", map[string]any{
		"contracts": []any{toMap(t, contract)},
	})
	if err == nil || !strings.Contains(err.Error(), "config_schema_digest") {
		t.Fatalf("expected ProviderContract validation error, got %v", err)
	}
}

func TestProviderCatalogAcceptsRuntimeProfileResiduePolicy(t *testing.T) {
	contract := validProviderContract()
	contract.RuntimeContract.Profiles[0].HostWorkspaceSupported = true
	contract.RuntimeContract.Profiles[0].ResiduePolicy = coreprotocol.ResiduePolicy{
		Mode:          coreprotocol.ResidueModeProviderBound,
		AllowedModes:  []coreprotocol.ResidueMode{coreprotocol.ResidueModeIsolated, coreprotocol.ResidueModeProviderBound},
		MaxAgeSeconds: 600,
		WipeOnFailure: true,
	}
	module, err := newProviderCatalogModule("catalog", map[string]any{
		"contracts": []any{toMap(t, contract)},
	})
	if err != nil {
		t.Fatalf("newProviderCatalogModule: %v", err)
	}
	if module.config.Contracts[0].RuntimeContract.Profiles[0].ResiduePolicy.Mode != coreprotocol.ResidueModeProviderBound {
		t.Fatalf("residue policy not decoded: %+v", module.config.Contracts[0].RuntimeContract.Profiles[0].ResiduePolicy)
	}
}

func TestProviderCatalogRejectsReusableResidueWithoutWorkspace(t *testing.T) {
	contract := validProviderContract()
	contract.RuntimeContract.Profiles[0].HostWorkspaceSupported = false
	contract.RuntimeContract.Profiles[0].ResiduePolicy = coreprotocol.ResiduePolicy{
		Mode:         coreprotocol.ResidueModeProviderBound,
		AllowedModes: []coreprotocol.ResidueMode{coreprotocol.ResidueModeProviderBound},
	}
	_, err := newProviderCatalogModule("catalog", map[string]any{
		"contracts": []any{toMap(t, contract)},
	})
	if err == nil || !strings.Contains(err.Error(), "host workspace") {
		t.Fatalf("expected no-workspace residue validation error, got %v", err)
	}
}

func validProviderContract() coreprotocol.ProviderContract {
	return coreprotocol.ProviderContract{
		ProtocolVersion:        coreprotocol.Version,
		ID:                     "workflow-compute-control-plane-v1",
		PluginID:               "workflow-plugin-compute",
		ProviderID:             "workflow-compute-control-plane",
		ContractID:             "workflow-compute.control-plane.v1",
		Version:                "v1.0.0",
		DisplayName:            "workflow-compute Control Plane",
		ConfigSchemaRef:        "schema://providers/workflow-plugin-compute/workflow-compute-control-plane/v1",
		ConfigSchemaDigest:     "sha256:" + strings.Repeat("b", 64),
		OperatingModes:         []coreprotocol.NetworkOperatingMode{coreprotocol.NetworkModeBatch},
		WorkloadKinds:          []string{string(coreprotocol.WorkloadCommand), string(coreprotocol.WorkloadContainerBuild)},
		ExecutorProviders:      []string{"sandboxed-command"},
		ExecutionSecurityTiers: []coreprotocol.ExecutionSecurityTier{coreprotocol.ExecutionSandboxedContainer},
		ProofTiers:             []coreprotocol.ProofTier{coreprotocol.ProofArtifactHash},
		NetworkModes:           []coreprotocol.NetworkMode{coreprotocol.NetworkModeRelay},
		RuntimeContract: coreprotocol.ProviderRuntimeContract{
			Profiles: []coreprotocol.ProviderRuntimeProfile{{
				ID:                     "sandboxed-command-oci",
				RuntimeProfile:         coreprotocol.RuntimeProfileSandboxedOCI,
				ExecutorProvider:       "sandboxed-command",
				ExecutionSecurityTier:  coreprotocol.ExecutionSandboxedContainer,
				ProofTier:              coreprotocol.ProofArtifactHash,
				AllowedRuntimeTools:    []coreprotocol.ContainerRuntimeTool{coreprotocol.ContainerRuntimePodman, coreprotocol.ContainerRuntimeDocker, coreprotocol.ContainerRuntimeNerdctl},
				ImageDigestRequired:    true,
				RootFSDigestRequired:   true,
				AllowedMountRefs:       []string{"workspace"},
				WritableRootFS:         coreprotocol.RuntimePermissionForbidden,
				Privileged:             coreprotocol.RuntimePermissionForbidden,
				HostNamespaces:         coreprotocol.RuntimePermissionForbidden,
				HostSocket:             coreprotocol.RuntimePermissionForbidden,
				SeccompDisable:         coreprotocol.RuntimePermissionForbidden,
				NoNewPrivilegesDisable: coreprotocol.RuntimePermissionForbidden,
				ConformanceProfiles:    []string{"sandboxed-oci-v1"},
			}},
		},
	}
}

func toMap(t *testing.T, value any) map[string]any {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal value: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode value: %v", err)
	}
	return out
}
