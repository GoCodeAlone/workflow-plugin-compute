package internal

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/GoCodeAlone/workflow-compute/pkg/protocol"
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

func TestProviderCatalogUsesWorkflowComputeProviderContracts(t *testing.T) {
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

func TestProviderCatalogRejectsMalformedWorkflowComputeContract(t *testing.T) {
	contract := validProviderContract()
	contract.ConfigSchemaDigest = "sha256:not-hex"
	_, err := newProviderCatalogModule("catalog", map[string]any{
		"contracts": []any{toMap(t, contract)},
	})
	if err == nil || !strings.Contains(err.Error(), "config_schema_digest") {
		t.Fatalf("expected ProviderContract validation error, got %v", err)
	}
}

func TestEdgeWASMProviderCatalogPresetsAreWorkflowComputeContracts(t *testing.T) {
	contracts := EdgeWASMProviderContracts()
	if len(contracts) != 2 {
		t.Fatalf("edge contract count: got %d", len(contracts))
	}
	seen := map[string]bool{}
	for _, contract := range contracts {
		seen[contract.ProviderID] = true
		if contract.PluginID != "workflow-plugin-compute" {
			t.Fatalf("contract leaked provider plugin: %+v", contract)
		}
		if strings.Contains(strings.ToLower(contract.ID+contract.ProviderID+contract.ContractID), "product-capture") ||
			strings.Contains(strings.ToLower(contract.ID+contract.ProviderID+contract.ContractID), "bmw") {
			t.Fatalf("edge contract leaked product capture/BMW boundary: %+v", contract)
		}
		if len(contract.RuntimeContract.Profiles) != 1 {
			t.Fatalf("runtime profiles: %+v", contract.RuntimeContract.Profiles)
		}
		runtime := contract.RuntimeContract.Profiles[0]
		if runtime.RuntimeProfile != protocol.RuntimeProfileWASMComponent ||
			runtime.ExecutionSecurityTier != protocol.ExecutionWASMCapability ||
			runtime.ExecutorProvider != "wasm-component" ||
			runtime.WASM.ComponentDigest == "" ||
			runtime.WASM.Filesystem != "forbidden" ||
			runtime.WASM.NativeHostUpdates != "forbidden" {
			t.Fatalf("edge runtime contract: %+v", runtime)
		}
	}
	if !seen["edge-lambda"] || !seen["edge-cdn-filter"] {
		t.Fatalf("edge providers missing: %+v", seen)
	}
	module, err := newProviderCatalogModule("edge", map[string]any{
		"contracts": []any{toMap(t, contracts[0]), toMap(t, contracts[1])},
	})
	if err != nil {
		t.Fatalf("newProviderCatalogModule(edge): %v", err)
	}
	if len(module.config.Contracts) != 2 {
		t.Fatalf("module contracts: %+v", module.config.Contracts)
	}
}

func validProviderContract() protocol.ProviderContract {
	return protocol.ProviderContract{
		ProtocolVersion:        protocol.Version,
		ID:                     "workflow-compute-control-plane-v1",
		PluginID:               "workflow-plugin-compute",
		ProviderID:             "workflow-compute-control-plane",
		ContractID:             "workflow-compute.control-plane.v1",
		Version:                "v1.0.0",
		DisplayName:            "workflow-compute Control Plane",
		ConfigSchemaRef:        "schema://providers/workflow-plugin-compute/workflow-compute-control-plane/v1",
		ConfigSchemaDigest:     "sha256:" + strings.Repeat("b", 64),
		OperatingModes:         []protocol.NetworkOperatingMode{protocol.NetworkModeBatch},
		WorkloadKinds:          []string{string(protocol.WorkloadCommand), string(protocol.WorkloadContainerBuild)},
		ExecutorProviders:      []string{"sandboxed-command"},
		ExecutionSecurityTiers: []protocol.ExecutionSecurityTier{protocol.ExecutionSandboxedContainer},
		ProofTiers:             []protocol.ProofTier{protocol.ProofArtifactHash},
		NetworkModes:           []protocol.NetworkMode{protocol.NetworkModeRelay},
		RuntimeContract: protocol.ProviderRuntimeContract{
			Profiles: []protocol.ProviderRuntimeProfile{{
				ID:                     "sandboxed-command-oci",
				RuntimeProfile:         protocol.RuntimeProfileSandboxedOCI,
				ExecutorProvider:       "sandboxed-command",
				ExecutionSecurityTier:  protocol.ExecutionSandboxedContainer,
				ProofTier:              protocol.ProofArtifactHash,
				AllowedRuntimeTools:    []protocol.ContainerRuntimeTool{protocol.ContainerRuntimePodman, protocol.ContainerRuntimeDocker, protocol.ContainerRuntimeNerdctl},
				ImageDigestRequired:    true,
				RootFSDigestRequired:   true,
				AllowedMountRefs:       []string{"workspace"},
				WritableRootFS:         protocol.RuntimePermissionForbidden,
				Privileged:             protocol.RuntimePermissionForbidden,
				HostNamespaces:         protocol.RuntimePermissionForbidden,
				HostSocket:             protocol.RuntimePermissionForbidden,
				SeccompDisable:         protocol.RuntimePermissionForbidden,
				NoNewPrivilegesDisable: protocol.RuntimePermissionForbidden,
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
