package internal

import (
	"strings"

	"github.com/GoCodeAlone/workflow-compute/pkg/protocol"
)

func EdgeWASMProviderContracts() []protocol.ProviderContract {
	return []protocol.ProviderContract{
		edgeWASMProviderContract(
			"edge-lambda-wasm-v1",
			"Edge Lambda WASM",
			"edge-lambda",
			"edge-lambda.wasm.v1",
			"handle_request",
			"edge_lambda_response",
		),
		edgeWASMProviderContract(
			"edge-cdn-filter-wasm-v1",
			"Edge CDN Filter WASM",
			"edge-cdn-filter",
			"edge-cdn-filter.wasm.v1",
			"filter_request",
			"cdn_decision",
		),
	}
}

func edgeWASMProviderContract(id, displayName, providerID, contractID, operationID, artifactName string) protocol.ProviderContract {
	runtime := protocol.DefaultProviderRuntimeProfile("wasm-component", protocol.ExecutionWASMCapability, protocol.ProofArtifactHash)
	runtime.RuntimeProfile = protocol.RuntimeProfileWASMComponent
	runtime.WASM = protocol.WASMRuntimeContract{
		ABI:               "wasm-export-i32-v1",
		ComponentRef:      "provider://" + providerID + "/component.wasm",
		ComponentDigest:   "sha256:" + strings.Repeat("d", 64),
		Features:          []string{"edge-request-v1"},
		MaxMemoryBytes:    128 << 20,
		MaxRuntimeSeconds: 10,
		Filesystem:        "forbidden",
		Network:           protocol.RuntimePermissionForbidden,
		NativeHostUpdates: "forbidden",
	}
	return protocol.ProviderContract{
		ProtocolVersion:        protocol.Version,
		ID:                     id,
		DisplayName:            displayName,
		PluginID:               "workflow-plugin-compute",
		ProviderID:             providerID,
		ContractID:             contractID,
		Version:                "v1.0.0",
		ConfigSchemaRef:        "schema://providers/workflow-plugin-compute/" + providerID + "/v1",
		ConfigSchemaDigest:     "sha256:" + strings.Repeat("c", 64),
		OperatingModes:         []protocol.NetworkOperatingMode{protocol.NetworkModeBatch},
		WorkloadKinds:          []string{string(protocol.WorkloadProvider), string(protocol.WorkloadWASMComponent)},
		ExecutorProviders:      []string{"wasm-component"},
		ExecutionSecurityTiers: []protocol.ExecutionSecurityTier{protocol.ExecutionWASMCapability},
		ProofTiers:             []protocol.ProofTier{protocol.ProofArtifactHash},
		NetworkModes:           []protocol.NetworkMode{protocol.NetworkModeRelay, protocol.NetworkModeOffline},
		Operations: []protocol.ProviderOperation{{
			ID:                 operationID,
			InputSchemaRef:     "schema://providers/workflow-plugin-compute/" + providerID + "/operations/" + operationID + "/input/v1",
			InputSchemaDigest:  "sha256:" + strings.Repeat("a", 64),
			OutputSchemaRef:    "schema://providers/workflow-plugin-compute/" + providerID + "/operations/" + operationID + "/output/v1",
			OutputSchemaDigest: "sha256:" + strings.Repeat("b", 64),
			Artifacts:          []string{artifactName},
			ArtifactSpecs: []protocol.ProviderArtifactSpec{{
				Name:             artifactName,
				Required:         true,
				ContentType:      "application/json",
				MaxBytes:         1 << 20,
				RetentionSeconds: 3600,
				Forwardable:      true,
			}},
		}},
		RuntimeContract: protocol.ProviderRuntimeContract{Profiles: []protocol.ProviderRuntimeProfile{runtime}},
	}
}
