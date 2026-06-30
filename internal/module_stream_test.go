package internal

import (
	"strings"
	"testing"

	coreprotocol "github.com/GoCodeAlone/workflow-plugin-compute-core/protocol"
)

func TestStreamProviderCatalogAcceptsReleasedVideoStreamContract(t *testing.T) {
	contract := validProviderContract()
	contract.ID = "workflow-plugin-stream-mediamtx-v1"
	contract.PluginID = "workflow-plugin-stream"
	contract.ProviderID = "mediamtx"
	contract.ContractID = "stream.mediamtx.v1"
	contract.Version = "v0.1.0"
	contract.DisplayName = "MediaMTX Stream Provider"
	contract.ConfigSchemaRef = "schema://providers/workflow-plugin-stream/mediamtx/v1"
	contract.WorkloadKinds = []string{string(coreprotocol.WorkloadVideoStream)}
	contract.Operations = []coreprotocol.ProviderOperation{{
		ID:                 "start_stream",
		InputSchemaRef:     "schema://providers/workflow-plugin-stream/operations/start_stream/input/v1",
		InputSchemaDigest:  coreprotocol.CanonicalHash(map[string]string{"input": "stream"}),
		OutputSchemaRef:    "schema://providers/workflow-plugin-stream/operations/start_stream/output/v1",
		OutputSchemaDigest: coreprotocol.CanonicalHash(map[string]string{"output": "descriptor"}),
		Artifacts:          []string{"ingest_descriptor"},
	}}

	module, err := newProviderCatalogModule("catalog", map[string]any{
		"contracts": []any{toMap(t, contract)},
	})
	if err != nil {
		t.Fatalf("newProviderCatalogModule: %v", err)
	}
	got := module.config.Contracts[0]
	if got.PluginID != "workflow-plugin-stream" || got.ProviderID != "mediamtx" {
		t.Fatalf("stream contract tuple: got plugin=%q provider=%q", got.PluginID, got.ProviderID)
	}
	if !strings.EqualFold(got.WorkloadKinds[0], string(coreprotocol.WorkloadVideoStream)) || !got.SupportsOperation("start_stream") {
		t.Fatalf("stream contract not decoded: workload_kinds=%v operations=%v", got.WorkloadKinds, got.Operations)
	}
}
