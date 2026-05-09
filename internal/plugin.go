package internal

import (
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

var Version = "dev"

type computePlugin struct{}

func NewPlugin() sdk.PluginProvider {
	return &computePlugin{}
}

func (p *computePlugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-compute",
		Version:     Version,
		Author:      "GoCodeAlone",
		Description: "Workflow adapter for workflow-compute dispatch, wait, map, provider, and pool integration",
	}
}

func (p *computePlugin) ModuleTypes() []string {
	return []string{
		"compute.provider",
		"compute.pool",
	}
}

func (p *computePlugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	switch typeName {
	case "compute.provider":
		return newProviderModule(name, config)
	case "compute.pool":
		return newPoolModule(name, config)
	default:
		return nil, fmt.Errorf("compute plugin: unknown module type %q", typeName)
	}
}

func (p *computePlugin) ModuleSchemas() []sdk.ModuleSchemaData {
	return []sdk.ModuleSchemaData{
		providerModuleSchema(),
		poolModuleSchema(),
	}
}
