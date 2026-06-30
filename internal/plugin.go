package internal

import (
	"fmt"

	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

var Version = "0.0.0"

type computePlugin struct{}

func NewPlugin() sdk.PluginProvider {
	return &computePlugin{}
}

func (p *computePlugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-compute",
		Version:     Version,
		Author:      "GoCodeAlone",
		Description: "Workflow adapter for workflow-compute dispatch, wait, map, provider, pool, and setup integration",
	}
}

func (p *computePlugin) ModuleTypes() []string {
	return []string{
		"compute.provider",
		"compute.pool",
		"compute.provider_catalog",
	}
}

func (p *computePlugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	switch typeName {
	case "compute.provider":
		return newProviderModule(name, config)
	case "compute.pool":
		return newPoolModule(name, config)
	case "compute.provider_catalog":
		return newProviderCatalogModule(name, config)
	default:
		return nil, fmt.Errorf("compute plugin: unknown module type %q", typeName)
	}
}

func (p *computePlugin) StepTypes() []string {
	return []string{
		"step.compute_dispatch",
		"step.compute_wait",
		"step.compute_map",
		"step.compute_stream",
	}
}

func (p *computePlugin) CreateStep(typeName, name string, config map[string]any) (sdk.StepInstance, error) {
	switch typeName {
	case "step.compute_dispatch":
		return newDispatchStep(name, config)
	case "step.compute_wait":
		return newWaitStep(name, config)
	case "step.compute_map":
		return newMapStep(name, config)
	case "step.compute_stream":
		return newComputeStreamStep(name, config)
	default:
		return nil, fmt.Errorf("compute plugin: unknown step type %q", typeName)
	}
}

func (p *computePlugin) ModuleSchemas() []sdk.ModuleSchemaData {
	return []sdk.ModuleSchemaData{
		providerModuleSchema(),
		poolModuleSchema(),
		providerCatalogModuleSchema(),
	}
}
