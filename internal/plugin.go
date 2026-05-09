package internal

import sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"

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
