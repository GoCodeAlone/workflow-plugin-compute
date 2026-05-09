// Command workflow-plugin-compute runs the Workflow external plugin adapter for
// workflow-compute.
package main

import (
	"github.com/GoCodeAlone/workflow-plugin-compute/internal"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func main() {
	sdk.Serve(internal.NewPlugin())
}
