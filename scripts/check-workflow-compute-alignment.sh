#!/usr/bin/env bash
set -euo pipefail
export LANG=C
export LC_ALL=C

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPUTE_DIR="${WORKFLOW_COMPUTE_DIR:-${1:-}}"

if [[ -z "$COMPUTE_DIR" ]]; then
  for candidate in "$ROOT_DIR/../workflow-compute" "$ROOT_DIR/../workflow-compute-salvage-audit"; do
    if [[ -f "$candidate/go.mod" ]]; then
      COMPUTE_DIR="$candidate"
      break
    fi
  done
fi

if [[ -z "$COMPUTE_DIR" || ! -f "$COMPUTE_DIR/go.mod" ]]; then
  echo "workflow-compute checkout not found; pass path as arg or set WORKFLOW_COMPUTE_DIR" >&2
  exit 2
fi
COMPUTE_DIR="$(cd "$COMPUTE_DIR" && pwd)"

tmp="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT

mkdir -p "$tmp/plugin"
tar -C "$ROOT_DIR" \
  --exclude .git \
  --exclude workflow-compute \
  --exclude workflow-compute-salvage-audit \
  -cf - . | tar -C "$tmp/plugin" -xf -
cd "$tmp/plugin"

go mod edit -replace "github.com/GoCodeAlone/workflow-compute=$COMPUTE_DIR"
GOWORK=off go mod tidy
GOWORK=off go test ./internal -run 'Test(ModuleTypes|PluginManifestModuleTypesMatchRuntime|ProviderCatalog)' -count=1
