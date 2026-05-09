.PHONY: build test validate clean

BINARY_NAME = workflow-plugin-compute

build:
	GOWORK=off GOPRIVATE=github.com/GoCodeAlone/* go build -o bin/$(BINARY_NAME) ./cmd/$(BINARY_NAME)

test:
	GOWORK=off GOPRIVATE=github.com/GoCodeAlone/* go test ./...

validate:
	wfctl validate workflow.yaml
	GOWORK=off wfctl build --config workflow.yaml --no-push --tag local

clean:
	rm -rf bin/
