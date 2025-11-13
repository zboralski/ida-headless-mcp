.PHONY: proto proto-check clean build test run integration-test inspector

# Protobuf generation
proto:
	PATH="$(shell go env GOPATH)/bin:$${PATH}" go generate ./proto/ida/worker/v1

proto-check:
	PATH="$(shell go env GOPATH)/bin:$${PATH}" go generate ./proto/ida/worker/v1
	git diff --exit-code proto ida python/worker/gen

# Build server binary
build: proto
	go build -o bin/ida-mcp-server ./cmd/ida-mcp-server

# Run fast unit tests only (excludes integration tests)
test:
	go test -v ./internal/... ./ida/...
	@./scripts/consistency.sh

# Run all tests including IDA integration tests
test-all:
	go test -v -tags=integration ./...
	@./scripts/consistency.sh

# Run Go integration tests (MCP transports)
integration-test:
	go test ./internal/server -run TestStreamableHTTPTransportLifecycle -v
	go test ./internal/server -run TestSSETransportLifecycle -v

# Run server
run: build
	./bin/ida-mcp-server

# Clean generated files
clean:
	rm -rf ida/worker/v1/*.pb.go
	rm -rf bin/
	find python/worker -name "*.pyc" -delete
	find python/worker -name "__pycache__" -delete

# Install Go tools
install-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@latest

# Install Python dependencies
install-python:
	cd python && pip3 install -r requirements.txt -r requirements-test.txt

# Start MCP Inspector for testing
inspector:
	@./scripts/inspector.sh

.DEFAULT_GOAL := build
