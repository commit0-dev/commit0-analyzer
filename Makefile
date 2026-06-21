.PHONY: generate build test lint vet tidy clean

# Export GOPATH/bin so protoc-gen-go and protoc-gen-go-grpc are found.
GOPATH_BIN := $(shell go env GOPATH)/bin
export PATH := $(PATH):$(GOPATH_BIN)

## generate: regenerate protobuf/gRPC Go stubs from proto/anst/v1/plugin.proto
generate:
	buf generate

## build: compile all packages
build:
	go build ./...

## test: run all tests
test:
	go test ./...

## lint: run golangci-lint (falls back to go vet if golangci-lint is not installed)
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint not found, falling back to go vet"; \
		go vet ./...; \
	fi

## vet: run go vet
vet:
	go vet ./...

## tidy: tidy module dependencies
tidy:
	go mod tidy

## clean: remove build artifacts
clean:
	rm -f anst-analyzer
