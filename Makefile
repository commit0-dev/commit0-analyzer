.PHONY: generate build test lint vet tidy clean hooks build-js-plugin test-js

# Export GOPATH/bin so protoc-gen-go and protoc-gen-go-grpc are found.
GOPATH_BIN := $(shell go env GOPATH)/bin
export PATH := $(PATH):$(GOPATH_BIN)

## generate: regenerate protobuf/gRPC stubs (Go + TypeScript) from proto/commit0/v1/plugin.proto
generate:
	buf generate
	buf generate --template buf.gen.js.yaml

## build: compile all packages (Go + JS plugin)
build: build-js-plugin
	go build ./...

## build-js-plugin: compile the JS reachability plugin binary via Bun
## Requires Bun on PATH (https://bun.sh). Skips with a warning if Bun is absent.
##
## Sidecar naming: the Go host calls jsSidecarName() which uses runtime.GOOS and
## runtime.GOARCH (e.g. "darwin-arm64", "linux-amd64"). Node/npm uses different
## arch names on some platforms (e.g. "x64" for "amd64", "-gnu"/"-msvc" suffixes).
## The placement step below maps from the oxc-parser npm binding filename
## (parser.<node-platform>-<node-arch>[...].node) to the Go naming convention
## (parser.<GOOS>-<GOARCH>.node) so the host can find the sidecar deterministically.
##
## Current mapping in use (darwin-arm64 is consistent between Go and npm):
##   @oxc-parser/binding-darwin-arm64 → parser.darwin-arm64.node  (Go: darwin/arm64)
##
## Cross-platform naming reconciliation (Go "amd64" vs npm "x64", Linux "-gnu"/"-musl"
## suffixes, Windows "-msvc" suffix) is deferred to Phase 7 as a CI matrix concern.
## When adding support for additional platforms, extend the mapping below rather than
## using npm/node platform detection, so the output filename always matches Go naming.
build-js-plugin:
	@if command -v bun >/dev/null 2>&1; then \
		echo "Building js-reachability plugin..."; \
		(cd plugins/js-reachability && bun install && bun build src/main.ts --compile --outfile dist/commit0-js-reachability); \
		echo "Placing oxc sidecar..."; \
		mkdir -p plugins/js-reachability/dist/oxc-binding; \
		GOOS=$$(go env GOOS); \
		GOARCH=$$(go env GOARCH); \
		GO_PLATFORM="$$GOOS-$$GOARCH"; \
		NODE_PLATFORM=$$(node -e " \
		  const p=process.platform, a=process.arch; \
		  const sfx = p==='linux' ? '-gnu' : p==='win32' ? '-msvc' : ''; \
		  const na = a==='x64' ? 'x64' : a; \
		  console.log(p+'-'+na+sfx)"); \
		SRC="plugins/js-reachability/node_modules/@oxc-parser/binding-$$NODE_PLATFORM/parser.$$NODE_PLATFORM.node"; \
		DST="plugins/js-reachability/dist/oxc-binding/parser.$$GO_PLATFORM.node"; \
		if [ -f "$$SRC" ]; then \
			cp "$$SRC" "$$DST"; \
			echo "Sidecar placed: $$SRC -> $$DST"; \
		else \
			echo "WARNING: oxc sidecar not found at $$SRC (run 'bun install' in plugins/js-reachability)"; \
			exit 1; \
		fi; \
	else \
		echo "WARNING: bun not found; skipping build-js-plugin. Install Bun (https://bun.sh) to build the JS plugin."; \
	fi

## test: run all tests (Go + JS if Node is present)
test: test-js
	go test ./...

## test-js: run JS plugin unit tests via vitest (skips with warning if Node absent)
test-js:
	@if command -v node >/dev/null 2>&1; then \
		echo "Running JS plugin tests..."; \
		cd plugins/js-reachability && npm install --silent && npx vitest run; \
	else \
		echo "WARNING: node not found; skipping JS plugin tests."; \
	fi

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
	rm -f commit0-analyzer

## hooks: install git hooks via lefthook (run once after cloning)
hooks:
	lefthook install
