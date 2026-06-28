package main

import (
	"context"
	"fmt"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
	anstplugin "github.com/commit0-dev/commit0-analyzer/pkg/plugin"
	engine "github.com/commit0-dev/commit0-analyzer/plugins/go-reachability/internal/engine"
)

// grpcServer implements commit0v1.AnalyzerServer by delegating to the engine.
type grpcServer struct {
	commit0v1.UnimplementedAnalyzerServer
	builder engine.GraphBuilder // nil → DefaultGraphBuilder (VTA)
}

// Metadata returns plugin identity and protocol version for the host handshake.
func (s *grpcServer) Metadata(
	_ context.Context,
	_ *commit0v1.MetadataRequest,
) (*commit0v1.MetadataResponse, error) {
	return &commit0v1.MetadataResponse{
		Name:               "go-reachability",
		Version:            "0.1.0",
		ProtocolVersion:    "0.1",
		Description:        "Go SCA reachability analyzer: SSA + VTA call graph, symbol-level confidence tiers.",
		SupportedLanguages: []string{"go"},
	}, nil
}

// Analyze runs the reachability engine and streams findings to the host.
func (s *grpcServer) Analyze(
	req *commit0v1.AnalyzeRequest,
	stream commit0v1.Analyzer_AnalyzeServer,
) error {
	findings, err := engine.Analyze(stream.Context(), req, s.builder)
	if err != nil {
		return fmt.Errorf("go-reachability: analyze: %w", err)
	}
	for _, f := range findings {
		if err := stream.Send(f); err != nil {
			return fmt.Errorf("go-reachability: stream.Send: %w", err)
		}
	}
	return nil
}

// main starts the go-reachability plugin using the go-plugin handshake helper.
// The host (internal/host) launches this binary via exec and communicates over
// the go-plugin managed gRPC transport (stdio mux). This replaces the raw TCP
// listener from Phase 4 so the host can drive the plugin through pkg/plugin.Serve.
func main() {
	anstplugin.Serve(&grpcServer{builder: nil})
}
