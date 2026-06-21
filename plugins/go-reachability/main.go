package main

import (
	"context"
	"fmt"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
	anstplugin "github.com/ducthinh993/anst-analyzer/pkg/plugin"
	engine "github.com/ducthinh993/anst-analyzer/plugins/go-reachability/internal/engine"
)

// grpcServer implements anstv1.AnalyzerServer by delegating to the engine.
type grpcServer struct {
	anstv1.UnimplementedAnalyzerServer
	builder engine.GraphBuilder // nil → DefaultGraphBuilder (VTA)
}

// Metadata returns plugin identity and protocol version for the host handshake.
func (s *grpcServer) Metadata(
	_ context.Context,
	_ *anstv1.MetadataRequest,
) (*anstv1.MetadataResponse, error) {
	return &anstv1.MetadataResponse{
		Name:               "go-reachability",
		Version:            "0.1.0",
		ProtocolVersion:    "0.1",
		Description:        "Go SCA reachability analyzer: SSA + VTA call graph, symbol-level confidence tiers.",
		SupportedLanguages: []string{"go"},
	}, nil
}

// Analyze runs the reachability engine and streams findings to the host.
func (s *grpcServer) Analyze(
	req *anstv1.AnalyzeRequest,
	stream anstv1.Analyzer_AnalyzeServer,
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
