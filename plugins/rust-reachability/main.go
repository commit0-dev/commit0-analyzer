// Command rust-reachability is the anst-analyzer plugin for Rust (crates.io)
// reachability-first SCA. It implements the anstv1.Analyzer gRPC service via
// the shared pkg/plugin.Serve helper, mirroring go-reachability/main.go.
//
// # Transport
//
// The host (internal/host) launches this binary as a subprocess and
// communicates over go-plugin's stdio-multiplexed gRPC transport. This binary
// must NOT write to stdout except through gRPC framing.
//
// # Supported ecosystems
//
// SupportedLanguages: ["rust"]
// Ecosystem:          ECOSYSTEM_CRATES_IO
//
// # Reachability model
//
// Lane A (manifest + advisory-match, no call graph):
//   - Run `cargo metadata --format-version 1 --all-features --offline` to
//     obtain the full resolved dependency closure.
//   - For each advisory, locate the crate in the closure:
//     absent → NOT_REACHABLE (the only condition that earns NOT_REACHABLE).
//     present with undecidable condition (cfg, proc-macro, build.rs) → UNKNOWN.
//     present and decidable → PACKAGE_REACHABLE.
//   - Cargo failure / timeout / partial graph → all advisories → UNKNOWN +
//     Incomplete=true (partiality invariant: unknown ≠ safe).
//
// # Partiality marker
//
// When the cargo closure is incomplete or unavailable, every Finding streamed
// to the host carries Incomplete=true. This is the wire-level partiality
// signal: the host marks the scan incomplete and surfaces it in the policy gate.
package main

import (
	"context"
	"fmt"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
	anstplugin "github.com/ducthinh993/anst-analyzer/pkg/plugin"
	"github.com/ducthinh993/anst-analyzer/plugins/rust-reachability/internal/cargo"
	"github.com/ducthinh993/anst-analyzer/plugins/rust-reachability/internal/engine"
)

// grpcServer implements anstv1.AnalyzerServer for the Rust reachability plugin.
type grpcServer struct {
	anstv1.UnimplementedAnalyzerServer
}

// Metadata returns plugin identity and protocol version for the host handshake.
func (s *grpcServer) Metadata(
	_ context.Context,
	_ *anstv1.MetadataRequest,
) (*anstv1.MetadataResponse, error) {
	return &anstv1.MetadataResponse{
		Name:               "rust-reachability",
		Version:            "0.1.0",
		ProtocolVersion:    "0.1",
		Description:        "Rust SCA reachability analyzer: cargo closure resolution, PACKAGE_REACHABLE confidence tier.",
		SupportedLanguages: []string{"rust"},
	}, nil
}

// Analyze loads the Cargo closure and streams one Finding per advisory to the
// host. When the closure is unavailable, every finding carries Incomplete=true
// (the wire-level partiality marker).
func (s *grpcServer) Analyze(
	req *anstv1.AnalyzeRequest,
	stream anstv1.Analyzer_AnalyzeServer,
) error {
	ctx := stream.Context()

	// Load the cargo closure. On failure, LoadManifest returns a non-nil
	// Manifest with ClosureUnknown=true — the engine degrades gracefully.
	manifest, loadErr := cargo.LoadManifest(ctx, req.GetModuleRoot())
	if loadErr != nil {
		// Log the error in the properties of every degraded finding; the
		// engine handles the UNKNOWN+incomplete emission.
		_ = loadErr // error is encoded in manifest.ClosureError
	}

	a := &engine.Analyzer{
		Manifest:   manifest,
		Advisories: req.GetAdvisories(),
	}

	findings := a.Analyze()
	for _, f := range findings {
		if err := stream.Send(f); err != nil {
			return fmt.Errorf("rust-reachability: stream.Send: %w", err)
		}
	}
	return nil
}

// main starts the rust-reachability plugin using the go-plugin handshake helper.
// The host (internal/host) launches this binary via exec and communicates over
// the go-plugin managed gRPC transport (stdio mux).
func main() {
	anstplugin.Serve(&grpcServer{})
}
