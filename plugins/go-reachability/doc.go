// Package main implements the Go reachability analyzer plugin for anst-analyzer.
//
// This plugin satisfies the [anstv1.AnalyzerServer] gRPC interface and is
// launched as a child process by the plugin host (internal/host).
//
// Responsibilities:
//   - Accept an [anstv1.AnalyzeRequest] containing a module root, entry points,
//     build config, and pre-resolved advisories.
//   - Build a call graph using go/packages + go/ssa + go/callgraph/vta (VTA on
//     an initial CHA/RTA base graph), chosen for interface-dispatch precision.
//   - For each advisory, walk the call graph from the configured entry points to
//     determine reachability of vulnerable symbols.
//   - Stream [anstv1.Finding] messages back, each with the appropriate
//     Confidence tier (SYMBOL_REACHABLE > PACKAGE_REACHABLE > NOT_REACHABLE >
//     UNKNOWN) and, where SYMBOL_REACHABLE, a populated ReachabilityPath.
//
// Degradation rules (unknown ≠ safe):
//   - Reflection / dynamic dispatch / cgo / plugin.Open → CONFIDENCE_UNKNOWN
//   - Build-config mismatch (module does not compile for GOOS/GOARCH/tags) →
//     CONFIDENCE_UNKNOWN (never NOT_REACHABLE)
//   - IllTyped packages, unresolved symbols → CONFIDENCE_UNKNOWN
//   - No call-graph edge found → CONFIDENCE_NOT_REACHABLE (only when the graph
//     is complete and no edge exists; not when the graph is partial)
//
// The plugin is designed to be standalone-testable without the host (Gate G1):
// tests in this package construct an AnalyzeRequest directly and invoke the
// gRPC handler without a network round-trip.
package main
