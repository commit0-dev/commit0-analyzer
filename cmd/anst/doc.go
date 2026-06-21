// Package main is the entry point for the anst-analyzer CLI binary.
//
// It parses command-line flags, wires together the plugin host, advisory
// resolver, renderers, and policy gate, then drives a scan to completion.
// All scan logic lives in internal/; this package contains only the CLI
// surface and wiring.
package main
