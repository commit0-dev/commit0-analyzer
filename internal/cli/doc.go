// Package cli implements the anst-analyzer command-line interface.
//
// Commands:
//
//	anst-analyzer scan [path]   Run the full reachability SCA pipeline.
//
// The scan command resolves module dependencies, queries the advisory service,
// drives the go-reachability plugin through the host, renders findings, and
// evaluates the policy gate. Exit codes follow policy.ExitPass (0),
// policy.ExitGateFailure (1), and policy.ExitOperationalError (3).
package cli
