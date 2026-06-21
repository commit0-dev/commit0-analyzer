package policy

import "fmt"

// Exit code constants for the policy gate.
//
// Contract (Red Team #8):
//   - 0: clean pass — all findings within policy thresholds, scan complete.
//   - 1: gate failure — one or more findings exceed the configured threshold.
//   - 3: operational error — incomplete scan, crash, or unrecoverable host error.
//
// Code 2 is intentionally absent: it is reserved by Go's runtime for panic exits
// and would collide with govulncheck's own exit code. Never use 2.
const (
	// ExitPass indicates all findings are within policy thresholds and the scan completed.
	ExitPass = 0
	// ExitGateFailure indicates one or more findings exceeded the configured threshold.
	ExitGateFailure = 1
	// ExitOperationalError indicates an incomplete scan, crash, or unrecoverable error.
	// Always 3 — never 2, which is reserved by Go's panic exit.
	ExitOperationalError = 3
)

// RunWithRecovery wraps fn in a deferred recover so that any panic inside fn
// is caught and mapped to ExitOperationalError (3) rather than crashing the
// process with Go's runtime exit code 2.
//
// This is the fail-closed contract: a panicking (incomplete) scan MUST NOT
// produce exit code 0 (which would signal a clean pass to CI).
//
// Usage in main:
//
//	os.Exit(policy.RunWithRecovery(func() int {
//	    return runScan(ctx, cfg)
//	}))
func RunWithRecovery(fn func() int) (code int) {
	defer func() {
		if r := recover(); r != nil {
			// Log the panic value without importing a logger here; callers may
			// wrap this further with structured logging.
			fmt.Printf("anst-analyzer: panic recovered (exit %d): %v\n", ExitOperationalError, r)
			code = ExitOperationalError
		}
	}()
	return fn()
}
