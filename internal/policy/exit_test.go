package policy_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/commit0-dev/commit0-analyzer/internal/policy"
)

// TestExitCodes_Values verifies the numeric values of each exit code constant
// match the documented contract: 0=pass, 1=gate failure, 3=operational error.
// Code 2 is intentionally absent (reserved by Go's panic exit).
func TestExitCodes_Values(t *testing.T) {
	assert.Equal(t, 0, policy.ExitPass, "ExitPass must be 0")
	assert.Equal(t, 1, policy.ExitGateFailure, "ExitGateFailure must be 1")
	assert.Equal(t, 3, policy.ExitOperationalError, "ExitOperationalError must be 3 (NOT 2, reserved by Go panic)")
	// Confirm 2 is not used as any named constant.
	assert.NotEqual(t, 2, policy.ExitPass)
	assert.NotEqual(t, 2, policy.ExitGateFailure)
	assert.NotEqual(t, 2, policy.ExitOperationalError)
}

// TestRunWithRecovery_PanicMapsToCode3 verifies that a panic in the scan function
// is caught by RunWithRecovery and mapped to exit code 3 (fail-closed).
// A panic must NEVER produce exit code 0 (which would signal a clean pass).
func TestRunWithRecovery_PanicMapsToCode3(t *testing.T) {
	code := policy.RunWithRecovery(func() int {
		panic("simulated scan failure")
	})
	assert.Equal(t, policy.ExitOperationalError, code,
		"a panic in the scan fn must map to ExitOperationalError (3), not 0 or 1")
	assert.NotEqual(t, policy.ExitPass, code,
		"a panic must NEVER produce exit code 0 (would read as clean pass)")
}

// TestRunWithRecovery_NormalReturn_PassThrough verifies that a non-panicking
// function has its return value passed through unchanged.
func TestRunWithRecovery_NormalReturn_PassThrough(t *testing.T) {
	for _, want := range []int{policy.ExitPass, policy.ExitGateFailure, policy.ExitOperationalError} {
		got := policy.RunWithRecovery(func() int { return want })
		assert.Equal(t, want, got, "non-panicking fn return value must pass through unchanged")
	}
}

// TestRunWithRecovery_PanicWithError verifies that a panic with an error value
// (not a string) is also caught and maps to exit code 3.
func TestRunWithRecovery_PanicWithError(t *testing.T) {
	code := policy.RunWithRecovery(func() int {
		panic(errors.New("structured error panic"))
	})
	assert.Equal(t, policy.ExitOperationalError, code,
		"panic with error value must also map to ExitOperationalError")
}

// TestRunWithRecovery_PanicWithNil verifies that even a nil panic maps to code 3.
func TestRunWithRecovery_PanicWithNil(t *testing.T) {
	code := policy.RunWithRecovery(func() int {
		panic(nil) //nolint:govet // intentional nil panic for test coverage
	})
	assert.Equal(t, policy.ExitOperationalError, code,
		"nil panic must also map to ExitOperationalError (fail closed)")
}

// TestExitCode_IncompleteScan_NeverZero verifies the incomplete-scan fail-closed
// contract at the exit-code level: any incomplete scan must produce code 3, not 0.
func TestExitCode_IncompleteScan_NeverZero(t *testing.T) {
	// Simulate a scan that reports no gate-failing findings but is incomplete.
	p := &policy.Policy{
		FailOn:       "high",
		ReachableOnly: false,
	}
	// Empty findings + incomplete flag → must exit 3, not 0.
	code := p.EvaluateWithFlags(nil, policy.EvalFlags{Incomplete: true})
	require.NotEqual(t, policy.ExitPass, code,
		"incomplete scan with no findings must not exit 0")
	assert.Equal(t, policy.ExitOperationalError, code,
		"incomplete scan must exit ExitOperationalError (3)")
}

// TestExitCode_CompleteCleanScan_ExitsZero verifies the positive path:
// a complete scan with no gate-failing findings exits 0.
func TestExitCode_CompleteCleanScan_ExitsZero(t *testing.T) {
	p := &policy.Policy{
		FailOn:       "high",
		ReachableOnly: false,
	}
	code := p.EvaluateWithFlags(nil, policy.EvalFlags{Incomplete: false})
	assert.Equal(t, policy.ExitPass, code,
		"complete scan with no failing findings must exit 0")
}
