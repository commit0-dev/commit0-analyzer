// Package telemetry provides lightweight phase timing for the scan pipeline.
// All output goes to stderr and is gated on COMMIT0_DEBUG or COMMIT0_TELEMETRY env vars
// so normal runs are completely unaffected.
package telemetry

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// out is the writer for telemetry lines. Overridable in tests.
var out io.Writer = os.Stderr

// Enabled returns true when COMMIT0_DEBUG or COMMIT0_TELEMETRY is set to a truthy
// value: "1", "true", or "yes" (case-insensitive).
func Enabled() bool {
	return isTruthy(os.Getenv("COMMIT0_DEBUG")) || isTruthy(os.Getenv("COMMIT0_TELEMETRY"))
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// Span starts a named phase timer. The caller must invoke the returned stop
// function (typically via defer) to record the elapsed time.
// When telemetry is disabled the returned function is a no-op and no allocation
// of a timer is made beyond the closure itself.
func Span(name string) func() {
	if !Enabled() {
		return func() {}
	}
	start := time.Now()
	return func() {
		ms := time.Since(start).Milliseconds()
		_, _ = fmt.Fprintf(out, "telemetry: phase=%s ms=%d\n", name, ms)
	}
}
