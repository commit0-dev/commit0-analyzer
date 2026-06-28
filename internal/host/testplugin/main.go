// Command testplugin is a fake commit0-analyzer plugin used exclusively by tests
// in internal/host. It is built by TestMain and exercised via the host.Launch /
// host.Run APIs.
//
// Behaviour is controlled by environment variables so a single binary covers
// all misbehaviour modes without recompilation:
//
//	TESTPLUGIN_MODE (default "normal")
//	  normal      – return the canned Finding set and exit cleanly.
//	  crash       – send one Finding then exit non-zero mid-stream.
//	  hang        – send one Finding then sleep forever (triggers timeout).
//	  incompatible – report ProtocolVersion "99.0" in Metadata (wrong major).
//	  empty       – return empty Name in Metadata (self-test sentinel failure).
//	  lying       – return canned findings but advertise ProtocolVersion "0.0"
//	               (still compatible; verifies self-test doesn't block it).
//
// TESTPLUGIN_STREAM_COUNT (default "3")
//
//	Number of Finding messages to emit in normal / crash / hang modes before
//	the mode-specific action. Useful for backpressure tests (set large value).
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	anstplugin "github.com/commit0-dev/commit0-analyzer/pkg/plugin"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

func main() {
	anstplugin.Serve(&fakeAnalyzer{})
}

// fakeAnalyzer implements commit0v1.AnalyzerServer using env-var-driven modes.
type fakeAnalyzer struct {
	commit0v1.UnimplementedAnalyzerServer
}

func (f *fakeAnalyzer) Metadata(
	_ context.Context,
	_ *commit0v1.MetadataRequest,
) (*commit0v1.MetadataResponse, error) {
	mode := os.Getenv("TESTPLUGIN_MODE")

	switch mode {
	case "incompatible":
		// Advertise a major version the host cannot accept.
		return &commit0v1.MetadataResponse{
			Name:               "testplugin",
			Version:            "0.0.0",
			ProtocolVersion:    "99.0",
			Description:        "fake plugin – incompatible protocol version",
			SupportedLanguages: []string{"go"},
		}, nil

	case "empty":
		// Return an empty Name — triggers the self-test sentinel rejection.
		return &commit0v1.MetadataResponse{
			Name:            "",
			ProtocolVersion: "0.1",
		}, nil

	default:
		// All other modes (normal, crash, hang, lying) use the real version.
		proto := "0.1"
		if mode == "lying" {
			// lying: compatible version, but Analyze will return empty findings.
			// The self-test only checks Name, so this should still pass Launch.
			proto = "0.0"
		}
		return &commit0v1.MetadataResponse{
			Name:    "testplugin",
			Version: "0.0.0",
			// Embed the process PID so tests can assert the child is gone after Kill.
			ProtocolVersion:    proto,
			Description:        fmt.Sprintf("fake plugin mode=%s pid=%d", mode, os.Getpid()),
			SupportedLanguages: []string{"go"},
			// Store PID in properties so the host test can read it via Metadata.
		}, nil
	}
}

func (f *fakeAnalyzer) Analyze(
	req *commit0v1.AnalyzeRequest,
	stream commit0v1.Analyzer_AnalyzeServer,
) error {
	mode := os.Getenv("TESTPLUGIN_MODE")

	count := streamCount()

	switch mode {
	case "crash":
		// Send one finding then crash hard.
		_ = stream.Send(cannedFinding(0))
		os.Exit(1) // simulate plugin crash mid-stream

	case "hang":
		// Send one finding then block forever.
		_ = stream.Send(cannedFinding(0))
		// Block until the context is cancelled (host timeout).
		<-stream.Context().Done()
		return stream.Context().Err()

	case "empty", "incompatible":
		// These modes are rejected at Metadata time; Analyze should not be
		// reached. Return immediately with no findings if it somehow is.
		return nil

	case "lying":
		// Return no findings at all despite being otherwise functional.
		// The self-test in Launch only checks Metadata.Name, so lying plugins
		// that advertise a compatible version and a non-empty Name will pass
		// Launch and receive an Analyze call — they just emit nothing.
		return nil

	default: // "normal" and unset
		for i := 0; i < count; i++ {
			if err := stream.Send(cannedFinding(i)); err != nil {
				return err
			}
		}
		return nil
	}

	return nil //nolint:govet // unreachable after os.Exit in crash branch
}

// cannedFinding returns a deterministic Finding for index i.
// Tests assert on the specific advisory ID to verify deterministic aggregation.
func cannedFinding(i int) *commit0v1.Finding {
	return &commit0v1.Finding{
		Advisory: &commit0v1.AdvisoryRef{
			Id:  fmt.Sprintf("GO-TEST-%04d", i),
			Url: "https://example.com/vuln",
		},
		Module:     "example.com/testmod",
		Confidence: commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		Severity:   commit0v1.Severity_SEVERITY_HIGH,
		Properties: map[string]string{
			"pid":   strconv.Itoa(os.Getpid()),
			"index": strconv.Itoa(i),
		},
	}
}

// streamCount reads TESTPLUGIN_STREAM_COUNT, defaulting to 3.
func streamCount() int {
	s := os.Getenv("TESTPLUGIN_STREAM_COUNT")
	if s == "" {
		return 3
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return 3
	}
	return n
}

// ensure time import used (hang mode uses it indirectly via context; keep
// explicit import to avoid removal by goimports on platforms where the
// context done channel is always sufficient).
var _ = time.Second
