package host

import (
	"context"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
)

// RunOptions configures a Run call.
type RunOptions struct {
	// Timeout is the per-plugin deadline for the entire Analyze stream.
	// Zero means no per-plugin timeout (only the parent ctx deadline applies).
	Timeout time.Duration

	// MaxConcurrency caps the number of plugins running simultaneously.
	// Zero or negative means unlimited (all plugins run concurrently).
	MaxConcurrency int

	// LaunchOpts is forwarded to Launch for every plugin.
	LaunchOpts LaunchOptions
}

// PluginResult is the aggregated output from a single plugin.
type PluginResult struct {
	// Manifest is the plugin that produced this result.
	Manifest *Manifest

	// Findings contains every Finding received from the plugin, in the order
	// they arrived over the stream. Deterministic aggregation across plugins is
	// applied by Run after all workers finish.
	Findings []*anstv1.Finding

	// Err is non-nil when the plugin crashed, timed out, or returned a gRPC
	// error. In all error cases a synthetic CONFIDENCE_UNKNOWN Finding is also
	// appended to Findings so no coverage is silently dropped.
	Err error
}

// Run fans-out req to every plugin registered in reg, collects their streaming
// Finding responses, and returns one PluginResult per plugin in deterministic
// order (sorted by plugin Name).
//
// Crash isolation (plan invariant "unknown ≠ safe"):
//   - A plugin that crashes or times out never causes Run to return an error.
//   - Instead, a synthetic CONFIDENCE_UNKNOWN Finding is appended to that
//     plugin's result and Err is set. The caller decides how to handle it.
//
// Timeout / OS process cleanup (Red Team #10):
//   - Each plugin gets its own context derived from ctx with an optional
//     per-plugin timeout (opts.Timeout).
//   - On cancellation or timeout, the plugin stream is drained (or the context
//     error is surfaced) and pc.Kill() is called to terminate the OS process.
//     go-plugin's Kill waits for the process to exit, preventing zombies.
//   - The plugin's stdout pipe is closed by the context cancellation / Kill
//     sequence, so a plugin blocked on a full write buffer gets EPIPE and exits.
func Run(
	ctx context.Context,
	reg *Registry,
	req *anstv1.AnalyzeRequest,
	opts RunOptions,
) ([]*PluginResult, error) {
	manifests := reg.All()
	if len(manifests) == 0 {
		return nil, nil
	}

	concurrency := opts.MaxConcurrency
	if concurrency <= 0 {
		concurrency = len(manifests)
	}

	sem := make(chan struct{}, concurrency)
	results := make([]*PluginResult, len(manifests))

	var wg sync.WaitGroup
	for i, m := range manifests {
		wg.Add(1)
		go func(idx int, manifest *Manifest) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			results[idx] = runPlugin(ctx, manifest, req, opts)
		}(i, m)
	}
	wg.Wait()

	// Deterministic aggregation: sort results by plugin Name so output order
	// is stable regardless of which goroutine finished first.
	sort.Slice(results, func(i, j int) bool {
		return results[i].Manifest.Name < results[j].Manifest.Name
	})

	return results, nil
}

// runPlugin launches a single plugin, streams its findings, and returns a
// PluginResult. It never panics. On any error (launch, crash, timeout) it
// returns a result with Err set and a synthetic UNKNOWN finding appended.
func runPlugin(
	ctx context.Context,
	m *Manifest,
	req *anstv1.AnalyzeRequest,
	opts RunOptions,
) *PluginResult {
	result := &PluginResult{Manifest: m}

	// Build a per-plugin context with optional timeout.
	pluginCtx := ctx
	var cancel context.CancelFunc
	if opts.Timeout > 0 {
		pluginCtx, cancel = context.WithTimeout(ctx, opts.Timeout)
	} else {
		pluginCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	// Launch the plugin subprocess.
	pc, err := Launch(pluginCtx, m, opts.LaunchOpts)
	if err != nil {
		result.Err = fmt.Errorf("plugin %s: launch: %w", m.Name, err)
		result.Findings = append(result.Findings, syntheticUnknown(m, result.Err))
		return result
	}
	// Kill is idempotent; ensures the OS process is reaped even on happy path.
	defer pc.Kill()

	// Open the server-streaming Analyze RPC.
	stream, err := pc.Analyzer().Analyze(pluginCtx, req)
	if err != nil {
		result.Err = fmt.Errorf("plugin %s: Analyze RPC: %w", m.Name, err)
		result.Findings = append(result.Findings, syntheticUnknown(m, result.Err))
		return result
	}

	// Drain the stream. Any error (plugin crash → gRPC status, timeout →
	// context.DeadlineExceeded surfaced as gRPC Canceled/DeadlineExceeded)
	// is treated as a crash: partial findings are kept and a synthetic UNKNOWN
	// is appended so coverage is never silently dropped.
	for {
		f, err := stream.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Partial findings already collected remain; add synthetic marker.
			result.Err = fmt.Errorf("plugin %s: stream recv: %w", m.Name, err)
			result.Findings = append(result.Findings, syntheticUnknown(m, result.Err))
			return result
		}
		result.Findings = append(result.Findings, f)
	}

	return result
}

// syntheticUnknown returns a CONFIDENCE_UNKNOWN Finding that records the crash
// or timeout error as a property. It carries the plugin's name as the module
// field so callers can correlate it with the responsible plugin without parsing
// the error string.
//
// Plan invariant ("unknown ≠ safe"): this finding must be surfaced to the user,
// never suppressed. The CONFIDENCE_UNKNOWN zero value ensures that a downstream
// policy gate that only suppresses NOT_REACHABLE will not accidentally drop it.
func syntheticUnknown(m *Manifest, cause error) *anstv1.Finding {
	return &anstv1.Finding{
		Module:     m.Name,
		Confidence: anstv1.Confidence_CONFIDENCE_UNKNOWN,
		Pillar:     m.Pillar,
		Properties: map[string]string{
			"synthetic": "true",
			"cause":     cause.Error(),
			"plugin":    m.Name,
		},
	}
}
