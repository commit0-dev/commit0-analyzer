// Package host implements the anst-analyzer plugin host.
//
// Responsibilities:
//
//   - Registry (registry.go): explicit allowlist of plugin manifests. Each
//     manifest records the binary path, expected SHA-256 hash, pillar, and
//     supported languages. Conventional-path discovery is intentionally absent
//     (Red Team #7: plugin loading is a trust boundary).
//
//   - Manifest (manifest.go): the unit of plugin configuration: name, exec
//     path, pillar, languages, and SHA-256 hash for SecureConfig pinning.
//
//   - Client (client.go): launches one plugin binary via hashicorp/go-plugin,
//     performs the magic-cookie handshake, optionally verifies the binary hash
//     (SecureConfig), dispenses the anstv1.AnalyzerClient, validates the plugin's
//     declared protocol version against contract.Compatible, and runs a self-test
//     sentinel (non-empty Metadata.Name) to catch lying or broken plugins.
//
//   - Orchestrator (run.go): fans-out AnalyzeRequest to N registered plugins
//     concurrently, drains their server-streaming Finding responses, enforces
//     per-plugin timeouts, and aggregates results in deterministic order (sorted
//     by plugin name). On plugin crash or timeout: kill the OS process (no
//     zombie), drain/close the stream (EPIPE unblocks a stalled writer), and
//     emit a synthetic CONFIDENCE_UNKNOWN Finding so no coverage is silently
//     dropped (plan invariant: unknown ≠ safe).
//
// The host is deliberately thin: it owns plumbing, not analysis logic. All
// reachability reasoning lives in the plugin processes.
//
// Transport validation: this package validates and freezes the transport choice
// (hashicorp/go-plugin + gRPC over stdio). The server-streaming Analyze RPC
// carries findings without protocol-level constraints on stream length. The
// go-plugin layer adds magic-cookie handshake, optional mTLS, and subprocess
// lifecycle management on top of the gRPC channel.
package host
