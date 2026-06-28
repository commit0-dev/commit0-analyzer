package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	hclog "github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"

	"github.com/commit0-dev/commit0-analyzer/pkg/contract"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
	anstplugin "github.com/commit0-dev/commit0-analyzer/pkg/plugin"
)

// PluginClient wraps a launched go-plugin Client together with the dispensed
// commit0v1.AnalyzerClient. Callers issue RPCs through Analyzer() and tear down
// the subprocess through Kill().
type PluginClient struct {
	manifest *Manifest
	raw      *goplugin.Client // manages the OS subprocess
	analyzer commit0v1.AnalyzerClient
}

// Manifest returns the Manifest this client was launched from.
func (pc *PluginClient) Manifest() *Manifest { return pc.manifest }

// Analyzer returns the gRPC client for issuing Metadata / Analyze RPCs.
func (pc *PluginClient) Analyzer() commit0v1.AnalyzerClient { return pc.analyzer }

// Kill terminates the plugin subprocess immediately. go-plugin calls the OS
// kill and waits for the process to be reaped, so no zombie is left behind.
// It is safe to call Kill multiple times.
func (pc *PluginClient) Kill() { pc.raw.Kill() }

// LaunchOptions controls optional behaviour when launching a plugin.
type LaunchOptions struct {
	// SkipHashCheck disables the SHA-256 binary integrity check. This must
	// only be used in tests where the binary is freshly compiled and its hash
	// is not yet known at manifest registration time.
	SkipHashCheck bool
}

// Launch launches the plugin described by m, performs the go-plugin handshake
// (magic cookie + optional binary hash pin), dispenses the gRPC client, and
// validates protocol compatibility.
//
// Security (Red Team #7):
//
//   - Magic cookie: enforced by go-plugin's HandshakeConfig; a binary that does
//     not read COMMIT0_PLUGIN_MAGIC_COOKIE will be rejected before any RPC.
//
//   - Hash pinning: when m.SHA256 != "" and opts.SkipHashCheck == false,
//     VerifyHash is called first to check ALL artifacts (main binary and every
//     AdditionalArtifacts entry such as the napi sidecar). go-plugin's
//     SecureConfig then re-verifies the main binary immediately before exec.
//     Together these close the TOCTOU window and ensure the sidecar is never
//     skipped on the real launch path. Note that in the default self-build flow
//     the manifest hash is computed from the same artifact, so this only guards
//     the TOCTOU window, not supply-chain integrity (see Manifest doc).
//
//   - Protocol compatibility: MetadataResponse.ProtocolVersion is parsed and
//     checked with contract.Compatible. A different MAJOR is always rejected;
//     a higher plugin MINOR than the host MINOR is also rejected.
//
//   - Self-test / sentinel: after a compatible handshake the host requires the
//     plugin's Metadata Name to be non-empty. A plugin returning a zeroed
//     MetadataResponse passes the version check but is treated as broken or
//     lying and is rejected. Version compat alone cannot prove liveness.
func Launch(ctx context.Context, m *Manifest, opts LaunchOptions) (*PluginClient, error) {
	// Verify ALL artifact hashes (main binary + every AdditionalArtifacts entry,
	// e.g. the napi sidecar) before starting the subprocess. This ensures the
	// sidecar check is never bypassed on the real launch path.
	// SkipHashCheck and an empty SHA256 both skip this (test-only escape hatch).
	if !opts.SkipHashCheck && m.SHA256 != "" {
		if err := m.VerifyHash(); err != nil {
			return nil, fmt.Errorf("launch %s: artifact integrity check failed: %w", m.Name, err)
		}
	}

	// Build SecureConfig for binary hash pinning.
	var secureConfig *goplugin.SecureConfig
	if !opts.SkipHashCheck && m.SHA256 != "" {
		checksum, err := hex.DecodeString(m.SHA256)
		if err != nil {
			return nil, fmt.Errorf("launch %s: invalid SHA256 in manifest: %w", m.Name, err)
		}
		secureConfig = &goplugin.SecureConfig{
			Checksum: checksum,
			Hash:     sha256.New(),
		}
	}

	//nolint:gosec // path validated by registry (absolute + not world-writable)
	cmd := exec.CommandContext(ctx, m.ExecPath)

	cfg := &goplugin.ClientConfig{
		HandshakeConfig: anstplugin.HandshakeConfig,
		Plugins:         anstplugin.PluginMap(nil), // nil Impl: client side
		Cmd:             cmd,
		AllowedProtocols: []goplugin.Protocol{
			goplugin.ProtocolGRPC,
		},
		SecureConfig: secureConfig,
		// Suppress go-plugin's internal log noise; tests and callers may wrap
		// with their own logger if structured output is needed.
		Logger: hclog.NewNullLogger(),
	}

	raw := goplugin.NewClient(cfg)

	// Establish the go-plugin managed gRPC transport.
	rpcClient, err := raw.Client()
	if err != nil {
		raw.Kill()
		return nil, fmt.Errorf("launch %s: rpc client: %w", m.Name, err)
	}

	// Dispense the commit0v1.Analyzer interface through the plugin map.
	dispensed, err := rpcClient.Dispense(anstplugin.PluginName)
	if err != nil {
		raw.Kill()
		return nil, fmt.Errorf("launch %s: dispense %q: %w", m.Name, anstplugin.PluginName, err)
	}

	analyzer, ok := dispensed.(commit0v1.AnalyzerClient)
	if !ok {
		raw.Kill()
		return nil, fmt.Errorf(
			"launch %s: dispensed value is not commit0v1.AnalyzerClient (got %T)",
			m.Name, dispensed,
		)
	}

	// ── Handshake step 2: protocol version compatibility ─────────────────────
	meta, err := analyzer.Metadata(ctx, &commit0v1.MetadataRequest{})
	if err != nil {
		raw.Kill()
		return nil, fmt.Errorf("launch %s: Metadata RPC: %w", m.Name, err)
	}

	major, minor, err := parseProtocolVersion(meta.GetProtocolVersion())
	if err != nil {
		raw.Kill()
		return nil, fmt.Errorf("launch %s: parse protocol_version %q: %w",
			m.Name, meta.GetProtocolVersion(), err)
	}

	if !contract.Compatible(major, minor) {
		raw.Kill()
		return nil, fmt.Errorf(
			"launch %s: incompatible protocol version %q "+
				"(host requires major=%d minor<=%d, plugin advertises major=%d minor=%d)",
			m.Name, meta.GetProtocolVersion(),
			contract.ProtocolMajor, contract.ProtocolMinor,
			major, minor,
		)
	}

	// ── Self-test / sentinel (Red Team #7) ───────────────────────────────────
	// An empty Name in MetadataResponse indicates a broken or adversarial
	// plugin that passes the version check but does nothing real.
	if strings.TrimSpace(meta.GetName()) == "" {
		raw.Kill()
		return nil, fmt.Errorf(
			"launch %s: self-test failed: Metadata returned an empty Name "+
				"(possible broken or lying plugin)",
			m.Name,
		)
	}

	return &PluginClient{manifest: m, raw: raw, analyzer: analyzer}, nil
}

// parseProtocolVersion parses a "major.minor" string into (major, minor int).
func parseProtocolVersion(v string) (major, minor int, err error) {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("expected \"major.minor\", got %q", v)
	}
	major, err = strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid major %q: %w", parts[0], err)
	}
	minor, err = strconv.Atoi(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid minor %q: %w", parts[1], err)
	}
	return major, minor, nil
}
