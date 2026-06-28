package contract_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/commit0-dev/commit0-analyzer/pkg/contract"
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// TestFinding_ConfidenceZeroValue asserts that a freshly-constructed Finding
// has Confidence == CONFIDENCE_UNKNOWN (the proto3 zero value), not
// CONFIDENCE_NOT_REACHABLE. This guards against silent suppression: the safe
// default must be "unknown", not "not reachable".
func TestFinding_ConfidenceZeroValue(t *testing.T) {
	f := &commit0v1.Finding{}
	assert.Equal(t, commit0v1.Confidence_CONFIDENCE_UNKNOWN, f.Confidence,
		"zero-value Finding must have CONFIDENCE_UNKNOWN, not CONFIDENCE_NOT_REACHABLE")
	assert.NotEqual(t, commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE, f.Confidence,
		"zero-value Confidence must NOT be CONFIDENCE_NOT_REACHABLE")
}

// TestFinding_ConfidenceUnknownIsZero asserts that CONFIDENCE_UNKNOWN == 0
// at the protobuf enum level.
func TestFinding_ConfidenceUnknownIsZero(t *testing.T) {
	assert.Equal(t, int32(0), int32(commit0v1.Confidence_CONFIDENCE_UNKNOWN),
		"CONFIDENCE_UNKNOWN must be enum value 0 (proto3 zero/default)")
	assert.NotEqual(t, int32(0), int32(commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE),
		"CONFIDENCE_NOT_REACHABLE must NOT be 0")
}

// TestFinding_IsSuppressible_UnknownReturnsFalse asserts the contract helper:
// a Finding with CONFIDENCE_UNKNOWN must not be suppressed.
func TestFinding_IsSuppressible_UnknownReturnsFalse(t *testing.T) {
	f := &commit0v1.Finding{Confidence: commit0v1.Confidence_CONFIDENCE_UNKNOWN}
	w := contract.WrapFinding(f)
	assert.False(t, w.IsSuppressible(),
		"UNKNOWN confidence must not be suppressible")
}

// TestFinding_IsSuppressible_OnlyNotReachableIsTrue asserts that only
// CONFIDENCE_NOT_REACHABLE findings are suppressible.
func TestFinding_IsSuppressible_OnlyNotReachableIsTrue(t *testing.T) {
	cases := []struct {
		confidence commit0v1.Confidence
		want       bool
	}{
		{commit0v1.Confidence_CONFIDENCE_UNKNOWN, false},
		{commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE, true},
		{commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, false},
		{commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE, false},
	}
	for _, tc := range cases {
		f := &commit0v1.Finding{Confidence: tc.confidence}
		w := contract.WrapFinding(f)
		assert.Equal(t, tc.want, w.IsSuppressible(),
			"confidence=%v: IsSuppressible()=%v, want %v", tc.confidence, w.IsSuppressible(), tc.want)
	}
}

// TestFinding_ProtoRoundTrip_ReachabilityPath verifies that a Finding with a
// multi-step ReachabilityPath survives proto.Marshal / proto.Unmarshal intact.
func TestFinding_ProtoRoundTrip_ReachabilityPath(t *testing.T) {
	original := &commit0v1.Finding{
		Advisory: &commit0v1.AdvisoryRef{
			Id:      "GO-2024-0001",
			Url:     "https://pkg.go.dev/vuln/GO-2024-0001",
			Aliases: []string{"CVE-2024-12345"},
		},
		Module:     "golang.org/x/net",
		Confidence: commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
		Severity:   commit0v1.Severity_SEVERITY_HIGH,
		Path: &commit0v1.ReachabilityPath{
			Steps: []*commit0v1.CallStep{
				{
					Location: &commit0v1.Location{File: "cmd/main.go", Line: 42, Column: 5},
					Symbol:   "main.main",
				},
				{
					Location: &commit0v1.Location{File: "internal/client/client.go", Line: 17, Column: 3},
					Symbol:   "internal/client.Client.Do",
				},
				{
					Location: &commit0v1.Location{File: "vendor/golang.org/x/net/http2/transport.go", Line: 99, Column: 12},
					Symbol:   "golang.org/x/net/http2.(*Transport).RoundTrip",
				},
			},
		},
		Properties: map[string]string{
			"goos":            "linux",
			"goarch":          "amd64",
			"algorithm":       "vta",
			"snapshot_digest": "sha256:abc123",
		},
		Pillar:   "sca",
		Language: "go",
	}

	b, err := proto.Marshal(original)
	require.NoError(t, err, "proto.Marshal must not error")

	got := &commit0v1.Finding{}
	require.NoError(t, proto.Unmarshal(b, got), "proto.Unmarshal must not error")

	assert.True(t, proto.Equal(original, got), "round-tripped Finding must equal the original")

	// Spot-check nested fields explicitly.
	require.NotNil(t, got.Advisory)
	assert.Equal(t, "GO-2024-0001", got.Advisory.Id)
	assert.Equal(t, []string{"CVE-2024-12345"}, got.Advisory.Aliases)

	require.NotNil(t, got.Path)
	require.Len(t, got.Path.Steps, 3)
	assert.Equal(t, "cmd/main.go", got.Path.Steps[0].Location.File)
	assert.Equal(t, int32(42), got.Path.Steps[0].Location.Line)
	assert.Equal(t, "golang.org/x/net/http2.(*Transport).RoundTrip", got.Path.Steps[2].Symbol)

	assert.Equal(t, "linux", got.Properties["goos"])
	assert.Equal(t, "vta", got.Properties["algorithm"])
}

// TestAnalyzeRequest_ProtoRoundTrip verifies that AnalyzeRequest round-trips
// its advisories (with symbols, symbol_level, sources) and build_config intact.
// This guards Red Team finding #1: advisory transport must be a contract input.
func TestAnalyzeRequest_ProtoRoundTrip(t *testing.T) {
	original := &commit0v1.AnalyzeRequest{
		ModuleRoot:  "/home/user/myproject",
		Entrypoints: []string{"./cmd/myapp", "./cmd/worker"},
		BuildConfig: &commit0v1.BuildConfig{
			Goos:   "linux",
			Goarch: "amd64",
			Tags:   []string{"integration", "netgo"},
		},
		Advisories: []*commit0v1.Advisory{
			{
				Id:          "GO-2024-0001",
				Module:      "golang.org/x/net",
				VersionRange: "<0.17.0",
				Symbols: []*commit0v1.Symbol{
					{Package: "golang.org/x/net/http2", Name: "(*Transport).RoundTrip"},
					{Package: "golang.org/x/net/http2", Name: "(*ClientConn).RoundTrip"},
				},
				SymbolLevel: true,
				Sources:     []string{"go-vuln-db"},
			},
			{
				Id:          "GO-2024-0002",
				Module:      "github.com/example/lib",
				VersionRange: ">=1.0.0,<1.2.3",
				Symbols:     nil,
				SymbolLevel: false,
				Sources:     []string{"go-vuln-db", "osv"},
			},
		},
	}

	b, err := proto.Marshal(original)
	require.NoError(t, err, "proto.Marshal must not error")

	got := &commit0v1.AnalyzeRequest{}
	require.NoError(t, proto.Unmarshal(b, got), "proto.Unmarshal must not error")

	assert.True(t, proto.Equal(original, got), "round-tripped AnalyzeRequest must equal the original")

	// Spot-check nested advisory fields.
	require.Len(t, got.Advisories, 2)

	adv0 := got.Advisories[0]
	assert.Equal(t, "GO-2024-0001", adv0.Id)
	assert.True(t, adv0.SymbolLevel)
	assert.Equal(t, []string{"go-vuln-db"}, adv0.Sources)
	require.Len(t, adv0.Symbols, 2)
	assert.Equal(t, "golang.org/x/net/http2", adv0.Symbols[0].Package)
	assert.Equal(t, "(*Transport).RoundTrip", adv0.Symbols[0].Name)

	adv1 := got.Advisories[1]
	assert.False(t, adv1.SymbolLevel)
	assert.Equal(t, []string{"go-vuln-db", "osv"}, adv1.Sources)

	// Spot-check BuildConfig.
	require.NotNil(t, got.BuildConfig)
	assert.Equal(t, "linux", got.BuildConfig.Goos)
	assert.Equal(t, "amd64", got.BuildConfig.Goarch)
	assert.Equal(t, []string{"integration", "netgo"}, got.BuildConfig.Tags)
}
