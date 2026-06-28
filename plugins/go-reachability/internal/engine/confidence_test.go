package engine

// Unit tests for the pure AssignConfidence function.
// These tests exercise every confidence-tier transition without loading any
// packages or running SSA analysis — they construct ConfidenceInput directly.
//
// Tier transitions covered:
//   IllTyped                          → UNKNOWN,          nil path
//   SymbolLevel=false + imported      → PACKAGE_REACHABLE, nil path
//   SymbolLevel=false + not-imported  → NOT_REACHABLE,    nil path
//   SymbolLevel=true  + unresolved    → UNKNOWN,          nil path
//   resolved + BFS.Reachable=true     → SYMBOL_REACHABLE, path returned
//   resolved + no-edge + reflect + addr-taken → UNKNOWN,  nil path
//   resolved + no-edge + clean        → NOT_REACHABLE,   nil path

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
)

// dummyPath is a minimal non-nil PathStep slice used to verify that
// AssignConfidence forwards the BFS path on SYMBOL_REACHABLE.
var dummyPath = []PathStep{
	{Fn: nil, Edge: nil},
	{Fn: nil, Edge: nil},
}

func TestAssignConfidence(t *testing.T) {
	tests := []struct {
		name         string
		inp          ConfidenceInput
		wantConf     commit0v1.Confidence
		wantPathNil  bool
		wantPathLen  int // only checked when wantPathNil==false
	}{
		// ── IllTyped → UNKNOWN ────────────────────────────────────────────────
		{
			name: "ill-typed package → UNKNOWN",
			inp: ConfidenceInput{
				IllTyped:    true,
				SymbolLevel: true,
				Resolved:    true, // ill-typed overrides everything
				BFSResult:   ReachResult{Reachable: true, Path: dummyPath},
			},
			wantConf:    commit0v1.Confidence_CONFIDENCE_UNKNOWN,
			wantPathNil: true,
		},
		// ── package-level advisory (SymbolLevel=false) ───────────────────────
		{
			name: "pkg-level + imported → PACKAGE_REACHABLE",
			inp: ConfidenceInput{
				SymbolLevel: false,
				PkgImported: true,
			},
			wantConf:    commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
			wantPathNil: true,
		},
		{
			name: "pkg-level + not imported → NOT_REACHABLE",
			inp: ConfidenceInput{
				SymbolLevel: false,
				PkgImported: false,
			},
			wantConf:    commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE,
			wantPathNil: true,
		},
		// ── symbol-level + unresolved → UNKNOWN ──────────────────────────────
		{
			name: "symbol-level + unresolved → UNKNOWN",
			inp: ConfidenceInput{
				SymbolLevel:     true,
				Resolved:        false,
				ResolutionError: "package not found in SSA program",
			},
			wantConf:    commit0v1.Confidence_CONFIDENCE_UNKNOWN,
			wantPathNil: true,
		},
		// ── resolved + BFS found a path → SYMBOL_REACHABLE ───────────────────
		{
			name: "resolved + BFS reachable → SYMBOL_REACHABLE with path",
			inp: ConfidenceInput{
				SymbolLevel: true,
				Resolved:    true,
				PkgImported: true,
				BFSResult:   ReachResult{Reachable: true, Path: dummyPath},
			},
			wantConf:    commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE,
			wantPathNil: false,
			wantPathLen: len(dummyPath),
		},
		// ── resolved + no-edge + reflect + addr-taken → UNKNOWN ──────────────
		{
			name: "resolved + no edge + reflect present + addr-taken → UNKNOWN",
			inp: ConfidenceInput{
				SymbolLevel:     true,
				Resolved:        true,
				PkgImported:     true,
				BFSResult:       ReachResult{Reachable: false},
				ReflectInPath:   true,
				TargetAddrTaken: true,
			},
			wantConf:    commit0v1.Confidence_CONFIDENCE_UNKNOWN,
			wantPathNil: true,
		},
		// ── reflect present but addr-NOT-taken → NOT_REACHABLE ───────────────
		// (reflect alone is not sufficient; the target must also be address-taken)
		{
			name: "resolved + no edge + reflect present but addr-NOT-taken → NOT_REACHABLE",
			inp: ConfidenceInput{
				SymbolLevel:     true,
				Resolved:        true,
				PkgImported:     true,
				BFSResult:       ReachResult{Reachable: false},
				ReflectInPath:   true,
				TargetAddrTaken: false,
			},
			wantConf:    commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE,
			wantPathNil: true,
		},
		// ── resolved + no edge + clean graph → NOT_REACHABLE ─────────────────
		{
			name: "resolved + no edge + clean graph → NOT_REACHABLE",
			inp: ConfidenceInput{
				SymbolLevel:     true,
				Resolved:        true,
				PkgImported:     true,
				BFSResult:       ReachResult{Reachable: false},
				ReflectInPath:   false,
				TargetAddrTaken: false,
			},
			wantConf:    commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE,
			wantPathNil: true,
		},
		// ── addr-taken alone (no reflect) must not escalate to UNKNOWN ────────
		{
			name: "resolved + no edge + addr-taken only (no reflect) → NOT_REACHABLE",
			inp: ConfidenceInput{
				SymbolLevel:     true,
				Resolved:        true,
				PkgImported:     true,
				BFSResult:       ReachResult{Reachable: false},
				ReflectInPath:   false,
				TargetAddrTaken: true,
			},
			wantConf:    commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE,
			wantPathNil: true,
		},
		// ── ill-typed overrides even a BFS hit ────────────────────────────────
		{
			name: "ill-typed + BFS reachable → UNKNOWN (ill-typed wins)",
			inp: ConfidenceInput{
				IllTyped:    true,
				SymbolLevel: true,
				Resolved:    true,
				BFSResult:   ReachResult{Reachable: true, Path: dummyPath},
			},
			wantConf:    commit0v1.Confidence_CONFIDENCE_UNKNOWN,
			wantPathNil: true,
		},
		// ── package-level advisory ignores BFS / resolution ──────────────────
		{
			name: "pkg-level + imported (BFS data ignored) → PACKAGE_REACHABLE",
			inp: ConfidenceInput{
				SymbolLevel: false,
				PkgImported: true,
				Resolved:    true,
				BFSResult:   ReachResult{Reachable: true, Path: dummyPath},
			},
			wantConf:    commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE,
			wantPathNil: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			conf, path := AssignConfidence(tt.inp)

			assert.Equal(t, tt.wantConf, conf,
				"confidence mismatch for %q", tt.name)

			if tt.wantPathNil {
				assert.Nil(t, path,
					"path must be nil for confidence=%s in case %q", conf, tt.name)
			} else {
				require.NotNil(t, path,
					"path must be non-nil for SYMBOL_REACHABLE in case %q", tt.name)
				assert.Len(t, path, tt.wantPathLen,
					"path length mismatch in case %q", tt.name)
			}
		})
	}
}

// TestAssignConfidence_PathOnlyOnSymbolReachable is an exhaustive cross-check:
// for every tier except SYMBOL_REACHABLE, Path must be nil.
// This documents the invariant used in SARIF lowering (empty codeFlows is invalid SARIF).
func TestAssignConfidence_PathOnlyOnSymbolReachable(t *testing.T) {
	cases := []ConfidenceInput{
		// NOT_REACHABLE cases.
		{SymbolLevel: false, PkgImported: false},
		{SymbolLevel: true, Resolved: true, BFSResult: ReachResult{Reachable: false}},
		// PACKAGE_REACHABLE.
		{SymbolLevel: false, PkgImported: true},
		// UNKNOWN cases.
		{IllTyped: true},
		{SymbolLevel: true, Resolved: false},
		{SymbolLevel: true, Resolved: true, BFSResult: ReachResult{Reachable: false}, ReflectInPath: true, TargetAddrTaken: true},
	}

	for i, inp := range cases {
		conf, path := AssignConfidence(inp)
		if conf != commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE {
			assert.Nil(t, path,
				"case %d (conf=%s): path must be nil for non-SYMBOL_REACHABLE confidence",
				i, conf)
		}
	}
}
