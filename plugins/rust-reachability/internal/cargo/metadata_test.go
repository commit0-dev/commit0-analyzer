package cargo_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/commit0-dev/commit0-analyzer/plugins/rust-reachability/internal/cargo"
)

// ─── ParseMetadataJSON ───────────────────────────────────────────────────────

// TestParseMetadataJSON_SimpleCrate verifies that a single crate with normal
// (runtime) deps is parsed into a Manifest whose Packages map is keyed by
// crate name, and every crate appearing in the resolve graph is present.
func TestParseMetadataJSON_SimpleCrate(t *testing.T) {
	raw := []byte(`{
		"version": 1,
		"packages": [
			{
				"name": "my-app",
				"version": "0.1.0",
				"id": "my-app 0.1.0 (path+file:///tmp/my-app)",
				"manifest_path": "/tmp/my-app/Cargo.toml",
				"license": null,
				"dependencies": []
			},
			{
				"name": "serde",
				"version": "1.0.197",
				"id": "serde 1.0.197 (registry+https://github.com/rust-lang/crates.io-index)",
				"manifest_path": "/tmp/.cargo/registry/serde-1.0.197/Cargo.toml",
				"license": "MIT OR Apache-2.0",
				"dependencies": []
			}
		],
		"workspace_members": ["my-app 0.1.0 (path+file:///tmp/my-app)"],
		"resolve": {
			"nodes": [
				{
					"id": "my-app 0.1.0 (path+file:///tmp/my-app)",
					"dependencies": ["serde 1.0.197 (registry+https://github.com/rust-lang/crates.io-index)"],
					"deps": [
						{
							"name": "serde",
							"pkg": "serde 1.0.197 (registry+https://github.com/rust-lang/crates.io-index)",
							"dep_kinds": [{"kind": null, "target": null}]
						}
					]
				},
				{
					"id": "serde 1.0.197 (registry+https://github.com/rust-lang/crates.io-index)",
					"dependencies": [],
					"deps": []
				}
			],
			"root": "my-app 0.1.0 (path+file:///tmp/my-app)"
		},
		"target_directory": "/tmp/my-app/target",
		"workspace_root": "/tmp/my-app"
	}`)

	m, err := cargo.ParseMetadataJSON(raw)
	if err != nil {
		t.Fatalf("ParseMetadataJSON: %v", err)
	}

	// Both crates must be in the map.
	if _, ok := m.Packages["my-app"]; !ok {
		t.Error("want my-app in Packages")
	}
	serdeP, ok := m.Packages["serde"]
	if !ok {
		t.Fatal("want serde in Packages")
	}

	// serde is a normal (runtime) dep of my-app.
	if !serdeP.ReachableAsNormal {
		t.Error("serde: want ReachableAsNormal=true")
	}
	if serdeP.ReachableAsDev {
		t.Error("serde: want ReachableAsDev=false")
	}
	if serdeP.ReachableAsBuild {
		t.Error("serde: want ReachableAsBuild=false")
	}

	// Version must be stored without "v" prefix.
	if serdeP.Version != "1.0.197" {
		t.Errorf("serde version: got %q, want %q", serdeP.Version, "1.0.197")
	}
}

// TestParseMetadataJSON_DevOnlyDep verifies that a dep reachable only via
// dev dep_kind is tagged ReachableAsDev=true, ReachableAsNormal=false.
func TestParseMetadataJSON_DevOnlyDep(t *testing.T) {
	raw := []byte(`{
		"version": 1,
		"packages": [
			{
				"name": "my-lib",
				"version": "0.1.0",
				"id": "my-lib 0.1.0 (path+file:///tmp/my-lib)",
				"manifest_path": "/tmp/my-lib/Cargo.toml",
				"dependencies": []
			},
			{
				"name": "dev-tools",
				"version": "2.0.0",
				"id": "dev-tools 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
				"manifest_path": "/tmp/.cargo/dev-tools-2.0.0/Cargo.toml",
				"dependencies": []
			}
		],
		"workspace_members": ["my-lib 0.1.0 (path+file:///tmp/my-lib)"],
		"resolve": {
			"nodes": [
				{
					"id": "my-lib 0.1.0 (path+file:///tmp/my-lib)",
					"dependencies": ["dev-tools 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)"],
					"deps": [
						{
							"name": "dev-tools",
							"pkg": "dev-tools 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
							"dep_kinds": [{"kind": "dev", "target": null}]
						}
					]
				},
				{
					"id": "dev-tools 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
					"dependencies": [],
					"deps": []
				}
			],
			"root": "my-lib 0.1.0 (path+file:///tmp/my-lib)"
		},
		"target_directory": "/tmp/my-lib/target",
		"workspace_root": "/tmp/my-lib"
	}`)

	m, err := cargo.ParseMetadataJSON(raw)
	if err != nil {
		t.Fatalf("ParseMetadataJSON: %v", err)
	}

	dt, ok := m.Packages["dev-tools"]
	if !ok {
		t.Fatal("want dev-tools in Packages")
	}
	if dt.ReachableAsNormal {
		t.Error("dev-tools: want ReachableAsNormal=false")
	}
	if !dt.ReachableAsDev {
		t.Error("dev-tools: want ReachableAsDev=true")
	}
}

// TestParseMetadataJSON_BuildDep verifies that a build-only dep (kind="build")
// is tagged ReachableAsBuild=true, ReachableAsNormal=false.
func TestParseMetadataJSON_BuildDep(t *testing.T) {
	raw := []byte(`{
		"version": 1,
		"packages": [
			{
				"name": "my-app",
				"version": "0.1.0",
				"id": "my-app 0.1.0 (path+file:///tmp/my-app)",
				"manifest_path": "/tmp/my-app/Cargo.toml",
				"dependencies": []
			},
			{
				"name": "cc",
				"version": "1.0.0",
				"id": "cc 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
				"manifest_path": "/tmp/.cargo/cc-1.0.0/Cargo.toml",
				"dependencies": []
			}
		],
		"workspace_members": ["my-app 0.1.0 (path+file:///tmp/my-app)"],
		"resolve": {
			"nodes": [
				{
					"id": "my-app 0.1.0 (path+file:///tmp/my-app)",
					"dependencies": ["cc 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"],
					"deps": [
						{
							"name": "cc",
							"pkg": "cc 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
							"dep_kinds": [{"kind": "build", "target": null}]
						}
					]
				},
				{
					"id": "cc 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
					"dependencies": [],
					"deps": []
				}
			],
			"root": "my-app 0.1.0 (path+file:///tmp/my-app)"
		},
		"target_directory": "/tmp/my-app/target",
		"workspace_root": "/tmp/my-app"
	}`)

	m, err := cargo.ParseMetadataJSON(raw)
	if err != nil {
		t.Fatalf("ParseMetadataJSON: %v", err)
	}

	cc, ok := m.Packages["cc"]
	if !ok {
		t.Fatal("want cc in Packages")
	}
	if cc.ReachableAsNormal {
		t.Error("cc: want ReachableAsNormal=false")
	}
	if !cc.ReachableAsBuild {
		t.Error("cc: want ReachableAsBuild=true")
	}
}

// TestParseMetadataJSON_BothNormalAndDev verifies a crate that appears as BOTH
// a normal dep AND a dev dep is tagged as both.
func TestParseMetadataJSON_BothNormalAndDev(t *testing.T) {
	raw := []byte(`{
		"version": 1,
		"packages": [
			{
				"name": "my-app",
				"version": "0.1.0",
				"id": "my-app 0.1.0 (path+file:///tmp/my-app)",
				"manifest_path": "/tmp/my-app/Cargo.toml",
				"dependencies": []
			},
			{
				"name": "serde",
				"version": "1.0.197",
				"id": "serde 1.0.197 (registry+https://github.com/rust-lang/crates.io-index)",
				"manifest_path": "/tmp/.cargo/serde-1.0.197/Cargo.toml",
				"dependencies": []
			}
		],
		"workspace_members": ["my-app 0.1.0 (path+file:///tmp/my-app)"],
		"resolve": {
			"nodes": [
				{
					"id": "my-app 0.1.0 (path+file:///tmp/my-app)",
					"dependencies": ["serde 1.0.197 (registry+https://github.com/rust-lang/crates.io-index)"],
					"deps": [
						{
							"name": "serde",
							"pkg": "serde 1.0.197 (registry+https://github.com/rust-lang/crates.io-index)",
							"dep_kinds": [
								{"kind": null, "target": null},
								{"kind": "dev", "target": null}
							]
						}
					]
				},
				{
					"id": "serde 1.0.197 (registry+https://github.com/rust-lang/crates.io-index)",
					"dependencies": [],
					"deps": []
				}
			],
			"root": "my-app 0.1.0 (path+file:///tmp/my-app)"
		},
		"target_directory": "/tmp/my-app/target",
		"workspace_root": "/tmp/my-app"
	}`)

	m, err := cargo.ParseMetadataJSON(raw)
	if err != nil {
		t.Fatalf("ParseMetadataJSON: %v", err)
	}

	s, ok := m.Packages["serde"]
	if !ok {
		t.Fatal("want serde in Packages")
	}
	if !s.ReachableAsNormal {
		t.Error("serde: want ReachableAsNormal=true (also used as runtime dep)")
	}
	if !s.ReachableAsDev {
		t.Error("serde: want ReachableAsDev=true (also used as dev dep)")
	}
}

// TestParseMetadataJSON_Workspace verifies that a workspace with multiple
// members produces a flat Packages map containing all member crates.
func TestParseMetadataJSON_Workspace(t *testing.T) {
	raw := []byte(`{
		"version": 1,
		"packages": [
			{
				"name": "workspace-root",
				"version": "0.1.0",
				"id": "workspace-root 0.1.0 (path+file:///tmp/ws)",
				"manifest_path": "/tmp/ws/Cargo.toml",
				"dependencies": []
			},
			{
				"name": "member-a",
				"version": "0.1.0",
				"id": "member-a 0.1.0 (path+file:///tmp/ws/a)",
				"manifest_path": "/tmp/ws/a/Cargo.toml",
				"dependencies": []
			},
			{
				"name": "member-b",
				"version": "0.2.0",
				"id": "member-b 0.2.0 (path+file:///tmp/ws/b)",
				"manifest_path": "/tmp/ws/b/Cargo.toml",
				"dependencies": []
			},
			{
				"name": "transitive-c",
				"version": "3.0.0",
				"id": "transitive-c 3.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
				"manifest_path": "/tmp/.cargo/transitive-c-3.0.0/Cargo.toml",
				"dependencies": []
			}
		],
		"workspace_members": [
			"member-a 0.1.0 (path+file:///tmp/ws/a)",
			"member-b 0.2.0 (path+file:///tmp/ws/b)"
		],
		"resolve": {
			"nodes": [
				{
					"id": "member-a 0.1.0 (path+file:///tmp/ws/a)",
					"dependencies": ["transitive-c 3.0.0 (registry+https://github.com/rust-lang/crates.io-index)"],
					"deps": [
						{
							"name": "transitive-c",
							"pkg": "transitive-c 3.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
							"dep_kinds": [{"kind": null, "target": null}]
						}
					]
				},
				{
					"id": "member-b 0.2.0 (path+file:///tmp/ws/b)",
					"dependencies": ["member-a 0.1.0 (path+file:///tmp/ws/a)"],
					"deps": [
						{
							"name": "member-a",
							"pkg": "member-a 0.1.0 (path+file:///tmp/ws/a)",
							"dep_kinds": [{"kind": null, "target": null}]
						}
					]
				},
				{
					"id": "transitive-c 3.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
					"dependencies": [],
					"deps": []
				},
				{
					"id": "workspace-root 0.1.0 (path+file:///tmp/ws)",
					"dependencies": [],
					"deps": []
				}
			],
			"root": null
		},
		"target_directory": "/tmp/ws/target",
		"workspace_root": "/tmp/ws"
	}`)

	m, err := cargo.ParseMetadataJSON(raw)
	if err != nil {
		t.Fatalf("ParseMetadataJSON: %v", err)
	}

	for _, name := range []string{"member-a", "member-b", "transitive-c"} {
		if _, ok := m.Packages[name]; !ok {
			t.Errorf("want %q in Packages", name)
		}
	}

	// transitive-c is a normal dep of member-a.
	tc, ok := m.Packages["transitive-c"]
	if !ok {
		t.Fatal("want transitive-c in Packages")
	}
	if !tc.ReachableAsNormal {
		t.Error("transitive-c: want ReachableAsNormal=true")
	}

	// member-b is a workspace member. In this fixture member-b depends on
	// member-a, so it has an in-graph dependent relationship; still it must
	// also carry ReachableAsNormal and IsWorkspaceMember from the
	// workspace_members list.
	mb, ok := m.Packages["member-b"]
	if !ok {
		t.Fatal("want member-b in Packages")
	}
	if !mb.ReachableAsNormal {
		t.Error("member-b: want ReachableAsNormal=true (workspace member)")
	}
	if !mb.IsWorkspaceMember {
		t.Error("member-b: want IsWorkspaceMember=true")
	}

	// WorkspaceMembers slice must be populated.
	if len(m.WorkspaceMembers) == 0 {
		t.Error("want non-empty WorkspaceMembers slice")
	}

	// Root should be empty (this is a workspace).
	if m.Root != "" {
		t.Errorf("Root: got %q, want empty (workspace)", m.Root)
	}
}

// TestParseMetadataJSON_TransitiveClosure verifies that a dependency that is
// reachable only through an intermediate crate (A→B→C) is still classified
// correctly in the manifest. The closure is build-time transitive — every
// package in resolve.nodes that is depended upon via kind=null is normal.
func TestParseMetadataJSON_TransitiveClosure(t *testing.T) {
	raw := []byte(`{
		"version": 1,
		"packages": [
			{
				"name": "app",
				"version": "0.1.0",
				"id": "app 0.1.0 (path+file:///tmp/app)",
				"manifest_path": "/tmp/app/Cargo.toml",
				"dependencies": []
			},
			{
				"name": "middle",
				"version": "1.0.0",
				"id": "middle 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
				"manifest_path": "/tmp/.cargo/middle-1.0.0/Cargo.toml",
				"dependencies": []
			},
			{
				"name": "leaf",
				"version": "2.0.0",
				"id": "leaf 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
				"manifest_path": "/tmp/.cargo/leaf-2.0.0/Cargo.toml",
				"dependencies": []
			}
		],
		"workspace_members": ["app 0.1.0 (path+file:///tmp/app)"],
		"resolve": {
			"nodes": [
				{
					"id": "app 0.1.0 (path+file:///tmp/app)",
					"dependencies": ["middle 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)"],
					"deps": [
						{
							"name": "middle",
							"pkg": "middle 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
							"dep_kinds": [{"kind": null, "target": null}]
						}
					]
				},
				{
					"id": "middle 1.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
					"dependencies": ["leaf 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)"],
					"deps": [
						{
							"name": "leaf",
							"pkg": "leaf 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
							"dep_kinds": [{"kind": null, "target": null}]
						}
					]
				},
				{
					"id": "leaf 2.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
					"dependencies": [],
					"deps": []
				}
			],
			"root": "app 0.1.0 (path+file:///tmp/app)"
		},
		"target_directory": "/tmp/app/target",
		"workspace_root": "/tmp/app"
	}`)

	m, err := cargo.ParseMetadataJSON(raw)
	if err != nil {
		t.Fatalf("ParseMetadataJSON: %v", err)
	}

	// Both middle and leaf should be ReachableAsNormal since they are connected
	// by normal dep_kinds through the resolve graph.
	for _, name := range []string{"middle", "leaf"} {
		pkg, ok := m.Packages[name]
		if !ok {
			t.Fatalf("want %q in Packages", name)
		}
		if !pkg.ReachableAsNormal {
			t.Errorf("%s: want ReachableAsNormal=true (transitive normal dep)", name)
		}
	}
}

// TestParseMetadataJSON_InvalidJSON verifies that malformed JSON returns an
// error with ClosureUnknown=true on the returned Manifest.
func TestParseMetadataJSON_InvalidJSON(t *testing.T) {
	m, err := cargo.ParseMetadataJSON([]byte(`{invalid json`))
	if err == nil {
		t.Fatal("want error for invalid JSON")
	}
	if m != nil && !m.ClosureUnknown {
		t.Error("want ClosureUnknown=true on error")
	}
}

// TestParseMetadataJSON_EmptyResolve verifies that a metadata blob with an
// empty resolve.nodes list (e.g. cargo ran but produced nothing) results in
// ClosureUnknown=true and NO empty-clean result (invariant: partial/empty
// resolve must never masquerade as "nothing reachable").
func TestParseMetadataJSON_EmptyResolve(t *testing.T) {
	raw := []byte(`{
		"version": 1,
		"packages": [],
		"workspace_members": [],
		"resolve": {
			"nodes": [],
			"root": null
		},
		"target_directory": "/tmp/app/target",
		"workspace_root": "/tmp/app"
	}`)

	m, err := cargo.ParseMetadataJSON(raw)
	// An empty resolve is treated as a partial/unknown result.
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("want non-nil Manifest even on empty resolve")
	}
	if !m.ClosureUnknown {
		t.Error("want ClosureUnknown=true for empty resolve (never a clean empty result)")
	}
}

// ─── LoadManifest (integration-style, requires cargo on PATH) ────────────────

// TestLoadManifest_MissingCargo verifies that when cargo is not available (or
// the moduleRoot is invalid), LoadManifest returns a Manifest with
// ClosureUnknown=true and a non-nil error, never an empty-clean result.
//
// This test uses an empty directory (no Cargo.toml). The expected outcome is
// that cargo exits non-zero and LoadManifest returns ClosureUnknown=true.
func TestLoadManifest_MissingCargo(t *testing.T) {
	ctx := context.Background()
	// An empty dir has no Cargo.toml; cargo metadata will fail.
	dir := t.TempDir()
	m, err := cargo.LoadManifest(ctx, dir)
	if m == nil {
		t.Fatal("want non-nil Manifest (ClosureUnknown sentinel)")
	}
	if !m.ClosureUnknown {
		// If cargo somehow succeeded in an empty dir the manifest must still
		// not have a clean closure. Fail with a descriptive message.
		t.Errorf("want ClosureUnknown=true when cargo metadata fails (err=%v)", err)
	}
}

// TestLoadManifest_Timeout verifies that a very short timeout causes
// LoadManifest to return ClosureUnknown=true rather than hanging forever.
func TestLoadManifest_Timeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()

	dir := t.TempDir()
	m, err := cargo.LoadManifest(ctx, dir)
	_ = err // may or may not be nil; what matters is ClosureUnknown
	if m == nil {
		t.Fatal("want non-nil Manifest")
	}
	if !m.ClosureUnknown {
		t.Error("want ClosureUnknown=true on timeout")
	}
}

// ─── CrateNameFromID ─────────────────────────────────────────────────────────

// TestCrateNameFromID verifies the helper that extracts a crate name from a
// cargo package ID string in both the legacy and the cargo >= 1.77 space-free
// formats.
//
// Legacy format:  "name version (source_kind+url)"
// New format:     "scheme+url#name@version"  (space-free; cargo >= 1.77)
// Version-only:   "scheme+url#version"       (name must be derived from URL segment)
func TestCrateNameFromID(t *testing.T) {
	cases := []struct {
		id   string
		want string
	}{
		// Legacy format (cargo < 1.77)
		{"serde 1.0.197 (registry+https://github.com/rust-lang/crates.io-index)", "serde"},
		{"my-app 0.1.0 (path+file:///tmp/my-app)", "my-app"},
		{"tokio 1.40.0 (registry+https://github.com/rust-lang/crates.io-index)", "tokio"},
		{"my_crate 0.1.0 (path+file:///workspace/my_crate)", "my_crate"},

		// New space-free format: scheme+url#name@version (cargo >= 1.77)
		{"registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18", "itoa"},
		{"registry+https://github.com/rust-lang/crates.io-index#serde@1.0.197", "serde"},
		{"path+file:///abs/path/demo#demo@0.1.0", "demo"},
		{"path+file:///x/demo#demo@0.1.0", "demo"},
		{"path+file:///workspace/my-app#my-app@0.2.3", "my-app"},

		// Version-only after '#' (name must be derived from last URL path segment)
		{"path+file:///abs/path/my-crate#0.1.0", "my-crate"},
		{"registry+https://github.com/rust-lang/crates.io-index#1.0.0", "crates.io-index"},

		// Edge cases
		{"", ""},
		{"single", "single"},
	}
	for _, tc := range cases {
		got := cargo.CrateNameFromID(tc.id)
		if got != tc.want {
			t.Errorf("CrateNameFromID(%q): got %q, want %q", tc.id, got, tc.want)
		}
	}
}

// TestCrateNameFromID_NewFormatWorkspaceParsing verifies that when cargo >= 1.77
// emits space-free IDs in workspace_members and resolve.root, ParseMetadataJSON
// correctly resolves crate names and stamps IsWorkspaceMember / ReachableAsNormal.
// This is the regression scenario: if CrateNameFromID misparses the new format
// the pkgByName lookup fails and workspace members are NOT flagged, which would
// cause the engine to emit NOT_REACHABLE for the scanned project's own crates.
func TestCrateNameFromID_NewFormatWorkspaceParsing(t *testing.T) {
	// JSON uses cargo >= 1.77 space-free IDs in workspace_members, resolve.root,
	// and resolve.nodes while packages[].id still carries the same space-free form.
	raw := []byte(`{
		"version": 1,
		"packages": [
			{
				"name": "demo",
				"version": "0.1.0",
				"id": "path+file:///workspace/demo#demo@0.1.0",
				"manifest_path": "/workspace/demo/Cargo.toml",
				"dependencies": []
			},
			{
				"name": "itoa",
				"version": "1.0.18",
				"id": "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18",
				"manifest_path": "/root/.cargo/registry/src/itoa-1.0.18/Cargo.toml",
				"dependencies": []
			}
		],
		"workspace_members": ["path+file:///workspace/demo#demo@0.1.0"],
		"resolve": {
			"nodes": [
				{
					"id": "path+file:///workspace/demo#demo@0.1.0",
					"dependencies": ["registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18"],
					"deps": [
						{
							"name": "itoa",
							"pkg": "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18",
							"dep_kinds": [{"kind": null, "target": null}]
						}
					]
				},
				{
					"id": "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.18",
					"dependencies": [],
					"deps": []
				}
			],
			"root": "path+file:///workspace/demo#demo@0.1.0"
		},
		"target_directory": "/workspace/demo/target",
		"workspace_root": "/workspace/demo"
	}`)

	m, err := cargo.ParseMetadataJSON(raw)
	if err != nil {
		t.Fatalf("ParseMetadataJSON: %v", err)
	}
	if m.ClosureUnknown {
		t.Fatalf("want ClosureUnknown=false (complete graph), got true: %s", m.ClosureError)
	}

	// Root must be resolved correctly from the new ID format.
	if m.Root != "demo" {
		t.Errorf("Root: got %q, want %q", m.Root, "demo")
	}

	// demo (root/workspace member) must be flagged even though nothing depends on it.
	demo, ok := m.Packages["demo"]
	if !ok {
		t.Fatal("want 'demo' in Packages")
	}
	if !demo.ReachableAsNormal {
		t.Error("demo (root): want ReachableAsNormal=true")
	}
	if !demo.IsWorkspaceMember {
		t.Error("demo (root): want IsWorkspaceMember=true")
	}

	// itoa is a normal dep of demo.
	itoa, ok := m.Packages["itoa"]
	if !ok {
		t.Fatal("want 'itoa' in Packages")
	}
	if !itoa.ReachableAsNormal {
		t.Error("itoa: want ReachableAsNormal=true (normal dep)")
	}
	if itoa.IsWorkspaceMember {
		t.Error("itoa: want IsWorkspaceMember=false (third-party crate)")
	}

	// WorkspaceMembers must contain "demo".
	if len(m.WorkspaceMembers) == 0 || m.WorkspaceMembers[0] != "demo" {
		t.Errorf("WorkspaceMembers: got %v, want [demo]", m.WorkspaceMembers)
	}
}

// ─── JSON marshaling fidelity ─────────────────────────────────────────────────

// ─── Workspace-member / root reachability (critical finding) ─────────────────

// TestParseMetadataJSON_WorkspaceMemberReachable verifies that workspace
// members have ReachableAsNormal=true and IsWorkspaceMember=true even when
// nothing in the graph depends on them. Without this, a workspace root or a
// top-level binary crate would have all-false Reachable* flags, causing the
// engine to emit NOT_REACHABLE for the scanned project's own code — a critical
// false negative.
func TestParseMetadataJSON_WorkspaceMemberReachable(t *testing.T) {
	// member-b has no in-graph dependents (nothing depends on it), but it IS
	// a workspace member and must be flagged ReachableAsNormal.
	raw := []byte(`{
		"version": 1,
		"packages": [
			{
				"name": "workspace-root",
				"version": "0.1.0",
				"id": "workspace-root 0.1.0 (path+file:///tmp/ws)",
				"manifest_path": "/tmp/ws/Cargo.toml",
				"dependencies": []
			},
			{
				"name": "member-a",
				"version": "0.1.0",
				"id": "member-a 0.1.0 (path+file:///tmp/ws/a)",
				"manifest_path": "/tmp/ws/a/Cargo.toml",
				"dependencies": []
			},
			{
				"name": "member-b",
				"version": "0.2.0",
				"id": "member-b 0.2.0 (path+file:///tmp/ws/b)",
				"manifest_path": "/tmp/ws/b/Cargo.toml",
				"dependencies": []
			},
			{
				"name": "transitive-c",
				"version": "3.0.0",
				"id": "transitive-c 3.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
				"manifest_path": "/tmp/.cargo/transitive-c-3.0.0/Cargo.toml",
				"dependencies": []
			}
		],
		"workspace_members": [
			"member-a 0.1.0 (path+file:///tmp/ws/a)",
			"member-b 0.2.0 (path+file:///tmp/ws/b)"
		],
		"resolve": {
			"nodes": [
				{
					"id": "member-a 0.1.0 (path+file:///tmp/ws/a)",
					"dependencies": ["transitive-c 3.0.0 (registry+https://github.com/rust-lang/crates.io-index)"],
					"deps": [
						{
							"name": "transitive-c",
							"pkg": "transitive-c 3.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
							"dep_kinds": [{"kind": null, "target": null}]
						}
					]
				},
				{
					"id": "member-b 0.2.0 (path+file:///tmp/ws/b)",
					"dependencies": [],
					"deps": []
				},
				{
					"id": "transitive-c 3.0.0 (registry+https://github.com/rust-lang/crates.io-index)",
					"dependencies": [],
					"deps": []
				},
				{
					"id": "workspace-root 0.1.0 (path+file:///tmp/ws)",
					"dependencies": [],
					"deps": []
				}
			],
			"root": null
		},
		"target_directory": "/tmp/ws/target",
		"workspace_root": "/tmp/ws"
	}`)

	m, err := cargo.ParseMetadataJSON(raw)
	if err != nil {
		t.Fatalf("ParseMetadataJSON: %v", err)
	}
	if m.ClosureUnknown {
		t.Fatalf("want ClosureUnknown=false, got true: %s", m.ClosureError)
	}

	// WorkspaceMembers must be populated.
	if len(m.WorkspaceMembers) != 2 {
		t.Errorf("WorkspaceMembers: got %v, want [member-a member-b]", m.WorkspaceMembers)
	}

	// member-b has no in-graph dependents but IS a workspace member.
	mb, ok := m.Packages["member-b"]
	if !ok {
		t.Fatal("want member-b in Packages")
	}
	if !mb.ReachableAsNormal {
		t.Error("member-b: want ReachableAsNormal=true (workspace member; scanned project code)")
	}
	if !mb.IsWorkspaceMember {
		t.Error("member-b: want IsWorkspaceMember=true")
	}

	// member-a is both a workspace member AND depended on by member-b (in the
	// original test fixture, member-b depends on member-a). Here member-a has
	// no dependents but is a workspace member.
	ma, ok := m.Packages["member-a"]
	if !ok {
		t.Fatal("want member-a in Packages")
	}
	if !ma.ReachableAsNormal {
		t.Error("member-a: want ReachableAsNormal=true (workspace member)")
	}
	if !ma.IsWorkspaceMember {
		t.Error("member-a: want IsWorkspaceMember=true")
	}

	// transitive-c is a normal dep of member-a.
	tc, ok := m.Packages["transitive-c"]
	if !ok {
		t.Fatal("want transitive-c in Packages")
	}
	if !tc.ReachableAsNormal {
		t.Error("transitive-c: want ReachableAsNormal=true (normal dep)")
	}
	if tc.IsWorkspaceMember {
		t.Error("transitive-c: want IsWorkspaceMember=false (third-party crate)")
	}
}

// TestParseMetadataJSON_RootCrateReachable verifies that a single-crate repo
// (non-workspace; resolve.root != null) has its root crate flagged
// ReachableAsNormal=true and IsWorkspaceMember=true. The root crate is the
// entry point of the scanned binary/library; it is always reachable.
func TestParseMetadataJSON_RootCrateReachable(t *testing.T) {
	raw := []byte(`{
		"version": 1,
		"packages": [
			{
				"name": "my-app",
				"version": "0.1.0",
				"id": "my-app 0.1.0 (path+file:///tmp/my-app)",
				"manifest_path": "/tmp/my-app/Cargo.toml",
				"dependencies": []
			},
			{
				"name": "serde",
				"version": "1.0.197",
				"id": "serde 1.0.197 (registry+https://github.com/rust-lang/crates.io-index)",
				"manifest_path": "/tmp/.cargo/serde-1.0.197/Cargo.toml",
				"dependencies": []
			}
		],
		"workspace_members": ["my-app 0.1.0 (path+file:///tmp/my-app)"],
		"resolve": {
			"nodes": [
				{
					"id": "my-app 0.1.0 (path+file:///tmp/my-app)",
					"dependencies": ["serde 1.0.197 (registry+https://github.com/rust-lang/crates.io-index)"],
					"deps": [
						{
							"name": "serde",
							"pkg": "serde 1.0.197 (registry+https://github.com/rust-lang/crates.io-index)",
							"dep_kinds": [{"kind": null, "target": null}]
						}
					]
				},
				{
					"id": "serde 1.0.197 (registry+https://github.com/rust-lang/crates.io-index)",
					"dependencies": [],
					"deps": []
				}
			],
			"root": "my-app 0.1.0 (path+file:///tmp/my-app)"
		},
		"target_directory": "/tmp/my-app/target",
		"workspace_root": "/tmp/my-app"
	}`)

	m, err := cargo.ParseMetadataJSON(raw)
	if err != nil {
		t.Fatalf("ParseMetadataJSON: %v", err)
	}
	if m.ClosureUnknown {
		t.Fatalf("want ClosureUnknown=false, got true: %s", m.ClosureError)
	}

	// Root must be set.
	if m.Root != "my-app" {
		t.Errorf("Root: got %q, want %q", m.Root, "my-app")
	}

	app, ok := m.Packages["my-app"]
	if !ok {
		t.Fatal("want my-app in Packages")
	}
	if !app.ReachableAsNormal {
		t.Error("my-app (root): want ReachableAsNormal=true (scanned project root)")
	}
	if !app.IsWorkspaceMember {
		t.Error("my-app (root): want IsWorkspaceMember=true")
	}
}

// TestParseMetadataJSON_UnknownDepPkgSetsClosureUnknown verifies that when
// resolve.nodes references a dep.pkg ID absent from packages[], ParseMetadataJSON
// sets ClosureUnknown=true. In cargo --format-version 1 every resolve ID is
// present in packages[], so a miss indicates a malformed or partial blob rather
// than a benign platform-filter gap.
func TestParseMetadataJSON_UnknownDepPkgSetsClosureUnknown(t *testing.T) {
	// phantom-crate appears in resolve.nodes deps but NOT in packages[].
	raw := []byte(`{
		"version": 1,
		"packages": [
			{
				"name": "my-app",
				"version": "0.1.0",
				"id": "my-app 0.1.0 (path+file:///tmp/my-app)",
				"manifest_path": "/tmp/my-app/Cargo.toml",
				"dependencies": []
			}
		],
		"workspace_members": ["my-app 0.1.0 (path+file:///tmp/my-app)"],
		"resolve": {
			"nodes": [
				{
					"id": "my-app 0.1.0 (path+file:///tmp/my-app)",
					"dependencies": ["phantom-crate 9.9.9 (registry+https://github.com/rust-lang/crates.io-index)"],
					"deps": [
						{
							"name": "phantom-crate",
							"pkg": "phantom-crate 9.9.9 (registry+https://github.com/rust-lang/crates.io-index)",
							"dep_kinds": [{"kind": null, "target": null}]
						}
					]
				}
			],
			"root": "my-app 0.1.0 (path+file:///tmp/my-app)"
		},
		"target_directory": "/tmp/my-app/target",
		"workspace_root": "/tmp/my-app"
	}`)

	m, err := cargo.ParseMetadataJSON(raw)
	if err != nil {
		t.Fatalf("ParseMetadataJSON returned unexpected error: %v", err)
	}
	if m == nil {
		t.Fatal("want non-nil Manifest")
	}
	if !m.ClosureUnknown {
		t.Error("want ClosureUnknown=true when a dep pkg ID is absent from packages[] (partial blob)")
	}
	if m.ClosureError == "" {
		t.Error("want non-empty ClosureError describing the missing dep")
	}
}

// TestParseMetadataJSON_WorkspaceMembersField verifies that WorkspaceMembers
// and Root are correctly populated on the returned Manifest. These fields are
// consumed by callers that need to identify first-party crates.
func TestParseMetadataJSON_WorkspaceMembersField(t *testing.T) {
	raw := []byte(`{
		"version": 1,
		"packages": [
			{
				"name": "alpha",
				"version": "0.1.0",
				"id": "alpha 0.1.0 (path+file:///tmp/ws/alpha)",
				"manifest_path": "/tmp/ws/alpha/Cargo.toml",
				"dependencies": []
			},
			{
				"name": "beta",
				"version": "0.1.0",
				"id": "beta 0.1.0 (path+file:///tmp/ws/beta)",
				"manifest_path": "/tmp/ws/beta/Cargo.toml",
				"dependencies": []
			}
		],
		"workspace_members": [
			"alpha 0.1.0 (path+file:///tmp/ws/alpha)",
			"beta 0.1.0 (path+file:///tmp/ws/beta)"
		],
		"resolve": {
			"nodes": [
				{
					"id": "alpha 0.1.0 (path+file:///tmp/ws/alpha)",
					"dependencies": [],
					"deps": []
				},
				{
					"id": "beta 0.1.0 (path+file:///tmp/ws/beta)",
					"dependencies": [],
					"deps": []
				}
			],
			"root": null
		},
		"target_directory": "/tmp/ws/target",
		"workspace_root": "/tmp/ws"
	}`)

	m, err := cargo.ParseMetadataJSON(raw)
	if err != nil {
		t.Fatalf("ParseMetadataJSON: %v", err)
	}
	if m.ClosureUnknown {
		t.Fatalf("want ClosureUnknown=false, got true: %s", m.ClosureError)
	}

	// Root should be empty for a workspace.
	if m.Root != "" {
		t.Errorf("Root: got %q, want empty string (workspace has no single root)", m.Root)
	}

	// Both members must appear in WorkspaceMembers.
	wantMembers := map[string]bool{"alpha": true, "beta": true}
	for _, name := range m.WorkspaceMembers {
		delete(wantMembers, name)
	}
	if len(wantMembers) > 0 {
		t.Errorf("WorkspaceMembers missing: %v", wantMembers)
	}

	// Both workspace members must be flagged.
	for _, name := range []string{"alpha", "beta"} {
		pkg, ok := m.Packages[name]
		if !ok {
			t.Fatalf("want %q in Packages", name)
		}
		if !pkg.IsWorkspaceMember {
			t.Errorf("%s: want IsWorkspaceMember=true", name)
		}
		if !pkg.ReachableAsNormal {
			t.Errorf("%s: want ReachableAsNormal=true (workspace member)", name)
		}
	}
}

// ─── Cargo env scrubbing (toolchain-pinning security) ────────────────────────

// TestSanitizedCargoEnv_PinsToolchain verifies that SanitizedCargoEnv always
// includes RUSTUP_TOOLCHAIN=stable regardless of the host process's environment,
// preventing a repo-supplied rust-toolchain.toml from redirecting the toolchain.
func TestSanitizedCargoEnv_PinsToolchain(t *testing.T) {
	// Poison the host env to simulate an attacker-supplied toolchain override.
	orig, hadOrig := os.LookupEnv("RUSTUP_TOOLCHAIN")
	if err := os.Setenv("RUSTUP_TOOLCHAIN", "nightly-attacker-12345"); err != nil {
		t.Fatalf("Setenv: %v", err)
	}
	t.Cleanup(func() {
		if hadOrig {
			_ = os.Setenv("RUSTUP_TOOLCHAIN", orig)
		} else {
			_ = os.Unsetenv("RUSTUP_TOOLCHAIN")
		}
	})

	env := cargo.SanitizedCargoEnv()

	// RUSTUP_TOOLCHAIN must be exactly "stable" — never the attacker value.
	found := false
	for _, kv := range env {
		if kv == "RUSTUP_TOOLCHAIN=stable" {
			found = true
		}
		if kv == "RUSTUP_TOOLCHAIN=nightly-attacker-12345" {
			t.Error("sanitized env must NOT forward the host RUSTUP_TOOLCHAIN value")
		}
	}
	if !found {
		t.Error("sanitized env must contain RUSTUP_TOOLCHAIN=stable")
	}
}

// TestSanitizedCargoEnv_ForwardsToolchainDirsAndPinsToolchain verifies the real
// security property: CARGO_HOME / RUSTUP_HOME are host-process env vars (a scanned
// repo cannot set them), so their inherited values are forwarded — cargo/rustup
// need them to locate the installed toolchain. The repo-controlled vector is a
// rust-toolchain.toml file, neutralized by pinning RUSTUP_TOOLCHAIN to "stable"
// regardless of any inherited RUSTUP_TOOLCHAIN value.
func TestSanitizedCargoEnv_ForwardsToolchainDirsAndPinsToolchain(t *testing.T) {
	hostCargoHome := "/host/cargo-home"
	hostRustupHome := "/host/rustup-home"
	restore := func(key, val string, had bool) func() {
		return func() {
			if had {
				_ = os.Setenv(key, val)
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}

	cargoHomeOrig, hadCH := os.LookupEnv("CARGO_HOME")
	rustupHomeOrig, hadRH := os.LookupEnv("RUSTUP_HOME")
	toolchainOrig, hadTC := os.LookupEnv("RUSTUP_TOOLCHAIN")

	_ = os.Setenv("CARGO_HOME", hostCargoHome)
	_ = os.Setenv("RUSTUP_HOME", hostRustupHome)
	_ = os.Setenv("RUSTUP_TOOLCHAIN", "repo-evil-toolchain")
	t.Cleanup(restore("CARGO_HOME", cargoHomeOrig, hadCH))
	t.Cleanup(restore("RUSTUP_HOME", rustupHomeOrig, hadRH))
	t.Cleanup(restore("RUSTUP_TOOLCHAIN", toolchainOrig, hadTC))

	var gotCargoHome, gotRustupHome, gotToolchain string
	for _, kv := range cargo.SanitizedCargoEnv() {
		switch {
		case strings.HasPrefix(kv, "CARGO_HOME="):
			gotCargoHome = kv
		case strings.HasPrefix(kv, "RUSTUP_HOME="):
			gotRustupHome = kv
		case strings.HasPrefix(kv, "RUSTUP_TOOLCHAIN="):
			gotToolchain = kv
		}
	}

	// Host toolchain dirs are forwarded so the toolchain stays discoverable.
	if gotCargoHome != "CARGO_HOME="+hostCargoHome {
		t.Errorf("CARGO_HOME should be forwarded, got %q", gotCargoHome)
	}
	if gotRustupHome != "RUSTUP_HOME="+hostRustupHome {
		t.Errorf("RUSTUP_HOME should be forwarded, got %q", gotRustupHome)
	}
	// RUSTUP_TOOLCHAIN is pinned to stable, never inherited — a repo cannot
	// redirect which toolchain runs.
	if gotToolchain != "RUSTUP_TOOLCHAIN=stable" {
		t.Errorf("RUSTUP_TOOLCHAIN must be pinned to stable, got %q", gotToolchain)
	}
}

// TestSanitizedCargoEnv_ForwardsPath verifies that PATH is forwarded so cargo
// can locate itself and any required sidecar binaries.
func TestSanitizedCargoEnv_ForwardsPath(t *testing.T) {
	env := cargo.SanitizedCargoEnv()
	for _, kv := range env {
		if strings.HasPrefix(kv, "PATH=") {
			return // found — pass
		}
	}
	t.Error("sanitized env must forward PATH so cargo can be located")
}

// ─── JSON marshaling fidelity ─────────────────────────────────────────────────

// TestCargoMetadataUnmarshal_DepKindNull checks that JSON null for dep kind
// (representing a normal/runtime dep) is correctly parsed as kind==nil in Go.
func TestCargoMetadataUnmarshal_DepKindNull(t *testing.T) {
	type DepKind struct {
		Kind   *string `json:"kind"`
		Target string  `json:"target,omitempty"`
	}
	type Dep struct {
		Pkg      string    `json:"pkg"`
		DepKinds []DepKind `json:"dep_kinds"`
	}

	raw := []byte(`{"pkg":"foo 1.0.0","dep_kinds":[{"kind":null,"target":null}]}`)
	var d Dep
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(d.DepKinds) != 1 {
		t.Fatalf("want 1 dep_kind, got %d", len(d.DepKinds))
	}
	if d.DepKinds[0].Kind != nil {
		t.Errorf("kind: got %v, want nil (runtime dep)", d.DepKinds[0].Kind)
	}
}
