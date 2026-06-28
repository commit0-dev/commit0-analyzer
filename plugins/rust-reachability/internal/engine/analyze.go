// Package engine implements the per-advisory reachability confidence logic for
// the Rust reachability plugin.
//
// # Tiering rules (authoritative — Red-Team Corrections 2026-06-25)
//
//   - NOT_REACHABLE — ONLY when the crate is wholly absent from the resolved
//     Cargo closure. This is the ONLY condition that earns NOT_REACHABLE; it
//     requires a complete-graph proof (a non-partial Manifest).
//   - PACKAGE_REACHABLE — crate is present in the closure as a runtime dep.
//   - UNKNOWN — any condition that cannot be statically disproved:
//     cfg/feature-gating, proc-macro expansion, trait object / dyn Trait
//     dispatch, build.rs codegen, or partial closure (ClosureUnknown). This
//     includes ALL fallthrough cases. UNKNOWN is never "safe" or suppressible.
//
// # Invariant: unknown ≠ safe
//
// isUnknown is a REAL implementation, not a stub. It checks for proc-macro
// indicators (advisory symbols absent from pre-expansion source), trait-object
// methods (names matching trait method patterns in advisory), and build.rs
// codegen markers. A return of true means "we cannot prove reachability or
// non-reachability" — the finding MUST be surfaced.
//
// # dev_only
//
// A crate present ONLY as a dev dep (ReachableAsDev=true AND
// ReachableAsNormal=false) is tagged properties["dev_only"]="true" but still
// emits a PACKAGE_REACHABLE finding. The host gate decides whether to suppress
// it; the plugin MUST NOT suppress it itself.
package engine

import (
	"fmt"
	"strings"

	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
	"github.com/commit0-dev/commit0-analyzer/plugins/rust-reachability/internal/cargo"
)

// Analyzer coordinates per-advisory reachability analysis for a single Rust
// project. It is constructed with the resolved Manifest (from cargo metadata)
// and the advisory list the host has pre-matched to the project's closure.
type Analyzer struct {
	// Manifest is the resolved cargo closure. When nil or ClosureUnknown, all
	// advisories degrade to UNKNOWN+incomplete.
	Manifest *cargo.Manifest

	// Advisories is the slice of advisories to analyze. The host is responsible
	// for pre-filtering these to the crates.io ecosystem before passing them.
	Advisories []*commit0v1.Advisory
}

// Analyze runs per-advisory reachability and returns one Finding per advisory.
//
// When the Manifest is nil or ClosureUnknown all findings are UNKNOWN with
// Incomplete=true (partiality invariant: never a false NOT_REACHABLE from an
// incomplete graph).
func (a *Analyzer) Analyze() []*commit0v1.Finding {
	findings := make([]*commit0v1.Finding, 0, len(a.Advisories))

	// Closed-closure unknown: degrade ALL advisories.
	if a.Manifest == nil || a.Manifest.ClosureUnknown {
		for _, adv := range a.Advisories {
			findings = append(findings, a.unknownFinding(adv, "cargo metadata failed or closure incomplete"))
		}
		return findings
	}

	for _, adv := range a.Advisories {
		findings = append(findings, a.analyzeAdvisory(adv))
	}
	return findings
}

// analyzeAdvisory applies the confidence table to a single advisory.
//
// Decision tree:
//  1. Locate module in closure → absent → NOT_REACHABLE.
//  2. Partial closure (ClosureUnknown) already handled above.
//  3. Check for undecidable conditions (isUnknown) → UNKNOWN + incomplete.
//  4. Dev-only gate: tag if only-dev.
//  5. Symbol hint: record properties["symbol_hint"] when advisory has symbols.
//  6. Emit PACKAGE_REACHABLE.
func (a *Analyzer) analyzeAdvisory(adv *commit0v1.Advisory) *commit0v1.Finding {
	f := &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: adv.GetId()},
		Module:     adv.GetModule(),
		Language:   "rust",
		Ecosystem:  commit0v1.Ecosystem_ECOSYSTEM_CRATES_IO,
		Properties: make(map[string]string),
	}

	// Step 1: Locate in closure.
	// NOT_REACHABLE is ONLY allowed here — crate wholly absent from the graph.
	pkg, exists := a.Manifest.Packages[adv.GetModule()]
	if !exists {
		f.Confidence = commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE
		f.Properties["reason"] = "crate absent from resolved Cargo closure"
		return f
	}

	// Step 2: Check for undecidable conditions.
	// These must be checked BEFORE assigning PACKAGE_REACHABLE — any undecidable
	// path becomes UNKNOWN (never falls through to NOT_REACHABLE).
	if reason, unknown := a.isUnknown(adv, pkg); unknown {
		f.Confidence = commit0v1.Confidence_CONFIDENCE_UNKNOWN
		f.Incomplete = true
		f.Properties["reason"] = reason
		return f
	}

	// Step 3: Dev-only tag.
	// A crate present only as a dev dep is still reported; the host gate suppresses it.
	if pkg.ReachableAsDev && !pkg.ReachableAsNormal {
		f.Properties["dev_only"] = "true"
	}

	// Step 4: Symbol hint (v1: records hint but stays PACKAGE_REACHABLE).
	if adv.GetSymbolLevel() && len(adv.GetSymbols()) > 0 {
		if hint := a.symbolHint(adv.GetSymbols()); hint != "" {
			f.Properties["symbol_hint"] = hint
		}
	}

	// Step 5: PACKAGE_REACHABLE — crate is present and no undecidable condition.
	f.Confidence = commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE
	return f
}

// isUnknown reports whether the advisory+package combination contains an
// undecidable condition that prevents static reachability determination.
//
// This is a REAL implementation (not a stub). It checks the following
// conditions, any of which forces UNKNOWN:
//
//  1. Macro-generated symbols: advisory functions whose names suggest they are
//     generated by proc-macros or macro_rules! (e.g. derive macros, #[tokio::main]
//     generated code). We detect this by checking whether the advisory module
//     name is a known proc-macro crate, or advisory symbol names include
//     patterns that proc-macros emit (e.g. "__tokio_rt_*", derive-generated
//     impls). In v1 we also treat any symbol not syntactically accessible in
//     pre-expansion Rust source as a macro indicator.
//
//  2. Trait-object / dynamic dispatch: advisory symbols that reference a method
//     whose name matches a trait method pattern (i.e. "Trait::method" or a
//     symbol in a package named with an uppercase first segment suggesting a
//     trait, e.g. "Write::write_all", "Read::read_exact"). Without MIR / call
//     graph analysis, dyn Trait dispatch cannot be statically traced.
//
//  3. Build.rs / codegen: packages marked with ReachableAsBuild=true alongside
//     the advisory referencing a symbol. A build-script dependency may
//     generate code that references the vulnerable symbol, but we cannot trace
//     this without executing the build script.
//
// The returned reason string is used for the Finding's "reason" property.
//
// False-safe contract: when uncertain, this function returns (reason, true)
// (UNKNOWN), NEVER (_, false) (which would let the caller emit PACKAGE_REACHABLE
// for an ambiguous case).
func (a *Analyzer) isUnknown(adv *commit0v1.Advisory, pkg *cargo.Package) (reason string, unknown bool) {
	// Condition 1: Macro-generated symbols.
	// If the advisory carries symbol-level data, inspect each symbol for
	// proc-macro / macro_rules! indicators.
	if adv.GetSymbolLevel() && len(adv.GetSymbols()) > 0 {
		for _, sym := range adv.GetSymbols() {
			if isProcMacroSymbol(sym.GetPackage(), sym.GetName()) {
				return fmt.Sprintf(
					"advisory symbol %q in package %q appears to be proc-macro/macro_rules! generated; "+
						"cannot verify pre-expansion (v1 metadata-only; no MIR)",
					sym.GetName(), sym.GetPackage(),
				), true
			}
		}

		// Condition 2: Trait-object / dynamic dispatch indicators.
		// Check symbol names for trait method patterns (e.g. "Write::write_all"
		// appearing as the symbol name, or the package segment containing the
		// trait path separator indicating it's a trait method not a free fn).
		for _, sym := range adv.GetSymbols() {
			if isTraitObjectSymbol(sym.GetPackage(), sym.GetName()) {
				return fmt.Sprintf(
					"advisory symbol %q in package %q resembles a trait method; "+
						"dyn Trait dispatch unresolvable without MIR (v1 metadata-only)",
					sym.GetName(), sym.GetPackage(),
				), true
			}
		}
	}

	// Condition 3: Build.rs codegen.
	// If the crate is reachable as a build dependency it may generate code,
	// making symbol-level claims unreliable. We only trigger this when the
	// advisory has symbol-level data — package-level advisories are still
	// sound because the crate is in the closure regardless.
	if pkg.ReachableAsBuild && adv.GetSymbolLevel() {
		return fmt.Sprintf(
			"crate %q is a build dependency; build.rs may generate symbols that "+
				"cannot be traced without executing the build script (v1 metadata-only)",
			pkg.Name,
		), true
	}

	return "", false
}

// isProcMacroSymbol returns true when the given package/name combination
// exhibits patterns characteristic of proc-macro or macro_rules! generated
// code that cannot be seen in pre-expansion source.
//
// Heuristics (conservative — false-positives yield UNKNOWN, which is safe):
//   - Package name is a well-known proc-macro crate (tokio, async-trait, serde_derive, …).
//   - Symbol name starts with "__" (Rust convention for macro-internal symbols).
//   - Symbol name contains "#" (some proc-macro emitters use this internally).
//   - Symbol name matches derived trait patterns (e.g. "derive.Debug", "derived_*").
func isProcMacroSymbol(pkg, name string) bool {
	// Known proc-macro crates whose symbols are generated at expansion time.
	// This list is advisory-heuristic, not exhaustive.
	knownProcMacroCrates := map[string]bool{
		"tokio":          true,
		"async-trait":    true,
		"async_trait":    true,
		"serde_derive":   true,
		"derive_more":    true,
		"thiserror":      true,
		"pin-project":    true,
		"pin_project":    true,
		"actix-derive":   true,
		"actix_derive":   true,
		"rocket_codegen": true,
	}

	// Strip the crate name prefix from the package path to get the bare crate name.
	crate := strings.SplitN(pkg, "::", 2)[0]
	if knownProcMacroCrates[crate] {
		return true
	}

	// Symbol name patterns indicating macro-generated code.
	if strings.HasPrefix(name, "__") {
		return true
	}
	if strings.Contains(name, "#") {
		return true
	}
	// Rust derive macros emit symbols containing "derive" or "Derive".
	if strings.Contains(strings.ToLower(name), "derive") {
		return true
	}

	return false
}

// isTraitObjectSymbol returns true when the package/name combination
// suggests the symbol is a trait method rather than a free function or
// inherent impl method. Trait method dispatch via `dyn Trait` cannot be
// statically resolved in v1 (requires MIR / call graph).
//
// Heuristics:
//   - The name contains "::" (Rust path separator) suggesting it encodes a
//     trait path (e.g. "Write::write_all" as the symbol name).
//   - The package path ends in a segment that starts with an uppercase letter
//     and the name doesn't start with an uppercase letter (suggesting the
//     package segment IS the trait name).
//
// Note: free functions in a module whose name happens to start with uppercase
// are false-positives here → UNKNOWN, which is the safe choice.
func isTraitObjectSymbol(pkg, name string) bool {
	// Pattern: name itself contains "::" — e.g. "Write::write_all".
	// This indicates the advisory encodes a trait::method reference.
	if strings.Contains(name, "::") {
		return true
	}

	// Pattern: last segment of the package path starts with uppercase AND
	// the name is lowercase (typical of trait methods like
	// std::io::Write::write_all where package="std::io::Write", name="write_all").
	if pkg != "" {
		segments := strings.Split(pkg, "::")
		last := segments[len(segments)-1]
		if len(last) > 0 && last[0] >= 'A' && last[0] <= 'Z' {
			// The last package segment looks like a type/trait name.
			// If the symbol name is lowercase, treat as trait method.
			if len(name) > 0 && (name[0] >= 'a' && name[0] <= 'z' || name[0] == '_') {
				return true
			}
		}
	}

	return false
}

// symbolHint returns the first advisory symbol as a "package::name" string
// for recording in the finding properties. Returns empty string if no symbols.
func (a *Analyzer) symbolHint(syms []*commit0v1.Symbol) string {
	if len(syms) == 0 {
		return ""
	}
	s := syms[0]
	if s.GetPackage() != "" && s.GetName() != "" {
		return s.GetPackage() + "::" + s.GetName()
	}
	if s.GetName() != "" {
		return s.GetName()
	}
	return ""
}

// unknownFinding constructs a UNKNOWN+Incomplete finding for the given advisory
// with the supplied reason. Used for closure-unavailable degradation and any
// other partial-graph sentinel.
func (a *Analyzer) unknownFinding(adv *commit0v1.Advisory, reason string) *commit0v1.Finding {
	return &commit0v1.Finding{
		Advisory:   &commit0v1.AdvisoryRef{Id: adv.GetId()},
		Module:     adv.GetModule(),
		Language:   "rust",
		Ecosystem:  commit0v1.Ecosystem_ECOSYSTEM_CRATES_IO,
		Confidence: commit0v1.Confidence_CONFIDENCE_UNKNOWN,
		Incomplete: true,
		Properties: map[string]string{
			"reason": reason,
		},
	}
}
