package engine

import (
	commit0v1 "github.com/commit0-dev/commit0-analyzer/pkg/contract/commit0v1"
	"golang.org/x/tools/go/ssa"
)

// ConfidenceInput gathers all inputs the tier-assignment logic needs for one
// advisory symbol. It is a value type to keep AssignConfidence pure/testable.
type ConfidenceInput struct {
	// Advisory metadata.
	SymbolLevel bool   // advisory.SymbolLevel — false means package-level only
	PkgPath     string

	// Resolution outcome.
	Resolved        bool
	ResolutionError string

	// Graph outcome.
	PkgImported     bool        // package is present in the SSA program
	BFSResult       ReachResult // BFS result (only meaningful when Resolved==true)
	ReflectInPath   bool        // any reachable function uses reflect.Value.Call*
	TargetAddrTaken bool        // target fn is address-taken (may be called via reflect)

	// Partial-build / build-config flags.
	IllTyped   bool
	BuildError string
}

// AssignConfidence returns the Confidence tier and, for SYMBOL_REACHABLE,
// the call path to include in the Finding.
//
// Invariants enforced:
//
//   - unknown ≠ safe: any ambiguity → CONFIDENCE_UNKNOWN, never NOT_REACHABLE.
//   - ReachabilityPath is nil for everything except SYMBOL_REACHABLE.
//   - PACKAGE_REACHABLE requires SymbolLevel==false and PkgImported==true.
//   - Interface dispatch resolved by VTA yields SYMBOL_REACHABLE (not UNKNOWN).
func AssignConfidence(inp ConfidenceInput) (commit0v1.Confidence, []PathStep) {
	// Partial build / IllTyped → UNKNOWN (Red Team Crit #4).
	if inp.IllTyped {
		return commit0v1.Confidence_CONFIDENCE_UNKNOWN, nil
	}

	// Package-level advisory (SymbolLevel==false).
	if !inp.SymbolLevel {
		if inp.PkgImported {
			return commit0v1.Confidence_CONFIDENCE_PACKAGE_REACHABLE, nil
		}
		return commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE, nil
	}

	// Symbol-level but resolution failed → UNKNOWN (Red Team Crit #12b).
	if !inp.Resolved {
		return commit0v1.Confidence_CONFIDENCE_UNKNOWN, nil
	}

	// Symbol resolved and BFS found a path → SYMBOL_REACHABLE.
	// This covers plain calls AND VTA-resolved interface dispatch
	// (Red Team Med #15a: interface dispatch ≠ reflection).
	if inp.BFSResult.Reachable {
		return commit0v1.Confidence_CONFIDENCE_SYMBOL_REACHABLE, inp.BFSResult.Path
	}

	// No call-graph edge. Check for reflection / address-taken pattern
	// (Red Team Crit #3): if reflection is present in the reachable subgraph
	// AND the target is address-taken, we cannot safely claim NOT_REACHABLE.
	if inp.ReflectInPath && inp.TargetAddrTaken {
		return commit0v1.Confidence_CONFIDENCE_UNKNOWN, nil
	}

	// Clean graph, symbol resolved, no edge found → NOT_REACHABLE.
	return commit0v1.Confidence_CONFIDENCE_NOT_REACHABLE, nil
}

// EntryPointsForProgram auto-detects the BFS root set from the SSA program.
//
// Detection rules (Red Team High #12a):
//
//	main package present → roots = main + init + test functions
//	pure library        → roots = all exported functions/methods + init
//
// Explicit req.Entrypoints override auto-detection.
func EntryPointsForProgram(prog *ssa.Program, ssaPkgs []*ssa.Package, explicit []string) []*ssa.Function {
	if len(explicit) > 0 {
		return resolveExplicitEntrypoints(prog, ssaPkgs, explicit)
	}

	var roots []*ssa.Function
	hasMain := false

	for _, pkg := range ssaPkgs {
		if pkg == nil || pkg.Pkg == nil {
			continue
		}
		if pkg.Pkg.Name() == "main" {
			hasMain = true
			if fn := pkg.Func("main"); fn != nil {
				roots = append(roots, fn)
			}
			if fn := pkg.Func("init"); fn != nil {
				roots = append(roots, fn)
			}
			// Include test functions (Tests:true set in load config).
			for name, mem := range pkg.Members {
				fn, ok := mem.(*ssa.Function)
				if !ok {
					continue
				}
				if isTestFunc(name) {
					roots = append(roots, fn)
				}
			}
		}
	}

	if hasMain {
		return roots
	}

	// Pure library: roots = all exported functions/methods + init in each package.
	for _, pkg := range ssaPkgs {
		if pkg == nil || pkg.Pkg == nil {
			continue
		}
		if fn := pkg.Func("init"); fn != nil {
			roots = append(roots, fn)
		}
		for name, mem := range pkg.Members {
			fn, ok := mem.(*ssa.Function)
			if !ok {
				continue
			}
			if len(name) > 0 && name[0] >= 'A' && name[0] <= 'Z' {
				roots = append(roots, fn)
			}
		}
	}
	return roots
}

// isTestFunc reports whether name matches Go test function naming conventions.
func isTestFunc(name string) bool {
	if len(name) > 4 && name[:4] == "Test" {
		return true
	}
	if len(name) > 9 && name[:9] == "Benchmark" {
		return true
	}
	if len(name) > 7 && name[:7] == "Example" {
		return true
	}
	return false
}

// resolveExplicitEntrypoints maps explicit package patterns to SSA functions.
func resolveExplicitEntrypoints(prog *ssa.Program, ssaPkgs []*ssa.Package, patterns []string) []*ssa.Function {
	patSet := make(map[string]bool, len(patterns))
	for _, p := range patterns {
		patSet[p] = true
	}

	var roots []*ssa.Function
	for _, pkg := range ssaPkgs {
		if pkg == nil || pkg.Pkg == nil {
			continue
		}
		path := pkg.Pkg.Path()
		if !patSet[path] && !patSet["./..."] {
			continue
		}
		if fn := pkg.Func("init"); fn != nil {
			roots = append(roots, fn)
		}
		if fn := pkg.Func("main"); fn != nil {
			roots = append(roots, fn)
		}
		for name, mem := range pkg.Members {
			fn, ok := mem.(*ssa.Function)
			if !ok {
				continue
			}
			if len(name) > 0 && name[0] >= 'A' && name[0] <= 'Z' {
				roots = append(roots, fn)
			}
		}
	}
	return roots
}
