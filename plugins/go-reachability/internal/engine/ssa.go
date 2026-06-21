package engine

import (
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// BuildSSA constructs an SSA program from a set of already-loaded packages.
//
// InstantiateGenerics is required for correct generic handling and is also
// needed by RTA (which is used as the base graph for VTA). Without it,
// generic instantiations are not represented as distinct SSA functions.
func BuildSSA(pkgs []*packages.Package) (*ssa.Program, []*ssa.Package) {
	// ssautil.AllPackages creates the SSA program from the type-checked package
	// graph produced by go/packages. The mode flags control how bodies are built:
	//
	//   ssa.SanityCheckFunctions  — extra correctness assertions (useful in tests)
	//   ssa.InstantiateGenerics   — materialise generic instantiations as SSA funcs
	//
	// We do NOT use ssa.GlobalDebug here because it bloats memory for large repos;
	// position information is still available via fn.Pos() from the token.FileSet.
	mode := ssa.SanityCheckFunctions | ssa.InstantiateGenerics
	prog, ssaPkgs := ssautil.AllPackages(pkgs, mode)

	// prog.Build() builds function bodies for every reachable package.
	// Must be called before any call-graph construction.
	prog.Build()

	return prog, ssaPkgs
}
