package engine

import (
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/callgraph/rta"
	"golang.org/x/tools/go/callgraph/vta"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Algorithm names stamped into finding properties["algorithm"].
const (
	AlgorithmVTA = "vta"
	AlgorithmRTA = "rta"
	AlgorithmCHA = "cha"
)

// GraphBuilder is a pluggable seam for call-graph construction.
// Implementations receive the SSA program and the set of root entry-point
// functions, and return a call graph plus the algorithm name.
type GraphBuilder func(prog *ssa.Program, roots []*ssa.Function) (*callgraph.Graph, string, error)

// DefaultGraphBuilder is the production builder: VTA on a CHA base graph.
//
// Why VTA over CHA/RTA alone?
//   - CHA over-approximates: it adds edges for every type that implements the
//     interface anywhere in the type hierarchy, including types never allocated.
//     This produces false-positive SYMBOL_REACHABLE findings.
//   - RTA is sound for concrete types allocated in the program but misses some
//     dynamic dispatch patterns and has no interface precision for unexported types.
//   - VTA refines the initial CHA graph using a type-propagation analysis that
//     considers only types that flow to interface values actually reached from
//     the roots. It is strictly more precise than CHA and comparable to RTA for
//     most programs, with better interface-dispatch handling.
//
// Perf watch-item: VTA is slower than RTA on large programs. If analysis exceeds
// the ≤1.5× govulncheck budget (Phase 6 corpus), switch DefaultGraphBuilder to
// RTAGraphBuilder via the seam and document the precision trade-off.
func DefaultGraphBuilder(prog *ssa.Program, roots []*ssa.Function) (*callgraph.Graph, string, error) {
	return buildVTA(prog, roots)
}

// RTAGraphBuilder is the RTA-only fallback. It is faster than VTA but less
// precise on interface dispatch. Use when VTA exceeds the perf budget.
func RTAGraphBuilder(prog *ssa.Program, roots []*ssa.Function) (*callgraph.Graph, string, error) {
	return buildRTA(prog, roots)
}

// buildVTA constructs a VTA call graph on a CHA base.
//
// VTA requires a base call graph to seed its type-propagation lattice.
// CHA is the standard choice: it is fast and its over-approximation is refined
// away by VTA's subsequent pointer/type-flow analysis.
func buildVTA(prog *ssa.Program, _ []*ssa.Function) (*callgraph.Graph, string, error) {
	// Step 1: build the CHA base graph over ALL program functions (not just roots).
	// CHA operates on the type hierarchy and does not need roots.
	chaGraph := cha.CallGraph(prog)

	// Step 2: refine with VTA. allFunctions is the universe VTA propagates over.
	// vta.CallGraph returns a new graph with edges only reachable from the
	// type-propagation fixed point seeded by the CHA edges.
	allFuncs := ssautil.AllFunctions(prog)
	vtaGraph := vta.CallGraph(allFuncs, chaGraph)

	return vtaGraph, AlgorithmVTA, nil
}

// buildRTA constructs an RTA call graph.
//
// RTA (Rapid Type Analysis) builds the graph incrementally starting from roots,
// adding edges only for types actually allocated (transitively reachable).
// It is faster than VTA but misses some interface-dispatch edges that VTA catches.
//
// Note: RTA requires InstantiateGenerics (set in BuildSSA) for correct generic
// function handling — without it, generic instantiations are missing from the
// reachable set and vulnerable symbols inside them appear NOT_REACHABLE.
func buildRTA(prog *ssa.Program, roots []*ssa.Function) (*callgraph.Graph, string, error) {
	// Filter out nil roots; rta.Analyze panics on nil entries.
	valid := make([]*ssa.Function, 0, len(roots))
	for _, r := range roots {
		if r != nil {
			valid = append(valid, r)
		}
	}
	_ = prog // RTA only needs the roots; prog is already built
	result := rta.Analyze(valid, true /* buildCallGraph */)
	return result.CallGraph, AlgorithmRTA, nil
}
