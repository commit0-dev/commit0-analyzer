package engine

import (
	"go/token"
	"sort"

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// PathStep records one frame in a BFS traversal: the function at this node
// and the call-site edge that led here (nil edge means entry-point root).
type PathStep struct {
	Fn   *ssa.Function
	Edge *callgraph.Edge // edge whose Callee == Fn; nil for roots
}

// predEntry records how BFS reached a function.
type predEntry struct {
	fn   *ssa.Function
	edge *callgraph.Edge
}

// ReachResult is the outcome of a single BFS reachability query.
type ReachResult struct {
	// Reachable is true when a path from any root to target was found.
	Reachable bool
	// Path is the ordered sequence: root → … → target.
	// Only populated when Reachable==true.
	Path []PathStep
}

// BFSReachable performs a BFS over the call graph from the given roots,
// searching for target. It returns the shortest path found, or an empty
// result if target is not reachable.
//
// Determinism (Red Team Crit #5):
//
//	callgraph.Graph.Nodes is a map and each Node.Out slice is unordered.
//	We sort both the initial root set and each node's outbound edges by a
//	stable key = (callee package path, callee name, call-site position) before
//	enqueueing. Ties among equal-length paths are broken lexicographically by
//	the same key, so the output is byte-identical across runs regardless of
//	Go's map-iteration randomness or GODEBUG=randmapseed settings.
func BFSReachable(cg *callgraph.Graph, roots []*ssa.Function, target *ssa.Function) ReachResult {
	if target == nil {
		return ReachResult{}
	}

	predecessor := make(map[*ssa.Function]*predEntry)

	// Sort roots deterministically before seeding the queue.
	sortedRoots := make([]*ssa.Function, len(roots))
	copy(sortedRoots, roots)
	sort.Slice(sortedRoots, func(i, j int) bool {
		return FnKey(sortedRoots[i]) < FnKey(sortedRoots[j])
	})

	queue := make([]*ssa.Function, 0, len(sortedRoots))
	for _, r := range sortedRoots {
		if r == nil {
			continue
		}
		if _, seen := predecessor[r]; seen {
			continue
		}
		predecessor[r] = &predEntry{fn: nil, edge: nil}
		queue = append(queue, r)
		if r == target {
			return ReachResult{Reachable: true, Path: extractPath(predecessor, target)}
		}
	}

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		node := cg.Nodes[cur]
		if node == nil {
			continue
		}

		// Sort outbound edges for determinism before visiting.
		edges := sortedOutEdges(node.Out)
		for _, edge := range edges {
			callee := edge.Callee.Func
			if callee == nil {
				continue
			}
			if _, seen := predecessor[callee]; seen {
				continue
			}
			predecessor[callee] = &predEntry{fn: cur, edge: edge}
			if callee == target {
				return ReachResult{Reachable: true, Path: extractPath(predecessor, target)}
			}
			queue = append(queue, callee)
		}
	}

	return ReachResult{Reachable: false}
}

// extractPath reconstructs the path from a root to target by following the
// predecessor map backward, then reversing into root→target order.
func extractPath(predecessor map[*ssa.Function]*predEntry, target *ssa.Function) []PathStep {
	var reversed []PathStep
	cur := target
	for {
		pred, ok := predecessor[cur]
		if !ok {
			break
		}
		reversed = append(reversed, PathStep{Fn: cur, Edge: pred.edge})
		if pred.fn == nil {
			break // reached a root
		}
		cur = pred.fn
	}

	// Reverse to get root → target order.
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	return reversed
}

// FnKey returns a stable string key for deterministic sorting of SSA functions.
// Format: "<package-path>.<function-name>@<position>".
func FnKey(fn *ssa.Function) string {
	if fn == nil {
		return ""
	}
	pkg := ""
	if fn.Package() != nil && fn.Package().Pkg != nil {
		pkg = fn.Package().Pkg.Path()
	}
	pos := ""
	if fn.Pos().IsValid() {
		pos = fn.Prog.Fset.Position(fn.Pos()).String()
	}
	return pkg + "." + fn.Name() + "@" + pos
}

// edgeKey returns a stable sort key for a callgraph edge.
func edgeKey(e *callgraph.Edge) string {
	key := FnKey(e.Callee.Func)
	if e.Site != nil {
		pos := e.Site.Pos()
		if pos != token.NoPos {
			key += "|" + e.Callee.Func.Prog.Fset.Position(pos).String()
		}
	}
	return key
}

// sortedOutEdges returns a deterministically-ordered copy of a node's Out edges.
func sortedOutEdges(edges []*callgraph.Edge) []*callgraph.Edge {
	out := make([]*callgraph.Edge, len(edges))
	copy(out, edges)
	sort.Slice(out, func(i, j int) bool {
		return edgeKey(out[i]) < edgeKey(out[j])
	})
	return out
}

// CollectReachable returns the set of all SSA functions reachable from roots
// in the call graph. Used for reflection-detection (Red Team Crit #3).
func CollectReachable(cg *callgraph.Graph, roots []*ssa.Function) map[*ssa.Function]bool {
	visited := make(map[*ssa.Function]bool)
	queue := make([]*ssa.Function, 0, len(roots))
	for _, r := range roots {
		if r != nil && !visited[r] {
			visited[r] = true
			queue = append(queue, r)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		node := cg.Nodes[cur]
		if node == nil {
			continue
		}
		for _, e := range node.Out {
			if e.Callee == nil || e.Callee.Func == nil {
				continue
			}
			callee := e.Callee.Func
			if !visited[callee] {
				visited[callee] = true
				queue = append(queue, callee)
			}
		}
	}
	return visited
}

// IsReflectDynamic returns true if fn directly calls reflect.Value.Call,
// reflect.Value.CallSlice, reflect.Value.Method, or reflect.Value.MethodByName.
// These are the dynamic-dispatch entry points in the reflect package for which
// VTA/CHA produce no call-graph edge (Red Team Crit #3).
func IsReflectDynamic(fn *ssa.Function) bool {
	if fn == nil {
		return false
	}
	for _, b := range fn.Blocks {
		for _, instr := range b.Instrs {
			call, ok := instr.(ssa.CallInstruction)
			if !ok {
				continue
			}
			c := call.Common()
			if c.IsInvoke() {
				continue // statically-typed interface invoke — not reflection
			}
			callee, ok := c.Value.(*ssa.Function)
			if !ok {
				continue
			}
			if callee.Package() == nil || callee.Package().Pkg == nil {
				continue
			}
			if callee.Package().Pkg.Path() != "reflect" {
				continue
			}
			switch callee.Name() {
			case "Value.Call", "Value.CallSlice", "Value.Method", "Value.MethodByName",
				"Call", "CallSlice":
				return true
			}
		}
	}
	return false
}

// IsAddressTaken reports whether fn appears as a first-class value in any
// instruction operand outside of fn itself. This is the SSA approximation of
// "address-taken" — used to detect functions that may be called dynamically
// via reflection or function values without a static call-graph edge.
func IsAddressTaken(prog *ssa.Program, fn *ssa.Function) bool {
	for f := range ssautil.AllFunctions(prog) {
		for _, b := range f.Blocks {
			for _, instr := range b.Instrs {
				for _, op := range instr.Operands(nil) {
					if op != nil && *op == fn {
						if f == fn {
							continue // self-reference within own body
						}
						return true
					}
				}
			}
		}
	}
	return false
}
