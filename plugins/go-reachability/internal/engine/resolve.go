package engine

import (
	"go/types"
	"strings"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
	"golang.org/x/tools/go/ssa"
)

// ResolveResult is the outcome of resolving one advisory symbol.
type ResolveResult struct {
	Fn      *ssa.Function // nil when unresolved
	Unknown bool          // true when the symbol applies but cannot be resolved
	Reason  string        // human-readable reason for unknown
}

// ResolveSymbol maps an advisory Symbol (package + name) to an *ssa.Function in
// the SSA program. It handles three forms of symbol name:
//
//  1. Plain function:   "FuncName"          → pkg.Func("FuncName")
//  2. Value method:     "Type.Method"       → method set of *types.Named
//  3. Pointer method:   "(*Type).Method"    → pointer method set
//
// If the package is present but the named symbol does not resolve to an
// *ssa.Function, the result has Unknown=true. This satisfies Red Team Crit #12b:
// unresolved symbol → UNKNOWN, never drop.
func ResolveSymbol(prog *ssa.Program, sym *anstv1.Symbol) ResolveResult {
	pkgPath := sym.GetPackage()
	symName := sym.GetName()

	// Find the SSA package by import path.
	ssaPkg := prog.ImportedPackage(pkgPath)
	if ssaPkg == nil {
		return ResolveResult{
			Unknown: true,
			Reason:  "package not found in SSA program: " + pkgPath,
		}
	}

	// Ensure the package is built before member lookup.
	ssaPkg.Build()

	// Case 1: pointer receiver — strip "(*Type)." prefix.
	if strings.HasPrefix(symName, "(*") {
		inner := strings.TrimPrefix(symName, "(*")
		dot := strings.Index(inner, ").")
		if dot < 0 {
			return ResolveResult{Unknown: true, Reason: "malformed pointer-method symbol: " + symName}
		}
		typeName := inner[:dot]
		methodName := inner[dot+2:]
		return resolveMethodOnType(prog, ssaPkg, typeName, methodName, true)
	}

	// Case 2: value receiver method — "TypeName.MethodName".
	if dot := strings.Index(symName, "."); dot >= 0 {
		typeName := symName[:dot]
		methodName := symName[dot+1:]
		return resolveMethodOnType(prog, ssaPkg, typeName, methodName, false)
	}

	// Case 3: plain package-level function.
	mem := ssaPkg.Members[symName]
	if mem == nil {
		return ResolveResult{
			Unknown: true,
			Reason:  "symbol not found as package member: " + pkgPath + "." + symName,
		}
	}
	fn, ok := mem.(*ssa.Function)
	if !ok {
		return ResolveResult{
			Unknown: true,
			Reason:  "symbol is not a function: " + pkgPath + "." + symName,
		}
	}
	return ResolveResult{Fn: fn}
}

// resolveMethodOnType looks up a named method on a type within the given SSA package.
// pointer=true looks in the pointer receiver method set; false uses the value receiver set.
func resolveMethodOnType(prog *ssa.Program, pkg *ssa.Package, typeName, methodName string, pointer bool) ResolveResult {
	scope := pkg.Pkg.Scope()
	obj := scope.Lookup(typeName)
	if obj == nil {
		return ResolveResult{
			Unknown: true,
			Reason:  "type not found in package scope: " + typeName,
		}
	}
	named, ok := obj.Type().(*types.Named)
	if !ok {
		return ResolveResult{
			Unknown: true,
			Reason:  "object is not a named type: " + typeName,
		}
	}

	var recv types.Type = named
	if pointer {
		recv = types.NewPointer(named)
	}

	sel := prog.MethodSets.MethodSet(recv)
	for i := 0; i < sel.Len(); i++ {
		m := sel.At(i)
		if m.Obj().Name() == methodName {
			fn := prog.MethodValue(m)
			if fn == nil {
				return ResolveResult{
					Unknown: true,
					Reason:  "MethodValue returned nil for: " + typeName + "." + methodName,
				}
			}
			return ResolveResult{Fn: fn}
		}
	}

	return ResolveResult{
		Unknown: true,
		Reason:  "method not found in method set: " + typeName + "." + methodName,
	}
}

// IsPackageImported reports whether the given import path is present in the SSA program.
func IsPackageImported(prog *ssa.Program, pkgPath string) bool {
	return prog.ImportedPackage(pkgPath) != nil
}
