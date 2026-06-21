package engine

import (
	"context"
	"fmt"
	"go/token"
	"strings"

	anstv1 "github.com/ducthinh993/anst-analyzer/pkg/contract/anstv1"
	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
)

// Analyze is the top-level library entry point: given an AnalyzeRequest, it
// loads the module, builds SSA + a call graph, resolves every advisory symbol,
// computes reachability from the detected entry points, and returns Findings.
//
// The builder parameter is pluggable so callers (tests, runner) can select the
// call-graph algorithm. Pass nil to use DefaultGraphBuilder (VTA on CHA base).
func Analyze(ctx context.Context, req *anstv1.AnalyzeRequest, builder GraphBuilder) ([]*anstv1.Finding, error) {
	if builder == nil {
		builder = DefaultGraphBuilder
	}

	// Validate module root.
	moduleRoot, err := ResolveModuleRoot(req.GetModuleRoot())
	if err != nil {
		return nil, fmt.Errorf("analyze: %w", err)
	}

	// Resolve build config.
	bc := req.GetBuildConfig()
	goos := EffectiveGOOS("")
	goarch := EffectiveGOARCH("")
	var tags []string
	if bc != nil {
		goos = EffectiveGOOS(bc.GetGoos())
		goarch = EffectiveGOARCH(bc.GetGoarch())
		tags = bc.GetTags()
	}

	// Load packages.
	lcfg := LoadConfig{
		Dir:      moduleRoot,
		GOOS:     goos,
		GOARCH:   goarch,
		Tags:     tags,
		Patterns: req.GetEntrypoints(),
	}
	pkgs, fset, err := LoadPackages(lcfg)
	if err != nil {
		// Hard load failure — all advisories → UNKNOWN.
		return allUnknown(req, goos, goarch, tags, AlgorithmVTA,
			"packages.Load failed: "+err.Error()), nil
	}

	// Collect IllTyped packages for per-finding UNKNOWN promotion (Red Team Crit #4).
	illTypedMods := collectIllTypedModules(pkgs)

	// Build SSA.
	prog, ssaPkgs := BuildSSA(pkgs)

	// Detect entry points.
	roots := EntryPointsForProgram(prog, ssaPkgs, req.GetEntrypoints())

	// Build the call graph.
	cg, algorithm, err := builder(prog, roots)
	if err != nil {
		return allUnknown(req, goos, goarch, tags, AlgorithmVTA,
			"call-graph construction failed: "+err.Error()), nil
	}

	// Collect reachable function set for reflection detection (Crit #3).
	reachableFromRoots := CollectReachable(cg, roots)
	reflectPresent := false
	for fn := range reachableFromRoots {
		if IsReflectDynamic(fn) {
			reflectPresent = true
			break
		}
	}

	// Base properties stamped into every finding.
	baseProps := map[string]string{
		"goos":      goos,
		"goarch":    goarch,
		"algorithm": algorithm,
	}
	if len(tags) > 0 {
		baseProps["tags"] = strings.Join(tags, ",")
	}

	var findings []*anstv1.Finding
	for _, adv := range req.GetAdvisories() {
		findings = append(findings,
			analyzeAdvisory(prog, fset, cg, roots, reflectPresent, illTypedMods, adv, baseProps)...,
		)
	}
	return findings, nil
}

// analyzeAdvisory computes findings for a single advisory.
func analyzeAdvisory(
	prog *ssa.Program,
	fset *token.FileSet,
	cg *callgraph.Graph,
	roots []*ssa.Function,
	reflectPresent bool,
	illTypedMods map[string]string,
	adv *anstv1.Advisory,
	baseProps map[string]string,
) []*anstv1.Finding {
	advRef := &anstv1.AdvisoryRef{Id: adv.GetId()}
	props := copyProps(baseProps)

	// Build error for this advisory's module → UNKNOWN (Red Team Crit #4).
	if buildErr, bad := illTypedMods[adv.GetModule()]; bad {
		props["build_error"] = buildErr
		return []*anstv1.Finding{{
			Advisory:   advRef,
			Module:     adv.GetModule(),
			Confidence: anstv1.Confidence_CONFIDENCE_UNKNOWN,
			Properties: props,
		}}
	}

	// Package-level advisory (SymbolLevel==false).
	if !adv.GetSymbolLevel() {
		pkgImported := false
		if len(adv.GetSymbols()) > 0 {
			for _, sym := range adv.GetSymbols() {
				if IsPackageImported(prog, sym.GetPackage()) {
					pkgImported = true
					break
				}
			}
		} else {
			pkgImported = isModuleImported(prog, adv.GetModule())
		}
		conf := anstv1.Confidence_CONFIDENCE_NOT_REACHABLE
		if pkgImported {
			conf = anstv1.Confidence_CONFIDENCE_PACKAGE_REACHABLE
		}
		return []*anstv1.Finding{{
			Advisory:   advRef,
			Module:     adv.GetModule(),
			Confidence: conf,
			Properties: props,
		}}
	}

	// Symbol-level advisory: one finding per symbol.
	var findings []*anstv1.Finding
	for _, sym := range adv.GetSymbols() {
		rr := ResolveSymbol(prog, sym)

		inp := ConfidenceInput{
			SymbolLevel:   true,
			PkgPath:       sym.GetPackage(),
			Resolved:      rr.Fn != nil,
			PkgImported:   IsPackageImported(prog, sym.GetPackage()),
			ReflectInPath: reflectPresent,
		}
		if rr.Unknown {
			inp.ResolutionError = rr.Reason
		}
		if rr.Fn != nil {
			inp.BFSResult = BFSReachable(cg, roots, rr.Fn)
			inp.TargetAddrTaken = IsAddressTaken(prog, rr.Fn)
		}

		symProps := copyProps(props)
		if rr.Unknown && rr.Reason != "" {
			symProps["resolution_error"] = rr.Reason
		}

		conf, callPath := AssignConfidence(inp)
		f := &anstv1.Finding{
			Advisory:   advRef,
			Module:     adv.GetModule(),
			Confidence: conf,
			Properties: symProps,
		}
		if conf == anstv1.Confidence_CONFIDENCE_SYMBOL_REACHABLE && len(callPath) > 0 {
			f.Path = stepsToProto(callPath, fset)
		}
		findings = append(findings, f)
	}
	return findings
}

// allUnknown returns one UNKNOWN finding per advisory when analysis fails globally.
func allUnknown(req *anstv1.AnalyzeRequest, goos, goarch string, tags []string, algorithm, reason string) []*anstv1.Finding {
	props := map[string]string{
		"goos":      goos,
		"goarch":    goarch,
		"algorithm": algorithm,
		"error":     reason,
	}
	if len(tags) > 0 {
		props["tags"] = strings.Join(tags, ",")
	}
	var findings []*anstv1.Finding
	for _, adv := range req.GetAdvisories() {
		findings = append(findings, &anstv1.Finding{
			Advisory:   &anstv1.AdvisoryRef{Id: adv.GetId()},
			Module:     adv.GetModule(),
			Confidence: anstv1.Confidence_CONFIDENCE_UNKNOWN,
			Properties: copyProps(props),
		})
	}
	return findings
}

// collectIllTypedModules walks loaded packages and returns module path → error
// for every IllTyped package (Red Team Crit #4: never silent NOT_REACHABLE).
func collectIllTypedModules(pkgs []*packages.Package) map[string]string {
	result := make(map[string]string)
	packages.Visit(pkgs, func(pkg *packages.Package) bool {
		if pkg.IllTyped && pkg.Module != nil {
			var errs []string
			for _, e := range pkg.Errors {
				errs = append(errs, e.Error())
			}
			if len(errs) > 0 {
				result[pkg.Module.Path] = strings.Join(errs, "; ")
			} else {
				result[pkg.Module.Path] = "ill-typed (unknown error)"
			}
		}
		return true
	}, nil)
	return result
}

// isModuleImported reports whether any loaded package belongs to modulePath.
func isModuleImported(prog *ssa.Program, modulePath string) bool {
	for pkg := range ssautil.AllFunctions(prog) {
		if pkg == nil || pkg.Package() == nil || pkg.Package().Pkg == nil {
			continue
		}
		// Match the module path exactly or as a parent directory of the package
		// path. A bare HasPrefix would over-match prefix-colliding modules
		// (e.g. "golang.org/x/te" matching package "golang.org/x/text/...").
		path := pkg.Package().Pkg.Path()
		if path == modulePath || strings.HasPrefix(path, modulePath+"/") {
			return true
		}
	}
	return false
}

// stepsToProto converts the internal PathStep slice to the proto ReachabilityPath.
// The call-site location points to where the call happens (the edge Site).
func stepsToProto(steps []PathStep, fset *token.FileSet) *anstv1.ReachabilityPath {
	if len(steps) == 0 {
		return nil
	}
	proto := &anstv1.ReachabilityPath{}
	for _, s := range steps {
		cs := &anstv1.CallStep{Symbol: FullyQualifiedName(s.Fn)}
		if s.Edge != nil && s.Edge.Site != nil {
			pos := s.Edge.Site.Pos()
			if pos != token.NoPos {
				p := fset.Position(pos)
				cs.Location = &anstv1.Location{
					File:   p.Filename,
					Line:   int32(p.Line),
					Column: int32(p.Column),
				}
			}
		} else if s.Fn != nil && s.Fn.Pos().IsValid() {
			// Root step: use the function's declaration position.
			p := fset.Position(s.Fn.Pos())
			cs.Location = &anstv1.Location{
				File:   p.Filename,
				Line:   int32(p.Line),
				Column: int32(p.Column),
			}
		}
		proto.Steps = append(proto.Steps, cs)
	}
	return proto
}

// FullyQualifiedName returns "pkg/path.FuncName" for an SSA function.
func FullyQualifiedName(fn *ssa.Function) string {
	if fn == nil {
		return "<nil>"
	}
	pkg := ""
	if fn.Package() != nil && fn.Package().Pkg != nil {
		pkg = fn.Package().Pkg.Path() + "."
	}
	return pkg + fn.Name()
}

// copyProps shallow-copies a properties map so each finding gets its own map.
func copyProps(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
