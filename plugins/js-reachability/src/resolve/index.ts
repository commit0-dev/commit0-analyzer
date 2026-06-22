/**
 * Public API for the module resolver.
 * Re-exports the resolver and its types so callers import from "resolve/index.js".
 */
export {
  resolveSpecifier,
  type ResolveContext,
  type ResolveResult,
  type ResolveResultFirstParty,
  type ResolveResultThirdParty,
  type ResolveResultUnknown,
} from "./node-resolution.js";

export {
  resolveExportsMap,
  parsePackageSpecifier,
  type ExportsMapValue,
  type ExportsConditionMap,
} from "./exports-map.js";
