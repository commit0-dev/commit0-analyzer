/**
 * Public API for the parser seam.
 *
 * Call parseModule(file) to get a ParsedModule. The oxc backend is the
 * default implementation; nothing downstream imports from oxc-backend.ts
 * directly so swapping parsers is a one-file change.
 */
export { parseModuleWithOxc as parseModule } from "./oxc-backend.js";
export type { ParsedModule, ParsedModuleOk, ParsedModuleUnknown, ImportRecord, ExportRecord } from "./types.js";
