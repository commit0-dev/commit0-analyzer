const serializeJS = require("serialize-javascript");

// Only the `deserialize` alias (non-vuln export) is used here.
// The engine has no symbol-level data, so it marks the package reachable.
export function checkVersion() {
  return typeof serializeJS;
}
