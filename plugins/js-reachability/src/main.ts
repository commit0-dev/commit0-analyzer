/**
 * Entry point for the js-reachability plugin binary.
 *
 * Three subcommand modes:
 *   serve       (default) — start the gRPC plugin server for the host
 *   --list-deps           — enumerate npm dependencies from the project model
 *   --analyze             — run standalone reachability analysis
 *
 * Each mode delegates to its own module so the entry point stays stable
 * as individual modes evolve.
 */

// Sidecar shim must be the first import so the oxc .node resolution is
// patched before any downstream require() for native addons.
import "./sidecar.js";

const arg = process.argv[2];

if (arg === "--list-deps") {
  await import("./list-deps.js").then((m) => m.run());
} else if (arg === "--analyze") {
  await import("./analyze.js").then((m) => m.run());
} else if (arg === "--project-model") {
  await import("./project-model-cmd.js").then((m) => m.run());
} else {
  // Default mode: serve as a go-plugin gRPC subprocess.
  await import("./server.js").then((m) => m.run());
}
