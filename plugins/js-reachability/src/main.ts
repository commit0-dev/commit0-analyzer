/**
 * Entry point for the js-reachability plugin binary.
 *
 * Three subcommand modes:
 *   serve       (default) — start the gRPC plugin server for the host
 *   --list-deps           — list npm dependencies (stub; filled in Phase 3)
 *   --analyze             — run standalone analysis (stub; filled in Phase 5)
 *
 * Each mode delegates to its own module so later phases can extend those
 * modules without touching this file.
 */

// Sidecar shim must be the first import so the oxc .node resolution is
// patched before any downstream require() for native addons.
import "./sidecar.js";

const arg = process.argv[2];

if (arg === "--list-deps") {
  await import("./list-deps.js").then((m) => m.run());
} else if (arg === "--analyze") {
  await import("./analyze.js").then((m) => m.run());
} else {
  // Default mode: serve as a go-plugin gRPC subprocess.
  await import("./server.js").then((m) => m.run());
}
