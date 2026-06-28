/**
 * go-plugin v1.8.0 handshake implementation.
 *
 * Responsibilities:
 *  - Validate the magic-cookie env var; exit 1 with a human-readable error if missing/wrong.
 *  - Start a gRPC server on tcp 127.0.0.1:0 (ephemeral port, no AutoMTLS).
 *  - Write the exactly one handshake line to stdout so the host can parse it.
 *  - Return the bound server so the caller can register services before calling serve().
 *
 * Handshake line format (go-plugin client.go v1.8.0):
 *   1|<AppProto>|tcp|127.0.0.1:<port>|grpc
 *
 *   CoreProtocol = 1  (always the literal 1 in the 5-field form)
 *   AppProto     = ProtocolMajor + 1 = 0 + 1 = 1
 *   network      = tcp  (cross-platform; avoids unix-socket portability issues)
 *   protocol     = grpc (the literal token; host AllowedProtocols is gRPC-only)
 *
 * The 5-field form is accepted by go-plugin v1.8.0 because fields 6+ (serverCert,
 * grpcMux) are optional. AutoMTLS is OFF: the host does not send PLUGIN_CLIENT_CERT,
 * so insecure credentials are the correct choice.
 *
 * Shutdown sequence:
 *  1. Graceful (primary): go-plugin calls GRPCController.Shutdown RPC → handler calls
 *     process.exit(0). Measured ~0.15 s; this is the normal production path.
 *  2. SIGTERM (belt-and-suspenders): registered in serveUntilDone as a fallback for
 *     platforms or scenarios where go-plugin kills via signal rather than RPC.
 *
 * Note on stdin: go-plugin v1.8.0 unconditionally sets cmd.Stdin = os.Stdin on the
 * host side (client.go:659), so the plugin always inherits the host's own stdin.
 * In production the host stdin stays open for its lifetime; in some test environments
 * it may be /dev/null (immediate EOF). stdin-EOF is therefore NOT used as a shutdown
 * trigger — it is not a reliable signal. Shutdown is driven by GRPCController only.
 */

import * as grpc from "@grpc/grpc-js";

const MAGIC_COOKIE_KEY = "ANST_PLUGIN_MAGIC_COOKIE";
const MAGIC_COOKIE_VALUE = "commit0-analyzer-v0-plugin"; // NOTE: prebuilt binary uses "anst-analyzer-v0-plugin" until bun recompiles it

// go-plugin protocol constants.
const CORE_PROTOCOL = 1;
// AppProto = contract.ProtocolMajor + 1. ProtocolMajor is 0, so AppProto = 1.
const APP_PROTO = 1;

export function checkMagicCookie(): void {
  const value = process.env[MAGIC_COOKIE_KEY];
  if (value !== MAGIC_COOKIE_VALUE) {
    process.stderr.write(
      `This binary is a plugin for commit0-analyzer and must be launched by the host process.\n` +
        `It cannot be run directly.\n` +
        `Expected env var ${MAGIC_COOKIE_KEY}=${MAGIC_COOKIE_VALUE}.\n`,
    );
    process.exit(1);
  }
}

/**
 * Builds the go-plugin handshake line for a given bound port.
 * Exported for unit-testing the format without starting a real server.
 */
export function buildHandshakeLine(port: number): string {
  return `${CORE_PROTOCOL}|${APP_PROTO}|tcp|127.0.0.1:${port}|grpc\n`;
}

/**
 * Starts the gRPC server on an ephemeral port, writes the handshake line,
 * and resolves once the server is listening.
 *
 * The caller registers gRPC service implementations on the returned server
 * before this function is called — pass a fully-wired server in.
 */
export function startAndHandshake(server: grpc.Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.bindAsync(
      "127.0.0.1:0",
      grpc.ServerCredentials.createInsecure(),
      (err, port) => {
        if (err) {
          reject(err);
          return;
        }

        // Emit the handshake line before signalling readiness so the host can
        // parse the port before any gRPC traffic arrives.
        process.stdout.write(buildHandshakeLine(port));

        resolve();
      },
    );
  });
}

/**
 * Blocks until a shutdown signal is received, then forces the gRPC server down.
 *
 * Primary shutdown path: the GRPCController.Shutdown RPC (registered in serve.ts)
 * calls process.exit(0) directly, so this promise will be resolved via the
 * forceShutdown() call or the process will have already exited. The SIGTERM
 * handler here is a belt-and-suspenders fallback — it fires the same shutdown
 * path without waiting for the RPC.
 *
 * stdin is NOT monitored here. go-plugin v1.8.0 passes the host's own stdin to
 * the plugin (cmd.Stdin = os.Stdin on the host), making stdin-EOF unreliable as
 * a shutdown signal (it fires immediately when the host stdin is /dev/null, e.g.
 * in some test environments). Correctness depends on GRPCController.Shutdown only.
 */
export function serveUntilDone(server: grpc.Server): Promise<void> {
  return new Promise((resolve) => {
    let resolved = false;
    function shutdown() {
      if (resolved) return;
      resolved = true;
      server.forceShutdown();
      resolve();
    }

    // SIGTERM: belt-and-suspenders fallback for platforms that signal rather than RPC.
    process.on("SIGTERM", shutdown);
  });
}
